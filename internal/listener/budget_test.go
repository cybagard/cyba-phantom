package listener

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// periodRec is what the wrapper of one connection counted in one period. The
// late bytes, read after the response write, are not in used.
type periodRec struct{ used, charged int64 }

func (c *limitConn) snapshot() periodRec {
	c.mu.Lock()
	defer c.mu.Unlock()
	return periodRec{c.used - c.late, c.charged}
}

// readTotal is the bytes that the wrapper read in this period, late ones too.
func (c *limitConn) readTotal() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.used
}

// periodLog records the counts of the wrapper at each idle state and at each
// close, before the production hook acts on them. conn is the last wrapper.
type periodLog struct {
	mu           sync.Mutex
	idle, closed []periodRec
	conn         atomic.Pointer[limitConn]
}

func (l *periodLog) lens() (int, int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.idle), len(l.closed)
}

// wait waits for at least idle idle records and closed close records, and
// returns copies of both lists.
func (l *periodLog) wait(t *testing.T, idle, closed int) (i, c []periodRec) {
	t.Helper()
	waitFor(t, "period records", func() bool { a, b := l.lens(); return a >= idle && b >= closed })
	l.mu.Lock()
	defer l.mu.Unlock()
	return append(i, l.idle...), append(c, l.closed...)
}

// watchPeriods wraps the ConnState hook of the server. Call it before serve.
func (r *rig) watchPeriods() *periodLog {
	l := new(periodLog)
	hook := r.s.srv.ConnState
	r.s.srv.ConnState = func(c net.Conn, st http.ConnState) {
		if tc, ok := c.(*tls.Conn); ok {
			if lc, ok := tc.NetConn().(*limitConn); ok {
				l.conn.Store(lc)
				l.mu.Lock()
				switch st {
				case http.StateIdle:
					l.idle = append(l.idle, lc.snapshot())
				case http.StateClosed:
					l.closed = append(l.closed, lc.snapshot())
				}
				l.mu.Unlock()
			}
		}
		hook(c, st)
	}
	return l
}

// dialWhole opens a TLS connection that puts a Write of up to 16 KiB in one
// record. The default client sends the first records of a connection small, so
// the server could read a request before it reads the end of the same Write.
func (r *rig) dialWhole(t *testing.T) *tls.Conn {
	t.Helper()
	cfg := r.clientConfig()
	cfg.DynamicRecordSizingDisabled = true
	c, err := tls.Dial("tcp", r.addr, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// countConn counts the bytes that the client writes.
type countConn struct {
	net.Conn
	n int
}

func (c *countConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.n += n
	return n, err
}

// dialReading opens a TLS 1.3 connection from 127.0.0.<host>. Then it writes one
// encrypted record with the start of a Certificate-type message, so that the
// server reads exactly total bytes in the first period and waits for more.
func (r *rig) dialReading(t *testing.T, host byte, total int) *tls.Conn {
	t.Helper()
	raw, err := loopbackDialer(host).Dial("tcp", r.addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	cc := &countConn{Conn: raw}
	var keyLog bytes.Buffer
	cfg := r.clientConfig()
	cfg.MinVersion, cfg.KeyLogWriter = tls.VersionTLS13, &keyLog
	tc := tls.Client(cc, cfg)
	if err := tc.Handshake(); err != nil {
		t.Fatal(err)
	}
	w := newRecordWriter(t, keyLog.String(), tc.ConnectionState().CipherSuite)
	// A record is 5 bytes of header, the message, 1 byte of type and 16 of tag.
	rec := w.handshake(certMessage()[:total-cc.n-22])
	if cc.n+len(rec) != total {
		t.Fatalf("record of %d bytes after %d handshake bytes, want %d in all", len(rec), cc.n, total)
	}
	_, _ = raw.Write(rec) // the server can close before the write ends
	return tc
}

// manyProtos returns n ALPN values of 255 bytes, then http/1.1.
func manyProtos(n int) []string {
	var ps []string
	for range n {
		ps = append(ps, strings.Repeat("a", 255))
	}
	return append(ps, "http/1.1")
}

// certMessage is a handshake message of the Certificate type, 4 + 262000 bytes.
func certMessage() []byte {
	m := make([]byte, 4+262000)
	m[0], m[1], m[2], m[3] = 11, 0x03, 0xFF, 0x70
	return m
}

// plainRecords puts msg in plaintext handshake records of 16384 bytes.
func plainRecords(msg []byte) []byte {
	var out bytes.Buffer
	for len(msg) > 0 {
		k := min(16384, len(msg))
		out.Write([]byte{22, 3, 3, byte(k >> 8), byte(k)})
		out.Write(msg[:k])
		msg = msg[k:]
	}
	return out.Bytes()
}

// nthWrite replaces the payload of its at-th Write with raw bytes.
type nthWrite struct {
	net.Conn
	n, at   int
	payload []byte
}

func (c *nthWrite) Write(p []byte) (int, error) {
	if c.n++; c.n != c.at {
		return c.Conn.Write(p)
	}
	_, err := c.Conn.Write(c.payload)
	return len(p), err
}

// recordWriter writes TLS 1.3 records with the client application traffic key,
// from the key log of the client. The first record that it writes has sequence
// number 0, so use it only for the first records after the handshake. Each
// record that it writes adds 1 to the number.
type recordWriter struct {
	aead cipher.AEAD
	iv   []byte
	seq  uint64
}

func expandLabel(t *testing.T, h func() hash.Hash, secret []byte, label string, n int) []byte {
	t.Helper()
	full := "tls13 " + label
	info := append([]byte{byte(n >> 8), byte(n), byte(len(full))}, full...)
	out, err := hkdf.Expand(h, secret, string(append(info, 0)), n)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func newRecordWriter(t *testing.T, keyLog string, suite uint16) *recordWriter {
	t.Helper()
	var secret []byte
	for _, line := range strings.Split(keyLog, "\n") {
		if f := strings.Fields(line); len(f) == 3 && f[0] == "CLIENT_TRAFFIC_SECRET_0" {
			secret, _ = hex.DecodeString(f[2])
		}
	}
	h, keyLen := sha256.New, 16
	switch suite {
	case tls.TLS_AES_128_GCM_SHA256:
	case tls.TLS_AES_256_GCM_SHA384:
		h, keyLen = sha512.New384, 32
	default:
		t.Fatalf("cipher suite %#x: the record writer does AES-GCM only", suite)
	}
	if secret == nil {
		t.Fatal("no client traffic secret in the key log")
	}
	blk, err := aes.NewCipher(expandLabel(t, h, secret, "key", keyLen))
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(blk)
	if err != nil {
		t.Fatal(err)
	}
	return &recordWriter{aead: aead, iv: expandLabel(t, h, secret, "iv", 12)}
}

// handshake returns msg as encrypted handshake records of 16384 bytes.
func (w *recordWriter) handshake(msg []byte) []byte {
	var out bytes.Buffer
	for len(msg) > 0 {
		k := min(16384, len(msg))
		inner := append(append([]byte{}, msg[:k]...), 22)
		msg = msg[k:]
		nonce := append([]byte{}, w.iv...)
		for j := range 8 {
			nonce[4+j] ^= byte(w.seq >> (56 - 8*j))
		}
		w.seq++
		l := len(inner) + w.aead.Overhead()
		ad := []byte{23, 3, 3, byte(l >> 8), byte(l)}
		out.Write(ad)
		out.Write(w.aead.Seal(nil, nonce, inner, ad))
	}
	return out.Bytes()
}

// lateResult is the result of lateRequests.
type lateResult struct {
	c      *tls.Conn
	br     *bufio.Reader
	second int   // status of the second response, 0: none
	base   int64 // bytes that the client wrote before rest
	l      *periodLog
}

// lateRequests forces the late bytes. The handler flushes a whole response and
// waits. The client writes first, reads that response, and writes rest. The
// test waits until the wrapper has read the late bytes (all of them with whole,
// else the first record), and only then lets the handler return. So the bytes
// reach the wrapper before the idle state in every run, with no sleep. With
// whole the client sends one record for each write.
func lateRequests(t *testing.T, whole bool, first, rest string) lateResult {
	t.Helper()
	release := make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	r := newRig(t, 8, testHeaderBytes, defaultTimeouts, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "2")
		_, _ = io.WriteString(w, "ok")
		w.(http.Flusher).Flush()
		<-release
	}))
	l := r.watchPeriods()
	r.serve(t)
	raw, err := net.Dial("tcp", r.addr)
	if err != nil {
		t.Fatal(err)
	}
	cc := &countConn{Conn: raw}
	cfg := r.clientConfig()
	cfg.DynamicRecordSizingDisabled = whole
	c := tls.Client(cc, cfg)
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if err := c.Handshake(); err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(c, first)
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	res := lateResult{c: c, br: br, base: int64(cc.n), l: l}
	_, _ = io.WriteString(c, rest)
	total := int64(cc.n)
	waitFor(t, "the late bytes in the wrapper", func() bool {
		lc := l.conn.Load()
		return lc != nil && (whole && lc.readTotal() >= total || !whole && lc.readTotal() > res.base)
	})
	once.Do(func() { close(release) })
	if resp2, err := http.ReadResponse(br, nil); err == nil {
		res.second = resp2.StatusCode
		_, _ = io.Copy(io.Discard, resp2.Body)
	}
	return res
}

// T-S-18: split write, forced. The client writes the rest of the second head
// after it read the first response and before the idle state. The rest is more
// than 4096 bytes, so the wrapper reads it in several Reads. The first period
// holds only the bytes before it, and the rest starts the next period. A head
// that fits the next budget gets 200. A head of header_bytes + 4097 bytes is
// not served.
func TestTS18LateBytesStartTheNextPeriod(t *testing.T) {
	const splitBytes = 2000
	for _, tc := range []struct {
		name    string
		n, want int
	}{
		{"fits", testHeaderBytes, 200},
		{"over", testHeaderBytes + keepAliveBytes + 1, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := head(tc.n)
			res := lateRequests(t, true, "GET / HTTP/1.1\r\nHost: a\r\n\r\n"+h[:splitBytes], h[splitBytes:])
			if res.second != tc.want {
				t.Fatalf("second head of %d bytes: status %d, want %d", tc.n, res.second, tc.want)
			}
			idle, _ := res.l.wait(t, 1, 0)
			if idle[0].used != res.base {
				t.Fatalf("first period %d bytes, want %d", idle[0].used, res.base)
			}
			if tc.want == 200 {
				// The late part is more than 4096 bytes: it is the whole next period,
				// so the connection closes after the second response.
				idle, _ = res.l.wait(t, 2, 1)
				if p := idle[1]; p.used <= keepAliveBytes || p.charged != p.used-keepAliveBytes {
					t.Fatalf("second period %+v", p)
				}
			}
		})
	}
}

// T-S-18: a normal keep-alive client, forced. It reads the whole first response
// and sends a request of 3000 bytes before the idle state. The request gets 200,
// the first period holds only the bytes before it, and the connection stays
// open for a third request. A second request over the next budget closes.
func TestTS18LateRequestOfNormalClient(t *testing.T) {
	const req = "GET / HTTP/1.1\r\nHost: a\r\n\r\n"
	res := lateRequests(t, false, req, head(3000))
	if res.second != 200 {
		t.Fatalf("request of 3000 bytes: status %d, want 200", res.second)
	}
	if idle, _ := res.l.wait(t, 1, 0); idle[0].used != res.base {
		t.Fatalf("first period %d bytes, want %d", idle[0].used, res.base)
	}
	res.l.wait(t, 2, 0)
	if got := roundTrip(res.c, head(0)); got != 200 {
		t.Fatalf("third request: status %d, want 200", got)
	}
	if res := lateRequests(t, false, req, head(testHeaderBytes+keepAliveBytes+1)); res.second == 200 {
		t.Fatal("a request over the budget got 200")
	}
}

// slowConn is a connection whose Read waits for the test.
type slowConn struct {
	net.Conn
	entered chan struct{} // gets a value when Read starts
	data    chan []byte
}

func (c *slowConn) Read(p []byte) (int, error) {
	c.entered <- struct{}{}
	return copy(p, <-c.data), nil
}

func (c *slowConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *slowConn) Close() error                { return nil }

// T-S-18: the pool and the keep-alive limit with late bytes. The late bytes are
// more than 4096 and come in two Reads, the first of them open at a write. At
// idle the period before them is within 4096 bytes, so the connection stays
// open, the pool holds the late bytes above 4096, and it gives them back one
// time at the next idle. A period of more than 4096 bytes before the late bytes
// closes.
func TestTS18LateBytesPoolAndKeepAlive(t *testing.T) {
	rd := newReadLimit(testHeaderBytes)
	conn := func() (*limitConn, *slowConn) {
		sc := &slowConn{entered: make(chan struct{}, 1), data: make(chan []byte)}
		src := newSourceCap(1)
		key := netip.MustParseAddr("192.0.2.1")
		src.take(key)
		sem := make(chan struct{}, 1)
		sem <- struct{}{}
		lc := &limitConn{Conn: sc, sem: sem, src: src, key: key, rd: rd, left: rd.first}
		lc.startRequest() // a Write now is a response write
		return lc, sc
	}
	read := func(lc *limitConn, sc *slowConn, n int, write bool) {
		t.Helper()
		done := make(chan int)
		go func() { m, _ := lc.Read(make([]byte, n)); done <- m }()
		<-sc.entered // the Read is open
		if write {
			_, _ = lc.Write([]byte("x"))
		}
		sc.data <- make([]byte, n)
		if m := <-done; m != n {
			t.Fatalf("read %d bytes, want %d", m, n)
		}
	}
	lc, sc := conn()
	read(lc, sc, 1000, false)
	read(lc, sc, keepAliveBytes, true)
	read(lc, sc, 1904, false)
	lc.nextPeriod()
	if lc.closed || lc.used != 6000 || lc.charged != 6000-keepAliveBytes || rd.pool.Load() != lc.charged || lc.left != rd.next-6000 {
		t.Fatalf("after the first idle: used %d, charged %d, pool %d, left %d, closed %v", lc.used, lc.charged, rd.pool.Load(), lc.left, lc.closed)
	}
	lc.nextPeriod() // this period read more than 4096 bytes
	if !lc.closed || rd.pool.Load() != 0 {
		t.Fatalf("after the second idle: closed %v, pool %d", lc.closed, rd.pool.Load())
	}
	_ = lc.Close()
	if rd.pool.Load() != 0 {
		t.Fatalf("pool %d after Close, want 0", rd.pool.Load())
	}

	lc, sc = conn()
	read(lc, sc, keepAliveBytes, false)
	read(lc, sc, 1000, false)
	read(lc, sc, 100, true)
	lc.nextPeriod() // 5096 bytes before the late ones
	if !lc.closed || rd.pool.Load() != 0 {
		t.Fatalf("a period over 4096 bytes before the late bytes: closed %v, pool %d", lc.closed, rd.pool.Load())
	}
}

// T-S-18: a request body that the handler does not read. A body of 6000 bytes
// gets its response, and the connection is closed at the idle state of the next
// request at the latest. A body over the next budget closes the connection. The
// pool is back to 0 after the close.
func TestTS18UnreadBody(t *testing.T) {
	r := newRig(t, 8, testHeaderBytes, defaultTimeouts, okHandler)
	l := r.watchPeriods()
	r.serve(t)
	post := func(c net.Conn, n int) int {
		return roundTrip(c, fmt.Sprintf("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: %d\r\n\r\n%s", n, strings.Repeat("a", n)))
	}
	c := r.dialWhole(t)
	if got := post(c, 6000); got != 200 {
		t.Fatalf("body of 6000 bytes: status %d, want 200", got)
	}
	_ = post(c, 10) // the connection may be closed already
	l.wait(t, 1, 1)
	waitFor(t, "pool and slots free", func() bool { return r.s.rd.pool.Load() == 0 && len(r.s.sem) == 0 })

	c = r.dialWhole(t)
	if got := status(c, 0); got != 200 {
		t.Fatalf("first request: status %d, want 200", got)
	}
	_ = post(c, int(r.s.rd.next)+1)
	l.wait(t, 1, 2)
	waitFor(t, "pool and slots free", func() bool { return r.s.rd.pool.Load() == 0 && len(r.s.sem) == 0 })
}

// expectBudgetClose checks that the client got a close and that the wrapper of
// the one closed connection counted exactly the budget of the first period.
func expectBudgetClose(t *testing.T, r *rig, l *periodLog, err error) {
	t.Helper()
	if err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("want a closed connection, got %v", err)
	}
	_, closed := l.wait(t, 0, 1)
	if closed[0].used != r.s.rd.first {
		t.Fatalf("the server read %d bytes, want the budget %d", closed[0].used, r.s.rd.first)
	}
}

// T-S-18: a ClientHello of 40 KiB closes the connection before a response.
func TestTS18LargeClientHello(t *testing.T) {
	r := newRig(t, 4, testHeaderBytes, defaultTimeouts, okHandler)
	l := r.watchPeriods()
	r.serve(t)
	raw, err := net.Dial("tcp", r.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
	cfg := r.clientConfig(manyProtos(160)...)
	expectBudgetClose(t, r, l, tls.Client(raw, cfg).Handshake())
}

// T-S-18: a Certificate-type handshake message of about 256 KiB in a TLS 1.2
// handshake: the client sends it in place of its second flight.
func TestTS18CertificateMessageTLS12(t *testing.T) {
	r := newRig(t, 4, testHeaderBytes, defaultTimeouts, okHandler)
	l := r.watchPeriods()
	r.serve(t)
	raw, err := net.Dial("tcp", r.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
	cfg := r.clientConfig()
	cfg.MaxVersion = tls.VersionTLS12
	conn := &nthWrite{Conn: raw, at: 2, payload: plainRecords(certMessage())}
	expectBudgetClose(t, r, l, tls.Client(conn, cfg).Handshake())
}

// T-S-18: an encrypted Certificate-type handshake message after a TLS 1.3
// handshake. The test writes the records itself, with the client traffic key.
func TestTS18EncryptedMessageTLS13(t *testing.T) {
	r := newRig(t, 4, testHeaderBytes, defaultTimeouts, okHandler)
	l := r.watchPeriods()
	r.serve(t)
	raw, err := net.Dial("tcp", r.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
	var keyLog bytes.Buffer
	cfg := r.clientConfig()
	cfg.MinVersion, cfg.KeyLogWriter = tls.VersionTLS13, &keyLog
	tc := tls.Client(raw, cfg)
	if err := tc.Handshake(); err != nil {
		t.Fatal(err)
	}
	w := newRecordWriter(t, keyLog.String(), tc.ConnectionState().CipherSuite)
	_, _ = raw.Write(w.handshake(certMessage()))
	_, err = tc.Read(make([]byte, 1))
	expectBudgetClose(t, r, l, err)
}
