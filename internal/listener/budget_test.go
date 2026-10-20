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
	"syscall"
	"testing"
	"time"

	"github.com/cybagard/cyba-phantom/internal/testutil"
)

// periodRec is what the wrapper of one connection counted in one period. The
// late run starts at each Write while a request without a body is active. The
// late bytes are not in used. The field used of limitConn has them.
type periodRec struct{ used, charged int64 }

// idleRec is the record of an idle state. It also has the late bytes.
type idleRec struct {
	periodRec
	late int64
}

func (c *limitConn) snapshot() periodRec {
	c.mu.Lock()
	defer c.mu.Unlock()
	return periodRec{c.used - c.late, c.charged}
}

func (c *limitConn) idleSnapshot() idleRec {
	c.mu.Lock()
	defer c.mu.Unlock()
	return idleRec{periodRec{c.used - c.late, c.charged}, c.late}
}

// readBytes is the number of bytes that the wrapper read in this period. The
// late bytes are in it.
func (c *limitConn) readBytes() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.used
}

// periodLog records the counts of the wrapper at each idle state and at each
// close, before the production hook acts on them. conn is the last wrapper.
type periodLog struct {
	mu     sync.Mutex
	idle   []idleRec
	closed []periodRec
	conn   atomic.Pointer[limitConn]
}

func (l *periodLog) lens() (int, int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.idle), len(l.closed)
}

// wait waits for at least idle idle records and closed close records, and
// returns copies of both lists.
func (l *periodLog) wait(t *testing.T, idle, closed int) (i []idleRec, c []periodRec) {
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
					l.idle = append(l.idle, lc.idleSnapshot())
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

// recordOverhead is the size of a TLS 1.3 record without its message. It is 5
// bytes of header, 1 byte of type and 16 bytes of tag.
const recordOverhead = 22

// dialTLS13 does a TLS 1.3 handshake on raw. The client writes through the
// returned countConn, so its n is the number of handshake bytes. A Write of up
// to 16 KiB is one record. The returned recordWriter writes records with the
// client traffic key.
func (r *rig) dialTLS13(t *testing.T, raw net.Conn) (*tls.Conn, *recordWriter, *countConn) {
	t.Helper()
	cc := &countConn{Conn: raw}
	var keyLog bytes.Buffer
	cfg := r.clientConfig()
	cfg.MinVersion, cfg.KeyLogWriter, cfg.DynamicRecordSizingDisabled = tls.VersionTLS13, &keyLog, true
	tc := tls.Client(cc, cfg)
	if err := tc.Handshake(); err != nil {
		t.Fatal(err)
	}
	return tc, newRecordWriter(t, keyLog.String(), tc.ConnectionState().CipherSuite), cc
}

// dialReading opens a TLS 1.3 connection from 127.0.0.<host>. Then it writes
// one encrypted record that starts a Certificate-type message. The server reads
// exactly total bytes in the first period and waits for more.
func (r *rig) dialReading(t *testing.T, host byte, total int) *tls.Conn {
	t.Helper()
	requireLoopback(t, host)
	raw, err := loopbackDialer(host).Dial("tcp", r.addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	tc, w, cc := r.dialTLS13(t, raw)
	rec := w.handshake(certMessage()[:total-cc.n-recordOverhead])
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
// record that it writes adds 1 to the number. keyUpdate moves it to the next key.
type recordWriter struct {
	aead   cipher.AEAD
	iv     []byte
	seq    uint64
	secret []byte
	h      func() hash.Hash
	keyLen int
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
	w := &recordWriter{secret: secret, h: h, keyLen: keyLen}
	w.setKeys(t)
	return w
}

// setKeys derives the key and the iv from the current secret.
func (w *recordWriter) setKeys(t *testing.T) {
	t.Helper()
	blk, err := aes.NewCipher(expandLabel(t, w.h, w.secret, "key", w.keyLen))
	if err != nil {
		t.Fatal(err)
	}
	if w.aead, err = cipher.NewGCM(blk); err != nil {
		t.Fatal(err)
	}
	w.iv = expandLabel(t, w.h, w.secret, "iv", 12)
}

// handshake returns msg as encrypted handshake records of 16384 bytes.
func (w *recordWriter) handshake(msg []byte) []byte { return w.records(msg, 22) }

// data returns msg as encrypted application data records of 16384 bytes.
func (w *recordWriter) data(msg []byte) []byte { return w.records(msg, 23) }

// keyUpdate returns a KeyUpdate record with update_requested, and then moves
// the writer to the next key, with sequence number 0.
func (w *recordWriter) keyUpdate(t *testing.T) []byte {
	t.Helper()
	rec := w.records([]byte{24, 0, 0, 1, 1}, 22)
	w.secret = expandLabel(t, w.h, w.secret, "traffic upd", w.h().Size())
	w.setKeys(t)
	w.seq = 0
	return rec
}

// records returns msg as encrypted records of 16384 bytes with inner type typ.
func (w *recordWriter) records(msg []byte, typ byte) []byte {
	var out bytes.Buffer
	for len(msg) > 0 {
		k := min(16384, len(msg))
		inner := append(append([]byte{}, msg[:k]...), typ)
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

// holdReq is a request that the handler of lateRequests holds.
const holdReq = "GET /hold HTTP/1.1\r\nHost: a\r\n\r\n"

// lateOpts is the input of lateRequests. With whole, the client sends one
// record for each write. With poolFull, the pool is full before the late bytes.
// The client sends pre first, if it is not empty, and waits for its idle state.
type lateOpts struct {
	whole, poolFull  bool
	pre, first, rest string
}

// lateResult is the result of lateRequests.
type lateResult struct {
	r      *rig
	c      *tls.Conn
	br     *bufio.Reader
	second int   // status of the second response, 0: none
	base   int64 // bytes that the client wrote before rest
	l      *periodLog
}

// lateRequests sends the late bytes with a held handler. The handler of /hold
// flushes a whole response and waits. The client sends first, reads that
// response, and sends rest. The test waits until the wrapper has read the late
// bytes, and only then lets the handler return. With whole it waits for all of
// them, or for the next budget. Without whole it waits for the first late Read.
// So the bytes reach the wrapper before the idle state in every run, with no
// sleep.
func lateRequests(t *testing.T, o lateOpts) lateResult {
	t.Helper()
	release := make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	r := newRig(t, 8, testHeaderBytes, defaultTimeouts, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/hold" {
			_, _ = io.WriteString(w, "ok")
			return
		}
		w.Header().Set("Content-Length", "2")
		_, _ = io.WriteString(w, "ok")
		w.(http.Flusher).Flush()
		<-release
	}))
	if o.poolFull {
		r.s.rd.pool.Store(poolBytes)
	}
	l := r.watchPeriods()
	r.serve(t)
	raw, err := net.Dial("tcp", r.addr)
	if err != nil {
		t.Fatal(err)
	}
	cc := &countConn{Conn: raw}
	cfg := r.clientConfig()
	cfg.DynamicRecordSizingDisabled = o.whole
	c := tls.Client(cc, cfg)
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if err := c.Handshake(); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(c)
	read := func() {
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
	}
	if o.pre != "" {
		_, _ = io.WriteString(c, o.pre)
		read()
		l.wait(t, 1, 0)
	}
	_, _ = io.WriteString(c, o.first)
	read()
	res := lateResult{r: r, c: c, br: br, base: int64(cc.n), l: l}
	lc := l.conn.Load()
	lc.mu.Lock()
	before, left := lc.used, lc.left
	lc.mu.Unlock()
	_, _ = io.WriteString(c, o.rest)
	// The wrapper reads no more than the budget left. The test waits on the
	// bytes that the wrapper reads in this period, late or not. So the wait
	// also ends when the late handling is off. Then a wrong status shows in
	// the status check of the test.
	total := min(int64(cc.n)-res.base, left)
	waitFor(t, "the bytes of rest in the wrapper", func() bool {
		got := lc.readBytes() - before
		return o.whole && got >= total || !o.whole && got > 0
	})
	once.Do(func() { close(release) })
	if resp2, err := http.ReadResponse(br, nil); err == nil {
		res.second = resp2.StatusCode
		_, _ = io.Copy(io.Discard, resp2.Body)
	}
	return res
}

// T-S-18: split write with a held handler. The client writes the rest of the
// second head after it read the first response and before the idle state. The
// first period holds only the bytes before the rest. The rest starts the next
// period. The wrapper counts the 22 bytes of TLS record overhead with the rest.
// A rest of 100 bytes under keepAliveBytes gets 200. A rest of keepAliveBytes
// is over the limit with that overhead, and it is not served.
func TestTS18LateBytesStartTheNextPeriod(t *testing.T) {
	const splitBytes = 2000
	for _, tc := range []struct {
		name    string
		n, want int
	}{
		{"fits", splitBytes + keepAliveBytes - 100, 200},
		{"over", splitBytes + keepAliveBytes, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := head(tc.n)
			res := lateRequests(t, lateOpts{whole: true, first: holdReq + h[:splitBytes], rest: h[splitBytes:]})
			if res.second != tc.want {
				t.Fatalf("second head of %d bytes: status %d, want %d", tc.n, res.second, tc.want)
			}
			idle, _ := res.l.wait(t, 1, 0)
			if idle[0].used != res.base {
				t.Fatalf("first period %d bytes, want %d", idle[0].used, res.base)
			}
			if tc.want == 200 {
				// The late part is the whole next period, and it has no charge.
				idle, _ = res.l.wait(t, 2, 0)
				if p := idle[1]; p.used < int64(tc.n-splitBytes) || p.used > keepAliveBytes || p.charged != 0 {
					t.Fatalf("second period %+v", p)
				}
			} else {
				res.l.wait(t, 1, 1)
			}
		})
	}
}

// T-S-18: a normal keep-alive client with a held handler. It reads the whole
// first response and sends a request of 3000 bytes before the idle state. The
// request gets 200. The first period holds only the bytes before it. The
// connection stays open for a third request. A late request of more than
// keepAliveBytes gets no response, and the connection closes.
func TestTS18LateRequestOfNormalClient(t *testing.T) {
	res := lateRequests(t, lateOpts{first: holdReq, rest: head(3000)})
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
	over := lateRequests(t, lateOpts{whole: true, first: holdReq, rest: head(keepAliveBytes + 1)})
	if over.second != 0 {
		t.Fatalf("a late request over %d bytes: status %d, want no response", keepAliveBytes, over.second)
	}
	over.l.wait(t, 0, 1)
}

// T-S-18: with the pool full, a late request of 2600 bytes after a normal first
// period gets 200. The late bytes are within keepAliveBytes of their own
// period, so the pool holds no charge for them. The pool has its start value
// after Close.
func TestTS18LateRequestWithFullPool(t *testing.T) {
	res := lateRequests(t, lateOpts{poolFull: true, first: holdReq, rest: head(2600)})
	if res.second != 200 {
		t.Fatalf("late request of 2600 bytes with a full pool: status %d, want 200", res.second)
	}
	if idle, _ := res.l.wait(t, 1, 0); idle[0].used != res.base || idle[0].charged != 0 {
		t.Fatalf("first period %+v, want %d bytes and no charge", idle[0], res.base)
	}
	_ = res.c.Close()
	res.l.wait(t, 0, 1)
	if got := res.r.s.rd.pool.Load(); got != poolBytes {
		t.Fatalf("pool %d after Close, want %d", got, poolBytes)
	}
}

// T-S-18: a late head of 6000 bytes after a next period of about 3000 bytes is
// more than keepAliveBytes, and it fits the budget of the period. It gets no
// response, and the connection closes at the idle state. The pool and the slots
// are free when the test ends.
func TestTS18LargeLateHeadCloses(t *testing.T) {
	first := strings.Replace(head(3000), "GET /", "GET /hold", 1)
	res := lateRequests(t, lateOpts{whole: true, pre: head(0), first: first, rest: head(6000)})
	if res.second != 0 {
		t.Fatalf("late head of 6000 bytes: status %d, want no response", res.second)
	}
	idle, _ := res.l.wait(t, 2, 1)
	if p := idle[1]; p.used > keepAliveBytes || p.late < 6000 {
		t.Fatalf("next period %+v, want at most %d bytes and a late head", p, keepAliveBytes)
	}
	waitFor(t, "pool and slots free", func() bool { return res.r.s.rd.pool.Load() == 0 && len(res.r.s.sem) == 0 })
}

// slowConn is a connection whose Read waits for the test. A Read that gets no
// data in 5 seconds fails, so a Read that the test did not expect cannot hang.
type slowConn struct {
	net.Conn
	entered chan struct{} // gets a value when Read starts
	data    chan []byte
	asked   int // the size of the buffer of the last Read
}

func (c *slowConn) Read(p []byte) (int, error) {
	c.asked = len(p)
	select {
	case c.entered <- struct{}{}:
	default:
	}
	select {
	case d := <-c.data:
		return copy(p, d), nil
	case <-time.After(5 * time.Second):
		return 0, errors.New("slowConn: the test sent no data")
	}
}

func (c *slowConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *slowConn) Close() error                { return nil }

// activeConn returns a limitConn on a slowConn with an active request without a
// body, so that the next Write starts the late run.
func activeConn(rd *readLimit) (*limitConn, *slowConn) {
	sc := &slowConn{entered: make(chan struct{}, 1), data: make(chan []byte)}
	src := newSourceCap(1)
	key := netip.MustParseAddr("192.0.2.1")
	src.take(key)
	sem := make(chan struct{}, 1)
	sem <- struct{}{}
	lc := newLimitConn(sc, sem, src, key, rd)
	lc.startRequest()
	return lc, sc
}

// within waits for a value from ch, and fails the test after 5 s.
func within[T any](t *testing.T, ch <-chan T, what string) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(5 * time.Second):
		t.Fatalf("timeout: %s", what)
		panic("unreachable")
	}
}

// slowReadN makes a Read of n bytes and returns the bytes that it got. With
// write, a Write happens while the Read is open.
func slowReadN(t *testing.T, lc *limitConn, sc *slowConn, n int, write bool) int {
	t.Helper()
	done := make(chan int, 1)
	go func() { m, _ := lc.Read(make([]byte, n)); done <- m }()
	within(t, sc.entered, "the Read is open")
	if write {
		_, _ = lc.Write([]byte("x"))
	}
	select {
	case sc.data <- make([]byte, n):
	case <-time.After(5 * time.Second):
		t.Fatal("timeout: the Read takes no data")
	}
	return within(t, done, "the Read returns")
}

// slowRead makes a Read of n bytes and checks that it gets all of them.
func slowRead(t *testing.T, lc *limitConn, sc *slowConn, n int, write bool) {
	t.Helper()
	if m := slowReadN(t, lc, sc, n, write); m != n {
		t.Fatalf("read %d bytes, want %d", m, n)
	}
}

// T-S-18: the pool and the keep-alive limit with late bytes. Late bytes of
// keepAliveBytes or less have no charge, and the connection stays open with
// them as the next period. Late bytes of more than keepAliveBytes come in two
// Reads, the first of them open at a write. The pool charge of late bytes is
// their own count above keepAliveBytes. The 3000 bytes before them do not
// change it. The pool holds the charge while the bytes are read. The
// connection closes at the idle state, and the pool is then 0. A period of
// more than 4096 bytes before the late bytes closes.
func TestTS18LateBytesPoolAndKeepAlive(t *testing.T) {
	rd := newReadLimit(testHeaderBytes)
	conn := func() (*limitConn, *slowConn) { return activeConn(rd) }
	read := func(lc *limitConn, sc *slowConn, n int, write bool) { t.Helper(); slowRead(t, lc, sc, n, write) }
	lc, sc := conn()
	read(lc, sc, 1000, false)
	read(lc, sc, keepAliveBytes, true)
	lc.nextPeriod()
	if lc.closed || lc.used != keepAliveBytes || lc.charged != 0 || rd.pool.Load() != 0 || lc.left != rd.next-keepAliveBytes {
		t.Fatalf("late bytes of %d: used %d, charged %d, pool %d, left %d, closed %v", keepAliveBytes, lc.used, lc.charged, rd.pool.Load(), lc.left, lc.closed)
	}

	lc, sc = conn()
	read(lc, sc, 3000, false)
	read(lc, sc, keepAliveBytes, true)
	if rd.pool.Load() != 0 {
		t.Fatalf("pool %d after late bytes of %d, want 0", rd.pool.Load(), keepAliveBytes)
	}
	read(lc, sc, 1904, false)
	const charge = 6000 - keepAliveBytes
	if rd.pool.Load() != charge || lc.charged != charge {
		t.Fatalf("pool %d, charged %d before the idle state, want %d", rd.pool.Load(), lc.charged, charge)
	}
	lc.nextPeriod()
	if !lc.closed || lc.charged != 0 || rd.pool.Load() != 0 {
		t.Fatalf("late bytes of 6000: closed %v, charged %d, pool %d", lc.closed, lc.charged, rd.pool.Load())
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
// gets its response. The body is not late, because the handler wrapper does not
// mark a request with a body. So the period has the body. The connection closes
// at the first idle state, and the next request gets no response. A request
// over the next budget gets no response, and the closed record has the budget
// as used bytes. The pool is 0 after the close.
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
	// A request with a body is not marked, so its body is not late.
	idle, _ := l.wait(t, 1, 0)
	if idle[0].late != 0 || idle[0].used <= keepAliveBytes {
		t.Fatalf("idle record %+v, want no late bytes and a period over %d bytes", idle[0], keepAliveBytes)
	}
	if got := post(c, 10); got != 0 {
		t.Fatalf("next request after an unread body: status %d, want no response", got)
	}
	l.wait(t, 1, 1)
	waitFor(t, "pool and slots free", func() bool { return r.s.rd.pool.Load() == 0 && len(r.s.sem) == 0 })

	c = r.dialWhole(t)
	if got := status(c, 0); got != 200 {
		t.Fatalf("first request: status %d, want 200", got)
	}
	// The next request goes out after the idle record of the first request.
	// So the test always reaches the close for a request over the budget.
	l.wait(t, 2, 1)
	if got := post(c, int(r.s.rd.next)+1); got != 0 {
		t.Fatalf("request over the budget: status %d, want no response", got)
	}
	if _, closed := l.wait(t, 2, 2); closed[1].used != r.s.rd.next {
		t.Fatalf("the server read %d bytes, want the budget %d", closed[1].used, r.s.rd.next)
	}
	waitFor(t, "pool and slots free", func() bool { return r.s.rd.pool.Load() == 0 && len(r.s.sem) == 0 })
}

// readBodyHandler reads the whole request body, and then it replies.
var readBodyHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	_, _ = io.Copy(io.Discard, r.Body)
	_, _ = io.WriteString(w, "ok")
})

// readStatus reads one response from br and returns its status, or 0 for none.
func readStatus(br *bufio.Reader) int {
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return 0
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode
}

// continueHead is the head of a POST with Expect: 100-continue and n body bytes.
func continueHead(n int) string {
	return fmt.Sprintf("POST / HTTP/1.1\r\nHost: a\r\nExpect: 100-continue\r\nContent-Length: %d\r\n\r\n", n)
}

// continueBody sends a POST with Expect: 100-continue, waits for the 100 reply,
// sends a body of n bytes, and returns the final status (0: none).
func continueBody(c net.Conn, br *bufio.Reader, n int) int {
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(c, continueHead(n)); err != nil {
		return 0
	}
	if resp, err := http.ReadResponse(br, nil); err != nil || resp.StatusCode != 100 {
		return 0
	}
	if _, err := io.WriteString(c, strings.Repeat("a", n)); err != nil {
		return 0
	}
	return readStatus(br)
}

// T-S-18: a handler that reads the body after a 100-continue reply. The body
// belongs to a request with a body, so it is not late: the reply does not start
// a late run. A body of 6000 bytes gets 200, and the idle record shows no late
// bytes and a period over keepAliveBytes. The connection closes at the first
// idle state: the next request gets no response. The same holds for a head and
// a body that are together 1000 bytes over keepAliveBytes. The pool and the
// slots are free when the test ends.
func TestTS18ContinueBodyIsNotLate(t *testing.T) {
	for _, tc := range []struct {
		name string
		n    int
	}{
		{"large body", 6000},
		{"split", keepAliveBytes + 1000 - len(continueHead(5000))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t, 8, testHeaderBytes, defaultTimeouts, readBodyHandler)
			l := r.watchPeriods()
			r.serve(t)
			c := r.dialWhole(t)
			br := bufio.NewReader(c)
			if got := continueBody(c, br, tc.n); got != 200 {
				t.Fatalf("body of %d bytes after 100-continue: status %d, want 200", tc.n, got)
			}
			idle, _ := l.wait(t, 1, 0)
			if idle[0].late != 0 || idle[0].used <= keepAliveBytes {
				t.Fatalf("idle record %+v, want no late bytes and a period over %d bytes", idle[0], keepAliveBytes)
			}
			_, _ = io.WriteString(c, head(0))
			if got := readStatus(br); got != 0 {
				t.Fatalf("next request: status %d, want no response", got)
			}
			l.wait(t, 1, 1)
			waitFor(t, "pool and slots free", func() bool { return r.s.rd.pool.Load() == 0 && len(r.s.sem) == 0 })
		})
	}
}

// T-S-18: late reads have a budget at read time. The period has a budget of
// 5000 bytes. A read of 1000 bytes before the late bytes and a read of 3000
// late bytes leave 1000 bytes. The next read gets 1000 bytes only. With no
// budget left, a read that gets no byte does not close. A read that gets a byte
// asks for one byte, closes with errBudgetRead, and does not count the byte.
// The bytes before the late bytes and the late bytes together are at most the
// budget.
func TestTS18LateReadBudget(t *testing.T) {
	const budget = 5000
	lc, sc := activeConn(newReadLimit(testHeaderBytes))
	lc.left = budget
	slowRead(t, lc, sc, 1000, false)
	slowRead(t, lc, sc, 3000, true)
	if m := slowReadN(t, lc, sc, 2000, false); m != budget-4000 {
		t.Fatalf("late read of 2000 bytes got %d bytes, want %d", m, budget-4000)
	}
	// read gives the open Read of lc the bytes in data. It returns the result.
	read := func(data []byte) (m int, err error) {
		done := make(chan struct{})
		go func() { m, err = lc.Read(make([]byte, 100)); close(done) }()
		within(t, sc.entered, "the Read is open")
		sc.data <- data
		within(t, done, "the Read returns")
		return m, err
	}
	if m, err := read(nil); m != 0 || err != nil || lc.closed || sc.asked != 1 {
		t.Fatalf("no budget, no byte: got %d bytes, error %v, closed %v, asked %d, want 0, nil, open, 1", m, err, lc.closed, sc.asked)
	}
	if m, err := read(make([]byte, 100)); m != 0 || err != errBudgetRead || !lc.closed || sc.asked != 1 {
		t.Fatalf("no budget, a byte: got %d bytes, error %v, closed %v, asked %d, want 0, %v, closed, 1", m, err, lc.closed, sc.asked, errBudgetRead)
	}
	if lc.used != budget || lc.late != 4000 {
		t.Fatalf("used %d, late %d, want used %d and late 4000", lc.used, lc.late, budget)
	}
}

// T-S-18: a TLS 1.3 KeyUpdate with update_requested inside a request body makes
// the server write while it reads the body. The rest of the body is not late,
// because the handler wrapper does not mark a request with a body. The idle
// record has no late bytes and a period over keepAliveBytes. The connection
// closes at that idle state. The pool and the slots are free at the end. The
// KeyUpdate is at 500 bytes of the body in the first period. In the second
// period it is at 2000 bytes of the body.
func TestTS18KeyUpdateInBody(t *testing.T) {
	for _, tc := range []struct {
		name   string
		second bool
		before int
	}{
		{"first period", false, 500},
		{"second period", true, 2000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t, 8, testHeaderBytes, defaultTimeouts, okHandler)
			l := r.watchPeriods()
			r.serve(t)
			raw, err := net.Dial("tcp", r.addr)
			if err != nil {
				t.Fatal(err)
			}
			defer raw.Close()
			_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
			_, w, _ := r.dialTLS13(t, raw)
			want := 0 // idle states before the POST
			if tc.second {
				_, _ = raw.Write(w.data([]byte(head(0))))
				l.wait(t, 1, 0)
				want = 1
			}
			post := "POST / HTTP/1.1\r\nHost: a\r\nX-Pad: " + strings.Repeat("a", 40) + "\r\nContent-Length: 6000\r\n\r\n"
			body := strings.Repeat("a", 6000)
			var out bytes.Buffer
			out.Write(w.data([]byte(post)))
			out.Write(w.data([]byte(body[:tc.before])))
			out.Write(w.keyUpdate(t))
			out.Write(w.data([]byte(body[tc.before:])))
			_, _ = raw.Write(out.Bytes()) // the server can close before the write ends
			idle, _ := l.wait(t, want+1, 0)
			if p := idle[want]; p.late != 0 || p.used <= keepAliveBytes {
				t.Fatalf("idle record %+v, want no late bytes and a period over %d bytes", p, keepAliveBytes)
			}
			idle, _ = l.wait(t, want+1, 1)
			if len(idle) != want+1 {
				t.Fatalf("%d idle records, want %d: the connection closes at the idle state of the POST", len(idle), want+1)
			}
			waitFor(t, "pool and slots free", func() bool { return r.s.rd.pool.Load() == 0 && len(r.s.sem) == 0 })
		})
	}
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
	tc, w, _ := r.dialTLS13(t, raw)
	_, _ = raw.Write(w.handshake(certMessage()))
	_, err = tc.Read(make([]byte, 1))
	expectBudgetClose(t, r, l, err)
}

// postText returns a POST request of exactly total bytes.
func postText(t *testing.T, total int) string {
	t.Helper()
	const format = "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: %d\r\n\r\n"
	n := total - len(fmt.Sprintf(format, total))
	req := fmt.Sprintf(format, n) + strings.Repeat("a", n)
	if len(req) != total {
		t.Fatalf("POST of %d bytes, want %d", len(req), total)
	}
	return req
}

// zeroGate is what the handler of TestTS18ExactBudget waits on. The hook
// readAtZero closes seen at the first Read with no budget left.
type zeroGate struct {
	once sync.Once
	seen chan struct{}
}

// T-S-18: a request that uses exactly the budget of its period gets 200. One
// byte more closes the connection with no reply, and the wrapper counts the
// budget only. The first period has the handshake bytes. The test sets its
// budget to the bytes of the handshake and of one request. A later period has
// the budget of header_bytes + 1024. The client sends a POST in one TLS record
// of that size. In an exact case the handler waits before it replies. It waits
// until a Read of the wrapper has started with no budget left, or until the
// request context ends because the connection closed. So a Read that closes
// the connection with no budget left always loses the reply.
func TestTS18ExactBudget(t *testing.T) {
	// dial13 opens a TLS 1.3 connection to r and returns the handshake bytes.
	dial13 := func(t *testing.T, r *rig) (*tls.Conn, int) {
		t.Helper()
		raw, err := dialTCP(r.addr)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = raw.Close() })
		c, _, cc := r.dialTLS13(t, raw)
		return c, cc.n
	}
	// The hook is set before any server runs, so no Read races with the set.
	// A test case arms the gate that the hook closes.
	var armed atomic.Pointer[zeroGate]
	testutil.Set(t, &readAtZero, func() {
		if g := armed.Load(); g != nil {
			g.once.Do(func() { close(g.seen) })
		}
	})
	probe := newRig(t, 4, testHeaderBytes, defaultTimeouts, okHandler)
	probe.serve(t)
	_, handshake := dial13(t, probe)
	for _, period := range []string{"first", "later"} {
		for _, tc := range []struct {
			name        string
			extra, want int
		}{{"exact", 0, 200}, {"one byte more", 1, 0}} {
			t.Run(period+" period, "+tc.name, func(t *testing.T) {
				t.Cleanup(func() { armed.Store(nil) })
				r := newRig(t, 4, testHeaderBytes, defaultTimeouts, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
					// Reading the body lets net/http start its background read.
					_, _ = io.Copy(io.Discard, req.Body)
					if g := armed.Load(); g != nil {
						select {
						case <-g.seen:
						case <-req.Context().Done():
						}
					}
					okHandler.ServeHTTP(w, req)
				}))
				budget, req := r.s.rd.next, head(3000+tc.extra)
				if period == "first" {
					r.s.rd.first = int64(handshake + recordOverhead + len(head(3000)))
					budget = r.s.rd.first
				}
				l := r.watchPeriods()
				r.serve(t)
				c, _ := dial13(t, r)
				if period == "later" {
					if got := status(c, 0); got != 200 {
						t.Fatalf("first request: status %d, want 200", got)
					}
					// This request goes out after the idle state.
					l.wait(t, 1, 0)
					req = postText(t, int(budget)-recordOverhead+tc.extra)
				}
				if tc.extra == 0 {
					armed.Store(&zeroGate{seen: make(chan struct{})})
				}
				if got := roundTrip(c, req); got != tc.want {
					t.Fatalf("request of %d bytes over the budget: status %d, want %d", tc.extra, got, tc.want)
				}
				_ = c.Close()
				if _, closed := l.wait(t, 0, 1); closed[0].used != budget {
					t.Fatalf("the server read %d bytes, want the budget %d", closed[0].used, budget)
				}
				// After the slot is free, no Read of this connection runs.
				waitFor(t, "slots free", func() bool { return len(r.s.sem) == 0 })
			})
		}
	}
}

// T-S-18: a response that reached the client before the idle close is not
// lost. A request head of more than keepAliveBytes makes the connection close
// at its idle state. The ConnState hook of the test writes 100 raw bytes from
// the client before that close. The server never reads them, so a reset can
// follow the close. Bytes that arrive after the close give an end of stream
// in place of a reset. The client reads the response after the close and
// gets all of it. Then it reads a reset or an end of stream. The test does
// not cover a response that is still in the send queue of the server.
func TestTS18IdleCloseWithUnreadBytes(t *testing.T) {
	r := newRig(t, 4, testHeaderBytes, defaultTimeouts, okHandler)
	ln := listenLoopback(t)
	raw, err := dialTCP(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	closed := make(chan struct{})
	hook := r.s.srv.ConnState
	r.s.srv.ConnState = func(c net.Conn, st http.ConnState) {
		if st == http.StateIdle {
			_, _ = raw.Write(make([]byte, 100))
		}
		hook(c, st)
		if st == http.StateIdle {
			close(closed)
		}
	}
	r.serveOn(t, ln)
	c := tls.Client(raw, r.clientConfig())
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if err := c.Handshake(); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(c, head(keepAliveBytes+500)); err != nil {
		t.Fatal(err)
	}
	within(t, closed, "the idle close")
	if got := readStatus(bufio.NewReader(c)); got != 200 {
		t.Fatalf("response after the idle close with unread bytes: status %d, want 200", got)
	}
	// Unread bytes at the close give a reset. Bytes after the close give EOF.
	_, err = c.Read(make([]byte, 1))
	if !errors.Is(err, syscall.ECONNRESET) && !errors.Is(err, io.EOF) {
		t.Fatalf("read after the response: %v, want a reset or an end of stream", err)
	}
	t.Logf("read after the response: %v", err)
}

// T-S-18: a refused pool take in a body read closes the socket before net/http
// writes a reply. The pool is full, so the body bytes above keepAliveBytes are
// refused. The client sends the body after the 100 reply, so the head is read
// already. The handler reads the body and replies. Without the Close in Read,
// net/http writes the reply, and the client gets 200.
func TestTS18RefusedTakeClosesBeforeReply(t *testing.T) {
	r := newRig(t, 4, testHeaderBytes, defaultTimeouts, readBodyHandler)
	l := r.watchPeriods()
	r.serve(t)
	r.s.rd.pool.Store(poolBytes)
	c := r.dialWhole(t)
	if got := continueBody(c, bufio.NewReader(c), 6000); got != 0 {
		t.Fatalf("body above keepAliveBytes with a full pool: status %d, want no response", got)
	}
	l.wait(t, 0, 1)
	if got := r.s.rd.pool.Load(); got != poolBytes {
		t.Fatalf("pool %d after the refused take, want %d", got, poolBytes)
	}
}
