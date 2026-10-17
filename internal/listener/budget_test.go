package listener

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"hash"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// periodRec is what the wrapper of one connection counted in one period.
type periodRec struct{ used, charged int64 }

func (c *limitConn) snapshot() periodRec {
	c.mu.Lock()
	defer c.mu.Unlock()
	return periodRec{c.used, c.charged}
}

// periodLog records the counts of the wrapper at each idle state and at each
// close, before the production hook acts on them.
type periodLog struct {
	mu           sync.Mutex
	idle, closed []periodRec
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
