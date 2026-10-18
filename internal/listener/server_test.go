package listener

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"math/big"
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
)

const testName = "decoy.test"

// testHeaderBytes is the smallest HeaderBytes that New accepts.
const testHeaderBytes = 8192

// testCert makes a self-signed certificate in the test: no fixture file.
func testCert(t testing.TB) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: testName},
		DNSNames:     []string{testName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

type rig struct {
	s    *Server
	addr string
	pool *x509.CertPool
}

var okHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") })

// newRig builds a server; the test can change s.tls before it calls serve.
func newRig(t *testing.T, maxConns, headerBytes int, tm timeouts, h http.Handler) *rig {
	t.Helper()
	cert, pool := testCert(t)
	s, err := newServer(Config{TLS: &tls.Config{Certificates: []tls.Certificate{cert}}, MaxConns: maxConns, HeaderBytes: headerBytes}, h, tm)
	if err != nil {
		t.Fatal(err)
	}
	return &rig{s: s, pool: pool}
}

func (r *rig) serve(t *testing.T) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r.addr = ln.Addr().String()
	go func() { _ = r.s.Serve(ln) }()
	t.Cleanup(func() { _ = r.s.Close() })
}

func (r *rig) clientConfig(protos ...string) *tls.Config {
	return &tls.Config{RootCAs: r.pool, ServerName: testName, NextProtos: protos}
}

func (r *rig) dial(t *testing.T) *tls.Conn {
	t.Helper()
	c, err := tls.Dial("tcp", r.addr, r.clientConfig())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// status sends a request with a head of n bytes (0: a short head) and returns
// the status code, or 0 when the server closed the connection.
func status(c net.Conn, n int) int {
	return roundTrip(c, head(n))
}

// head returns a request head of n bytes (0: a short head): the request line,
// the header lines and the blank line.
func head(n int) string {
	const start = "GET / HTTP/1.1\r\nHost: a\r\nX-Pad: "
	pad := 0
	if n > len(start)+4 {
		pad = n - len(start) - 4
	}
	return start + strings.Repeat("a", pad) + "\r\n\r\n"
}

// statusValues sends a request with n header values (Host and n-1 others, each
// on its own line) and returns the status code, or 0 when the server closed
// the connection.
func statusValues(c net.Conn, n int) int {
	var b strings.Builder
	b.WriteString("GET / HTTP/1.1\r\nHost: a\r\n")
	for i := 1; i < n; i++ {
		fmt.Fprintf(&b, "X-H%d: v\r\n", i)
	}
	b.WriteString("\r\n")
	return roundTrip(c, b.String())
}

// roundTrip writes req, reads the whole response and returns its status code,
// or 0 when the write or the read fails.
func roundTrip(c net.Conn, req string) int {
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(c, req); err != nil {
		return 0
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		return 0
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode
}

// shortTimeouts has three different values. The read-header timeout is short.
// The read and write timeouts are long, so a close before them comes from the
// read-header timeout and the handshake deadline.
func shortTimeouts() timeouts {
	return timeouts{readHeader: 300 * time.Millisecond, read: 5 * time.Second, write: 7 * time.Second, idle: time.Second}
}

// closeBound is the upper bound for a close that the short read-header
// timeout causes. It is below the read and write timeouts.
const closeBound = time.Second

// closesWithin reads until the server closes the connection and returns the
// time that took.
func closesWithin(t *testing.T, c net.Conn) time.Duration {
	t.Helper()
	start := time.Now()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.Copy(io.Discard, c); err != nil && !isClosed(err) {
		t.Fatalf("connection not closed by the server (timeout: %v): %v", errors.Is(err, os.ErrDeadlineExceeded), err)
	}
	return time.Since(start)
}

// isClosed tells if err is an end of stream or a reset.
func isClosed(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, syscall.ECONNRESET)
}

// connEnded tells if err is an end of stream, a reset, or an unexpected end of stream.
func connEnded(err error) bool {
	return isClosed(err) || errors.Is(err, io.ErrUnexpectedEOF)
}

// T-S-17: the production bounds are 10 s, 10 s, 10 s and 30 s.
func TestTS17DefaultBounds(t *testing.T) {
	if defaultTimeouts != (timeouts{10 * time.Second, 10 * time.Second, 10 * time.Second, 30 * time.Second}) {
		t.Fatalf("defaults: %+v", defaultTimeouts)
	}
	r := newRig(t, 1, 9000, defaultTimeouts, okHandler)
	s := r.s.srv
	if s.ReadHeaderTimeout != 10*time.Second || s.ReadTimeout != 10*time.Second || s.WriteTimeout != 10*time.Second ||
		s.IdleTimeout != 30*time.Second || s.MaxHeaderBytes != 9000-4096 || s.MaxHeaderValueCount != 64 {
		t.Fatalf("server: %v %v %v %v %v %v", s.ReadHeaderTimeout, s.ReadTimeout, s.WriteTimeout, s.IdleTimeout, s.MaxHeaderBytes, s.MaxHeaderValueCount)
	}
	if !s.Protocols.HTTP1() || s.Protocols.HTTP2() || s.Protocols.UnencryptedHTTP2() {
		t.Fatalf("protocols: %v", s.Protocols)
	}
}

// T-S-17: an idle connection and a partial ClientHello close at the
// handshake deadline. The error log shows that the close comes from the
// handshake path.
func TestTS17IdleAndPartialHelloClose(t *testing.T) {
	r := newRig(t, 4, testHeaderBytes, shortTimeouts(), okHandler)
	r.serve(t)
	for name, partial := range map[string][]byte{"idle": nil, "partial hello": {0x16, 0x03, 0x01, 0x01, 0x00, 0x01}} {
		lines := r.s.ErrorLines()
		c, err := net.Dial("tcp", r.addr)
		if err != nil {
			t.Fatal(err)
		}
		if partial != nil {
			_, _ = c.Write(partial)
		}
		d := closesWithin(t, c)
		_ = c.Close()
		if d < 200*time.Millisecond || d > closeBound {
			t.Errorf("%s closed after %v", name, d)
		}
		if got := r.s.ErrorLines(); got <= lines {
			t.Errorf("%s: error lines %d, want more than %d", name, got, lines)
		}
	}
}

// T-S-17: slow headers close at the read-header timeout.
func TestTS17SlowHeadersClose(t *testing.T) {
	r := newRig(t, 4, testHeaderBytes, shortTimeouts(), okHandler)
	r.serve(t)
	c := r.dial(t)
	_, _ = io.WriteString(c, "GET / HTTP/1.1\r\nHost: a\r\n")
	if d := closesWithin(t, c); d < 200*time.Millisecond || d > closeBound {
		t.Errorf("closed after %v", d)
	}
}

// T-S-17: the header cap. The server sets MaxHeaderBytes to header_bytes -
// 4096, and net/http reads 4096 bytes more than that before it answers 431.
// The head is the request line, the header lines and the blank line. A head
// of header_bytes bytes gets 200 and a head of header_bytes + 1 bytes gets 431.
func TestTS17HeaderCapBoundary(t *testing.T) {
	// 16384 is the largest value that the config accepts.
	for _, tc := range []struct {
		headerBytes int
		heads       []struct{ n, want int }
	}{
		{testHeaderBytes, []struct{ n, want int }{
			{testHeaderBytes, 200}, {testHeaderBytes + 1, 431}, {testHeaderBytes + 4096, 431},
		}},
		{16384, []struct{ n, want int }{{16384, 200}, {16385, 431}}},
	} {
		r := newRig(t, 8, tc.headerBytes, defaultTimeouts, okHandler)
		r.serve(t)
		for _, h := range tc.heads {
			c := r.dial(t)
			got := status(c, h.n)
			t.Logf("header_bytes %d: head of %d bytes (header_bytes + %d): status %d", tc.headerBytes, h.n, h.n-tc.headerBytes, got)
			if got != h.want {
				t.Errorf("header_bytes %d: head of %d bytes: status %d, want %d", tc.headerBytes, h.n, got, h.want)
			}
		}
	}
}

// T-S-17: the header value count. A request with 64 header values (Host and
// 63 others) gets 200 and a request with 65 gets 431.
func TestTS17HeaderValueCount(t *testing.T) {
	r := newRig(t, 8, testHeaderBytes, defaultTimeouts, okHandler)
	r.serve(t)
	for _, tc := range []struct{ n, want int }{{64, 200}, {65, 431}} {
		c := r.dial(t)
		got := statusValues(c, tc.n)
		t.Logf("%d header values: status %d", tc.n, got)
		if got != tc.want {
			t.Errorf("%d header values: status %d, want %d", tc.n, got, tc.want)
		}
	}
}

// T-S-17: New refuses a nil handler and a header cap below 8192.
func TestTS17NewRefusals(t *testing.T) {
	cert, _ := testCert(t)
	cfg := Config{TLS: &tls.Config{Certificates: []tls.Certificate{cert}}, MaxConns: 1, HeaderBytes: testHeaderBytes}
	if _, err := New(cfg, nil); err == nil {
		t.Error("nil handler: no error")
	}
	cfg.HeaderBytes = testHeaderBytes - 1
	if _, err := New(cfg, okHandler); err == nil {
		t.Error("header bytes 8191: no error")
	}
	cfg.HeaderBytes = testHeaderBytes
	if _, err := New(cfg, okHandler); err != nil {
		t.Errorf("header bytes 8192: %v", err)
	}
}

// T-S-17: connection max_conns + 1 closes before the handshake and the others
// serve. A connection that is closed gives its slot back.
func TestTS17ConnectionCap(t *testing.T) {
	const nConns = 3
	r := newRig(t, nConns, testHeaderBytes, defaultTimeouts, okHandler)
	var calls atomic.Int32
	r.s.tls.GetConfigForClient = func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
		calls.Add(1)
		return captureHello(chi)
	}
	r.serve(t)
	var conns []*tls.Conn
	// The open connections finish the handshake and wait: they keep their slots
	// until the client closes them.
	for range nConns {
		conns = append(conns, r.dial(t))
	}
	over, err := net.Dial("tcp", r.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer over.Close()
	// The connection over the cap sends a ClientHello. The handshake must end
	// with an end of stream or a reset; a timeout fails the test.
	_ = over.SetDeadline(time.Now().Add(3 * time.Second))
	if err := tls.Client(over, r.clientConfig()).Handshake(); !isClosed(err) {
		t.Fatalf("connection over the cap: handshake error %v; want an end of stream or a reset", err)
	}
	_ = over.Close()
	if calls.Load() != nConns {
		t.Fatalf("capture ran %d times, want %d", calls.Load(), nConns)
	}
	// The others serve a request after the connection over the cap. The server
	// keeps the connection open, so each client closes its connection to give
	// the slot back.
	for i, c := range conns {
		if got := status(c, 0); got != 200 {
			t.Fatalf("open connection %d: status %d after the connection over the cap", i, got)
		}
		_ = c.Close()
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if c, err := tls.Dial("tcp", r.addr, r.clientConfig()); err == nil {
			ok := status(c, 0) == 200
			_ = c.Close()
			if ok {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("slot not given back")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// pipelined sends a first request and a second head of n bytes. With split 0 it
// is one write. With split p it sends the first request and the first p bytes
// of the head, waits for the first response, and then sends the rest. It
// returns the status of the second response (0: none, the connection ended) and
// the bytes that the wrapper counted in the first period.
func pipelined(t *testing.T, r *rig, l *periodLog, n, split int) (second int, used int64) {
	t.Helper()
	before, _ := l.lens()
	c := r.dialWhole(t)
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	h := head(n)
	if split == 0 {
		split = len(h)
	}
	_, _ = io.WriteString(c, "GET / HTTP/1.1\r\nHost: a\r\n\r\n"+h[:split])
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("second head of %d bytes: first response: %v", n, err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("second head of %d bytes: first status %d, want 200", n, resp.StatusCode)
	}
	// The rest of the head goes out only after the idle state of the first
	// request. So its bytes cannot reach the wrapper before that state.
	want := before + 1
	l.wait(t, want, 0)
	_, _ = io.WriteString(c, h[split:])
	if resp2, err := http.ReadResponse(br, nil); err == nil {
		second = resp2.StatusCode
		_ = resp2.Body.Close()
		if second == 200 {
			want++ // the second request ends a period too
		}
	} else if !connEnded(err) {
		t.Fatalf("second head of %d bytes: want a response or the end of the connection, got %v", n, err)
	}
	idle, _ := l.wait(t, want, 0)
	return second, idle[before].used
}

// largestServed finds, with a binary search, the largest second head from lo
// (served) to hi (not served) that gets 200, with the given split. A served
// head must come after a first period of 4096 bytes or less. It returns the
// head size and the bytes of the first period for it.
func largestServed(t *testing.T, r *rig, l *periodLog, lo, hi, split int) (int, int64) {
	t.Helper()
	for hi-lo > 1 {
		mid := (lo + hi) / 2
		if second, used := pipelined(t, r, l, mid, split); second == 200 {
			if used > keepAliveBytes {
				t.Fatalf("second head of %d bytes served after a first period of %d bytes", mid, used)
			}
			lo = mid
		} else {
			hi = mid
		}
	}
	_, used := pipelined(t, r, l, lo, split)
	return lo, used
}

// T-S-18: pipelined second heads, in two forms. net/http does not count the
// bytes in its buffer against its header limit.
//
// One write (first request and the whole second head). The first period holds
// the whole second head. When it reads more than 4096 bytes, the wrapper closes
// the connection after the first response and the second head is not served. A
// second head is served only when the first period stays at 4096 bytes or less.
// Measured with header_bytes 8192 and a TLS 1.3 client of the Go library: the
// largest second head with status 200 is 2469 bytes, the first period read 4096
// bytes, and a head one byte larger is not served. A second head of
// header_bytes + 1 bytes gets no response (the connection closes).
func TestTS18PipelinedHeadOneWrite(t *testing.T) {
	r := newRig(t, 8, testHeaderBytes, defaultTimeouts, okHandler)
	l := r.watchPeriods()
	r.serve(t)
	if second, used := pipelined(t, r, l, 5000, 0); second != 0 || used <= keepAliveBytes {
		t.Fatalf("first period of %d bytes: second status %d, want no second response", used, second)
	}
	second, used := pipelined(t, r, l, testHeaderBytes+1, 0)
	t.Logf("second head of header_bytes + 1 bytes: status %d, first period %d bytes", second, used)
	if second != 0 && second != 431 {
		t.Fatalf("second head of header_bytes + 1 bytes: status %d", second)
	}
	if second, _ := pipelined(t, r, l, 0, 0); second != 200 {
		t.Fatalf("a short second head: status %d, want 200", second)
	}
	lo, used := largestServed(t, r, l, 0, testHeaderBytes+1, 0)
	t.Logf("one write: largest second head with status 200: %d bytes; the first period read %d bytes", lo, used)
	if lo > testHeaderBytes+keepAliveBytes {
		t.Fatalf("a pipelined head of %d bytes was served, over header_bytes + 4096", lo)
	}
}

// T-S-18: split write. The first write is the first request and the first
// splitBytes bytes of the second head, so the first period stays at 4096 bytes
// or less and the connection stays open after the first response. The client
// then sends the rest of the head. The bytes that net/http holds from the first
// period do not count against its header limit, so the second head can be
// larger than header_bytes. The test asserts only a bound. A head of
// header_bytes + 4097 bytes gets no response. A served head is not larger than
// header_bytes + 4096. The client sends the rest of the head only after the
// idle record of the first request, so the test does not depend on time.
// TestTS18LateBytesStartTheNextPeriod holds the handler. So the rest arrives
// before the idle state in every run.
//
// Measured with header_bytes 8192, splitBytes 2000 and a TLS 1.3 client of the
// Go library: the largest second head with status 200 is 10192 bytes
// (header_bytes + 2000, the same as splitBytes). The first period read 3627
// bytes. A head of 12289 bytes (header_bytes + 4097) gets no response.
func TestTS18PipelinedHeadSplitWrite(t *testing.T) {
	const splitBytes = 2000
	r := newRig(t, 8, testHeaderBytes, defaultTimeouts, okHandler)
	l := r.watchPeriods()
	r.serve(t)
	over := testHeaderBytes + keepAliveBytes + 1
	second, used := pipelined(t, r, l, over, splitBytes)
	t.Logf("split write: second head of %d bytes: status %d, first period %d bytes", over, second, used)
	if second != 0 || used > keepAliveBytes {
		t.Fatalf("second head of %d bytes: status %d, first period %d bytes; want no response", over, second, used)
	}
	if second, _ := pipelined(t, r, l, splitBytes, splitBytes); second != 200 {
		t.Fatalf("a second head of %d bytes: status %d, want 200", splitBytes, second)
	}
	lo, used := largestServed(t, r, l, splitBytes, over, splitBytes)
	t.Logf("split write: largest second head with status 200: %d bytes (header_bytes + %d); split at %d bytes; the first period read %d bytes", lo, lo-testHeaderBytes, splitBytes, used)
	if lo > testHeaderBytes+keepAliveBytes {
		t.Fatalf("a pipelined head of %d bytes was served, over header_bytes + 4096", lo)
	}
}

// T-S-17: all Serve calls of one server share max_conns. With max_conns 1, a
// connection on the second listener closes before the handshake while the
// connection on the first listener is open, and it serves after that one closes.
func TestTS17ConnectionCapSharedByServeCalls(t *testing.T) {
	r := newRig(t, 1, testHeaderBytes, defaultTimeouts, okHandler)
	r.serve(t)
	first := r.addr
	r.serve(t)
	second := r.addr

	c1, err := tls.Dial("tcp", first, r.clientConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer c1.Close()
	over, err := net.Dial("tcp", second)
	if err != nil {
		t.Fatal(err)
	}
	defer over.Close()
	_ = over.SetDeadline(time.Now().Add(3 * time.Second))
	if err := tls.Client(over, r.clientConfig()).Handshake(); !isClosed(err) {
		t.Fatalf("second listener over the cap: handshake error %v; want an end of stream or a reset", err)
	}
	// The connection on the first listener serves its request and stays open.
	// The client closes it to give the slot back.
	if got := status(c1, 0); got != 200 {
		t.Fatalf("first listener: status %d", got)
	}
	_ = c1.Close()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if c, err := tls.Dial("tcp", second, r.clientConfig()); err == nil {
			ok := status(c, 0) == 200
			_ = c.Close()
			if ok {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("second listener does not serve after the slot is free")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// T-S-17: Close gives the slot back one time, also when called two times.
func TestTS17DoubleCloseReleasesOneSlot(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	src := newSourceCap(2)
	l := newLimitListener(ln, make(chan struct{}, 2), src, newReadLimit(testHeaderBytes))
	defer l.Close()
	var served []net.Conn
	for range 2 {
		cc, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer cc.Close()
		c, err := l.Accept()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		served = append(served, c)
	}
	_ = served[0].Close()
	_ = served[0].Close()
	if n := l.inUse(); n != 1 {
		t.Fatalf("slots in use: %d, want 1", n)
	}
	// Both connections share one source: the count is 2, then 1 after the
	// double close. A second give would make it 0 and delete the key.
	if got := src.count[netip.MustParseAddr("127.0.0.1")]; got != 1 {
		t.Fatalf("source count %d, want 1", got)
	}
}

// T-S-17: ALPN h2 is not selected.
func TestTS17NoH2(t *testing.T) {
	r := newRig(t, 4, testHeaderBytes, defaultTimeouts, okHandler)
	r.serve(t)
	c, err := tls.Dial("tcp", r.addr, r.clientConfig("h2", "http/1.1"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if p := c.ConnectionState().NegotiatedProtocol; p != "http/1.1" {
		t.Fatalf("negotiated %q", p)
	}
	// A client that offers only h2 gets a handshake error, or a protocol that
	// is not h2. A timeout is neither: the dial has a limit of 3 s and a
	// timeout fails the test.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	d := tls.Dialer{NetDialer: &net.Dialer{Timeout: 3 * time.Second}, Config: r.clientConfig("h2")}
	nc, err := d.DialContext(ctx, "tcp", r.addr)
	var c2 *tls.Conn
	if err == nil {
		c2 = nc.(*tls.Conn)
	}
	if err != nil {
		var ne net.Error
		if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()) {
			t.Fatalf("h2-only dial timed out: %v", err)
		}
		t.Logf("h2-only dial: handshake error: %v", err)
		return
	}
	defer c2.Close()
	p := c2.ConnectionState().NegotiatedProtocol
	t.Logf("h2-only dial: negotiated %q", p)
	if p == "h2" {
		t.Fatal("h2 selected")
	}
}

// T-S-17: failed handshakes write no log line with an address or a server
// name, and they add to the counter.
func TestTS17FailedHandshakesCountedNotLogged(t *testing.T) {
	var std, structured bytes.Buffer
	prevOut, prevSlog := log.Writer(), slog.Default()
	t.Cleanup(func() { slog.SetDefault(prevSlog); log.SetOutput(prevOut) })
	slog.SetDefault(slog.New(slog.NewTextHandler(&structured, nil)))
	log.SetOutput(&std)

	r := newRig(t, 8, testHeaderBytes, defaultTimeouts, okHandler)
	// The error log writes to the counter and to no other writer.
	if r.s.srv.ErrorLog.Writer() != &r.s.errLines {
		t.Fatal("the server error log does not write only to the counter")
	}
	r.serve(t)
	var addrs []string
	for range 3 {
		raw, err := net.Dial("tcp", r.addr)
		if err != nil {
			t.Fatal(err)
		}
		_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
		addrs = append(addrs, raw.LocalAddr().String())
		// No trusted root: the client refuses the certificate and fails the handshake.
		if err := tls.Client(raw, &tls.Config{ServerName: "marker-sni.example"}).Handshake(); err == nil {
			t.Fatal("handshake worked")
		}
		_ = raw.Close()
	}
	garbage, err := net.Dial("tcp", r.addr)
	if err != nil {
		t.Fatal(err)
	}
	_ = garbage.SetDeadline(time.Now().Add(5 * time.Second))
	addrs = append(addrs, garbage.LocalAddr().String())
	_, _ = io.WriteString(garbage, "GET /marker-path HTTP/1.1\r\nHost: marker-sni.example\r\n\r\n")
	_ = garbage.Close()
	// A bad request over TLS: no Host header.
	c := r.dial(t)
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	addrs = append(addrs, c.LocalAddr().String())
	_, _ = io.WriteString(c, "GET /marker-path HTTP/1.1\r\n\r\n")
	_, _ = io.Copy(io.Discard, c)

	deadline := time.Now().Add(5 * time.Second)
	for r.s.ErrorLines() < 4 {
		if time.Now().After(deadline) {
			t.Fatalf("counter is %d, want at least 4", r.s.ErrorLines())
		}
		time.Sleep(10 * time.Millisecond)
	}
	for _, out := range []string{std.String(), structured.String()} {
		for _, m := range append(addrs, "127.0.0.1", "marker-sni", "marker-path") {
			if strings.Contains(out, m) {
				t.Errorf("log output holds %q", m)
			}
		}
	}
}

// servePlain serves a plain socket of the server with h. It returns the address
// and the channel that gets the result of ServePlain.
func (r *rig) servePlain(t *testing.T, h http.Handler) (string, <-chan error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- r.s.ServePlain(ln, h) }()
	t.Cleanup(func() { _ = r.s.Close() })
	return ln.Addr().String(), done
}

// dialPlain opens a plain connection to addr from 127.0.0.<host>. The test closes
// it at the end.
func dialPlain(t *testing.T, addr string, host byte) net.Conn {
	t.Helper()
	c, err := loopbackDialer(host).Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// countingHandler counts its requests and answers 200.
func countingHandler(n *atomic.Int32) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n.Add(1)
		_, _ = io.WriteString(w, "ok")
	})
}

// T-S-17: a client that offers only acme-tls/1 completes the handshake and gets
// no HTTP: the server closes the connection, sends no byte and gives no request
// event, also when the client sends a request.
func TestTS17ChallengeProtoGetsNoHTTP(t *testing.T) {
	h, q, _ := newHelloQueue(t, 16)
	r := newRig(t, 4, testHeaderBytes, defaultTimeouts, h)
	r.serve(t)
	c, err := tls.Dial("tcp", r.addr, r.clientConfig(challengeProto))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if p := c.ConnectionState().NegotiatedProtocol; p != challengeProto {
		t.Fatalf("negotiated %q, want %q", p, challengeProto)
	}
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = io.WriteString(c, "GET / HTTP/1.1\r\nHost: decoy.test\r\n\r\n")
	if n, err := c.Read(make([]byte, 512)); n != 0 || err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("read after acme-tls/1: %d bytes, error %v; want a close and no bytes", n, err)
	}
	waitFor(t, "slot free", func() bool { return len(r.s.sem) == 0 })
	if evs := q.Drain(); len(evs) != 0 {
		t.Fatalf("%d request events, want 0", len(evs))
	}
}

// T-S-17: the server lists http/1.1 before acme-tls/1. A client with ALPN
// http/1.1, with no ALPN, or with both values gets HTTP/1.1 only, and h2 is not
// negotiated.
func TestTS17ALPNListKeepsHTTP11(t *testing.T) {
	r := newRig(t, 8, testHeaderBytes, defaultTimeouts, okHandler)
	r.serve(t)
	if got := r.s.tls.NextProtos; len(got) != 2 || got[0] != "http/1.1" || got[1] != challengeProto {
		t.Fatalf("server ALPN list %v", got)
	}
	for _, tc := range []struct {
		offer []string
		want  string
	}{
		{nil, ""},
		{[]string{"http/1.1"}, "http/1.1"},
		{[]string{challengeProto, "http/1.1"}, "http/1.1"},
		{[]string{"h2", challengeProto, "http/1.1"}, "http/1.1"},
		{[]string{"h2", "http/1.1"}, "http/1.1"},
	} {
		c, err := tls.Dial("tcp", r.addr, r.clientConfig(tc.offer...))
		if err != nil {
			t.Fatalf("offer %v: %v", tc.offer, err)
		}
		if p := c.ConnectionState().NegotiatedProtocol; p != tc.want {
			t.Errorf("offer %v: negotiated %q, want %q", tc.offer, p, tc.want)
		}
		if got := status(c, 0); got != 200 {
			t.Errorf("offer %v: status %d, want 200", tc.offer, got)
		}
		_ = c.Close()
	}
}

// T-S-17: the TLS socket and the plain socket share the slots. When one socket
// holds all of them, a connection on the other socket closes before a read.
func TestTS17SlotsSharedByPlainAndTLS(t *testing.T) {
	const slots = 2
	t.Run("TLS holds the slots", func(t *testing.T) {
		var served atomic.Int32
		r := newRig(t, slots, testHeaderBytes, defaultTimeouts, countingHandler(&served))
		r.serve(t)
		plain, _ := r.servePlain(t, countingHandler(&served))
		for range slots {
			r.dial(t)
		}
		waitFor(t, "slots taken", func() bool { return len(r.s.sem) == slots })
		over := dialPlain(t, plain, 1)
		_, _ = io.WriteString(over, head(0))
		if d := closesWithin(t, over); d > closeBound {
			t.Fatalf("close took %v, want at most %v", d, closeBound)
		}
		if served.Load() != 0 || r.s.SourceCapCloses() != 0 {
			t.Fatalf("requests served %d, source cap closes %d; want 0 and 0", served.Load(), r.s.SourceCapCloses())
		}
	})
	t.Run("plain holds the slots", func(t *testing.T) {
		r := newRig(t, slots, testHeaderBytes, defaultTimeouts, okHandler)
		r.serve(t)
		plain, _ := r.servePlain(t, okHandler)
		for range slots {
			dialPlain(t, plain, 1)
		}
		waitFor(t, "slots taken", func() bool { return len(r.s.sem) == slots })
		expectCapClose(t, r, r.addr, 1)
		if r.s.SourceCapCloses() != 0 {
			t.Fatalf("source cap closes %d, want 0", r.s.SourceCapCloses())
		}
	})
}

// T-S-17: the source cap is for both sockets. 16 connections on each socket are
// 32 from one source address. Connection 33 closes on the plain socket, and then
// on the TLS socket, and each close adds one to the source cap count.
func TestTS17SourceCapSharedByPlainAndTLS(t *testing.T) {
	r := newRig(t, 2*maxConnsPerSource, testHeaderBytes, defaultTimeouts, okHandler)
	r.serve(t)
	tlsAddr := r.addr
	plain, _ := r.servePlain(t, okHandler)
	for range maxConnsPerSource / 2 {
		r.dialTLSFrom(t, tlsAddr, 2)
		dialPlain(t, plain, 2)
	}
	waitFor(t, "slots taken", func() bool { return len(r.s.sem) == maxConnsPerSource })
	if d := closesWithin(t, dialPlain(t, plain, 2)); d > closeBound {
		t.Fatalf("close on the plain socket took %v", d)
	}
	if got := r.s.SourceCapCloses(); got != 1 {
		t.Fatalf("source cap closes %d after the plain socket, want 1", got)
	}
	expectCapClose(t, r, tlsAddr, 2)
	if got := r.s.SourceCapCloses(); got != 2 {
		t.Fatalf("source cap closes %d after the TLS socket, want 2", got)
	}
}

// T-S-18: the read budget is the same on the plain socket. After a first request,
// a head of header_bytes bytes gets 200 and a head of header_bytes + 2000 bytes
// closes the connection with no response, on both sockets.
func TestTS18PlainReadBudget(t *testing.T) {
	r := newRig(t, 8, testHeaderBytes, defaultTimeouts, okHandler)
	l := r.watchPeriods()
	r.serve(t)
	plain, _ := r.servePlain(t, okHandler)
	// Only the TLS connection waits for the idle state. A TLS read can take a
	// whole record. So a large head that arrives before the idle state is late
	// and closes the connection. The background read of net/http on a plain
	// connection takes 1 byte. So no plain head is late by more than 1 byte.
	var tlsIdle int
	for name, k := range map[string]struct {
		dial func() net.Conn
		idle func()
	}{
		"TLS":   {func() net.Conn { return r.dial(t) }, func() { tlsIdle++; l.wait(t, tlsIdle, 0) }},
		"plain": {func() net.Conn { return dialPlain(t, plain, 1) }, func() {}},
	} {
		dial, idle := k.dial, k.idle
		c := dial()
		if got := status(c, 0); got != 200 {
			t.Fatalf("%s: first request: status %d", name, got)
		}
		idle()
		if got := status(c, testHeaderBytes); got != 200 {
			t.Fatalf("%s: head of header_bytes bytes: status %d, want 200", name, got)
		}
		idle()
		over := dial()
		if got := status(over, 0); got != 200 {
			t.Fatalf("%s: first request: status %d", name, got)
		}
		idle()
		if got := status(over, testHeaderBytes+2000); got != 0 {
			t.Errorf("%s: head over the budget: status %d, want a close", name, got)
		}
	}
}

// T-S-18: the keep-alive limit runs on the plain socket. A connection that read
// 4096 bytes or less in its period stays open. One that read more closes after
// its response.
func TestTS18PlainKeepAliveLimit(t *testing.T) {
	r := newRig(t, 8, testHeaderBytes, defaultTimeouts, okHandler)
	plain, _ := r.servePlain(t, okHandler)
	small := dialPlain(t, plain, 1)
	for i := range 2 {
		if got := status(small, 0); got != 200 {
			t.Fatalf("small request %d: status %d, want 200", i, got)
		}
	}
	big := dialPlain(t, plain, 1)
	if got := status(big, keepAliveBytes+904); got != 200 {
		t.Fatalf("large request: status %d, want 200", got)
	}
	if got := status(big, 0); got != 0 {
		t.Fatalf("request after a period of more than %d bytes: status %d, want a close", keepAliveBytes, got)
	}
}

// blockingHandler tells on started that a request is in the handler, and holds
// the request until release is closed.
type blockingHandler struct{ started, release chan struct{} }

func (b blockingHandler) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	b.started <- struct{}{}
	<-b.release
	_, _ = io.WriteString(w, "ok")
}

// openRequests serves a TLS socket and a plain socket with a blockingHandler,
// sends one request to each, and waits until both are in the handler. It returns
// the results of the two Serve calls and the channel of the two client statuses.
func openRequests(t *testing.T, r *rig, bh blockingHandler) (serves [2]<-chan error, statuses <-chan int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r.addr = ln.Addr().String()
	tlsDone := make(chan error, 1)
	go func() { tlsDone <- r.s.Serve(ln) }()
	plain, plainDone := r.servePlain(t, bh)
	res := make(chan int, 2)
	go func() {
		c, err := tls.Dial("tcp", r.addr, r.clientConfig())
		if err != nil {
			res <- 0
			return
		}
		defer c.Close()
		res <- status(c, 0)
	}()
	go func() {
		c, err := net.Dial("tcp", plain)
		if err != nil {
			res <- 0
			return
		}
		defer c.Close()
		res <- status(c, 0)
	}()
	for range 2 {
		select {
		case <-bh.started:
		case <-time.After(5 * time.Second):
			t.Fatal("a request did not reach the handler")
		}
	}
	return [2]<-chan error{tlsDone, plainDone}, res
}

// T-S-17: Shutdown returns after the open requests of the TLS socket and the
// plain socket are done, and both Serve calls return http.ErrServerClosed.
func TestTS17ShutdownWaitsForBothSockets(t *testing.T) {
	bh := blockingHandler{started: make(chan struct{}, 2), release: make(chan struct{})}
	r := newRig(t, 4, testHeaderBytes, defaultTimeouts, bh)
	serves, statuses := openRequests(t, r, bh)
	done := make(chan error, 1)
	go func() { done <- r.s.Shutdown(context.Background()) }()
	select {
	case err := <-done:
		t.Fatalf("Shutdown returned with two open requests: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	close(bh.release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Shutdown: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Shutdown did not return after the handlers returned")
	}
	for range 2 {
		if got := <-statuses; got != 200 {
			t.Errorf("client status %d, want 200", got)
		}
	}
	for i, ch := range serves {
		if err := <-ch; !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("Serve call %d returned %v, want http.ErrServerClosed", i, err)
		}
	}
	if _, err := net.DialTimeout("tcp", r.addr, time.Second); err == nil {
		t.Error("the TLS socket still accepts connections")
	}
}

// T-S-17: a request that is still open when the context of Shutdown ends is
// closed on both sockets, and Shutdown returns at the deadline with its error.
func TestTS17ShutdownClosesOpenConnectionsAtTheDeadline(t *testing.T) {
	const deadline = 300 * time.Millisecond
	bh := blockingHandler{started: make(chan struct{}, 2), release: make(chan struct{})}
	t.Cleanup(func() { close(bh.release) })
	r := newRig(t, 4, testHeaderBytes, defaultTimeouts, bh)
	_, statuses := openRequests(t, r, bh)
	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()
	begin := time.Now()
	err := r.s.Shutdown(ctx)
	took := time.Since(begin)
	if !errors.Is(err, context.DeadlineExceeded) || took < deadline-50*time.Millisecond || took > deadline+time.Second {
		t.Fatalf("Shutdown returned %v after %v; want the deadline error at about %v", err, took, deadline)
	}
	for range 2 {
		select {
		case got := <-statuses:
			if got != 0 {
				t.Errorf("client status %d, want a closed connection", got)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("a client connection is still open after Shutdown")
		}
	}
	waitFor(t, "slots free", func() bool { return len(r.s.sem) == 0 })
}

// stallConn is a raw connection whose Write cannot complete once the test sets
// stall, like a socket with a full send buffer. A stalled Write waits until the
// write deadline or until Close, and returns at once on Close like a real socket.
type stallConn struct {
	net.Conn
	stall  *atomic.Bool
	closed chan struct{}
	once   sync.Once

	mu       sync.Mutex
	deadline time.Time // the write deadline; the zero value means none
}

func (c *stallConn) setDeadline(d time.Time) {
	c.mu.Lock()
	c.deadline = d
	c.mu.Unlock()
}

func (c *stallConn) SetDeadline(d time.Time) error {
	c.setDeadline(d)
	return c.Conn.SetDeadline(d)
}

func (c *stallConn) SetWriteDeadline(d time.Time) error {
	c.setDeadline(d)
	return c.Conn.SetWriteDeadline(d)
}

func (c *stallConn) Write(p []byte) (int, error) {
	if !c.stall.Load() {
		return c.Conn.Write(p)
	}
	c.mu.Lock()
	d := c.deadline
	c.mu.Unlock()
	var expired <-chan time.Time // nil: no deadline, wait for Close only
	if !d.IsZero() {
		timer := time.NewTimer(time.Until(d))
		defer timer.Stop()
		expired = timer.C
	}
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	case <-expired:
		return 0, os.ErrDeadlineExceeded
	}
}

func (c *stallConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

// stallListener wraps the raw listener that the test gives to Serve, so that
// each accepted connection is a stallConn.
type stallListener struct {
	net.Listener
	stall atomic.Bool
}

func (l *stallListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &stallConn{Conn: c, stall: &l.stall, closed: make(chan struct{})}, nil
}

// T-S-17: three idle TLS connections whose write below TLS cannot complete close
// at the deadline of Shutdown. Shutdown returns the error of its context in at
// most the deadline + 1 s, and all slots are free after it. The close_notify
// write of each connection would wait for its own 5 s write deadline.
//
// The test simulates the full send buffer and does not use a real kernel send
// buffer. A connection with a real full buffer is hard to keep idle: a response
// that fills the buffer holds the handler, so the connection is not idle. The
// stallConn above lets the test read every response, wait for the idle state of
// each connection, and only then stop its writes. Its Write returns at once when
// the connection is closed, like a real socket.
func TestTS17ShutdownClosesIdleTLSConnectionsWithStalledWrites(t *testing.T) {
	const (
		nConns   = 3
		deadline = 300 * time.Millisecond
	)
	r := newRig(t, nConns, testHeaderBytes, defaultTimeouts, okHandler)
	l := r.watchPeriods()
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := &stallListener{Listener: raw}
	r.addr = raw.Addr().String()
	serveDone := make(chan error, 1)
	go func() { serveDone <- r.s.Serve(ln) }()
	t.Cleanup(func() { _ = r.s.Close() })

	for range nConns {
		if got := status(r.dial(t), 0); got != 200 {
			t.Fatalf("status %d, want 200", got)
		}
	}
	l.wait(t, nConns, 0)
	waitFor(t, "slots taken", func() bool { return len(r.s.sem) == nConns })
	ln.stall.Store(true)

	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()
	res := make(chan error, 1)
	begin := time.Now()
	go func() { res <- r.s.Shutdown(ctx) }()
	var got error
	select {
	case got = <-res:
	case <-time.After(30 * time.Second):
		t.Fatal("Shutdown did not return in 30 s")
	}
	took := time.Since(begin)
	t.Logf("Shutdown returned %v after %v", got, took)
	if !errors.Is(got, context.DeadlineExceeded) || took > deadline+time.Second {
		t.Fatalf("Shutdown returned %v after %v; want the deadline error in at most %v", got, took, deadline+time.Second)
	}
	waitFor(t, "slots free", func() bool { return len(r.s.sem) == 0 })
	if err := <-serveDone; !errors.Is(err, http.ErrServerClosed) {
		t.Errorf("Serve returned %v, want http.ErrServerClosed", err)
	}
}

// T-S-17: the record of open connections holds each open connection of the TLS
// socket and the plain socket, never more than max_conns, and no connection that
// a cap refused. A closed connection leaves it.
func TestTS17OpenConnectionRecord(t *testing.T) {
	t.Run("slot cap", func(t *testing.T) {
		const slots = 2
		r := newRig(t, slots, testHeaderBytes, defaultTimeouts, okHandler)
		r.serve(t)
		tlsAddr := r.addr
		plain, _ := r.servePlain(t, okHandler)
		tc := r.dial(t)
		pc := dialPlain(t, plain, 1)
		waitFor(t, "both connections in the record", func() bool { return r.s.src.openConns() == slots })
		// A connection over the slot cap closes at once on each socket and never
		// enters the record.
		expectCapClose(t, r, tlsAddr, 1)
		if d := closesWithin(t, dialPlain(t, plain, 1)); d > closeBound {
			t.Fatalf("close on the plain socket took %v", d)
		}
		if n := r.s.src.openConns(); n != slots {
			t.Fatalf("record holds %d connections after the refused ones, want %d", n, slots)
		}
		_ = tc.Close()
		waitFor(t, "TLS connection out of the record", func() bool { return r.s.src.openConns() == 1 })
		_ = pc.Close()
		waitFor(t, "record empty", func() bool { return r.s.src.openConns() == 0 })
		waitFor(t, "slots free", func() bool { return len(r.s.sem) == 0 })
	})
	t.Run("source cap", func(t *testing.T) {
		r := newRig(t, 2*maxConnsPerSource, testHeaderBytes, defaultTimeouts, okHandler)
		r.serve(t)
		tlsAddr := r.addr
		plain, _ := r.servePlain(t, okHandler)
		var conns []net.Conn
		for range maxConnsPerSource / 2 {
			conns = append(conns, r.dialTLSFrom(t, tlsAddr, 2), dialPlain(t, plain, 2))
		}
		waitFor(t, "all connections in the record", func() bool { return r.s.src.openConns() == maxConnsPerSource })
		// Connection 33 of the source closes on each socket and never enters the record.
		if d := closesWithin(t, dialPlain(t, plain, 2)); d > closeBound {
			t.Fatalf("close on the plain socket took %v", d)
		}
		expectCapClose(t, r, tlsAddr, 2)
		if got := r.s.SourceCapCloses(); got != 2 {
			t.Fatalf("source cap closes %d, want 2", got)
		}
		if n := r.s.src.openConns(); n != maxConnsPerSource {
			t.Fatalf("record holds %d connections after the refused ones, want %d", n, maxConnsPerSource)
		}
		for _, c := range conns {
			_ = c.Close()
		}
		waitFor(t, "record empty", func() bool { return r.s.src.openConns() == 0 })
		waitFor(t, "slots free", func() bool { return len(r.s.sem) == 0 })
	})
}

// T-S-17: a TCP connection from the address of the sensor that sends no byte and
// closes, like the self-check of certmagic before a challenge, gives no request
// event and no ClientHello capture. The test logs the change of the error lines
// and of the slots in use.
func TestTS17SelfDialGivesNoEventAndNoCapture(t *testing.T) {
	h, q, _ := newHelloQueue(t, 16)
	r := newRig(t, 4, testHeaderBytes, defaultTimeouts, h)
	var hellos atomic.Int32
	r.s.tls.GetConfigForClient = func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
		hellos.Add(1)
		return captureHello(chi)
	}
	r.serve(t)
	lines, used := r.s.ErrorLines(), len(r.s.sem)
	c, err := loopbackDialer(1).Dial("tcp", r.addr)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	waitFor(t, "the failed handshake in the error log", func() bool { return r.s.ErrorLines() > lines })
	waitFor(t, "slot free", func() bool { return len(r.s.sem) == used })
	t.Logf("error lines %d -> %d; slots in use %d -> %d", lines, r.s.ErrorLines(), used, len(r.s.sem))
	if n := hellos.Load(); n != 0 {
		t.Errorf("%d ClientHello captures, want 0", n)
	}
	if evs := q.Drain(); len(evs) != 0 {
		t.Errorf("%d request events, want 0", len(evs))
	}
}
