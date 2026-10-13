package listener

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const testName = "decoy.test"

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

// newRig builds a server; the test may change s.tls before it calls serve.
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
	const head = "GET / HTTP/1.1\r\nHost: a\r\nX-Pad: "
	pad := 0
	if n > len(head)+4 {
		pad = n - len(head) - 4
	}
	req := head + strings.Repeat("a", pad) + "\r\n\r\n"
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(c, req); err != nil {
		return 0
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		return 0
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

func shortTimeouts() timeouts {
	return timeouts{readHeader: 300 * time.Millisecond, read: 300 * time.Millisecond, write: 300 * time.Millisecond, idle: time.Second}
}

// closesWithin reads until the server closes the connection and returns the
// time that took.
func closesWithin(t *testing.T, c net.Conn) time.Duration {
	t.Helper()
	start := time.Now()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.Copy(io.Discard, c); err != nil && !isClosed(err) {
		t.Fatalf("connection not closed by the server: %v", err)
	}
	return time.Since(start)
}

func isClosed(err error) bool {
	return err != nil && !strings.Contains(err.Error(), "i/o timeout")
}

// T-S-17: the production bounds are 10 s, 10 s, 10 s and 30 s.
func TestTS17DefaultBounds(t *testing.T) {
	if defaultTimeouts != (timeouts{10 * time.Second, 10 * time.Second, 10 * time.Second, 30 * time.Second}) {
		t.Fatalf("defaults: %+v", defaultTimeouts)
	}
	r := newRig(t, 1, 777, defaultTimeouts, okHandler)
	s := r.s.srv
	if s.ReadHeaderTimeout != 10*time.Second || s.ReadTimeout != 10*time.Second || s.WriteTimeout != 10*time.Second ||
		s.IdleTimeout != 30*time.Second || s.MaxHeaderBytes != 777 {
		t.Fatalf("server: %v %v %v %v %v", s.ReadHeaderTimeout, s.ReadTimeout, s.WriteTimeout, s.IdleTimeout, s.MaxHeaderBytes)
	}
	if !s.Protocols.HTTP1() || s.Protocols.HTTP2() || s.Protocols.UnencryptedHTTP2() {
		t.Fatalf("protocols: %v", s.Protocols)
	}
}

// T-S-17: an idle connection and a partial ClientHello close at the
// handshake deadline.
func TestTS17IdleAndPartialHelloClose(t *testing.T) {
	r := newRig(t, 4, 1024, shortTimeouts(), okHandler)
	r.serve(t)
	for name, partial := range map[string][]byte{"idle": nil, "partial hello": {0x16, 0x03, 0x01, 0x01, 0x00, 0x01}} {
		c, err := net.Dial("tcp", r.addr)
		if err != nil {
			t.Fatal(err)
		}
		if partial != nil {
			_, _ = c.Write(partial)
		}
		d := closesWithin(t, c)
		_ = c.Close()
		if d < 200*time.Millisecond || d > 3*time.Second {
			t.Errorf("%s closed after %v", name, d)
		}
	}
}

// T-S-17: slow headers close at the read-header timeout.
func TestTS17SlowHeadersClose(t *testing.T) {
	r := newRig(t, 4, 1024, shortTimeouts(), okHandler)
	r.serve(t)
	c := r.dial(t)
	_, _ = io.WriteString(c, "GET / HTTP/1.1\r\nHost: a\r\n")
	if d := closesWithin(t, c); d < 200*time.Millisecond || d > 3*time.Second {
		t.Errorf("closed after %v", d)
	}
}

// T-S-17: the header cap. net/http reads MaxHeaderBytes + 4096 bytes (the
// bufio slop) before it answers 431, so a head one byte over the cap is not
// refused. The test measures the boundary: the head is the request line, the
// header lines and the blank line. Measured: 200 up to cap + 4096 bytes, 431
// from cap + 4097 bytes.
func TestTS17HeaderCapBoundary(t *testing.T) {
	const cap = 1024
	r := newRig(t, 8, cap, defaultTimeouts, okHandler)
	r.serve(t)
	for _, tc := range []struct{ n, want int }{
		{cap, 200}, {cap + 1, 200}, {cap + 4096, 200}, {cap + 4096 + 1, 431}, {cap + 8192, 431},
	} {
		c := r.dial(t)
		got := status(c, tc.n)
		t.Logf("head of %d bytes (cap + %d): status %d", tc.n, tc.n-cap, got)
		if got != tc.want {
			t.Errorf("head of %d bytes: status %d, want %d", tc.n, got, tc.want)
		}
	}
}

// T-S-17: connection max_conns + 1 closes before the handshake and the others
// serve. A connection that is closed gives its slot back.
func TestTS17ConnectionCap(t *testing.T) {
	const max = 3
	r := newRig(t, max, 1024, defaultTimeouts, okHandler)
	var calls atomic.Int32
	r.s.tls.GetConfigForClient = func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
		calls.Add(1)
		return captureHello(chi)
	}
	r.serve(t)
	var conns []*tls.Conn
	for range max {
		c := r.dial(t)
		if got := status(c, 0); got != 200 {
			t.Fatalf("status %d", got)
		}
		conns = append(conns, c)
	}
	over, err := net.Dial("tcp", r.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer over.Close()
	_ = over.SetReadDeadline(time.Now().Add(3 * time.Second))
	start := time.Now()
	n, err := over.Read(make([]byte, 16))
	if n != 0 || !isClosed(err) || time.Since(start) > time.Second {
		t.Fatalf("connection over the cap: %d bytes, err %v after %v; want an end of stream or a reset at once", n, err, time.Since(start))
	}
	if calls.Load() != max {
		t.Fatalf("capture ran %d times, want %d", calls.Load(), max)
	}
	_ = conns[0].Close()
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

// T-S-17: Close gives the slot back one time, also when called two times.
func TestTS17DoubleCloseReleasesOneSlot(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := newLimitListener(ln, 2)
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
		served = append(served, c)
	}
	_ = served[0].Close()
	_ = served[0].Close()
	if n := l.inUse(); n != 1 {
		t.Fatalf("slots in use: %d, want 1", n)
	}
}

// T-S-17: ALPN h2 is not selected.
func TestTS17NoH2(t *testing.T) {
	r := newRig(t, 4, 1024, defaultTimeouts, okHandler)
	r.serve(t)
	c, err := tls.Dial("tcp", r.addr, r.clientConfig("h2", "http/1.1"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if p := c.ConnectionState().NegotiatedProtocol; p != "http/1.1" {
		t.Fatalf("negotiated %q", p)
	}
	if c2, err := tls.Dial("tcp", r.addr, r.clientConfig("h2")); err == nil {
		defer c2.Close()
		if p := c2.ConnectionState().NegotiatedProtocol; p == "h2" {
			t.Fatal("h2 selected")
		}
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

	r := newRig(t, 8, 1024, defaultTimeouts, okHandler)
	r.serve(t)
	var addrs []string
	for range 3 {
		raw, err := net.Dial("tcp", r.addr)
		if err != nil {
			t.Fatal(err)
		}
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
	addrs = append(addrs, garbage.LocalAddr().String())
	_, _ = io.WriteString(garbage, "GET /marker-path HTTP/1.1\r\nHost: marker-sni.example\r\n\r\n")
	_ = garbage.Close()
	// A bad request over TLS: no Host header.
	c := r.dial(t)
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
