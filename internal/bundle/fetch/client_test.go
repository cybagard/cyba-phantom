package fetch

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cybagard/cyba-phantom/internal/egress"
	"github.com/cybagard/cyba-phantom/internal/egress/egresstest"
)

// The test certificate of httptest is valid for this name. The URL of each test
// has it. The test seam changes only the address of this URL host. A proxy or
// a redirect target thus gets its own connection, to its own address.
const host = "example.com"

const (
	smallArchive = 4096
	smallSig     = 256
	allocEnv     = "FETCH_ALLOC_SERVER"
)

// TestMain runs the file server of the allocation tests in a child process.
// The allocations of the server thus stay out of the parent.
func TestMain(m *testing.M) {
	if os.Getenv(allocEnv) == "1" {
		serveChild()
		return
	}
	os.Exit(m.Run())
}

func serveChild() {
	archive, sig := make([]byte, maxArchive), make([]byte, maxSignature)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := archive
		if strings.HasSuffix(r.URL.Path, ".sig") {
			body = sig
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		_, _ = w.Write(body)
	}))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	fmt.Println(srv.Listener.Addr(), base64.StdEncoding.EncodeToString(srv.Certificate().Raw))
	_, _ = io.Copy(io.Discard, os.Stdin) // ends when the parent closes the pipe
	srv.Close()
}

type mode struct{ prodDialer, systemRoots bool }

type rig struct {
	c    *Client
	logs *bytes.Buffer
	srv  *httptest.Server
	port string
}

func start(t *testing.T, h http.Handler, tweak func(*httptest.Server)) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(h)
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	if tweak != nil {
		tweak(srv)
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func newClientFor(t *testing.T, srv *httptest.Server, s settings, m mode) *rig {
	t.Helper()
	addr := srv.Listener.Addr().String()
	_, port, _ := net.SplitHostPort(addr)
	if !m.prodDialer {
		s.dialer = egresstest.Dialer(t, dialTimeout, netip.MustParseAddr("127.0.0.1"))
	}
	if !m.systemRoots {
		s.roots = x509.NewCertPool()
		s.roots.AddCert(srv.Certificate())
	}
	s.dialAddr = func(a string) string {
		if a == host+":"+port {
			return addr
		}
		if ap, err := netip.ParseAddrPort(a); err == nil && ap.Addr() == netip.MustParseAddr("127.0.0.1") {
			return a
		}
		t.Errorf("unexpected dial %q", a)
		return "0.0.0.0:0" // the guard refuses it
	}
	buf := &bytes.Buffer{}
	c, err := newClient("https://"+host+":"+port+"/b/x.cbnd", nil, testLogger(buf), s)
	if err != nil {
		t.Fatal(err)
	}
	return &rig{c, buf, srv, port}
}

func newRig(t *testing.T, h http.Handler, s settings) *rig {
	t.Helper()
	return newClientFor(t, start(t, h, nil), s, mode{})
}

var fetchers = map[string]func(*Client) ([]byte, error){
	"archive":   func(c *Client) ([]byte, error) { return c.Archive(context.Background()) },
	"signature": func(c *Client) ([]byte, error) { return c.Signature(context.Background()) },
}

// hangBound is the longest wait for one fetch. A normal fetch ends in much less
// than one second. A fetch that does not end by then is a bug of the read loop.
const hangBound = 10 * time.Second

// within runs one fetch of f and fails the test if it does not end in time. A
// fetch that hangs stays in its goroutine until the test process ends.
func within(t *testing.T, f func(*Client) ([]byte, error), c *Client) ([]byte, error) {
	t.Helper()
	type result struct {
		got []byte
		err error
	}
	done := make(chan result, 1)
	go func() {
		got, err := f(c)
		done <- result{got, err}
	}()
	timer := time.NewTimer(hangBound)
	defer timer.Stop()
	select {
	case r := <-done:
		return r.got, r.err
	case <-timer.C:
		t.Fatalf("a fetch did not return in a bounded time (%v)", hangBound)
		return nil, nil
	}
}

// expect checks the error, the counters and the one log line of a failure.
func (r *rig) expect(t *testing.T, err error, class Class, status int) {
	t.Helper()
	if err != error(class) {
		t.Errorf("error = %v, want class %q", err, class)
	}
	for _, c := range classes {
		want := uint64(0)
		if c == class {
			want = 1
		}
		if got := r.c.Count(c); got != want {
			t.Errorf("count of %q = %d, want %d", c, got, want)
		}
	}
	line := strings.TrimSuffix(r.logs.String(), "\n")
	if strings.Contains(line, "\n") || !strings.Contains(line, "class="+string(class)+" ") ||
		!strings.HasSuffix(line, "status="+strconv.Itoa(status)) {
		t.Errorf("log is not one line with class %q and status %d: %q", class, status, line)
	}
	for _, bad := range []string{"127.0.0.1", r.port, host, "cbnd", "http", "://", "Get"} {
		if strings.Contains(line, bad) || strings.Contains(err.Error(), bad) {
			t.Errorf("log or error has %q: %q, %v", bad, line, err)
		}
	}
}

// testLogger writes to buf with no time, so a digit of the time cannot match.
func testLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return a
		},
	}))
}

func body(n int, flush bool) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		if flush { // no Content-Length: a chunked body
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
		}
		_, _ = w.Write(make([]byte, n))
	}
}

// rawResponse writes text to the connection as the whole response.
func rawResponse(text string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		_, _ = rw.WriteString(text)
		_ = rw.Flush()
		conn.Close()
	}
}

func waitDone(r *http.Request) {
	select {
	case <-r.Context().Done():
	case <-time.After(10 * time.Second):
	}
}

var small = settings{archiveCap: smallArchive, sigCap: smallSig}

func TestTS30Success(t *testing.T) {
	var methods, paths []string
	r := newRig(t, http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		methods, paths = append(methods, q.Method), append(paths, q.URL.Path)
		_, _ = io.WriteString(w, "data")
	}), small)
	for name, f := range fetchers {
		if got, err := within(t, f, r.c); err != nil || string(got) != "data" {
			t.Errorf("%s: %q, %v", name, got, err)
		}
	}
	if len(paths) != 2 || paths[0] == paths[1] || methods[0] != "GET" || methods[1] != "GET" {
		t.Errorf("methods %v, paths %v", methods, paths)
	}
	if r.logs.Len() != 0 || r.c.Count(ClassSize) != 0 || !r.c.LastGood().IsZero() {
		t.Errorf("a good GET logged %q or counted", r.logs)
	}
	body := bytes.Repeat([]byte{'x'}, smallArchive) // the cap itself passes
	r = newRig(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) }), small)
	if got, err := within(t, fetchers["archive"], r.c); err != nil || !bytes.Equal(got, body) {
		t.Errorf("a body of the cap: %d bytes, %v", len(got), err)
	}
}

func TestTS30SignatureURL(t *testing.T) {
	for in, want := range map[string]string{
		"https://example.com/b/x.cbnd":         "https://example.com/b/x.sig",
		"https://example.com:8443/x.y.cbnd":    "https://example.com:8443/x.y.sig",
		"https://example.com/a.cbnd/b%20.cbnd": "https://example.com/a.cbnd/b%20.sig",
		"https://example.com/a%2Fb.cbnd":       "https://example.com/a%2Fb.sig",
	} {
		c, err := New(in, nil, slog.Default())
		if err != nil || c.archiveURL != in || c.sigURL != want {
			t.Errorf("%s: %+v, %v", in, c, err)
		}
	}
	for _, in := range []string{
		"", "http://example.com/x.cbnd", "example.com/x.cbnd", "https://example.com/x.cbn",
		"https://example.com/.cbnd", "https://example.com/a/.cbnd", "https://example.com/x.cbnd/",
		"https://example.com/x.cbnd?", "https://example.com/x.cbnd?a=1", "https://example.com/x.cbnd#f",
		"https://u@example.com/x.cbnd", "https://example.com:0/x.cbnd", "https:///x.cbnd",
	} {
		if _, err := New(in, nil, slog.Default()); err == nil || strings.Contains(err.Error(), "example") {
			t.Errorf("%q: error %v", in, err)
		}
	}
	if _, err := New("https://example.com/x.cbnd", []netip.Prefix{netip.MustParsePrefix("8.8.8.0/24")}, slog.Default()); err == nil {
		t.Error("a public entry in the private list passed")
	}
}

func TestTS30TransportFields(t *testing.T) {
	c, err := New("https://example.com/x.cbnd", nil, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	tr := c.transport
	if c.itemDialer == nil || c.itemDialer.Timeout != 10*time.Second {
		t.Errorf("item dialer: %+v", c.itemDialer)
	}
	if tr.Proxy != nil || tr.DialContext == nil || tr.DialTLSContext != nil || tr.DialTLS != nil || tr.Dial != nil {
		t.Error("the proxy or a dialer hook is set wrong")
	}
	if c.dialer != c.itemDialer {
		t.Error("the transport does not use the item dialer")
	}
	if !tr.DisableKeepAlives {
		t.Error("keep-alive is on")
	}
	if tr.ForceAttemptHTTP2 || tr.TLSNextProto == nil || len(tr.TLSNextProto) != 0 || tr.TLSClientConfig.NextProtos != nil {
		t.Error("HTTP/2 is not off")
	}
	if tr.TLSClientConfig.MinVersion != tls.VersionTLS12 || tr.TLSClientConfig.RootCAs != nil ||
		tr.TLSClientConfig.InsecureSkipVerify || tr.TLSHandshakeTimeout != 10*time.Second ||
		tr.ResponseHeaderTimeout != 30*time.Second || tr.MaxResponseHeaderBytes != 16<<10 ||
		!tr.DisableCompression || tr.MaxIdleConns != 1 || tr.MaxIdleConnsPerHost != 1 {
		t.Errorf("transport: %+v, tls %+v", tr, tr.TLSClientConfig)
	}
	for _, hc := range []*http.Client{c.archive, c.sig} {
		if hc.Jar != nil || hc.Transport != tr || hc.CheckRedirect(nil, nil) != errRedirect {
			t.Error("a client has a jar, another transport, or follows a redirect")
		}
	}
	if maxArchive != 8<<20 || maxSignature != 1024 || c.archive.Timeout != 120*time.Second ||
		c.sig.Timeout != 30*time.Second || dialTimeout != 10*time.Second ||
		c.cfg.archiveCap != 8<<20 || c.cfg.sigCap != 1<<10 || c.cfg.headerTimeout != 30*time.Second {
		t.Errorf("production values: %+v", c.cfg)
	}
}

// proxyListener is the one proxy of the test binary. http.ProxyFromEnvironment
// reads the environment once for each process, so each run of the test must
// see the same address. The listener stays open until the process ends.
var proxyListener = sync.OnceValues(func() (net.Listener, *atomic.Int32) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	conns := new(atomic.Int32)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			conns.Add(1)
			c.Close()
		}
	}()
	return ln, conns
})

func TestTS30NoProxy(t *testing.T) {
	ln, conns := proxyListener()
	before := conns.Load()
	for _, k := range []string{"HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"} {
		t.Setenv(k, "http://"+ln.Addr().String())
	}
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")
	req, _ := http.NewRequest(http.MethodGet, "https://"+host+"/x.cbnd", nil)
	// Control: the variables apply to a default transport, with this address.
	if u, err := http.ProxyFromEnvironment(req); err != nil || u == nil || u.Host != ln.Addr().String() {
		t.Fatalf("control: proxy %v, %v, want host %s", u, err, ln.Addr())
	}
	r := newRig(t, body(10, false), small)
	for name, f := range fetchers {
		if _, err := within(t, f, r.c); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if n := conns.Load() - before; n != 0 {
		t.Errorf("%d connections to the proxy", n)
	}
}

func TestTS30TransportDialRefusesLoopback(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var accepts atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepts.Add(1)
			c.Close()
		}
	}()
	c, err := New("https://"+host+"/b/x.cbnd", nil, testLogger(&bytes.Buffer{}))
	if err != nil {
		t.Fatal(err)
	}
	conn, err := c.transport.DialContext(context.Background(), "tcp4", ln.Addr().String())
	if err == nil {
		conn.Close()
	}
	if !errors.Is(err, egress.ErrRefused) {
		t.Errorf("error = %v, want egress.ErrRefused", err)
	}
	if n := accepts.Load(); n != 0 {
		t.Errorf("%d connections reached the listener", n)
	}
}

func TestTS30RedirectRefused(t *testing.T) {
	var hits atomic.Int32
	target := start(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }), nil)
	for name, f := range fetchers {
		r := newRig(t, http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
			http.Redirect(w, q, target.URL+"/x.cbnd", http.StatusFound)
		}), small)
		_, err := within(t, f, r.c)
		if hits.Load() != 0 {
			t.Fatalf("%s: the target got %d requests", name, hits.Load())
		}
		r.expect(t, err, ClassRedirect, 302)
	}
}

func TestTS30HTTP1Only(t *testing.T) {
	var protos []string
	srv := start(t, http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		protos = append(protos, q.Proto)
		_, _ = io.WriteString(w, "ok")
	}), func(s *httptest.Server) { s.EnableHTTP2 = true })
	r := newClientFor(t, srv, small, mode{})
	resp, err := r.c.archive.Get(r.c.archiveURL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.Proto != "HTTP/1.1" || resp.TLS.NegotiatedProtocol == "h2" || len(protos) != 1 || protos[0] != "HTTP/1.1" {
		t.Errorf("response %s, ALPN %q, server saw %v", resp.Proto, resp.TLS.NegotiatedProtocol, protos)
	}
	// Control: the server does offer HTTP/2.
	h2 := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: r.c.cfg.roots}, ForceAttemptHTTP2: true}
	resp, err = (&http.Client{Transport: h2}).Get(srv.URL)
	if err != nil || resp.Proto != "HTTP/2.0" {
		t.Errorf("control: %v, %v", resp, err)
	}
}

func TestTS30NoCompression(t *testing.T) {
	var zipped bytes.Buffer
	zw := gzip.NewWriter(&zipped)
	_, _ = zw.Write(bytes.Repeat([]byte{'a'}, 100))
	_ = zw.Close()
	var accept []string
	r := newRig(t, http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		accept = append(accept, q.Header.Get("Accept-Encoding"))
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(zipped.Bytes())
	}), small)
	got, err := r.c.Archive(context.Background())
	if err != nil || !bytes.Equal(got, zipped.Bytes()) || len(accept) != 1 || accept[0] != "" {
		t.Errorf("%d bytes, %v, Accept-Encoding %q", len(got), err, accept)
	}
}

func TestTS30HeaderCaps(t *testing.T) {
	big := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Big", strings.Repeat("a", 1<<20))
		_, _ = io.WriteString(w, "ok")
	})
	flood := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		for range 100 {
			w.Header().Set("X-Info", strings.Repeat("a", 4<<10))
			w.WriteHeader(http.StatusEarlyHints)
		}
		_, _ = io.WriteString(w, "ok")
	})
	for name, h := range map[string]http.Handler{"1 MiB header": big, "100 1xx responses": flood} {
		r := newRig(t, h, small)
		_, err := r.c.Archive(context.Background())
		r.expect(t, err, ClassTransport, 0)
		if t.Failed() {
			t.Log(name)
		}
	}
}

func TestTS30SizeAndStatus(t *testing.T) {
	endless := http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		chunk := make([]byte, 1024)
		for q.Context().Err() == nil {
			if _, err := w.Write(chunk); err != nil {
				return
			}
			w.(http.Flusher).Flush()
		}
	})
	for name, f := range fetchers {
		limit := map[string]int{"archive": smallArchive, "signature": smallSig}[name]
		short := rawResponse("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort")
		// No body follows the header of over.
		over := rawResponse("HTTP/1.1 200 OK\r\nContent-Length: " + strconv.Itoa(limit+1) + "\r\n\r\n")
		noLen := rawResponse("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n" + strings.Repeat("a", limit+1))
		for what, h := range map[string]http.Handler{
			"endless":                 endless,
			"cap + 1, Content-Length": body(limit+1, false),
			"cap + 1, chunked":        body(limit+1, true),
			"cap + 1, no length":      noLen,
			"length over the cap":     over,
		} {
			r := newRig(t, h, small)
			_, err := within(t, f, r.c)
			r.expect(t, err, ClassSize, 200)
			if t.Failed() {
				t.Fatal(name, what)
			}
		}
		// A false length over the body: the body ends early.
		r := newRig(t, short, small)
		_, err := within(t, f, r.c)
		r.expect(t, err, ClassTransport, 200)
		// A false length under the body: the client reads the declared bytes
		// and no more. The bytes stay under the cap. The signature check of
		// the loader refuses them.
		r = newRig(t, rawResponse("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n"+strings.Repeat("a", 10*limit)), small)
		if got, err := within(t, f, r.c); err != nil || string(got) != "aaaaa" {
			t.Errorf("%s: false short length gave %q, %v", name, got, err)
		}
		for _, status := range []int{206, 404, 500} {
			r := newRig(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
				_, _ = w.Write(make([]byte, 10))
			}), small)
			_, err := within(t, f, r.c)
			r.expect(t, err, ClassStatus, status)
		}
	}
}

func TestTS30Timeouts(t *testing.T) {
	const (
		bound  = 2 * time.Second
		header = 100 * time.Millisecond
	)
	s := settings{archiveTimeout: bound, sigTimeout: bound, headerTimeout: header}
	slowHeader := http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) { waitDone(q) })
	slowBody := http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		w.WriteHeader(http.StatusOK)
		for q.Context().Err() == nil {
			if _, err := io.WriteString(w, "x"); err != nil {
				return
			}
			w.(http.Flusher).Flush()
			time.Sleep(20 * time.Millisecond)
		}
	})
	for name, f := range fetchers {
		for what, h := range map[string]http.Handler{"slow header": slowHeader, "slow body": slowBody} {
			r := newRig(t, h, s)
			begin := time.Now()
			_, err := f(r.c)
			took := time.Since(begin)
			r.expect(t, err, ClassTimeout, map[string]int{"slow header": 0, "slow body": 200}[what])
			want := map[string]time.Duration{"slow header": header, "slow body": bound}[what]
			slack := map[string]time.Duration{"slow header": 900 * time.Millisecond, "slow body": time.Second}[what]
			if took < want || took > want+slack {
				t.Errorf("%s, %s: ended after %v, want about %v", name, what, took, want)
			}
		}
	}
}

func TestTS30UntrustedRoots(t *testing.T) {
	srv := start(t, body(10, false), nil)
	// The test certificate is not in the system roots.
	r := newClientFor(t, srv, small, mode{systemRoots: true})
	_, err := r.c.Archive(context.Background())
	r.expect(t, err, ClassTLS, 0)
}

func TestTS30ProductionDialerRefusesLoopback(t *testing.T) {
	srv := start(t, body(10, false), nil)
	r := newClientFor(t, srv, small, mode{prodDialer: true})
	_, err := r.c.Archive(context.Background())
	r.expect(t, err, ClassAddress, 0)
	if strings.Contains(r.logs.String(), "refuse") {
		t.Errorf("log: %q", r.logs)
	}
}

func TestTS21ItemDialerPortRule(t *testing.T) {
	private := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	for _, tc := range []struct {
		fetchURL, dial string
		refused        bool
	}{
		// Port 443 when the URL has none.
		{"https://10.1.2.3/x.cbnd", "10.1.2.3:443", false},
		{"https://10.1.2.3/x.cbnd", "10.1.2.3:444", true},
		{"https://10.1.2.3:8443/x.cbnd", "10.1.2.3:8443", false},
		{"https://10.1.2.3:8443/x.cbnd", "10.1.2.3:443", true},
		// Another address in the entry passes. One outside it does not.
		{"https://10.1.2.3:8443/x.cbnd", "10.9.9.9:8443", false},
		{"https://10.1.2.3:8443/x.cbnd", "172.16.0.1:8443", true},
	} {
		c, err := New(tc.fetchURL, private, slog.Default())
		if err != nil {
			t.Fatal(err)
		}
		// The control step runs before a connect: no packet leaves.
		err = c.dialer.ControlContext(context.Background(), "tcp4", tc.dial, nil)
		if tc.refused && !errors.Is(err, egress.ErrRefused) || !tc.refused && err != nil {
			t.Errorf("%+v: error %v", tc, err)
		}
	}
}

func TestTS30RecordAndLastGood(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	var logs bytes.Buffer
	c, err := newClient("https://example.com/x.cbnd", nil, testLogger(&logs), settings{now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if !c.LastGood().IsZero() {
		t.Error("last good fetch before the first one")
	}
	c.Good()
	if !c.LastGood().Equal(now) {
		t.Errorf("last good = %v", c.LastGood())
	}
	for _, class := range []Class{ClassChanged, ClassRejected, ClassRejected} {
		if err := c.Record(class, 0); err != error(class) {
			t.Errorf("Record gave %v", err)
		}
	}
	c.Record("other", 0)
	if c.Count(ClassChanged) != 1 || c.Count(ClassRejected) != 2 || c.Count("other") != 0 ||
		strings.Count(logs.String(), "\n") != 3 || strings.Contains(logs.String(), "other") {
		t.Errorf("counts %d %d, log %q", c.Count(ClassChanged), c.Count(ClassRejected), &logs)
	}
}

// allocClients starts the file server in a child process, so its allocations
// are not in MemStats. It gives a maker of clients at the production caps.
// The first TLS use of a process sets up shared tables once. The maker first
// runs a warm-up client, which takes that cost.
func allocClients(t *testing.T) func() *Client {
	t.Helper()
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), allocEnv+"=1")
	in, _ := cmd.StdinPipe()
	out, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { in.Close(); _ = cmd.Wait() })
	var addr, certText string
	if _, err := fmt.Fscan(out, &addr, &certText); err != nil {
		t.Fatal(err)
	}
	der, err := base64.StdEncoding.DecodeString(certText)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(addr)
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	mk := func() *Client {
		c, err := newClient("https://"+host+":"+port+"/b/x.cbnd", nil, slog.New(slog.DiscardHandler), settings{
			roots:    roots,
			dialer:   egresstest.Dialer(t, dialTimeout, netip.MustParseAddr("127.0.0.1")),
			dialAddr: func(string) string { return addr },
		})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	if _, err := mk().Signature(context.Background()); err != nil {
		t.Fatal(err)
	}
	return mk
}

// allocOfFetch gives the bytes that the client allocates for one archive GET
// and one signature GET.
func allocOfFetch(t *testing.T, c *Client) uint64 {
	t.Helper()
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	a, errA := c.Archive(context.Background())
	s, errS := c.Signature(context.Background())
	runtime.ReadMemStats(&after)
	if errA != nil || errS != nil || len(a) != maxArchive || len(s) != maxSignature {
		t.Fatalf("%d bytes, %v; %d bytes, %v", len(a), errA, len(s), errS)
	}
	return after.TotalAlloc - before.TotalAlloc
}

// TestTS30AllocationOfOneFetch: one fetch allocates at most 8 MiB + 1 KiB
// + 1 MiB. Each GET opens its own connection, so a fetch has two TLS
// handshakes. Two buffers of cap + 1 bytes are the base.
func TestTS30AllocationOfOneFetch(t *testing.T) {
	const (
		base    = maxArchive + maxSignature
		newConn = base + 1<<20
	)
	c := allocClients(t)()
	first := allocOfFetch(t, c)
	t.Logf("new connection: %d bytes (limit %d, %d over the base)", first, newConn, int64(first)-base-2)
	if first > newConn {
		t.Errorf("new connection: %d bytes allocated, limit %d", first, newConn)
	}
}

func TestTS30NoStdLogLine(t *testing.T) {
	written := make(chan string, 1)
	oldW, oldF := log.Writer(), log.Flags()
	log.SetOutput(signalWriter(func(p []byte) {
		select {
		case written <- string(p):
		default:
		}
	}))
	t.Cleanup(func() { log.SetOutput(oldW); log.SetFlags(oldF) })
	r := newRig(t, rawResponse("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n"+
		"aaaaa"+"extra text from the server\r\n"), small)
	if got, err := r.c.Archive(context.Background()); err != nil || string(got) != "aaaaa" {
		t.Fatalf("%q, %v", got, err)
	}
	select {
	case line := <-written:
		t.Errorf("std log %q", line)
	case <-time.After(300 * time.Millisecond):
	}
	if r.logs.Len() != 0 {
		t.Errorf("slog %q", r.logs)
	}
}

// signalWriter calls f for each write. A function value has no data to race on.
type signalWriter func([]byte)

func (f signalWriter) Write(p []byte) (int, error) { f(p); return len(p), nil }
