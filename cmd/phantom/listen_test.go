package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"

	"github.com/cybagard/cyba-phantom/internal/config"
	"github.com/cybagard/cyba-phantom/internal/event"
	"github.com/cybagard/cyba-phantom/internal/listener"
	"github.com/cybagard/cyba-phantom/internal/store"
	"github.com/cybagard/cyba-phantom/internal/tlog"
)

const decoyName = "decoy.example.com"

// syncBuf is a writer that the serve goroutine and the test use at the same time.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

// startWriter is a writer that closes started when the text written so far holds the start line.
// The line can come in more than one Write call. The named field `text` stops a caller from using the Write of
// syncBuf, which does not look for the start line. After started closes, Write does not scan the text again.
type startWriter struct {
	text    syncBuf
	started chan struct{}
}

func newStartWriter() *startWriter { return &startWriter{started: make(chan struct{})} }

// String returns the text written so far.
func (w *startWriter) String() string { return w.text.String() }

// hasStarted reports, without blocking, whether the writer has the start line. A wait that sees the end
// of serve or of the child calls hasStarted after it saw that end. When serve or the child writes the line
// and then ends, both channels are ready, and select picks one at random.
func (w *startWriter) hasStarted() bool {
	select {
	case <-w.started:
		return true
	default:
		return false
	}
}

// Write has one caller at a time: the writer of stdout of serve, or the copy of the child output.
func (w *startWriter) Write(p []byte) (int, error) {
	n, err := w.text.Write(p)
	if !w.hasStarted() && strings.Contains(w.text.String(), "phantom: started") {
		close(w.started)
	}
	return n, err
}

// startWait is what a test needs to wait for the start line of serve or of the child.
type startWait struct {
	who   string          // "serve" or "the child"
	out   *startWriter    // the stdout of who
	ended <-chan struct{} // closes when who ends
	info  func() string   // the exit and stderr of who. It runs after ended closed.
}

// until waits until ready closes, or until who ends. ready is the start line, or a later point of serve.
// When who ends first, the test fails, with one message for an end before the start line and one for
// an end after it. An end after the start line is not a failure when afterOK is true. Then the test goes on.
func (w startWait) until(t *testing.T, ready <-chan struct{}, afterOK bool) {
	t.Helper()
	select {
	case <-ready:
	case <-w.ended:
		switch {
		case !w.out.hasStarted():
			t.Fatalf("%s ended before the start line: %s", w.who, w.info())
		case !afterOK:
			t.Fatalf("%s ended after the start line, before the point that the test waits for: %s", w.who, w.info())
		}
	}
}

// trackedListener is a listener that the test opened. It notes when serve takes it through the listen seam.
// It also notes when it is closed.
type trackedListener struct {
	net.Listener
	bypass        bool // the listen seam does not give it to serve. It only holds its address.
	taken, closed atomic.Bool
	asked         atomic.Int64 // the place of its address in the listen calls of serve, from 1. 0: serve did not ask.
}

func (l *trackedListener) Close() error { l.closed.Store(true); return l.Listener.Close() }

// isBound reports whether serve took the listener and has not closed it.
func (l *trackedListener) isBound() bool { return l.taken.Load() && !l.closed.Load() }

// openListeners opens the https and the http listener on a loopback port. It keeps them open until the test
// ends. It replaces the listen seam until then. A listen call for the address of one of them gives that
// listener. Any other address goes to the real listen. So no port is closed and bound again.
// It also gives an address for the ACME CA, on a third listener that stays open until the test ends. One goroutine
// accepts each connection and closes it at once. So a client of the CA fails fast, as with a closed port, and no
// other socket can take the port. The cleanup waits for that goroutine.
func openListeners(t *testing.T) (https, plain *trackedListener, ca string) {
	t.Helper()
	open := func() *trackedListener {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		l := &trackedListener{Listener: ln}
		t.Cleanup(func() { l.Close() })
		return l
	}
	https, plain = open(), open()
	caLn, err := net.Listen("tcp", "127.0.0.1:0") // open while the other two are open, so the three ports differ
	if err != nil {
		t.Fatal(err)
	}
	ca = caLn.Addr().String()
	acceptEnded := make(chan struct{})
	go func() {
		defer close(acceptEnded)
		for {
			c, err := caLn.Accept()
			if err != nil { // the listener is closed
				return
			}
			c.Close()
		}
	}()
	t.Cleanup(func() { caLn.Close(); <-acceptEnded })
	byAddr := map[string]*trackedListener{https.Addr().String(): https, plain.Addr().String(): plain}
	var asks atomic.Int64
	old := listen
	t.Cleanup(func() { listen = old })
	listen = func(network, addr string) (net.Listener, error) {
		l := byAddr[addr]
		if l == nil {
			return old(network, addr)
		}
		l.asked.Store(asks.Add(1))
		if l.bypass {
			return old(network, addr)
		}
		l.taken.Store(true)
		return l, nil
	}
	return https, plain, ca
}

// serveCfg loads a config with the two listen addresses and the address of the ACME CA.
func serveCfg(t *testing.T, https, plain, ca string) *config.Config {
	env := []string{"CKPT_TOKEN=" + strings.Repeat("t", 32), "PHANTOM_LISTEN_HTTPS=" + https, "PHANTOM_LISTEN_HTTP=" + plain,
		"PHANTOM_ACME_CA=https://" + ca + "/directory"}
	cfg, err := config.Load(writeFile(t, validBody(t)), env)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// tempState returns the start values of cfg with a temporary state directory.
func tempState(t *testing.T, cfg *config.Config) startParams {
	p := paramsOf(cfg)
	p.Root = t.TempDir()
	if err := os.Chmod(p.Root, 0o700); err != nil {
		t.Fatal(err)
	}
	return p
}

// running is a serveWith call in a goroutine.
type running struct {
	cancel context.CancelFunc
	done   chan struct{}
	code   int
	out    *startWriter
	err    syncBuf
	begin  time.Time
}

// launchServe runs serveWith until the test ends, and restores the standard log output at the end.
func launchServe(t *testing.T, cfg *config.Config, p startParams, d startDeps) *running {
	oldLog := log.Writer()
	t.Cleanup(func() { log.SetOutput(oldLog) })
	ctx, cancel := context.WithCancel(t.Context())
	r := &running{cancel: cancel, done: make(chan struct{}), out: newStartWriter(), begin: time.Now()}
	go func() { r.code = serveWith(ctx, cancel, cfg, p, d, r.out, &r.err); close(r.done) }()
	t.Cleanup(func() { cancel(); <-r.done })
	return r
}

// captureServer wraps newServer until the test ends. The returned function gives the server that serveWith made.
func captureServer(t *testing.T) func() *listener.Server {
	var srv *listener.Server
	old := newServer
	t.Cleanup(func() { newServer = old })
	newServer = func(c listener.Config, h http.Handler) (*listener.Server, error) {
		s, err := old(c, h)
		srv = s
		return s, err
	}
	return func() *listener.Server { return srv }
}

// awaitErrorLines waits until the server error log counts at least n lines. It waits for a value on the line
// channel of the server. One value can stand for more than one line, so it reads the count again after each value.
// It has no deadline of its own. It fails when serve ends. If the server never writes the line, the wait
// ends at the go test timeout.
func (r *running) awaitErrorLines(t *testing.T, srv *listener.Server, n uint64) {
	t.Helper()
	sig := srv.ErrorLineSignal()
	for srv.ErrorLines() < n {
		select {
		case <-sig:
		case <-r.done:
			t.Fatalf("serve ended with exit %d when the error log had %d lines, want %d; stderr %q", r.code, srv.ErrorLines(), n, r.err.String())
		}
	}
}

// closedAtReturn replaces served until the test ends. The returned function gives, for each serve call that
// returned, whether the queue *q was closed then. A nil *q (no writer started) counts as not closed.
func closedAtReturn(t *testing.T, q **event.Queue) func() []bool {
	var mu sync.Mutex
	var closed []bool
	old := served
	t.Cleanup(func() { served = old })
	served = func() { mu.Lock(); closed = append(closed, *q != nil && (*q).Closed()); mu.Unlock() }
	return func() []bool { mu.Lock(); defer mu.Unlock(); return slices.Clone(closed) }
}

// waitStarted waits until serve has written the start line, or has ended.
func (r *running) waitStarted(t *testing.T) {
	t.Helper()
	r.startWait().until(t, r.out.started, true)
}

// startWait is the wait of the test for the start line of this serve call.
func (r *running) startWait() startWait {
	return startWait{"serve", r.out, r.done, func() string { return fmt.Sprintf("exit %d; stderr %q", r.code, r.err.String()) }}
}

// TestTS16_BindConflict checks a socket in use on listen.https and on listen.http. Each case gives exit 1,
// one fixed line, no open of the log or the store, no file in the state directory, and every listener that
// serve took is closed.
// The blocked address stays with a test listener that the listen seam does not give. So serve binds it with
// the real listen and fails. The other address is a test listener that the seam gives.
// Serve runs in a goroutine. If it binds the blocked address, the test fails at the start line.
func TestTS16_BindConflict(t *testing.T) {
	for _, key := range []string{"listen.https", "listen.http"} {
		t.Run(key, func(t *testing.T) {
			https, plain, ca := openListeners(t)
			blocker, other := https, plain
			if key == "listen.http" {
				blocker, other = plain, https
			}
			blocker.bypass = true
			cfg := serveCfg(t, https.Addr().String(), plain.Addr().String(), ca)
			p := tempState(t, cfg)
			var o opens
			r := launchServe(t, cfg, p, o.deps())
			select {
			case <-r.done:
			case <-r.out.started:
				t.Fatalf("serve bound the blocked address %s and wrote the start line; stderr %q", blocker.Addr(), r.err.String())
			}
			if r.out.hasStarted() { // serve wrote the start line, then ended
				t.Fatalf("serve bound the blocked address %s and wrote the start line; exit %d; stderr %q", blocker.Addr(), r.code, r.err.String())
			}
			if r.code != 1 {
				t.Errorf("exit code = %d, want 1", r.code)
			}
			if want := "phantom: cannot bind " + key + "\n"; r.err.String() != want || r.out.String() != "" {
				t.Errorf("stderr %q, stdout %q; want %q and nothing", r.err.String(), r.out.String(), want)
			}
			if o.log != 0 || o.store != 0 || o.migrate != 0 {
				t.Errorf("opens: log %d, store %d, migrate %d; want 0", o.log, o.store, o.migrate)
			}
			if files, _ := os.ReadDir(p.Root); len(files) != 0 {
				t.Errorf("the state directory has %d entries, want none", len(files))
			}
			// The other listener is taken, and then closed, only if serve asked for its address before the blocked one.
			tookOther := other.asked.Load() != 0 && other.asked.Load() < blocker.asked.Load()
			if other.taken.Load() != tookOther || other.closed.Load() != tookOther {
				t.Errorf("the other listener: taken %v, closed %v; want both %v", other.taken.Load(), other.closed.Load(), tookOther)
			}
		})
	}
}

// depsWithQueue returns the real parts of the store start. When the writer starts, it sets *q to the queue.
func depsWithQueue(q **event.Queue) startDeps {
	d := realDeps
	d.newWriter = func(db *sql.DB, qq *event.Queue, l *tlog.Log, c *event.Counters, bp bool, lg *slog.Logger, rec store.Recovery) *store.Writer {
		*q = qq
		return realDeps.newWriter(db, qq, l, c, bp, lg, rec)
	}
	return d
}

// TestTI03_StartAndStopOrder checks that the store and the certificate client start after serve holds the two test
// listeners. It checks that serve holds them while the sensor runs.
// After the context ends, the client stops and the queue closes after both serve calls returned (NFR-05).
func TestTI03_StartAndStopOrder(t *testing.T) {
	https, plain, ca := openListeners(t)
	cfg := serveCfg(t, https.Addr().String(), plain.Addr().String(), ca)
	var mu sync.Mutex
	var events []string
	note := func(s string) { mu.Lock(); events = append(events, s); mu.Unlock() }
	bound := func() bool { return https.isBound() && plain.isBound() }
	var q *event.Queue
	d := depsWithQueue(&q)
	d.openLog = func(r *os.Root, dir string) (*tlog.Log, error) {
		note(fmt.Sprint("store bound=", bound()))
		return tlog.OpenLog(r, dir)
	}
	oldStart, oldStop, oldServed := startACME, stopACME, served
	t.Cleanup(func() { startACME, stopACME, served = oldStart, oldStop, oldServed })
	startACME = func(a *listener.ACME, ctx context.Context) error {
		note(fmt.Sprint("acme bound=", bound()))
		return a.Start(ctx)
	}
	returned := 0
	served = func() { mu.Lock(); returned++; mu.Unlock(); note(fmt.Sprint("served closed=", q.Closed())) }
	stopACME = func(a *listener.ACME) {
		mu.Lock()
		n := returned
		mu.Unlock()
		note(fmt.Sprint("acme stop after serve calls=", n))
		a.Stop()
	}
	r := launchServe(t, cfg, tempState(t, cfg), d)
	r.waitStarted(t)
	if !bound() {
		t.Error("serve does not hold a test listener while the sensor runs")
	}
	r.cancel()
	<-r.done
	want := []string{"store bound=true", "acme bound=true", "served closed=false", "served closed=false", "acme stop after serve calls=2"}
	if !reflect.DeepEqual(events, want) {
		t.Errorf("events = %q, want %q", events, want)
	}
	if r.code != 0 || !q.Closed() || !https.closed.Load() || !plain.closed.Load() {
		t.Errorf("exit %d, queue closed %v, listeners closed %v %v; want 0, true, true true", r.code, q.Closed(), https.closed.Load(), plain.closed.Load())
	}
}

// seedCache writes a self-signed certificate of decoyName into the cache below p, where the client of the CA ca
// looks for it, and returns its DER bytes.
func seedCache(t *testing.T, p startParams, ca string) []byte {
	t.Helper()
	ok := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	root, err := os.OpenRoot(p.Root)
	ok(err)
	defer root.Close()
	cache, err := listener.Open(root, p.CacheDir)
	ok(err)
	defer cache.Close()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ok(err)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: decoyName}, DNSNames: []string{decoyName},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(10 * 365 * 24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	ok(err)
	keyDER, err := x509.MarshalECPrivateKey(key)
	ok(err)
	issuer := (&certmagic.ACMEIssuer{CA: ca}).IssuerKey()
	for k, v := range map[string][]byte{
		certmagic.StorageKeys.SiteCert(issuer, decoyName):       pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		certmagic.StorageKeys.SitePrivateKey(issuer, decoyName): pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
		certmagic.StorageKeys.SiteMeta(issuer, decoyName):       []byte(`{"sans":["` + decoyName + `"]}`),
	} {
		ok(cache.Store(t.Context(), k, v))
	}
	return der
}

// coldHandshake makes one TLS handshake for decoyName at https. It checks that the handshake ends at most 2 s
// after begin and gives the certificate der. The caller closes the connection.
func coldHandshake(t *testing.T, https string, begin time.Time, der []byte, stderr *syncBuf) *tls.Conn {
	t.Helper()
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", https, &tls.Config{ServerName: decoyName, InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("handshake: %v; stderr %q", err, stderr.String())
	}
	if d := time.Since(begin); d > 2*time.Second {
		t.Errorf("handshake after %v, want at most 2s", d)
	}
	if !bytes.Equal(conn.ConnectionState().PeerCertificates[0].Raw, der) {
		t.Error("the handshake did not give the cached certificate")
	}
	return conn
}

// TestTI03_ColdStart starts serve with a cached certificate and a CA that no one answers. It checks that a TLS
// handshake with the cached certificate works at most 2 s after the start (NFR-05).
// It runs serveWith in the test process, not the built binary. It logs the number of goroutines after the start.
func TestTI03_ColdStart(t *testing.T) {
	https, plain, caAddr := openListeners(t)
	cfg := serveCfg(t, https.Addr().String(), plain.Addr().String(), caAddr)
	p := tempState(t, cfg)
	ca, _ := cfg.Get("acme.ca")
	der := seedCache(t, p, ca.Str)
	before := runtime.NumGoroutine()
	r := launchServe(t, cfg, p, realDeps)
	// The wait comes first, so an early end of serve shows as "ended before the start line", not as a handshake error.
	r.waitStarted(t)
	defer coldHandshake(t, https.Addr().String(), r.begin, der, &r.err).Close()
	t.Logf("goroutines: %d before the start, %d after it", before, runtime.NumGoroutine())
}

// TestTS17_FailedHandshakeLogsNothing makes a failed handshake for a name that is not configured, and one with
// bytes that are no TLS. It checks that both write nothing to stderr, and that the line count of the server error log rises (SEC-22).
// On this path the failed handshakes write no line to the standard log. The test fails without log.SetOutput
// only through its own standard log line.
func TestTS17_FailedHandshakeLogsNothing(t *testing.T) {
	server := captureServer(t)
	oldLog := log.Writer()
	t.Cleanup(func() { log.SetOutput(oldLog) })
	var captured syncBuf
	log.SetOutput(&captured)
	httpsLn, plain, caAddr := openListeners(t)
	https := httpsLn.Addr().String()
	cfg := serveCfg(t, https, plain.Addr().String(), caAddr)
	p := tempState(t, cfg)
	ca, _ := cfg.Get("acme.ca")
	seedCache(t, p, ca.Str) // With a cached certificate the client starts no order, so it writes no line.
	r := launchServe(t, cfg, p, realDeps)
	r.waitStarted(t)
	srv := server()
	log.Print("a line of the standard log")
	lines, errBefore := srv.ErrorLines(), r.err.String()
	if _, err := tls.Dial("tcp", https, &tls.Config{ServerName: "other.example.com", InsecureSkipVerify: true}); err == nil {
		t.Error("a handshake for a name that is not configured worked")
	}
	if raw, err := net.Dial("tcp", https); err == nil {
		raw.Write([]byte("garbage that is no TLS\r\n\r\n"))
		raw.Close()
	}
	r.awaitErrorLines(t, srv, lines+2)
	if captured.String() != "" || r.err.String() != errBefore {
		t.Errorf("standard log %q; stderr %q", captured.String(), r.err.String())
	}
}

// TestTI03_ListenerFailureExits1 closes the https listener under the server. It checks that the sensor stops in
// order and gives exit 1, so that a supervisor restarts it (C3).
func TestTI03_ListenerFailureExits1(t *testing.T) {
	https, plain, ca := openListeners(t)
	cfg := serveCfg(t, https.Addr().String(), plain.Addr().String(), ca)
	var q *event.Queue
	closed := closedAtReturn(t, &q)
	r := launchServe(t, cfg, tempState(t, cfg), depsWithQueue(&q))
	r.waitStarted(t)
	https.Close() // the https listener, under the server
	<-r.done
	if r.code != 1 || !q.Closed() || !plain.closed.Load() || !reflect.DeepEqual(closed(), []bool{false, false}) {
		t.Errorf("exit %d, queue closed %v, http listener closed %v, closed at return %v; want 1, true, true, [false false]", r.code, q.Closed(), plain.closed.Load(), closed())
	}
}

// TestTI03_OpenFailureKeepsServing breaks the certificate cache, the state directory, and the start of the
// client. Each case must write its stderr lines and its start line exactly. The redirect on listen.http must
// answer 308, and a cancel must give exit 0 (C3). With no client, a handshake on listen.https must fail with
// the TLS alert "internal error" and count. With a client that did not start, the cached certificate serves,
// and the cancel stops the client once.
func TestTI03_OpenFailureKeepsServing(t *testing.T) {
	for _, c := range []struct {
		name, line, startLine string
		noState, cached       bool // noState: the store start writes its own error line first
		breakIt               func(t *testing.T, p *startParams)
	}{
		{"cache is a file", "phantom: certificate cache does not open", "phantom: started — certificate client not running", false, false, func(t *testing.T, p *startParams) {
			if err := os.WriteFile(filepath.Join(p.Root, p.CacheDir), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"no state directory", "phantom: state directory does not open", "phantom: started — store not healthy — certificate client not running", true, false,
			func(_ *testing.T, p *startParams) { p.Root = filepath.Join(p.Root, "missing") }},
		{"client start fails", "phantom: certificate client does not start", "phantom: started — certificate client start failed", false, true, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			httpsLn, plainLn, caAddr := openListeners(t)
			https, plain := httpsLn.Addr().String(), plainLn.Addr().String()
			cfg := serveCfg(t, https, plain, caAddr)
			p := tempState(t, cfg)
			if c.breakIt != nil {
				c.breakIt(t, &p)
			}
			var der []byte
			var stops atomic.Int32
			oldStart, oldStop := startACME, stopACME
			t.Cleanup(func() { startACME, stopACME = oldStart, oldStop })
			stopACME = func(a *listener.ACME) { stops.Add(1); a.Stop() }
			if c.cached {
				ca, _ := cfg.Get("acme.ca")
				der = seedCache(t, p, ca.Str)
				startACME = func(a *listener.ACME, ctx context.Context) error { a.Start(ctx); return errors.New("test error") }
			}
			server := captureServer(t)
			var q *event.Queue // stays nil when the state directory is missing: no writer starts
			closed := closedAtReturn(t, &q)
			r := launchServe(t, cfg, p, depsWithQueue(&q))
			r.waitStarted(t)
			// The store start writes its own line first: the error with the path, or the checkpoint key line.
			// The test drops the time attribute and the key value.
			want := []string{fmt.Sprintf("level=INFO msg=%q name=%s", "checkpoint signing key made", p.Origin), c.line}
			if c.noState {
				want[0] = fmt.Sprintf("level=ERROR msg=%q error=%q", "state directory does not open", "open "+p.Root+": no such file or directory")
			}
			got := strings.Split(strings.TrimSuffix(r.err.String(), "\n"), "\n")
			if !strings.HasPrefix(got[0], "phantom:") {
				_, got[0], _ = strings.Cut(got[0], " ")
				got[0], _, _ = strings.Cut(got[0], " vkey=")
			}
			if !slices.Equal(got, want) || r.out.String() != c.startLine+"\n" {
				t.Errorf("stderr lines %q, stdout %q; want %q and %q", got, r.out.String(), want, c.startLine+"\n")
			}
			req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+plain+"/", nil)
			req.Host = decoyName
			hc := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			if resp, err := hc.Do(req); err != nil || resp.StatusCode != http.StatusPermanentRedirect {
				t.Errorf("redirect: %v, %v; want 308", resp, err)
			}
			if c.cached {
				coldHandshake(t, https, r.begin, der, &r.err).Close()
			} else {
				srv := server()
				lines := srv.ErrorLines()
				// Without the check for a missing client, the handshake panics and the client sees EOF.
				conn, err := tls.Dial("tcp", https, &tls.Config{ServerName: decoyName, InsecureSkipVerify: true})
				if err == nil {
					conn.Close()
					t.Error("a handshake worked with no certificate client")
				} else if alert := "remote error: tls: internal error"; err.Error() != alert {
					t.Errorf("handshake error %q, want the TLS alert %q", err, alert)
				}
				r.awaitErrorLines(t, srv, lines+1)
			}
			r.cancel()
			<-r.done
			wantStops := int32(0)
			if c.cached {
				wantStops = 1
			}
			if r.code != 0 || !reflect.DeepEqual(closed(), []bool{false, false}) || stops.Load() != wantStops || (!c.noState && (q == nil || !q.Closed())) {
				t.Errorf("exit %d, closed at return %v, client stops %d; want 0, [false false], %d, and a closed queue", r.code, closed(), stops.Load(), wantStops)
			}
		})
	}
}

// TestTI03_ServerFailureExits1 makes the decoy server fail to start. It checks exit 1 with a fixed line, both
// listeners closed, the queue closed, the database closed, and no goroutine that serve left running.
// The test compares goroutine IDs right before the call and right after the return. It does not count
// goroutines. The runtime frees an ended goroutine later, and a count can include it.
// The close of a sql.DB cancels its connectionOpener goroutine but does not wait for it. The test skips a
// connectionOpener only when it belongs to the captured store database, and that database is closed with no
// open connection. Any other connectionOpener fails the test.
// The test also skips the other goroutines of database/sql, for example of a sql.Tx or sql.Rows, and the
// goroutines of the runtime, for example the finalizer goroutine. Limit: a leaked sql.Tx or sql.Rows of a
// second database that serve closes is not found. Every other new goroutine fails the test.
func TestTI03_ServerFailureExits1(t *testing.T) {
	https, plain, ca := openListeners(t)
	cfg := serveCfg(t, https.Addr().String(), plain.Addr().String(), ca)
	oldNew := newServer
	t.Cleanup(func() { newServer = oldNew })
	newServer = func(listener.Config, http.Handler) (*listener.Server, error) { return nil, errors.New("test error") }
	var q *event.Queue
	var db *sql.DB
	p, d := tempState(t, cfg), depsWithDB(depsWithQueue(&q), &db)
	var stdout, stderr strings.Builder
	before := goroutineBlocks() // after openListeners, so the accept goroutine of the CA listener is in the set
	code := serveWith(t.Context(), func() {}, cfg, p, d, &stdout, &stderr)
	after := goroutineBlocks()
	if code != 1 || !strings.Contains(stderr.String(), "phantom: decoy listener does not start\n") || stdout.Len() != 0 {
		t.Errorf("exit %d, stderr %q, stdout %q; want 1, the fixed line and no stdout", code, stderr.String(), stdout.String())
	}
	if !q.Closed() || !https.closed.Load() || !plain.closed.Load() {
		t.Errorf("queue closed %v, listeners closed %v %v; want true, true true", q.Closed(), https.closed.Load(), plain.closed.Load())
	}
	closedDB := "" // the pointer text of db, when db passed the closed check
	if db == nil {
		t.Error("serve did not start the writer, so the test has no database to check")
	} else if err := db.Ping(); err == nil || err.Error() != "sql: database is closed" {
		t.Errorf("database ping after serve returned: %v; want %q", err, "sql: database is closed")
	} else if st := db.Stats(); st.OpenConnections != 0 || st.InUse != 0 {
		t.Errorf("database connections after serve returned: %d open, %d in use; want 0 and 0", st.OpenConnections, st.InUse)
	} else {
		closedDB = fmt.Sprintf("%p", db)
	}
	var fresh []int
	for id := range after {
		if _, old := before[id]; !old {
			fresh = append(fresh, id)
		}
	}
	slices.Sort(fresh)
	openersOK := true
	for _, id := range fresh {
		if arg, ok := openerDB(after[id]); ok && (closedDB == "" || arg != closedDB) {
			openersOK = false
			t.Errorf("goroutine %d is the connectionOpener of a database that the test did not find closed (%s; closed database %q):\n%s", id, arg, closedDB, after[id])
		}
	}
	for _, id := range fresh {
		block := after[id]
		if _, ok := openerDB(block); ok {
			continue // checked above
		}
		if (openersOK && strings.Contains(block, "\ncreated by database/sql.")) || strings.Contains(block, "\ncreated by runtime.") {
			continue
		}
		t.Errorf("goroutine %d started in serve and is still running after serve returned:\n%s", id, block)
	}
}

// openerDB reports whether the top frame of a stack block is (*sql.DB).connectionOpener. If so, it returns the
// text of the first argument, the address of the database, as the dump prints it.
func openerDB(block string) (string, bool) {
	lines := strings.SplitN(block, "\n", 3)
	if len(lines) < 2 {
		return "", false
	}
	args, ok := strings.CutPrefix(lines[1], "database/sql.(*DB).connectionOpener(")
	if !ok {
		return "", false
	}
	if i := strings.IndexAny(args, ",)"); i >= 0 {
		args = args[:i]
	}
	return strings.TrimSuffix(args, "?"), true
}

// depsWithDB wraps the newWriter of d. When the writer starts, it sets *db to the database of the store.
func depsWithDB(d startDeps, db **sql.DB) startDeps {
	next := d.newWriter
	d.newWriter = func(x *sql.DB, qq *event.Queue, l *tlog.Log, c *event.Counters, bp bool, lg *slog.Logger, rec store.Recovery) *store.Writer {
		*db = x
		return next(x, qq, l, c, bp, lg, rec)
	}
	return d
}

// goroutineBlocks returns the stack block of each goroutine that runs now, by goroutine ID.
func goroutineBlocks() map[int]string {
	buf := make([]byte, 1<<16)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			buf = buf[:n]
			break
		}
		buf = make([]byte, 2*len(buf))
	}
	blocks := map[int]string{}
	for _, block := range strings.Split(string(buf), "\n\n") {
		var id int
		if _, err := fmt.Sscanf(block, "goroutine %d [", &id); err == nil {
			blocks[id] = block
		}
	}
	return blocks
}

// TestTI03_SigtermStopsServe sends SIGTERM to the real serve function. It checks that serve returns 0, and that
// the queue closes after both serve calls returned (NFR-05).
// The test registers its own SIGTERM handler before it starts serve, and keeps it to the end. So a SIGTERM never
// gets the default action in the test process, also when a failed serve call removes the handler of serve before
// the signal. The test wraps the waitStop seam. The wrapper tells the test that serve waits for the stop, and then
// it holds serve until the test has sent SIGTERM. A serve that ends without the wait fails the test.
func TestTI03_SigtermStopsServe(t *testing.T) {
	https, plain, ca := openListeners(t)
	cfg := serveCfg(t, https.Addr().String(), plain.Addr().String(), ca)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM)
	t.Cleanup(func() { signal.Stop(sig) })
	var q *event.Queue
	d, p := depsWithQueue(&q), tempState(t, cfg)
	oldSetup, oldLog := serveSetup, log.Writer()
	t.Cleanup(func() { serveSetup = oldSetup; log.SetOutput(oldLog) })
	serveSetup = func(startParams) (startParams, startDeps) { return p, d }
	closed := closedAtReturn(t, &q)
	waiting, sent := make(chan struct{}), make(chan struct{})
	var release sync.Once
	t.Cleanup(func() { release.Do(func() { close(sent) }) }) // frees serve if the test ends before it sent SIGTERM
	oldWait := waitStop
	t.Cleanup(func() { waitStop = oldWait })
	waitStop = func(ctx context.Context) {
		close(waiting)
		<-sent
		oldWait(ctx)
	}
	out := newStartWriter()
	var errb syncBuf
	var c int
	done := make(chan struct{})
	go func() { c = serve(cfg, out, &errb); close(done) }()
	t.Cleanup(func() { release.Do(func() { close(sent) }); <-done })
	startWait{"serve", out, done, func() string { return fmt.Sprintf("exit %d; stderr %q", c, errb.String()) }}.until(t, waiting, false)
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	release.Do(func() { close(sent) })
	<-done
	if c != 0 || !q.Closed() || !reflect.DeepEqual(closed(), []bool{false, false}) {
		t.Errorf("exit %d, queue closed %v, closed at return %v; want 0, true, [false false]", c, q.Closed(), closed())
	}
}

// TestTI03_ColdStartBinary builds the binary and starts it with a cached certificate in /var/lib/phantom and a CA
// that no one answers. A TLS handshake with the cached certificate must work at most 2 s after the process start.
// SIGTERM must end the process with exit 0 (NFR-05). The test needs root, because /var/lib/phantom is the state directory.
func TestTI03_ColdStartBinary(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("the test must run as root to make the state directory")
	}
	if err := os.Mkdir(stateDir, 0o700); err != nil {
		t.Skip("the state directory exists already, or cannot be made")
	}
	t.Cleanup(func() { os.RemoveAll(stateDir) })
	bin := filepath.Join(t.TempDir(), "phantom")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	// The child is a separate process and binds the https and http addresses itself. A separate process cannot
	// take a test listener. So the test frees these two listeners, and the window between the close and the bind
	// of the child stays. The listener of the CA stays open in the test process.
	httpsLn, plainLn, caAddr := openListeners(t)
	https, plain, ca := httpsLn.Addr().String(), plainLn.Addr().String(), "https://"+caAddr+"/directory"
	httpsLn.Close()
	plainLn.Close()
	der := seedCache(t, startParams{Root: stateDir, CacheDir: "certs"}, ca)
	cmd := exec.Command(bin, writeFile(t, validBody(t)))
	cmd.Env = append(os.Environ(), "CKPT_TOKEN="+strings.Repeat("t", 32), "PHANTOM_LISTEN_HTTPS="+https,
		"PHANTOM_LISTEN_HTTP="+plain, "PHANTOM_ACME_CA="+ca)
	out, errb := newStartWriter(), &syncBuf{}
	cmd.Stdout, cmd.Stderr = out, errb
	begin := time.Now()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var waitErr error
	exited := make(chan struct{})
	go func() { waitErr = cmd.Wait(); close(exited) }()
	t.Cleanup(func() { cmd.Process.Kill(); <-exited })
	// The child writes the start line after it has bound both addresses and started the two serve goroutines.
	// The child can write the line and then end. Then coldHandshake fails with its handshake error.
	startWait{"the child", out, exited, func() string { return fmt.Sprintf("%v; stderr %q", waitErr, errb.String()) }}.until(t, out.started, true)
	coldHandshake(t, https, begin, der, errb).Close()
	cmd.Process.Signal(syscall.SIGTERM)
	<-exited
	if waitErr != nil {
		t.Errorf("after SIGTERM: %v; stderr %q", waitErr, errb.String())
	}
}

// TestTS16_CADirectory checks that the default acme.ca (a shorthand) gives the directory URL of the CA, and
// that an https URL stays as it is (SEC-21).
func TestTS16_CADirectory(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"letsencrypt", "https://acme-v02.api.letsencrypt.org/directory"},
		{"https://ca.example.test:14000/dir", "https://ca.example.test:14000/dir"},
	} {
		cfg, err := config.Load(writeFile(t, validBody(t)), []string{"CKPT_TOKEN=" + strings.Repeat("t", 32), "PHANTOM_ACME_CA=" + c.in})
		if err != nil {
			t.Fatal(err)
		}
		if ca, _ := cfg.Get("acme.ca"); config.CADirectory(ca.Str) != c.want {
			t.Errorf("CADirectory(%q) = %q, want %q", ca.Str, config.CADirectory(ca.Str), c.want)
		}
	}
}
