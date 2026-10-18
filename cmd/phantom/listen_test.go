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

// freeAddr returns a loopback address with a port that no socket holds now.
func freeAddr(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

// inUse reports whether a socket holds addr.
func inUse(addr string) bool {
	ln, err := net.Listen("tcp", addr)
	if err == nil {
		ln.Close()
	}
	return err != nil
}

// serveCfg loads a config with the two listen addresses and an acme.ca on a loopback port that nothing holds.
func serveCfg(t *testing.T, https, plain string) *config.Config {
	env := []string{"CKPT_TOKEN=" + strings.Repeat("t", 32), "PHANTOM_LISTEN_HTTPS=" + https, "PHANTOM_LISTEN_HTTP=" + plain,
		"PHANTOM_ACME_CA=https://" + freeAddr(t) + "/directory"}
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
	cancel   context.CancelFunc
	done     chan struct{}
	code     int
	out, err syncBuf
	begin    time.Time
}

// launchServe runs serveWith until the test ends, and restores the standard log output at the end.
func launchServe(t *testing.T, cfg *config.Config, p startParams, d startDeps) *running {
	oldLog := log.Writer()
	t.Cleanup(func() { log.SetOutput(oldLog) })
	ctx, cancel := context.WithCancel(t.Context())
	r := &running{cancel: cancel, done: make(chan struct{}), begin: time.Now()}
	go func() { r.code = serveWith(ctx, cancel, cfg, p, d, &r.out, &r.err); close(r.done) }()
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

// waitErrorLines waits up to 2 s until the server error log counts n lines, and returns the count.
func waitErrorLines(srv *listener.Server, n uint64) uint64 {
	for end := time.Now().Add(2 * time.Second); srv.ErrorLines() < n && time.Now().Before(end); {
		time.Sleep(5 * time.Millisecond)
	}
	return srv.ErrorLines()
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

// waitStarted waits for the start line.
func (r *running) waitStarted(t *testing.T) {
	for !strings.Contains(r.out.String(), "phantom: started") {
		if time.Since(r.begin) > 5*time.Second {
			t.Fatalf("no start line; stderr %q", r.err.String())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestTS16_BindConflict checks a socket in use on listen.https and on listen.http. Each case gives exit 1,
// one fixed line, no open of the log or the store, no file in the state directory, and no socket left.
func TestTS16_BindConflict(t *testing.T) {
	for _, key := range []string{"listen.https", "listen.http"} {
		t.Run(key, func(t *testing.T) {
			addrs := map[string]string{"listen.https": freeAddr(t), "listen.http": freeAddr(t)}
			blocker, err := net.Listen("tcp", addrs[key])
			if err != nil {
				t.Fatal(err)
			}
			defer blocker.Close()
			cfg := serveCfg(t, addrs["listen.https"], addrs["listen.http"])
			p := tempState(t, cfg)
			var o opens
			var stdout, stderr strings.Builder
			if code := serveWith(t.Context(), func() {}, cfg, p, o.deps(), &stdout, &stderr); code != 1 {
				t.Errorf("exit code = %d, want 1", code)
			}
			if want := "phantom: cannot bind " + key + "\n"; stderr.String() != want || stdout.Len() != 0 {
				t.Errorf("stderr %q, stdout %q; want %q and nothing", stderr.String(), stdout.String(), want)
			}
			if o.log != 0 || o.store != 0 || o.migrate != 0 {
				t.Errorf("opens: log %d, store %d, migrate %d; want 0", o.log, o.store, o.migrate)
			}
			if files, _ := os.ReadDir(p.Root); len(files) != 0 {
				t.Errorf("the state directory has %d entries, want none", len(files))
			}
			delete(addrs, key)
			for _, other := range addrs {
				if inUse(other) {
					t.Error("the other socket is still bound")
				}
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

// TestTI03_StartAndStopOrder checks that the store and the certificate client start after both sockets are bound.
// It checks that one socket holds each address while the sensor runs.
// After the stop signal, the client stops and the queue closes after both serve calls returned (NFR-05).
func TestTI03_StartAndStopOrder(t *testing.T) {
	https, plain := freeAddr(t), freeAddr(t)
	cfg := serveCfg(t, https, plain)
	var mu sync.Mutex
	var events []string
	note := func(s string) { mu.Lock(); events = append(events, s); mu.Unlock() }
	bound := func() bool { return inUse(https) && inUse(plain) }
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
		t.Error("a socket is missing while the sensor runs")
	}
	r.cancel()
	<-r.done
	want := []string{"store bound=true", "acme bound=true", "served closed=false", "served closed=false", "acme stop after serve calls=2"}
	if !reflect.DeepEqual(events, want) {
		t.Errorf("events = %q, want %q", events, want)
	}
	if r.code != 0 || !q.Closed() || inUse(https) || inUse(plain) {
		t.Errorf("exit %d, queue closed %v, sockets held %v %v; want 0, true, false false", r.code, q.Closed(), inUse(https), inUse(plain))
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

// coldHandshake makes a TLS handshake for decoyName at https. The socket is bound a moment after the call, so it
// repeats the dial while the connection is refused, until 2 s after begin. It does not bind the address: a probe
// socket could hold the port when serve binds. It checks that the handshake ends at most 2 s after begin and gives
// the certificate der. The caller closes the connection.
func coldHandshake(t *testing.T, https string, begin time.Time, der []byte, stderr *syncBuf) *tls.Conn {
	t.Helper()
	var conn *tls.Conn
	var err error
	for {
		conn, err = tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", https, &tls.Config{ServerName: decoyName, InsecureSkipVerify: true})
		if !errors.Is(err, syscall.ECONNREFUSED) || time.Since(begin) >= 2*time.Second {
			break
		}
		time.Sleep(time.Millisecond)
	}
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
	https := freeAddr(t)
	cfg := serveCfg(t, https, freeAddr(t))
	p := tempState(t, cfg)
	ca, _ := cfg.Get("acme.ca")
	der := seedCache(t, p, ca.Str)
	before := runtime.NumGoroutine()
	r := launchServe(t, cfg, p, realDeps)
	defer coldHandshake(t, https, r.begin, der, &r.err).Close()
	r.waitStarted(t)
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
	https := freeAddr(t)
	cfg := serveCfg(t, https, freeAddr(t))
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
	if got := waitErrorLines(srv, lines+2); got < lines+2 {
		t.Errorf("error log lines rose from %d to %d, want at least 2 more", lines, got)
	}
	if captured.String() != "" || r.err.String() != errBefore {
		t.Errorf("standard log %q; stderr %q", captured.String(), r.err.String())
	}
}

// TestTI03_ListenerFailureExits1 closes the https socket under the server. It checks that the sensor stops in
// order and gives exit 1, so that a supervisor restarts it (C3).
func TestTI03_ListenerFailureExits1(t *testing.T) {
	https := freeAddr(t)
	cfg := serveCfg(t, https, freeAddr(t))
	var first net.Listener
	oldListen := listen
	t.Cleanup(func() { listen = oldListen })
	listen = func(network, addr string) (net.Listener, error) {
		ln, err := oldListen(network, addr)
		if first == nil {
			first = ln
		}
		return ln, err
	}
	var q *event.Queue
	closed := closedAtReturn(t, &q)
	r := launchServe(t, cfg, tempState(t, cfg), depsWithQueue(&q))
	r.waitStarted(t)
	first.Close() // the https socket, under the server
	<-r.done
	if r.code != 1 || !q.Closed() || inUse(https) || !reflect.DeepEqual(closed(), []bool{false, false}) {
		t.Errorf("exit %d, queue closed %v, socket held %v, closed at return %v; want 1, true, false, [false false]", r.code, q.Closed(), inUse(https), closed())
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
			https, plain := freeAddr(t), freeAddr(t)
			cfg := serveCfg(t, https, plain)
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
				if got := waitErrorLines(srv, lines+1); got <= lines {
					t.Errorf("error log lines = %d, want more than %d", got, lines)
				}
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
// sockets free, the queue closed, and the number of goroutines back to its value before the start.
func TestTI03_ServerFailureExits1(t *testing.T) {
	https, plain := freeAddr(t), freeAddr(t)
	cfg := serveCfg(t, https, plain)
	oldNew := newServer
	t.Cleanup(func() { newServer = oldNew })
	newServer = func(listener.Config, http.Handler) (*listener.Server, error) { return nil, errors.New("test error") }
	var q *event.Queue
	before := runtime.NumGoroutine()
	var stdout, stderr strings.Builder
	code := serveWith(t.Context(), func() {}, cfg, tempState(t, cfg), depsWithQueue(&q), &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "phantom: decoy listener does not start\n") || stdout.Len() != 0 {
		t.Errorf("exit %d, stderr %q, stdout %q; want 1, the fixed line and no stdout", code, stderr.String(), stdout.String())
	}
	if !q.Closed() || inUse(https) || inUse(plain) {
		t.Errorf("queue closed %v, sockets held %v %v; want true, false false", q.Closed(), inUse(https), inUse(plain))
	}
	for end := time.Now().Add(2 * time.Second); runtime.NumGoroutine() > before && time.Now().Before(end); {
		time.Sleep(5 * time.Millisecond)
	}
	if n := runtime.NumGoroutine(); n > before {
		t.Errorf("goroutines = %d, want at most %d", n, before)
	}
}

// TestTI03_SigtermStopsServe sends SIGTERM to the real serve function. It checks that serve returns 0, and that
// the queue closes after both serve calls returned (NFR-05).
func TestTI03_SigtermStopsServe(t *testing.T) {
	cfg := serveCfg(t, freeAddr(t), freeAddr(t))
	var q *event.Queue
	d, p := depsWithQueue(&q), tempState(t, cfg)
	oldSetup, oldLog := serveSetup, log.Writer()
	t.Cleanup(func() { serveSetup = oldSetup; log.SetOutput(oldLog) })
	serveSetup = func(startParams) (startParams, startDeps) { return p, d }
	closed := closedAtReturn(t, &q)
	var out, errb syncBuf
	code := make(chan int, 1)
	go func() { code <- serve(cfg, &out, &errb) }()
	for begin := time.Now(); !strings.Contains(out.String(), "phantom: started"); time.Sleep(5 * time.Millisecond) {
		if time.Since(begin) > 5*time.Second {
			t.Fatalf("no start line; stderr %q", errb.String())
		}
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case c := <-code:
		if c != 0 || !q.Closed() || !reflect.DeepEqual(closed(), []bool{false, false}) {
			t.Errorf("exit %d, queue closed %v, closed at return %v; want 0, true, [false false]", c, q.Closed(), closed())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not return after SIGTERM")
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
	https, ca := freeAddr(t), "https://"+freeAddr(t)+"/directory"
	der := seedCache(t, startParams{Root: stateDir, CacheDir: "certs"}, ca)
	cmd := exec.Command(bin, writeFile(t, validBody(t)))
	cmd.Env = append(os.Environ(), "CKPT_TOKEN="+strings.Repeat("t", 32), "PHANTOM_LISTEN_HTTPS="+https,
		"PHANTOM_LISTEN_HTTP="+freeAddr(t), "PHANTOM_ACME_CA="+ca)
	var errb syncBuf
	cmd.Stderr = &errb
	begin := time.Now()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill() })
	defer coldHandshake(t, https, begin, der, &errb).Close()
	cmd.Process.Signal(syscall.SIGTERM)
	if err := cmd.Wait(); err != nil {
		t.Errorf("after SIGTERM: %v; stderr %q", err, errb.String())
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
