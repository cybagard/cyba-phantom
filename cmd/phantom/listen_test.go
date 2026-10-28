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
	"io"
	"log"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strconv"
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

const decoyName = "decoy.host.zz"

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
	signal  sync.Once // closes started one time
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
		w.signal.Do(func() { close(w.started) })
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
// It also gives an address for the ACME CA. The host is a name below .invalid.
// RFC 6761 reserves that name, but Go still looks it up. On Linux, Go asks
// for A and AAAA, for the name and for the name with each search domain.
// With no network, the lookup fails in under 1 ms.
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
	return https, plain, "ca.phantom.invalid:14000"
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
// After a timeout in the cleanup, serve and its sockets stay in the process.
// Later results in the same process are not reliable.
func launchServe(t *testing.T, cfg *config.Config, p startParams, d startDeps) *running {
	oldLog := log.Writer()
	t.Cleanup(func() { log.SetOutput(oldLog) })
	ctx, cancel := context.WithCancel(t.Context())
	r := &running{cancel: cancel, done: make(chan struct{}), out: newStartWriter(), begin: time.Now()}
	go func() { r.code = serveWith(ctx, cancel, cfg, p, d, r.out, &r.err); close(r.done) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-r.done:
		case <-time.After(sigtermWait):
			t.Errorf("serve did not return %v after the cancel at the end of the test", sigtermWait)
		}
	})
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
	return startWait{
		who:   "serve",
		out:   r.out,
		ended: r.done,
		info:  func() string { return fmt.Sprintf("exit %d; stderr %q", r.code, r.err.String()) },
	}
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
				// serve wrote the start line. Stop it, then read the exit code.
				r.cancel()
				select {
				case <-r.done:
				case <-time.After(sigtermWait):
					t.Fatalf("serve did not return %v after the cancel", sigtermWait)
				}
			}
			if r.out.hasStarted() {
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

// freePorts returns two different TCP ports that no socket holds now.
// It holds both listeners while it takes the ports.
// Another process can take a port before the caller binds it.
func freePorts(t *testing.T) (int, int) {
	t.Helper()
	var ports [2]int
	for i := range ports {
		ln, err := net.Listen("tcp", ":0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		ports[i] = ln.Addr().(*net.TCPAddr).Port
	}
	return ports[0], ports[1]
}

// listenSockets returns the local port of each TCP socket that this
// process holds in the LISTEN state, by inode. It reads /proc/net/tcp
// and /proc/net/tcp6. It keeps the entries of the socket files of the
// process.
func listenSockets(t *testing.T) map[string]int {
	t.Helper()
	own := map[string]bool{}
	fds, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for _, fd := range fds {
		if link, err := os.Readlink("/proc/self/fd/" + fd.Name()); err == nil {
			if inode, ok := strings.CutPrefix(link, "socket:["); ok {
				own[strings.TrimSuffix(inode, "]")] = true
			}
		}
	}
	socks := map[string]int{}
	for _, name := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		data, err := os.ReadFile(name)
		if errors.Is(err, os.ErrNotExist) && name == "/proc/net/tcp6" {
			continue // a system with no IPv6
		}
		if err != nil {
			t.Fatal(err)
		}
		for line := range strings.Lines(string(data)) {
			f := strings.Fields(line)
			// State 0A is LISTEN.
			if len(f) < 10 || f[3] != "0A" || !own[f[9]] {
				continue
			}
			_, hexPort, _ := strings.Cut(f[1], ":")
			port, err := strconv.ParseUint(hexPort, 16, 16)
			if err != nil {
				t.Fatalf("%s: local address %q: %v", name, f[1], err)
			}
			socks[f[9]] = int(port)
		}
	}
	return socks
}

// TestTS16_WildcardListen starts serve with listen.https on 0.0.0.0,
// on [::], on 127.0.0.1, and on the empty host. After the start line,
// the process has exactly two new LISTEN sockets: the two decoy sockets.
// The test seeds a cached certificate, so no challenge runs. An
// unspecified IP gives the empty Host to the client, so the solver
// address is ":port". A bind on the solver address fails with "address
// already in use", because the decoy socket holds the port. The test
// checks the other parameters that serve gives to the client.
// The test needs /proc/net/tcp. It skips without it.
func TestTS16_WildcardListen(t *testing.T) {
	if _, err := os.Stat("/proc/net/tcp"); err != nil {
		t.Skip("there is no /proc/net/tcp: the test reads the LISTEN sockets from it")
	}
	for _, c := range []struct{ name, host, wantHost string }{
		{"0.0.0.0", "0.0.0.0", ""},
		{"[::]", "[::]", ""},
		{"127.0.0.1", "127.0.0.1", "127.0.0.1"},
		{"no host", "", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			// The test uses only the CA address. Serve binds the others
			// with the real listen.
			_, _, ca := openListeners(t)
			httpsPort, httpPort := freePorts(t)
			https := c.host + ":" + strconv.Itoa(httpsPort)
			cfg := serveCfg(t, https, "127.0.0.1:"+strconv.Itoa(httpPort), ca)
			p := tempState(t, cfg)
			caURL, _ := cfg.Get("acme.ca")
			// With a cached certificate the client makes no order.
			seedCache(t, p, caURL.Str)
			var got listener.ACMEParams
			oldNew := newACME
			t.Cleanup(func() { newACME = oldNew })
			newACME = func(ap listener.ACMEParams) (*listener.ACME, error) { got = ap; return oldNew(ap) }
			before := listenSockets(t)
			r := launchServe(t, cfg, p, realDeps)
			r.waitStarted(t)
			var fresh []int
			for inode, port := range listenSockets(t) {
				if _, old := before[inode]; !old {
					fresh = append(fresh, port)
				}
			}
			slices.Sort(fresh)
			want := []int{httpsPort, httpPort}
			slices.Sort(want)
			if !slices.Equal(fresh, want) {
				t.Errorf("new LISTEN ports %v, want exactly %v (the two decoy sockets)", fresh, want)
			}
			if got.Host != c.wantHost {
				t.Errorf("Host given to NewACME = %q, want %q", got.Host, c.wantHost)
			}
			if got.Port != httpsPort {
				t.Errorf("Port given to NewACME = %d, want %d", got.Port, httpsPort)
			}
			var wantNames []string
			for i := 0; ; i++ {
				v, _ := cfg.Get("acme.names[" + strconv.Itoa(i) + "]")
				if v.Str == "" {
					break
				}
				wantNames = append(wantNames, v.Str)
			}
			if !slices.Equal(got.Names, wantNames) {
				t.Errorf("Names given to NewACME = %q, want %q", got.Names, wantNames)
			}
			if want := config.CADirectory(caURL.Str); got.CA != want {
				t.Errorf("CA given to NewACME = %q, want %q", got.CA, want)
			}
			if email, _ := cfg.Get("acme.email"); got.Email != email.Str {
				t.Errorf("Email given to NewACME = %q, want %q", got.Email, email.Str)
			}
			if got.Storage == nil {
				t.Error("Storage given to NewACME is nil")
			}
			if got.Logger == nil {
				t.Error("Logger given to NewACME is nil")
			}
			solver := net.JoinHostPort(got.Host, strconv.Itoa(got.Port))
			if ln, err := net.Listen("tcp", solver); err == nil {
				ln.Close()
				t.Errorf("a bind on the solver address %q worked, want an error", solver)
			} else if !errors.Is(err, syscall.EADDRINUSE) || !strings.Contains(err.Error(), "address already in use") {
				t.Errorf("a bind on the solver address %q: %v; want address already in use", solver, err)
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

// holdServed is the time that TestTI03_StartAndStopOrder holds one
// serve call.
const holdServed = 300 * time.Millisecond

// netWait is the deadline of a dial or a request that a test makes to
// the local sensor.
const netWait = 5 * time.Second

// TestTI03_StartAndStopOrder checks that the store and the certificate client start after serve holds the two test
// listeners. It checks that serve holds them while the sensor runs.
// After the context ends, the client stops and the queue closes after both serve calls returned (NFR-05).
// The test holds one serve call. A stop of the client before that call
// returns frees the call. The count in the event of the stop shows it.
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
	startACME = func(ctx context.Context, a *listener.ACME) error {
		note(fmt.Sprint("acme bound=", bound()))
		return a.Start(ctx)
	}
	returned := 0
	stopSeen := make(chan struct{})
	markStop := sync.OnceFunc(func() { close(stopSeen) })
	var holdOne sync.Once
	served = func() {
		// The first serve call to return waits here until stopACME
		// runs, or until holdServed ends. With the correct order,
		// serveWith calls stopACME only after this call returns, so
		// the time ends the wait.
		// If stopACME runs before both serve calls returned, it
		// frees this call. Then the count in its event is below 2.
		holdOne.Do(func() {
			select {
			case <-stopSeen:
			case <-time.After(holdServed):
			}
		})
		mu.Lock()
		returned++
		mu.Unlock()
		note(fmt.Sprint("served closed=", q.Closed()))
	}
	stopACME = func(a *listener.ACME) {
		mu.Lock()
		n := returned
		mu.Unlock()
		note(fmt.Sprint("acme stop after serve calls=", n))
		markStop()
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
	// The timeout covers the TLS handshake too.
	dialer := &net.Dialer{Timeout: netWait}
	if _, err := tls.DialWithDialer(dialer, "tcp", https, &tls.Config{ServerName: "other.example.com", InsecureSkipVerify: true}); err == nil {
		t.Error("a handshake for a name that is not configured worked")
	}
	if raw, err := dialer.Dial("tcp", https); err == nil {
		raw.SetDeadline(time.Now().Add(netWait))
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

// TestTI03_OpenFailureKeepsServe breaks the certificate cache, the
// state directory, the make of the client, and the start of the client.
// Each case must write its stderr lines and its start line exactly.
// The redirect on listen.http must answer 308, and a cancel must give
// exit 0 (C3). With no client, a handshake on listen.https must fail
// with the TLS alert "internal error" and count. With a client that did
// not start, the cached certificate serves, and the cancel stops the
// client once.
func TestTI03_OpenFailureKeepsServe(t *testing.T) {
	for _, c := range []struct {
		name, line, startLine string
		// noState: the store start writes its own error line first.
		noState, cached bool
		// newFails: the make of the client fails. Serve calls newACME once.
		newFails bool
		breakIt  func(t *testing.T, p *startParams)
	}{
		{
			name:      "cache is a file",
			line:      "phantom: certificate cache does not open",
			startLine: "phantom: started — certificate client did not start",
			breakIt: func(t *testing.T, p *startParams) {
				if err := os.WriteFile(filepath.Join(p.Root, p.CacheDir), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name:      "no state directory",
			line:      "phantom: state directory does not open",
			startLine: "phantom: started — store not healthy — certificate client did not start",
			noState:   true,
			breakIt:   func(_ *testing.T, p *startParams) { p.Root = filepath.Join(p.Root, "missing") },
		},
		{
			name:      "client make fails",
			line:      "phantom: certificate client does not start",
			startLine: "phantom: started — certificate client did not start",
			newFails:  true,
		},
		{
			name:      "client start fails",
			line:      "phantom: certificate client does not start",
			startLine: "phantom: started — certificate client start failed",
			cached:    true,
		},
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
			oldNew, oldStart, oldStop := newACME, startACME, stopACME
			t.Cleanup(func() { newACME, startACME, stopACME = oldNew, oldStart, oldStop })
			stopACME = func(a *listener.ACME) { stops.Add(1); a.Stop() }
			var news atomic.Int32
			if c.newFails {
				// The value is not nil. So serve must reset it on the error.
				newACME = func(listener.ACMEParams) (*listener.ACME, error) {
					news.Add(1)
					return &listener.ACME{}, errors.New("test error")
				}
			}
			if c.cached {
				ca, _ := cfg.Get("acme.ca")
				der = seedCache(t, p, ca.Str)
				startACME = func(ctx context.Context, a *listener.ACME) error { a.Start(ctx); return errors.New("test error") }
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
			hc := &http.Client{Timeout: netWait, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			if resp, err := hc.Do(req); err != nil || resp.StatusCode != http.StatusPermanentRedirect {
				t.Errorf("redirect: %v, %v; want 308", resp, err)
			}
			if c.cached {
				coldHandshake(t, https, r.begin, der, &r.err).Close()
			} else {
				srv := server()
				lines := srv.ErrorLines()
				// Without the check for a missing client, the handshake panics and the client sees EOF.
				conn, err := tls.DialWithDialer(&net.Dialer{Timeout: netWait}, "tcp", https, &tls.Config{ServerName: decoyName, InsecureSkipVerify: true})
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
			if c.newFails && news.Load() != 1 {
				t.Errorf("newACME calls = %d, want 1", news.Load())
			}
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

// TestTU17_ListenerGetsQueueCounters checks that serve gives the listener
// the queue and the counters of that queue. After the queue is closed,
// a dropped event adds one to the counters of the listener.
func TestTU17_ListenerGetsQueueCounters(t *testing.T) {
	https, plain, ca := openListeners(t)
	cfg := serveCfg(t, https.Addr().String(), plain.Addr().String(), ca)
	var got listener.Config
	oldNew := newServer
	t.Cleanup(func() { newServer = oldNew })
	newServer = func(c listener.Config, _ http.Handler) (*listener.Server, error) {
		got = c
		return nil, errors.New("test error")
	}
	var q *event.Queue
	if code := serveWith(t.Context(), func() {}, cfg, tempState(t, cfg), depsWithQueue(&q), io.Discard, io.Discard); code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
	if q == nil || got.Queue != q || got.Counters == nil || !q.Closed() {
		t.Fatalf("listener queue %p, queue %p, counters %p, closed %v; want the same queue, counters and a closed queue", got.Queue, q, got.Counters, q != nil && q.Closed())
	}
	e, err := event.NewEvent(nil, event.Input{Kind: event.KindRefused, Reason: event.ReasonBadHello, ClientIP: "192.0.2.7"})
	if err != nil {
		t.Fatal(err)
	}
	q.Enqueue(e)
	if counts, _ := got.Counters.Snapshot(); counts[netip.MustParseAddr("192.0.2.7")] != 1 {
		t.Errorf("counters of the listener %v, want one drop for 192.0.2.7", counts)
	}
}

// TestTI03_ServerFailureExits1 makes the decoy server fail to start. It checks exit 1 with a fixed line, both
// listeners closed, the queue closed, the database closed, and no goroutine that serve left running.
// The test compares goroutine IDs right before the call and right after the return. It does not count
// goroutines. The runtime frees an ended goroutine later, and a count can include it.
// The close of a sql.DB cancels its connectionOpener goroutine but does not wait for it. The test skips a
// connectionOpener only when it belongs to the captured store database, and that database is closed with no
// open connection. Any other connectionOpener fails the test.
// The test also skips the other goroutines of database/sql,
// for example of a sql.Tx or sql.Rows. It does this only when
// openersOK is true: every connectionOpener passed the check.
// It also skips the goroutines of the runtime, for example the
// finalizer goroutine. Limit: the test does not find a leaked
// sql.Tx or sql.Rows of a second database that serve closes.
// Every other new goroutine fails the test.
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
	before := goroutineBlocks()
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
	// openers holds the database address of each new connectionOpener.
	openers := map[int]string{}
	for _, id := range fresh {
		if arg, ok := openerDB(after[id]); ok {
			openers[id] = arg
		}
	}
	openersOK := true
	for _, id := range fresh {
		arg, ok := openers[id]
		switch {
		case !ok:
		case closedDB == "":
			openersOK = false
			t.Errorf("goroutine %d is the connectionOpener of database %s, but no database passed the closed check:\n%s",
				id, arg, after[id])
		case arg != closedDB:
			openersOK = false
			t.Errorf("goroutine %d is the connectionOpener of database %s, not of the closed database %s:\n%s", id, arg, closedDB, after[id])
		}
	}
	for _, id := range fresh {
		block := after[id]
		if _, ok := openers[id]; ok {
			continue // checked above
		}
		if (openersOK && strings.Contains(block, "\ncreated by database/sql.")) || strings.Contains(block, "\ncreated by runtime.") {
			continue
		}
		t.Errorf("goroutine %d started in serve and is still running after serve returned:\n%s", id, block)
	}
}

// openerDB reports whether a frame of a stack block is
// (*sql.DB).connectionOpener. If so, it returns the text of the first
// argument, the address of the database, as the dump prints it.
func openerDB(block string) (string, bool) {
	for line := range strings.SplitSeq(block, "\n") {
		args, ok := strings.CutPrefix(line, "database/sql.(*DB).connectionOpener(")
		if !ok {
			continue
		}
		if i := strings.IndexAny(args, ",)"); i >= 0 {
			args = args[:i]
		}
		return strings.TrimSuffix(args, "?"), true
	}
	return "", false
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
// The test sends one SIGTERM only. The cleanup sends one if the body did not.
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
	// release frees serve from the wrapper of waitStop.
	release := sync.OnceFunc(func() { close(sent) })
	oldWait := waitStop
	t.Cleanup(func() { waitStop = oldWait })
	waitStop = func(ctx context.Context) {
		close(waiting)
		<-sent
		oldWait(ctx)
	}
	r := &running{done: make(chan struct{}), out: newStartWriter()}
	go func() { r.code = serve(cfg, r.out, &r.err); close(r.done) }()
	// sendSigterm sends one SIGTERM and waits until sig gets it.
	// A SIGTERM that comes after signal.Stop ends the process.
	// Thus the test waits for each delivery before it continues.
	// sigSent tells the cleanup that the test sent the signal.
	// sendSigterm empties sig before it sends. Thus the next value
	// on sig is from this signal.
	// late tells the cleanup that a receive timed out. The cleanup then waits
	// once more for the delivery before signal.Stop runs.
	var sigSent, late bool
	sendSigterm := func() error {
		select {
		case <-sig:
		default:
		}
		if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
			return err
		}
		sigSent = true
		select {
		case <-sig:
			return nil
		case <-time.After(sigtermWait):
			late = true
			return fmt.Errorf("the test did not get SIGTERM within %v", sigtermWait)
		}
	}
	// The cleanup ends in bounded time. It frees serve. It sends SIGTERM
	// only if the test body did not, and waits for its delivery.
	// Then it waits for serve to return.
	t.Cleanup(func() {
		release()
		if !sigSent {
			if err := sendSigterm(); err != nil {
				t.Error(err)
			}
		}
		select {
		case <-r.done:
		case <-time.After(sigtermWait):
			t.Errorf("serve did not return %v after the cleanup freed it", sigtermWait)
		}
		if late {
			select {
			case <-sig:
			case <-time.After(sigtermWait):
				t.Errorf("SIGTERM did not arrive in %v more", sigtermWait)
			}
		}
	})
	r.startWait().until(t, waiting, false)
	if err := sendSigterm(); err != nil {
		t.Fatal(err)
	}
	release()
	select {
	case <-r.done:
	case <-time.After(sigtermWait):
		t.Fatalf("serve did not return %v after SIGTERM", sigtermWait)
	}
	if r.code != 0 || !q.Closed() || !reflect.DeepEqual(closed(), []bool{false, false}) {
		t.Errorf("exit %d, queue closed %v, closed at return %v; want 0, true, [false false]", r.code, q.Closed(), closed())
	}
}

// sigtermWait is the time that serve gets to return after SIGTERM
// or a cancel. It is also the time that a signal of the test gets
// for its delivery. It is longer than shutdownTime.
const sigtermWait = shutdownTime + 10*time.Second

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
	// of the child stays. The CA name is below .invalid (see openListeners).
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
	startWait{
		who:   "the child",
		out:   out,
		ended: exited,
		info:  func() string { return fmt.Sprintf("%v; stderr %q", waitErr, errb.String()) },
	}.until(t, out.started, true)
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
