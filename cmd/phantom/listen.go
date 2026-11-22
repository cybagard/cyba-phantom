package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cybagard/cyba-phantom/internal/bait"
	"github.com/cybagard/cyba-phantom/internal/config"
	"github.com/cybagard/cyba-phantom/internal/event"
	"github.com/cybagard/cyba-phantom/internal/listener"
)

var errNoClient = errors.New("no certificate client")

// solverHost gives the host of the ACME solver for the bound address of the
// decoy listener. An unspecified address gives the empty host. An address
// that is specified gives the IP text, with "%" and the zone if it has one.
func solverHost(addr *net.TCPAddr) string {
	if addr.IP.IsUnspecified() {
		return ""
	}
	return (&net.IPAddr{IP: addr.IP, Zone: addr.Zone}).String()
}

// normalName returns a server name in lower case with one trailing dot
// removed. It returns false for a name with a byte of 0x80 or more.
// The certificate source applies the same rule: it refuses such a name.
func normalName(name string) (string, bool) {
	for i := 0; i < len(name); i++ {
		if name[i] >= 0x80 {
			return "", false
		}
	}
	return strings.TrimSuffix(strings.ToLower(name), "."), true
}

// shutdownTime is the time that the servers get to end their open connections at the stop.
const shutdownTime = 5 * time.Second

// closeTime is the time that serve waits for the close steps.
// The wait starts after the servers stopped.
const closeTime = 1500 * time.Millisecond

// The seams of serveWith. A test replaces them to see the order of the start and the stop.
var (
	newServer = listener.New
	newACME   = listener.NewACME
	startACME = func(ctx context.Context, a *listener.ACME) error { return a.Start(ctx) }
	stopACME  = (*listener.ACME).Stop
	warnCerts = (*listener.CertSource).WarnExpiry
	served    = func() {} // runs after Serve or ServePlain returned
	listen    = net.Listen
	waitStop  = func(ctx context.Context) { <-ctx.Done() } // serve waits here until the stop
	// serveSetup gives serve the start values and the parts of the store start. A test sets another state directory.
	serveSetup = func(p startParams) (startParams, startDeps) { return p, realDeps }
)

// serveArgs holds the values of serveWith, other than its context.
type serveArgs struct {
	stop           context.CancelFunc // the cancel function of the context
	hup            <-chan os.Signal   // asks for a bundle load; nil gives none
	cfg            *config.Config
	c              content // the parsed static certificates and roots
	p              startParams
	d              startDeps
	stdout, stderr io.Writer
}

// serveWith runs the sensor on the state of a.p until ctx ends.
// The start checks the CPU for hardware AES first. With none, it writes one
// fixed warning line, sets the health flag, and goes on (SEC-33).
// The start order is: the queue, the two listen sockets, the store part,
// the bundle part, and the decoy server.
// The bundle part loads only when the store part has a writer.
// Then: the cache and client, when acme.names is set.
// Then: the certificate source.
// Then: WarnExpiry, when there is a static entry.
// Then: the serve calls.
// serveNames gives the decoy names.
// a.c holds the parsed static certificates and roots.
// With no acme.names entry, no cache opens and no client starts.
// A static name gets its certificate from a.c.
// When the client is absent, an ACME name fails with errNoClient.
// It records no gate reason. A static name is still served.
// WarnExpiry runs with ctx when a.c holds a static certificate.
// A bind error ends the start before the store part opens a file.
// The stop is the reverse. Both serve calls return. Then the client stops, the cache closes,
// and the store part closes the queue. Thus no handler adds an event to a closed queue.
// closeBounded runs these close steps with a time bound (ADR-041).
// A failure of the state directory, the cache or the client does not end the process.
// The decoys serve, the sensor writes one fixed line, and the start line says that it is not healthy.
// A queue error, a bind error, or a decoy server that does not start
// gives exit 1 at once.
// A serve call that ends with an error also gives exit 1, after the stop.
// A signal on a.hup, a SIGHUP, asks for one bundle load with the source
// signal. A signal that comes during the start waits on a.hup until the
// serve calls run.
// Signals that come during a load give at most one more load.
// A nil a.hup gives none.
// The reload goroutine is in wg, so it ends before the queue closes.
// After the stop began, the goroutine starts no new load.
// A load in its wait for the swap gap at the stop ends the wait at once.
// It does not start, and it sends no event. A load that has started runs to
// its end. The goroutine ends before the queue closes.
// With a bundle.fetch_url and a loader, one fetcher starts after the start
// load. The expiry watch starts with a loader. Both are in wg, so they end
// before the queue closes. After the stop began, the fetcher starts no new
// load. A fetch load in its wait for the swap gap at the stop does not start.
// A fetch load that has started runs to its end. A newFetcher
// error gives one fixed line.
// a.stop is the cancel function of ctx.
func serveWith(ctx context.Context, a serveArgs) int {
	stop, hup, cfg, c, p, d := a.stop, a.hup, a.cfg, a.c, a.p, a.d
	stdout, stderr := a.stdout, a.stderr
	noAES := checkAES(stderr)
	counters := event.NewCounters()
	depth := cfg.Must("limits.queue_depth")
	q, err := event.NewQueue(int(depth.Int), counters)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	httpsLn, httpLn, ok := bindBoth(cfg, stderr)
	if !ok {
		return 1
	}
	lg := slog.New(slog.NewTextHandler(stderr, nil))
	s := start(p, q, d, lg)
	if line := s.refusal(); line != "" {
		fmt.Fprintln(stderr, line)
		abortStart(httpsLn, httpLn, nil, nil, s)
		return 1
	}
	b := startBundle(p, s, q, lg)
	names, decoys, acmeNames := serveNames(cfg, c)
	maxConns := cfg.Must("limits.max_conns")
	headerBytes := cfg.Must("limits.header_bytes")
	var cache *listener.Store
	var acme *listener.ACME         // nil when the client does not exist
	var source *listener.CertSource // set before the serve calls
	// The handshake runs only after Serve, which starts after source is set.
	srv, err := newServer(listener.Config{
		TLS: &tls.Config{GetCertificate: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if acme == nil {
				// A name that normalName refuses is no ACME name.
				// The source refuses it with its gate reason.
				if key, ok := normalName(h.ServerName); ok && acmeNames[key] {
					return nil, errNoClient
				}
			}
			return source.GetCertificate(h)
		}},
		MaxConns:    int(maxConns.Int),
		HeaderBytes: int(headerBytes.Int),
		Queue:       q,
		Counters:    counters,
	}, decoyHandler(cfg, b, s, q, decoys))
	if err != nil {
		fmt.Fprintln(stderr, "phantom: decoy listener does not start")
		abortStart(httpsLn, httpLn, nil, nil, s)
		return 1
	}
	// certmagic writes with the standard log package. Serve drops the text and
	// does not count it. This runs before the client exists.
	log.SetOutput(io.Discard)
	certLine := ""
	if len(names) > 0 {
		cache, acme, certLine = startCerts(ctx, cfg, c, p, s, names, httpsLn, stderr)
	}
	if certLine != "" {
		fmt.Fprintln(stderr, certLine)
	}
	if source, err = listener.NewCertSource(c.static, acme); err != nil {
		fmt.Fprintln(stderr, "phantom: decoy listener does not start")
		abortStart(httpsLn, httpLn, acme, cache, s)
		return 1
	}
	if len(c.static) > 0 {
		warnCerts(source, ctx, slog.New(slog.NewTextHandler(stderr, nil)))
	}
	var wg sync.WaitGroup
	var failed atomic.Bool // a serve call ended with an error: the exit code is 1, so a supervisor restarts the sensor
	serveOne := func(f func() error) {
		wg.Go(func() {
			if err := f(); !errors.Is(err, http.ErrServerClosed) {
				fmt.Fprintln(stderr, "phantom: listener stopped")
				failed.Store(true)
				stop()
			}
			served()
		})
	}
	// The fetcher and the watch start here. This is after the start load.
	// Serve sets the std log writer to io.Discard before this point.
	// No early return follows.
	b.startFetchAndWatch(ctx, &wg, cfg)
	serveOne(func() error { return srv.Serve(httpsLn) })
	serveOne(func() error { return srv.ServePlain(httpLn, listener.NewRedirect(decoys)) })
	// This starts after the last early return of serveWith. Each path that
	// starts it thus reaches wg.Wait before s.Stop().
	wg.Go(func() { b.reloadOnSignal(ctx, hup) })
	fmt.Fprintln(stdout, startLine(s, b, noAES, certLine, acme != nil))
	waitStop(ctx)
	stop() // A second signal during the stop gets the default action.
	shutdownServers(srv)
	wg.Wait()
	if !closeBounded(stderr, clientStop(acme), cache, s) || failed.Load() {
		return 1
	}
	return 0
}

// decoyHandler returns the handler of the decoy listener. With a loader, it is
// the bait handler. The hello handler is its fallback. With no loader, no load
// ran, and the hello handler serves alone. The bait handler shares the day key
// holder of the writer (SEC-35). With privacy.session_cookie false, the cookie
// is off. With privacy.js_beacon false, the beacon is off (SEC-38). The bait
// handler gets the token ring of the loader, so callback routes verify tokens
// (SEC-37). decoyHandler sets each switch and the ring before any Serve call,
// so the first request reads the value.
func decoyHandler(cfg *config.Config, b *bundlePart, s *storePart, q *event.Queue, decoys []string) http.Handler {
	hello := listener.NewHelloHandler(decoys, q)
	if b.l == nil {
		return hello
	}
	h := bait.NewWithDayKey(b.l, hello, q, s.DayKey())
	h.SetRing(b.l.Ring())
	if !cfg.Must("privacy.session_cookie").Bool {
		h.DisableSessionCookie()
	}
	if !cfg.Must("privacy.js_beacon").Bool {
		h.DisableBeacon()
	}
	return h
}

// bindBoth binds listen.https and then listen.http. On an error it writes one fixed line that names the
// key and no value, closes the socket that it bound, and returns false.
func bindBoth(cfg *config.Config, stderr io.Writer) (https, plain net.Listener, ok bool) {
	var lns []net.Listener
	for _, k := range []string{"listen.https", "listen.http"} {
		ln, err := listen("tcp", cfg.Must(k).Str)
		if err != nil {
			fmt.Fprintf(stderr, "phantom: cannot bind %s\n", k)
			for _, l := range lns {
				l.Close()
			}
			return nil, nil, false
		}
		lns = append(lns, ln)
	}
	return lns[0], lns[1], true
}
