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
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cybagard/cyba-phantom/internal/config"
	"github.com/cybagard/cyba-phantom/internal/event"
	"github.com/cybagard/cyba-phantom/internal/listener"
)

// shutdownTime is the time that the servers get to end their open connections at the stop.
const shutdownTime = 5 * time.Second

// The seams of serveWith. A test replaces them to see the order of the start and the stop.
var (
	newServer = listener.New
	startACME = (*listener.ACME).Start
	served    = func() {} // runs after Serve or ServePlain returned
	listen    = net.Listen
	// serveSetup gives serve the start values and the parts of the store start. A test sets another state directory.
	serveSetup = func(p startParams) (startParams, startDeps) { return p, realDeps }
)

// serveWith runs the sensor on the state of p until ctx ends. The order is fixed (T-S-16): the queue, the two
// listen sockets (a bind error ends it before the store part opens a file), the store part, the certificate
// cache and client, then the servers. The stop is the reverse: both servers return, then the client, the cache
// and the store part, which closes the queue. Thus no handler adds an event to a closed queue.
// stop is the cancel function of ctx.
func serveWith(ctx context.Context, stop context.CancelFunc, cfg *config.Config, p startParams, d startDeps, stdout, stderr io.Writer) int {
	c := event.NewCounters()
	depth, _ := cfg.Get("limits.queue_depth")
	q, err := event.NewQueue(int(depth.Int), c)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	httpsLn, httpLn, ok := bindBoth(cfg, stderr)
	if !ok {
		return 1
	}
	s := start(p, q, c, d, slog.New(slog.NewTextHandler(stderr, nil)))
	var cache *listener.Store
	var acme *listener.ACME
	// abort ends a start that failed, in the order of the stop. No server runs yet.
	abort := func(msg string) int {
		fmt.Fprintln(stderr, msg)
		httpsLn.Close()
		httpLn.Close()
		if acme != nil {
			acme.Stop()
		}
		if cache != nil {
			cache.Close()
		}
		s.Stop()
		return 1
	}
	if s.root == nil {
		return abort("phantom: certificate cache does not open")
	} else if cache, err = listener.Open(s.root, p.CacheDir); err != nil {
		return abort("phantom: certificate cache does not open")
	}
	var names []string
	for i := 0; ; i++ {
		v, _ := cfg.Get("acme.names[" + strconv.Itoa(i) + "]")
		if v.Str == "" {
			break
		}
		names = append(names, v.Str)
	}
	maxConns, _ := cfg.Get("limits.max_conns")
	headerBytes, _ := cfg.Get("limits.header_bytes")
	// The handshake runs only after Serve, which starts after acme is set.
	srv, err := newServer(listener.Config{
		TLS:         &tls.Config{GetCertificate: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) { return acme.GetCertificate(h) }},
		MaxConns:    int(maxConns.Int),
		HeaderBytes: int(headerBytes.Int),
	}, listener.NewHelloHandler(names, q))
	if err != nil {
		return abort("phantom: decoy listener does not start")
	}
	// certmagic also writes with the standard log package. It gets the counting writer of the server error log,
	// which keeps no text. This runs before the client exists.
	log.SetOutput(srv.ErrLog())
	ca, _ := cfg.Get("acme.ca")
	email, _ := cfg.Get("acme.email")
	addr := httpsLn.Addr().(*net.TCPAddr)
	host := ""
	if !addr.IP.IsUnspecified() {
		host = addr.IP.String()
	}
	acme, err = listener.NewACME(listener.ACMEParams{
		Names: names, CA: config.CADirectory(ca.Str), Email: email.Str, Storage: cache,
		Host: host, Port: addr.Port, Logger: slog.New(slog.NewTextHandler(stderr, nil)),
	})
	if err != nil {
		return abort("phantom: certificate client does not start")
	}
	if err := startACME(acme, ctx); err != nil {
		return abort("phantom: certificate client does not start")
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
	serveOne(func() error { return srv.Serve(httpsLn) })
	serveOne(func() error { return srv.ServePlain(httpLn, listener.NewRedirect(names)) })
	if s.Healthy() {
		fmt.Fprintln(stdout, "phantom: started")
	} else {
		fmt.Fprintln(stdout, "phantom: started — store not healthy")
	}
	<-ctx.Done()
	stop() // A second signal during the stop gets the default action.
	sctx, cancel := context.WithTimeout(context.Background(), shutdownTime)
	srv.Shutdown(sctx)
	cancel()
	wg.Wait()
	acme.Stop()
	cache.Close()
	s.Stop()
	if failed.Load() {
		return 1
	}
	return 0
}

// bindBoth binds listen.https and then listen.http. On an error it writes one fixed line that names the
// key and no value, closes the socket that it bound, and returns false.
func bindBoth(cfg *config.Config, stderr io.Writer) (https, plain net.Listener, ok bool) {
	var lns []net.Listener
	for _, k := range []string{"listen.https", "listen.http"} {
		v, _ := cfg.Get(k)
		ln, err := listen("tcp", v.Str)
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
