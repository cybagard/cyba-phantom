package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"slices"
	"time"

	"github.com/cybagard/cyba-phantom/internal/config"
	"github.com/cybagard/cyba-phantom/internal/listener"
)

// checkAES checks the CPU for hardware AES and sets the health flag. With
// none, it writes one fixed warning line (SEC-33). It returns true when
// there is no hardware AES.
func checkAES(stderr io.Writer) bool {
	noAES := !hasHardwareAES()
	noHardwareAES.Store(noAES)
	if noAES {
		fmt.Fprintln(stderr, aesWarning)
	}
	return noAES
}

// shutdownServers asks the servers to end their open connections. They get
// shutdownTime for it.
func shutdownServers(srv *listener.Server) {
	sctx, cancel := context.WithTimeout(context.Background(), shutdownTime)
	srv.Shutdown(sctx)
	cancel()
}

// abortStart closes the two listen sockets and then stops the certificate
// client, closes the cache, and stops the store part. It skips the client and
// the cache when they are nil. An early return of serveWith calls it.
func abortStart(httpsLn, httpLn net.Listener, acme *listener.ACME, cache *listener.Store, s *storePart) {
	httpsLn.Close()
	httpLn.Close()
	if acme != nil {
		stopACME(acme)
	}
	if cache != nil {
		cache.Close()
	}
	s.Stop()
}

// serveNames gives the acme.names entries and the decoy names. It also gives
// the acme.names entries as a map with the keys that normalName gives.
// The decoy names are the acme.names entries and then the tls.certs names.
func serveNames(cfg *config.Config, c content) (names, decoys []string, acmeNames map[string]bool) {
	names = cfg.List("acme.names")
	decoys = slices.Clone(names)
	acmeNames = make(map[string]bool, len(names))
	for _, n := range names {
		if key, ok := normalName(n); ok {
			acmeNames[key] = true
		}
	}
	for _, e := range c.static {
		decoys = append(decoys, e.Name)
	}
	return names, decoys, acmeNames
}

// startCerts opens the cache and starts the client. It returns the cache, the
// client, and the fixed line of the first failure, or "". The client is nil
// when it does not exist. The cache is what listener.Open returned.
func startCerts(ctx context.Context, cfg *config.Config, c content, p startParams, s *storePart, names []string, httpsLn net.Listener, stderr io.Writer) (cache *listener.Store, acme *listener.ACME, line string) {
	const clientLine = "phantom: certificate client does not start"
	if s.root == nil {
		return nil, nil, "phantom: state directory does not open"
	}
	cache, err := listener.Open(s.root, p.CacheDir)
	if err != nil {
		return cache, nil, "phantom: certificate cache does not open"
	}
	ca := cfg.Must("acme.ca")
	// Load requires acme.email with acme.names. Without it, no client.
	email, ok := cfg.Get("acme.email")
	if !ok {
		return cache, nil, clientLine
	}
	addr := httpsLn.Addr().(*net.TCPAddr)
	acme, err = newACME(listener.ACMEParams{
		Names: names, CA: config.CADirectory(ca.Str), Email: email.Str, Storage: cache,
		Host: solverHost(addr), Port: addr.Port, Logger: slog.New(slog.NewTextHandler(stderr, nil)),
		CARoots: c.roots, CAPrivate: cfg.PrivateList("acme.ca_private"),
	})
	if err != nil {
		return cache, nil, clientLine
	}
	if startACME(ctx, acme) != nil {
		// The client serves the cached certificates.
		return cache, acme, clientLine
	}
	return cache, acme, ""
}

// startLine gives the start line. It adds one part for each state that is
// not healthy. certLine is the line that startCerts gave. acmeSet is true when
// the certificate client exists.
func startLine(s *storePart, b *bundlePart, noAES bool, certLine string, acmeSet bool) string {
	line := "phantom: started"
	if !s.Healthy() {
		line += " — store not healthy"
	}
	if !b.Healthy() {
		line += " — bundle not healthy"
	}
	if noAES {
		line += " — no hardware AES"
	}
	if certLine != "" && acmeSet {
		line += " — certificate client start failed"
	} else if certLine != "" {
		line += " — certificate client did not start"
	}
	return line
}

// closeBounded stops the certificate client, closes the cache, and stops the
// store part, in this order. It skips the client and the cache when they are
// nil. These close steps run in one goroutine. Serve waits for it at most
// closeTime. When it does not end, serve writes one fixed line and gives
// exit 1. The process exit then cuts the close, as a crash does (ADR-041).
// It returns false when the close did not end in closeTime.
func closeBounded(stderr io.Writer, acme *listener.ACME, cache *listener.Store, s *storePart) bool {
	closed := make(chan struct{})
	go func() {
		defer close(closed)
		if acme != nil {
			stopACME(acme)
		}
		if cache != nil {
			cache.Close()
		}
		s.Stop()
	}()
	timer := time.NewTimer(closeTime)
	defer timer.Stop()
	select {
	case <-closed:
		return true
	case <-timer.C:
		// The close goes on in its goroutine. The exit cuts it (ADR-041).
		fmt.Fprintf(stderr, "phantom: close did not end in %v\n", closeTime)
		return false
	}
}
