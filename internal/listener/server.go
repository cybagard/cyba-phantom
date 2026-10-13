// Package listener is the core of the decoy listener: an HTTP/1.1 server over
// TLS with bounds on connections, headers and time (SEC-02, SEC-22), a fixed
// size copy of the first ClientHello of each connection (FR-05), and an error
// log that counts and keeps no client data (SEC-22).
package listener

import (
	"context"
	"crypto/tls"
	"errors"
	"log"
	"net"
	"net/http"
	"sync/atomic"
	"time"
)

// Config is the input of New.
type Config struct {
	// TLS gives the certificates. The server clones it, sets the ALPN list
	// to http/1.1 and sets the ClientHello capture.
	TLS *tls.Config
	// MaxConns is the number of open connections. limits.max_conns.
	MaxConns int
	// HeaderBytes is the header size cap. limits.header_bytes.
	HeaderBytes int
}

// timeouts holds the time bounds of the server. A test sets short values.
type timeouts struct {
	readHeader, read, write, idle time.Duration
}

// defaultTimeouts are the production values. The read-header timeout is also
// the handshake deadline: net/http uses the smallest of the three read and
// write timeouts, and only for a connection that is a *tls.Conn.
var defaultTimeouts = timeouts{
	readHeader: 10 * time.Second,
	read:       10 * time.Second,
	write:      10 * time.Second,
	idle:       30 * time.Second,
}

// countWriter counts the lines of the server error log and drops them.
type countWriter struct{ n atomic.Uint64 }

func (w *countWriter) Write(p []byte) (int, error) {
	w.n.Add(1)
	return len(p), nil
}

// Server is the decoy listener core.
type Server struct {
	srv      *http.Server
	tls      *tls.Config
	maxConns int
	errLines countWriter
}

// New returns a server with the production bounds.
func New(cfg Config, h http.Handler) (*Server, error) {
	return newServer(cfg, h, defaultTimeouts)
}

func newServer(cfg Config, h http.Handler, t timeouts) (*Server, error) {
	if cfg.TLS == nil || cfg.MaxConns < 1 || cfg.HeaderBytes < 1 {
		return nil, errors.New("listener: TLS config, max conns and header bytes are required")
	}
	s := &Server{tls: cfg.TLS.Clone(), maxConns: cfg.MaxConns}
	s.tls.NextProtos = []string{"http/1.1"}
	s.tls.GetConfigForClient = captureHello
	var p http.Protocols
	p.SetHTTP1(true)
	s.srv = &http.Server{
		Handler:           h,
		ReadHeaderTimeout: t.readHeader,
		ReadTimeout:       t.read,
		WriteTimeout:      t.write,
		IdleTimeout:       t.idle,
		MaxHeaderBytes:    cfg.HeaderBytes,
		Protocols:         &p,
		ErrorLog:          log.New(&s.errLines, "", 0),
		ConnContext: func(ctx context.Context, _ net.Conn) context.Context {
			return withConnState(ctx)
		},
	}
	return s, nil
}

// Serve accepts connections from the raw TCP listener ln until Close. The
// connection cap sits on the raw listener, the TLS layer on top of it.
func (s *Server) Serve(ln net.Listener) error {
	return s.srv.Serve(tls.NewListener(newLimitListener(ln, s.maxConns), s.tls))
}

// Close closes the listener and all connections.
func (s *Server) Close() error { return s.srv.Close() }

// ErrorLines is the number of lines that the server wrote to its error log.
// They include one line for each failed handshake. The log keeps no text.
func (s *Server) ErrorLines() uint64 { return s.errLines.n.Load() }
