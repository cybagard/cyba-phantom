package listener

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
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
	// MaxConns is the maximum number of open connections of the server, for
	// all Serve calls. limits.max_conns.
	MaxConns int
	// HeaderBytes is the size cap of the request head: the request line, the
	// header lines and the blank line. New refuses a value below 8192.
	// limits.header_bytes.
	HeaderBytes int
}

// minHeaderBytes is the smallest HeaderBytes. net/http reads 4096 bytes more
// than MaxHeaderBytes, so the server sets MaxHeaderBytes to HeaderBytes - 4096.
const minHeaderBytes = 8192

// maxHeaderValues is the cap of header values in one request (SEC-02).
const maxHeaderValues = 64

// timeouts holds the time bounds of the server. A test sets short values.
type timeouts struct {
	readHeader, read, write, idle time.Duration
}

// defaultTimeouts are the production values. The read-header timeout is also
// the handshake deadline: net/http uses the smallest of the three read and
// write timeouts. It sets the deadline only for a connection that has a
// ConnectionState method, such as a *tls.Conn.
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
	sem      chan struct{} // the connection slots, shared by all Serve calls
	errLines countWriter
}

// New returns a server with the production bounds.
func New(cfg Config, h http.Handler) (*Server, error) {
	return newServer(cfg, h, defaultTimeouts)
}

func newServer(cfg Config, h http.Handler, t timeouts) (*Server, error) {
	if h == nil {
		return nil, errors.New("listener: a handler is required")
	}
	if cfg.TLS == nil || cfg.MaxConns < 1 {
		return nil, errors.New("listener: TLS config and max conns are required")
	}
	if cfg.HeaderBytes < minHeaderBytes {
		return nil, fmt.Errorf("listener: header bytes must be at least %d", minHeaderBytes)
	}
	s := &Server{tls: cfg.TLS.Clone(), sem: make(chan struct{}, cfg.MaxConns)}
	s.tls.NextProtos = []string{"http/1.1"}
	s.tls.GetConfigForClient = captureHello
	var p http.Protocols
	p.SetHTTP1(true)
	s.srv = &http.Server{
		Handler:             h,
		ReadHeaderTimeout:   t.readHeader,
		ReadTimeout:         t.read,
		WriteTimeout:        t.write,
		IdleTimeout:         t.idle,
		MaxHeaderBytes:      cfg.HeaderBytes - 4096,
		MaxHeaderValueCount: maxHeaderValues,
		Protocols:           &p,
		ErrorLog:            log.New(&s.errLines, "", 0),
		ConnContext: func(ctx context.Context, _ net.Conn) context.Context {
			return withConnState(ctx)
		},
	}
	// Each connection serves one request. A request head that a client sends
	// after the first request on the same connection is not read, so the header
	// cap holds for each head that is served.
	s.srv.SetKeepAlivesEnabled(false)
	return s, nil
}

// Serve accepts connections from the raw TCP listener ln until Close. The
// connection cap is on the raw listener, and the TLS layer is on top of it.
// A connection that a handler hijacks keeps its slot until the handler closes
// it. All Serve calls of one server share the MaxConns slots.
func (s *Server) Serve(ln net.Listener) error {
	return s.srv.Serve(tls.NewListener(newLimitListener(ln, s.sem), s.tls))
}

// Close closes the listener and all connections.
func (s *Server) Close() error { return s.srv.Close() }

// ErrorLines is the number of lines that the server wrote to its error log.
// They include one line for each failed handshake. The log keeps no text.
func (s *Server) ErrorLines() uint64 { return s.errLines.n.Load() }
