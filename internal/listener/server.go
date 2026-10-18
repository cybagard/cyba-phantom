package listener

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// Config is the input of New.
type Config struct {
	// TLS gives the certificates. The server clones it, sets the ALPN list
	// to http/1.1 and acme-tls/1, and sets the ClientHello capture. A
	// connection that negotiates acme-tls/1 gets no HTTP and closes after the
	// handshake.
	TLS *tls.Config
	// MaxConns is the maximum number of open connections of the server, for
	// all Serve and ServePlain calls. limits.max_conns.
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

// challengeProto is the ALPN name of the TLS-ALPN-01 challenge.
const challengeProto = "acme-tls/1"

// Server is the decoy listener core.
type Server struct {
	srv      *http.Server
	tls      *tls.Config
	sem      chan struct{} // the connection slots, shared by all Serve calls
	src      *sourceCap    // the connection counts for each source, shared by all Serve calls
	rd       *readLimit    // the read budgets and the read pool, shared by all Serve calls
	errLines countWriter
	t        timeouts
	hdrBytes int

	mu     sync.Mutex
	plain  []*http.Server // one for each ServePlain call
	closed bool           // Close or Shutdown ran: ServePlain starts nothing
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
	s := &Server{tls: cfg.TLS.Clone(), sem: make(chan struct{}, cfg.MaxConns), src: newSourceCap(cfg.MaxConns), rd: newReadLimit(cfg.HeaderBytes), t: t, hdrBytes: cfg.HeaderBytes}
	// http/1.1 comes first, so a client that offers both gets http/1.1. A client
	// that offers only acme-tls/1 is a challenge client. If the list has no
	// acme-tls/1, crypto/tls refuses that client before it calls GetCertificate.
	s.tls.NextProtos = []string{"http/1.1", challengeProto}
	s.tls.GetConfigForClient = captureHello
	s.srv = s.newHTTP(h)
	// net/http also closes a TLS connection whose negotiated protocol has no
	// TLSNextProto function, without HTTP. This entry makes that behavior
	// explicit in this package, and tests use it to count the challenge
	// connections.
	s.srv.TLSNextProto = map[string]func(*http.Server, *tls.Conn, http.Handler){
		challengeProto: func(*http.Server, *tls.Conn, http.Handler) {},
	}
	return s, nil
}

// newHTTP returns an HTTP/1.1 server with the bounds of s. The TLS serve and
// each plain serve use it, so they have the same timeouts, caps and hooks.
func (s *Server) newHTTP(h http.Handler) *http.Server {
	var p http.Protocols
	p.SetHTTP1(true)
	return &http.Server{
		Handler:             markRequest(h),
		ReadHeaderTimeout:   s.t.readHeader,
		ReadTimeout:         s.t.read,
		WriteTimeout:        s.t.write,
		IdleTimeout:         s.t.idle,
		MaxHeaderBytes:      s.hdrBytes - 4096,
		MaxHeaderValueCount: maxHeaderValues,
		Protocols:           &p,
		ErrorLog:            log.New(&s.errLines, "", 0),
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if lc := limitConnOf(c); lc != nil {
				ctx = context.WithValue(ctx, limitConnKey{}, lc)
			}
			return withConnState(ctx)
		},
		ConnState: periodHook,
	}
}

// limitConnKey is the context key of the limitConn of a request.
type limitConnKey struct{}

// limitConnOf returns the limitConn of c, or nil for a connection of another
// type. The connection of a plain serve is the limitConn itself; the connection
// of the TLS serve has a *tls.Conn around it.
func limitConnOf(c net.Conn) *limitConn {
	if tc, ok := c.(*tls.Conn); ok {
		c = tc.NetConn()
	}
	lc, _ := c.(*limitConn)
	return lc
}

// markRequest wraps h. Before h runs, it marks a request without a body as
// active on its limitConn. A request with a body never starts a late run.
func markRequest(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if lc, ok := r.Context().Value(limitConnKey{}).(*limitConn); ok && r.Body == http.NoBody {
			lc.startRequest()
		}
		h.ServeHTTP(w, r)
	})
}

// periodHook is the ConnState hook. It starts the next read period of a
// connection that becomes idle. A connection that read more than keepAliveBytes
// in its period closes, so it gets no keep-alive. It also closes a connection
// with more than keepAliveBytes late bytes. It must not wait on the network. A
// connection of another type is left as it is.
func periodHook(c net.Conn, st http.ConnState) {
	if st != http.StateIdle {
		return
	}
	if lc := limitConnOf(c); lc != nil {
		lc.nextPeriod()
	}
}

// Serve accepts connections from the raw TCP listener ln until Close or
// Shutdown. A connection that negotiates acme-tls/1 closes after the handshake
// and gets no HTTP. The connection cap is on the raw listener, and the TLS layer
// is on top of it. A connection that a handler hijacks keeps its slot until the
// handler closes it, or until the context of Shutdown ends while Shutdown waits
// for another connection: Shutdown then closes it at the socket. When no other
// connection holds Shutdown, Shutdown returns at once and the hijacked
// connection stays open. All Serve calls of one server share the MaxConns slots
// and the cap of maxConnsPerSource open connections for each source address. The
// connections of ln must have a *net.TCPAddr peer address: all connections with
// another address type share one source count.
func (s *Server) Serve(ln net.Listener) error {
	return s.srv.Serve(tls.NewListener(newLimitListener(ln, s.sem, s.src, s.rd), s.tls))
}

// ServePlain accepts plain HTTP/1.1 connections from the raw TCP listener ln,
// for example the port 80 socket, and serves them with h. It uses the slots, the
// source cap, the read budget and the read pool of the Serve calls, and the same
// timeouts and header caps. It returns http.ErrServerClosed after Close or
// Shutdown. It closes ln when it returns.
func (s *Server) ServePlain(ln net.Listener, h http.Handler) error {
	if h == nil {
		_ = ln.Close()
		return errors.New("listener: a handler is required")
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		_ = ln.Close()
		return http.ErrServerClosed
	}
	hs := s.newHTTP(h)
	s.plain = append(s.plain, hs)
	s.mu.Unlock()
	return hs.Serve(newLimitListener(ln, s.sem, s.src, s.rd))
}

// all marks the server as closed and returns the HTTP servers of all serve calls.
func (s *Server) all() []*http.Server {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return append([]*http.Server{s.srv}, s.plain...)
}

// Close closes the listeners and all connections of all serve calls.
func (s *Server) Close() error {
	var err error
	for _, hs := range s.all() {
		if e := hs.Close(); err == nil {
			err = e
		}
	}
	return err
}

// Shutdown closes the listeners of all serve calls and waits until their open
// connections are done. A connection that is still open when ctx ends is
// closed, and Shutdown returns the error of ctx.
func (s *Server) Shutdown(ctx context.Context) error {
	servers := s.all()
	res := make(chan error, len(servers))
	for _, hs := range servers {
		go func() { res <- hs.Shutdown(ctx) }()
	}
	done := make(chan error, 1)
	go func() {
		var first error
		for range servers {
			if e := <-res; first == nil {
				first = e
			}
		}
		done <- first
	}()
	var err error
	select {
	case err = <-done:
	case <-ctx.Done():
		// http.Server.Shutdown closes an idle TLS connection with a close_notify
		// write that can wait for its own deadline, one connection after the other.
		// So close the sockets below TLS. The pending writes fail and the calls
		// return. After the sockets are closed, the calls can find no open
		// connection and return nil, so the error of ctx is the result.
		s.src.closeAll()
		<-done
		err = ctx.Err()
	}
	if err != nil {
		// http.Server.Shutdown leaves the open connections open when ctx ends.
		for _, hs := range servers {
			_ = hs.Close()
		}
	}
	return err
}

// ErrorLines is the number of lines that the server wrote to its error log.
// They include one line for each failed handshake. The log keeps no text.
func (s *Server) ErrorLines() uint64 { return s.errLines.n.Load() }

// ErrLog returns the counting writer of the error log, which ErrorLines counts. It keeps no text.
func (s *Server) ErrLog() io.Writer { return &s.errLines }

// SourceCapCloses is the number of connections that the server closed because
// their source had maxConnsPerSource open connections. It holds no address.
func (s *Server) SourceCapCloses() uint64 { return s.src.closes.Load() }
