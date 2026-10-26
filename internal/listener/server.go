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

	"github.com/cybagard/cyba-phantom/internal/event"
)

// Config is the input of New.
type Config struct {
	// TLS gives the certificates. New refuses a config that sets NextProtos or
	// GetConfigForClient, because the server sets both. The server clones the
	// config, sets the ALPN list to http/1.1 and acme-tls/1, and sets the
	// ClientHello capture. A connection that negotiates acme-tls/1 gets no HTTP
	// and closes after the handshake.
	TLS *tls.Config
	// MaxConns is the maximum number of open connections of the server, for
	// all Serve and ServePlain calls. limits.max_conns.
	MaxConns int
	// HeaderBytes is the size cap of the request head: the request line, the
	// header lines and the blank line. New refuses a value below 8192.
	// limits.header_bytes.
	HeaderBytes int
	// Queue takes the refused events of the server. New refuses nil.
	Queue *event.Queue
	// Counters counts the refused events that the server drops. These are the
	// events over a cap, and the emits with no valid peer address. It must
	// be the value that the Queue got from NewQueue. Then all drops of a
	// client key add up. New refuses nil.
	Counters *event.Counters
}

// minHeaderBytes is the smallest HeaderBytes. net/http reads 4096 bytes more
// than MaxHeaderBytes, so the server sets MaxHeaderBytes to HeaderBytes - 4096.
const minHeaderBytes = 8192

// maxHeaderValues is the cap of header values in one request (SEC-02).
const maxHeaderValues = 64

// handlerWait is the time that Shutdown waits for the running handlers after its
// context is done.
const handlerWait = time.Second

// errNoHandler is the error for a nil handler.
var errNoHandler = errors.New("listener: a handler is required")

// handlerCount counts the running handlers of a server. It does not use a
// sync.WaitGroup. A WaitGroup does not permit an Add from zero at the same time
// as a Wait. A request can start while Shutdown waits. So the count uses a
// mutex, a number and a channel.
type handlerCount struct {
	mu   sync.Mutex
	n    int
	idle chan struct{} // closed when n reaches 0; nil when no call waits
}

func (c *handlerCount) enter() {
	c.mu.Lock()
	c.n++
	c.mu.Unlock()
}

func (c *handlerCount) leave() {
	c.mu.Lock()
	c.n--
	if c.n == 0 && c.idle != nil {
		close(c.idle)
		c.idle = nil
	}
	c.mu.Unlock()
}

// idleChan returns a channel that closes when no handler runs. It returns nil
// when no handler runs now. The channel is made here and not in enter, so a
// request allocates nothing.
func (c *handlerCount) idleChan() <-chan struct{} {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.n == 0 {
		return nil
	}
	if c.idle == nil {
		c.idle = make(chan struct{})
	}
	return c.idle
}

// waitIdle waits until no handler runs, or until ctx is done. It returns true
// when no handler runs.
func (c *handlerCount) waitIdle(ctx context.Context) bool {
	idle := c.idleChan()
	if idle == nil {
		return true
	}
	select {
	case <-idle:
		return true
	case <-ctx.Done():
		return false
	}
}

// waitBound waits until no handler runs, or for handlerWait at most.
func (c *handlerCount) waitBound() {
	idle := c.idleChan()
	if idle == nil {
		return
	}
	t := time.NewTimer(handlerWait)
	defer t.Stop()
	select {
	case <-idle:
	case <-t.C:
	}
}

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
// After each line it sends a value on the channel lines, for tests. The send does not block.
type countWriter struct {
	n     atomic.Uint64
	lines chan struct{} // buffer 1
}

func (w *countWriter) Write(p []byte) (int, error) {
	w.n.Add(1)
	select {
	case w.lines <- struct{}{}:
	default: // a value waits in the channel already
	}
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
	handlers handlerCount // the running handlers of all serve calls
	refused  *refusedEmitter

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
		return nil, errNoHandler
	}
	if cfg.TLS == nil {
		return nil, errors.New("listener: a TLS config is required")
	}
	if cfg.Queue == nil || cfg.Counters == nil {
		return nil, errors.New("listener: a queue and counters are required")
	}
	if cfg.MaxConns < 1 {
		return nil, errors.New("listener: max conns must be at least 1")
	}
	if len(cfg.TLS.NextProtos) > 0 || cfg.TLS.GetConfigForClient != nil {
		return nil, errors.New("listener: the TLS config must not set NextProtos or GetConfigForClient")
	}
	if cfg.HeaderBytes < minHeaderBytes {
		return nil, fmt.Errorf("listener: header bytes must be at least %d", minHeaderBytes)
	}
	s := &Server{tls: cfg.TLS.Clone(), sem: make(chan struct{}, cfg.MaxConns), src: newSourceCap(cfg.MaxConns), rd: newReadLimit(cfg.HeaderBytes), t: t, hdrBytes: cfg.HeaderBytes, refused: newRefusedEmitter(cfg.Queue, cfg.Counters, monotonicSince(serverStart()))}
	s.errLines.lines = make(chan struct{}, 1)
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
		challengeProto: func(_ *http.Server, c *tls.Conn, _ http.Handler) {
			if lc := limitConnOf(c); lc != nil {
				lc.markACME()
			}
		},
	}
	return s, nil
}

// newHTTP returns an HTTP/1.1 server with the bounds of s. The TLS serve and
// each plain serve use it, so they have the same timeouts, caps and hooks.
func (s *Server) newHTTP(h http.Handler) *http.Server {
	var p http.Protocols
	p.SetHTTP1(true)
	return &http.Server{
		Handler:             s.markRequest(h),
		ReadHeaderTimeout:   s.t.readHeader,
		ReadTimeout:         s.t.read,
		WriteTimeout:        s.t.write,
		IdleTimeout:         s.t.idle,
		MaxHeaderBytes:      s.hdrBytes - 4096,
		MaxHeaderValueCount: maxHeaderValues,
		Protocols:           &p,
		// net/http answers "OPTIONS *" with 200 and no body, and skips the
		// handler. That answer is a Go fingerprint and gives no request event.
		DisableGeneralOptionsHandler: true,
		ErrorLog:                     log.New(&s.errLines, "", 0),
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if lc := limitConnOf(c); lc != nil {
				ctx = context.WithValue(ctx, limitConnKey{}, lc)
			}
			return withConnState(ctx)
		},
		ConnState: s.connHook,
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

// markRequest wraps h. It counts h as a running handler of s. The count goes
// down in a defer, because net/http recovers a panic of h outside this wrapper.
// Before h runs, it marks the request on its limitConn. A request without a
// body is also active. A request with a body never starts a late run.
func (s *Server) markRequest(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.handlers.enter()
		defer s.handlers.leave()
		if lc, ok := r.Context().Value(limitConnKey{}).(*limitConn); ok {
			lc.reachHandler(r.Body == http.NoBody)
		}
		h.ServeHTTP(w, r)
	})
}

// connHook is the ConnState hook. At an idle state, it starts the next read
// period of the connection. A connection that read more than keepAliveBytes in
// its period closes, so it gets no keep-alive. It also closes a connection with
// more than keepAliveBytes late bytes. At a close, it makes the refused event
// of a refused request head. It must not wait on the network. A connection of
// another type is left as it is.
func (s *Server) connHook(c net.Conn, st http.ConnState) {
	switch lc := limitConnOf(c); {
	case lc == nil:
	case st == http.StateIdle:
		lc.nextPeriod()
	case st == http.StateClosed:
		s.refusedAtClose(c, lc)
	}
}

// refusedAtClose makes one refused event when net/http refused a request head
// before the handler (ADR-031 decision 4). Only a *tls.Conn with a complete
// handshake counts. The rule does not use http.StateActive.
func (s *Server) refusedAtClose(c net.Conn, lc *limitConn) {
	tc, ok := c.(*tls.Conn)
	if !ok || !tc.ConnectionState().HandshakeComplete || !lc.refusedRequest() {
		return
	}
	s.mu.Lock()
	closing := s.closed
	s.mu.Unlock()
	if !closing {
		s.refused.emit(event.ReasonRefusedRequest, c.RemoteAddr())
	}
}

// Serve accepts connections from the raw TCP listener ln until Close or
// Shutdown. It then returns http.ErrServerClosed. A connection that negotiates
// acme-tls/1 closes after the handshake and gets no HTTP. The connection cap is
// on the raw listener, and the TLS layer is on top of it.
//
// A connection that a handler hijacks keeps its slot until it closes. It also
// keeps its entry in the record of open connections, and the record holds a
// reference to it until it closes. When Shutdown returns an error, it has closed
// each hijacked connection at the socket. A hijacked connection stays open after
// Close, and after a Shutdown that returns nil.
//
// All Serve calls of one server share the MaxConns slots and the cap of
// maxConnsPerSource open connections for each source address. The connections of
// ln must have a *net.TCPAddr peer address: all connections with another address
// type share one source count.
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
		return errNoHandler
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

// markClosed marks the server as closed, so that ServePlain starts nothing. It
// returns the HTTP servers of all serve calls.
func (s *Server) markClosed() []*http.Server {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return append([]*http.Server{s.srv}, s.plain...)
}

// closeServers closes the listeners and the connections of servers. It returns
// the first error.
func closeServers(servers []*http.Server) error {
	var first error
	for _, hs := range servers {
		if e := hs.Close(); first == nil {
			first = e
		}
	}
	return first
}

// Close closes the listeners and all connections of all serve calls. A hijacked
// connection stays open. Close does not wait for the running handlers.
func (s *Server) Close() error {
	return closeServers(s.markClosed())
}

// Shutdown closes the listeners of all serve calls. It waits until their open
// connections are closed or idle and their running handlers return. It does not
// wait for a hijacked connection, only for its handler.
//
// Shutdown returns an error in three cases. In the first case, ctx ends before
// http.Server.Shutdown finds each open connection closed or idle. The same
// holds when ctx ends before the running handlers return. net/http examines
// the connections at intervals of up to about 0.5 s. In the second case, ctx
// ended before the call. In the third case, a listener close gives an error.
// In each case Shutdown closes, at the socket below TLS, each connection in the
// record of open connections. This includes each hijacked connection. So a
// stalled close_notify write does not hold it. The error is the error of ctx,
// or the error of the listener close.
//
// When Shutdown returns nil, no handler runs. A hijacked connection whose
// handler returned can still be open.
//
// After ctx ends, Shutdown waits at most handlerWait (1 s) more for the running
// handlers. A handler that runs longer than this can still run after Shutdown
// returns. It can then, for example, call Enqueue on a queue that is closed.
// When ctx never ends, Shutdown waits for each running handler, also for one of
// a hijacked connection.
//
// So Shutdown returns at about the end of ctx plus handlerWait. The Accept retry
// sleep of net/http (up to 1 s) can add to this, because Shutdown waits until
// the Serve calls stop. This is not verified.
func (s *Server) Shutdown(ctx context.Context) error {
	servers := s.markClosed()
	if err := ctx.Err(); err != nil {
		// A connection that Accept returns after this sweep can be in its
		// handshake. Its send buffer holds at most its handshake messages, so the
		// close_notify write of its close does not wait for a full buffer.
		s.sweep(servers)
		s.handlers.waitBound()
		return err
	}
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
		if err != nil {
			// http.Server.Shutdown leaves the open connections open when it
			// returns an error, for example from a listener close.
			s.sweep(servers)
		}
	case <-ctx.Done():
		// http.Server.Shutdown closes an idle TLS connection with a close_notify
		// write that can wait for its own deadline, one connection after the other.
		// So close the sockets below TLS. The pending writes fail and the calls
		// return. After the sockets are closed, the calls can find no open
		// connection and return nil, so the error of ctx is the result.
		s.src.closeAll()
		// Wait for the Shutdown calls above, so that none runs after this
		// function returns.
		<-done
		s.sweep(servers)
		err = ctx.Err()
	}
	if !s.handlers.waitIdle(ctx) {
		// ctx ended while a handler runs. If no sweep ran yet, net/http returned
		// nil, so the handler can belong to a hijacked connection, which net/http
		// does not track. Close the sockets, so that the handler returns.
		if err == nil {
			s.sweep(servers)
			err = ctx.Err()
		}
		s.handlers.waitBound()
	}
	return err
}

// sweep closes the sockets below TLS, and then the HTTP servers. The order
// matters: with the sockets closed, hs.Close does not wait for a close_notify
// write.
func (s *Server) sweep(servers []*http.Server) {
	s.src.closeAll()
	_ = closeServers(servers)
}

// RefusedEventErrors is the number of refused events for which NewEvent
// returned an error. The server made no event for them.
func (s *Server) RefusedEventErrors() uint64 { return s.refused.errs.Load() }

// serverStart gives the start of the monotonic clock of the refused caps. A
// test replaces it.
var serverStart = time.Now

// ErrorLines is the number of lines that the server wrote to its error log.
// They include one line for each failed handshake. The log keeps no text.
func (s *Server) ErrorLines() uint64 { return s.errLines.n.Load() }

// ErrorLineSignal is for tests. It returns the channel that gets a value after a line of the error log. One value
// can stand for more than one line, so a receiver reads ErrorLines again after each receive.
func (s *Server) ErrorLineSignal() <-chan struct{} { return s.errLines.lines }

// ErrLog returns the counting writer of the error log, which ErrorLines counts. It keeps no text.
func (s *Server) ErrLog() io.Writer { return &s.errLines }

// SourceCapCloses is the number of connections that the server closed because
// their source had maxConnsPerSource open connections. It holds no address.
//
// The value can be too high when all slots are full. Accept takes the source
// count before it takes a slot, and Close gives the source count back before it
// frees the slot. In the window between these two steps, a connection that finds
// no slot holds a source count for a short time. A connection of the same source
// can then count as a close at the source cap, while the source has fewer than
// maxConnsPerSource open connections. The window needs two or more serve calls
// that accept at the same time, because one Accept loop is sequential.
func (s *Server) SourceCapCloses() uint64 { return s.src.closes.Load() }
