package listener

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/cybagard/cyba-phantom/internal/event"
)

// maxConnsPerSource is the number of open connections that one source key may
// have at the same time (SEC-22). It is a constant, not a config value.
const maxConnsPerSource = 32

// ipv6PrefixBits is the prefix length of the key of an IPv6 address.
const ipv6PrefixBits = 64

// sourceCap counts the open connections of each source key. One value serves
// all Serve calls of one Server, like the slot semaphore. It has no String or
// Format method, and no code prints the map.
//
// It also holds the record of the open limitConns of all Serve calls, so that
// Shutdown can close them at the socket. A connection enters the record after it
// got its slot, so the record holds at most maxConns entries. It leaves the
// record in the first Close, before its slot is free.
type sourceCap struct {
	mu     sync.Mutex
	count  map[netip.Addr]uint16
	open   map[*limitConn]struct{}
	closes atomic.Uint64 // connections closed at the source cap
}

// newSourceCap makes the map with room for maxConns keys. The map holds at most
// maxConns keys, plus one key for each Serve call that is between the source
// check and the slot. A delete does not shrink a Go map. Under churn the map
// can grow, to a bounded size. The record has room for maxConns connections.
func newSourceCap(maxConns int) *sourceCap {
	return &sourceCap{count: make(map[netip.Addr]uint16, maxConns), open: make(map[*limitConn]struct{}, maxConns)}
}

// track adds c to the record of open connections.
func (s *sourceCap) track(c *limitConn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.open[c] = struct{}{}
}

// untrack removes c from the record. A connection that is not in it is ignored.
func (s *sourceCap) untrack(c *limitConn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.open, c)
}

// openConns is the number of connections in the record.
func (s *sourceCap) openConns() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.open)
}

// closeAll closes each connection in the record at the socket below TLS, so
// there is no close_notify write. Close takes mu to remove the connection, so
// the loop runs without it.
func (s *sourceCap) closeAll() {
	s.mu.Lock()
	conns := make([]*limitConn, 0, len(s.open))
	for c := range s.open {
		conns = append(conns, c)
	}
	s.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
}

// take adds one connection to key and tells if it is within the cap.
func (s *sourceCap) take(key netip.Addr) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.count[key] >= maxConnsPerSource {
		return false
	}
	s.count[key]++
	return true
}

// give removes one connection from key and deletes the key at zero.
func (s *sourceCap) give(key netip.Addr) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n := s.count[key]; n > 1 {
		s.count[key] = n - 1
	} else {
		delete(s.count, key)
	}
}

// keys is the number of source keys in the map.
func (s *sourceCap) keys() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.count)
}

// sourceKey returns the key of the peer address a. It copies the rule of
// CounterKey in package event: an IPv4-mapped IPv6 address becomes IPv4, the
// zone goes away, and an IPv6 address is masked to its /64 prefix. An address
// that is not a *net.TCPAddr, or is not valid, gets the zero key, which all
// such connections share. The key comes only from the peer address of the
// connection, never from a header.
func sourceKey(a net.Addr) netip.Addr {
	t, ok := a.(*net.TCPAddr)
	if !ok || t == nil {
		return netip.Addr{}
	}
	ip := t.AddrPort().Addr().Unmap().WithZone("")
	if !ip.IsValid() {
		return netip.Addr{}
	}
	if ip.Is6() {
		return netip.PrefixFrom(ip, ipv6PrefixBits).Masked().Addr()
	}
	return ip
}

// Read budget constants (SEC-22). They are constants, not config keys.
const (
	// helloBudget is the part of the first budget for the TLS handshake.
	helloBudget = 16384
	// budgetSlack is added to the header size in each budget.
	budgetSlack = 1024
	// keepAliveBytes is the largest period that keeps its connection open. The
	// pool does not charge the first keepAliveBytes of a period. A Read asks the
	// socket for at most this many bytes.
	keepAliveBytes = 4096
	// poolBytes is the most charged bytes that all connections hold together.
	poolBytes = 8 << 20
)

// errBudgetRead is the error of a read that the budget or the pool refuses.
// Read closes the socket before it returns this error. So net/http cannot write
// a reply after the read error.
var errBudgetRead error = &net.OpError{Op: "read", Net: "tcp", Err: errors.New("read budget used")}

// readAtZero is a test hook. Read calls it with no budget left, before the
// socket read. It is nil in production.
var readAtZero func()

// readLimit is the read budget of one Server and its pool. All Serve calls of
// the Server share it, like the slots and the source counts.
type readLimit struct {
	first, next int64        // the budget of the first period and of each next one
	pool        atomic.Int64 // charged bytes of all connections, from 0 to poolBytes
}

func newReadLimit(headerBytes int) *readLimit {
	return &readLimit{first: helloBudget + int64(headerBytes) + budgetSlack, next: int64(headerBytes) + budgetSlack}
}

// take adds n charged bytes and tells if the pool stays within poolBytes. A
// refused take changes nothing.
func (r *readLimit) take(n int64) bool {
	for {
		cur := r.pool.Load()
		if cur+n > poolBytes {
			return false
		}
		if r.pool.CompareAndSwap(cur, cur+n) {
			return true
		}
	}
}

// limitListener caps the number of open connections, and the number for each
// source. It wraps the raw TCP listener. The TLS layer goes on top of it.
// So a connection over a cap closes before the handshake, and the listener
// makes no TLS state for that connection.
type limitListener struct {
	net.Listener
	sem chan struct{}
	src *sourceCap
	rd  *readLimit
}

// newLimitListener takes the semaphore, the source counts and the read limit
// from the caller, so that more than one listener can share them.
func newLimitListener(ln net.Listener, sem chan struct{}, src *sourceCap, rd *readLimit) *limitListener {
	return &limitListener{Listener: ln, sem: sem, src: src, rd: rd}
}

// Accept returns a connection that has a free slot and is within the source
// cap. It closes a connection over a cap at once and accepts the next one. It
// does not block on a full semaphore or on a full source count. It still blocks
// in the Accept of the wrapped listener.
func (l *limitListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		key := sourceKey(c.RemoteAddr())
		if !l.src.take(key) {
			l.src.closes.Add(1)
			_ = c.Close()
			continue
		}
		select {
		case l.sem <- struct{}{}:
			lc := newLimitConn(c, l.sem, l.src, key, l.rd)
			l.src.track(lc)
			return lc, nil
		default:
			l.src.give(key)
			_ = c.Close()
		}
	}
}

// inUse is the number of slots that are taken.
func (l *limitListener) inUse() int { return len(l.sem) }

// limitConn gives its source count and then its slot back on the first Close
// and only on the first. The count of the key goes down, and the record entry
// leaves, before the slot is free. The key leaves the map only when its count
// is 0.
//
// It also counts the bytes that Read takes from the socket. A period starts
// with the connection or at an idle state. It ends at the next idle state.
// Read fails when it gets a byte after the budget of the period is used. The
// bytes of a period above keepAliveBytes are charged to the pool of the
// Server. The charged bytes go back to the pool in Close. A connection with
// charged bytes read more than keepAliveBytes, so it also closes at its idle
// state.
//
// A client can send its next request before net/http reaches the idle state of
// the last one. Each Write while a request without a body is active starts the
// late run. This includes a crypto/tls KeyUpdate reply before the response. The
// handler wrapper marks the request after its head is complete. So the late
// bytes never hold bytes of that request. The bytes that Read takes after the
// late run starts are late. They are not part of that period. They start the
// next one. Read counts them against the budget of the period. It charges to
// the pool only the late bytes above keepAliveBytes.
type limitConn struct {
	net.Conn
	sem  chan struct{}
	src  *sourceCap
	key  netip.Addr
	once sync.Once
	rd   *readLimit

	mu   sync.Mutex
	left int64 // budget left in this period
	used int64 // bytes read in this period
	// charged is the pool charge. It has the part of the bytes before the late
	// bytes above keepAliveBytes. It also has the part of the late bytes above
	// keepAliveBytes.
	charged int64
	closed  bool
	active  bool  // a request without a body is active: each Write starts the late run
	late    int64 // bytes in used that Read took after the late run started
	lateOn  bool  // the late run started: all next bytes are late

	// These fields are the input of refusedRequest (SEC-22).
	handled      bool // a handler ran in this period
	lastReadErr  bool // the last read failed, not with a timeout
	budgetClosed bool // the budget or the pool closed the connection
	acme         bool // the connection negotiated acme-tls/1
	writes       int  // counted writes since a read with data or idle state

	// These fields are the input of handshakeReason (SEC-22).
	// gate is the reason of the name gate, or 0 if it did not refuse.
	gate event.RefusedReason
	// noCert is true when there is no certificate to give.
	noCert bool
	// lastData is true when the last read gave data, no error, no timeout. A
	// write that fails after that read sets it to false.
	lastData bool
}

// newLimitConn wraps c with a full first budget. The caller has the slot and
// the source count already.
func newLimitConn(c net.Conn, sem chan struct{}, src *sourceCap, key netip.Addr, rd *readLimit) *limitConn {
	return &limitConn{Conn: c, sem: sem, src: src, key: key, rd: rd, left: rd.first}
}

func (c *limitConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() {
		c.src.give(c.key)
		c.src.untrack(c)
		<-c.sem
	})
	c.mu.Lock()
	c.closed = true
	c.refund()
	c.mu.Unlock()
	return err
}

// refund gives the charge back to the pool, one time. The caller holds mu.
func (c *limitConn) refund() {
	c.rd.pool.Add(-c.charged)
	c.charged = 0
}

// Read asks the socket for at most the budget left and at most keepAliveBytes.
// With no budget left, it asks for one byte. Late bytes also count against the
// budget. A byte that arrives with no budget left is over the budget. A read
// that gets no byte does not close. A read that the budget or the pool refuses
// closes the socket. So net/http cannot send a reply after that close.
func (c *limitConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	left := c.left
	c.mu.Unlock()
	if hook := readAtZero; hook != nil && left <= 0 {
		hook()
	}
	p = p[:min(int64(len(p)), max(left, 1), keepAliveBytes)]
	n, err := c.Conn.Read(p)
	c.mu.Lock()
	ne, ok := err.(net.Error)
	timeout := ok && ne.Timeout()
	c.lastReadErr = err != nil && !timeout
	c.lastData = n > 0 && err == nil
	if n == 0 {
		c.mu.Unlock()
		return 0, err
	}
	c.writes = 0
	if c.left <= 0 {
		c.budgetClosed = true
		c.mu.Unlock()
		_ = c.Close()
		return 0, errBudgetRead
	}
	var over int64
	if c.lateOn {
		over = c.late + int64(n) - max(c.late, keepAliveBytes)
		c.late += int64(n)
	} else {
		over = c.used + int64(n) - max(c.used, keepAliveBytes)
	}
	c.left -= int64(n)
	c.used += int64(n)
	refused := false
	if over > 0 && !c.closed {
		if refused = !c.rd.take(over); refused {
			c.left, c.budgetClosed = 0, true
		} else {
			c.charged += over
		}
	}
	c.mu.Unlock()
	if refused {
		_ = c.Close()
		return 0, errBudgetRead
	}
	return n, err
}

// uncountedWriteMax is the largest size of an application-data write that is
// not counted. Write counts a write of more than uncountedWriteMax bytes that
// starts with recordApplicationData. After the handshake, a reply of net/http
// is such a record of more than 96 bytes. An alert or a key update record is
// smaller. A TLS 1.2 handshake flight starts with another record type
// (SEC-22).
const uncountedWriteMax = 96

// recordApplicationData is the TLS record type application_data.
const recordApplicationData = 23

// Write starts the late run when a request without a body is active, before it
// writes: a client that reads the response can answer before Write returns. The
// handshake writes before the first request is active. It also counts a write
// of more than uncountedWriteMax bytes that starts with recordApplicationData.
// A write that fails, also with a timeout, means that the client stopped. Then
// lastData is false, so the connection gives no bad_hello.
func (c *limitConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.lateOn = c.lateOn || c.active
	if len(p) > uncountedWriteMax && p[0] == recordApplicationData {
		c.writes++
	}
	c.mu.Unlock()
	n, err := c.Conn.Write(p)
	if err != nil {
		c.mu.Lock()
		c.lastData = false
		c.mu.Unlock()
	}
	return n, err
}

// startRequest marks a request without a body as active. A test calls it. The
// handler wrapper calls reachHandler.
func (c *limitConn) startRequest() { c.reachHandler(true) }

// reachHandler marks that a handler runs in this period, for each request. When
// active is true, the request has no body. Then the next Write starts the late
// run.
func (c *limitConn) reachHandler(active bool) {
	c.mu.Lock()
	c.handled = true
	c.active = c.active || active
	c.mu.Unlock()
}

// markACME marks the connection as an acme-tls/1 connection.
func (c *limitConn) markACME() {
	c.mu.Lock()
	c.acme = true
	c.mu.Unlock()
}

// refusedRequest tells if net/http refused a request head before the handler
// (SEC-22). The server made a counted write since the later of the last read
// with data and the last idle state. That write is the reply. The last read did
// not fail, unless it timed out. No handler ran in this period. Neither the
// budget nor the pool closed the connection. The connection is not an
// acme-tls/1 connection.
func (c *limitConn) refusedRequest() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writes >= 1 && !c.lastReadErr && !c.handled && !c.budgetClosed && !c.acme
}

// setGate records that the name gate refused the connection, with its reason.
func (c *limitConn) setGate(r event.RefusedReason) {
	c.mu.Lock()
	c.gate = r
	c.mu.Unlock()
}

// markNoCert records that the certificate callback failed and the name gate
// did not refuse the connection. Either the listener has no certificate to
// give, or the client offered only acme-tls/1 and no challenge is active.
func (c *limitConn) markNoCert() {
	c.mu.Lock()
	if c.gate == 0 {
		c.noCert = true
	}
	c.mu.Unlock()
}

// handshakeReason gives the reason of the refused event for a connection whose
// handshake failed (SEC-22). It gives none when the connection has the no
// certificate mark or the budget closed the connection. If not, the name gate
// gives its reason. If not, it gives bad_hello when the last read gave data.
// That read had no error, and no write failed after it. If not, it gives no
// reason: the client stopped.
func (c *limitConn) handshakeReason() (event.RefusedReason, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case c.noCert || c.budgetClosed:
		return 0, false
	case c.gate != 0:
		return c.gate, true
	case c.lastData:
		return event.ReasonBadHello, true
	}
	return 0, false
}

// nextPeriod ends the period at an idle state. The late bytes are not part of
// the ending period. They start the next one. The connection closes when the
// bytes before the late bytes are more than keepAliveBytes. It also closes when
// the late bytes are more than keepAliveBytes. It also closes when the
// connection is already closed. Close gives the charge back. On the stay-open
// path the charge is 0, so the refund gives back 0. The late bytes count against
// the next budget. This function does not wait on the network.
func (c *limitConn) nextPeriod() {
	c.mu.Lock()
	late := c.late
	// The clamp of a late read is the budget left in the period. When the
	// connection stays open, that is at least 5120 bytes. So late bytes can pass
	// keepAliveBytes before the clamp stops them.
	if c.used-late > keepAliveBytes || late > keepAliveBytes || c.closed {
		c.mu.Unlock()
		_ = c.Close()
		return
	}
	c.refund()
	c.used, c.left, c.late, c.lateOn, c.active = late, c.rd.next-late, 0, false, false
	c.handled, c.writes = false, 0
	c.mu.Unlock()
}
