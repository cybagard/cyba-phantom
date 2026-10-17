package listener

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
)

// maxConnsPerSource is the number of open connections that one source key may
// have at the same time (SEC-22). It is a constant, not a config value.
const maxConnsPerSource = 32

// ipv6PrefixBits is the prefix length of the key of an IPv6 address.
const ipv6PrefixBits = 64

// sourceCap counts the open connections of each source key. One value serves
// all Serve calls of one Server, like the slot semaphore. It has no String or
// Format method, and no code prints the map.
type sourceCap struct {
	mu     sync.Mutex
	count  map[netip.Addr]uint16
	closes atomic.Uint64 // connections closed at the source cap
}

// newSourceCap makes the map with room for maxConns keys. The map holds at most
// maxConns keys, plus one key for each Serve call that is between the source
// check and the slot. A delete does not shrink a Go map. Under churn the map
// can grow, to a bounded size.
func newSourceCap(maxConns int) *sourceCap {
	return &sourceCap{count: make(map[netip.Addr]uint16, maxConns)}
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
// counterKey in package event: an IPv4-mapped IPv6 address becomes IPv4, the
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

// errBudgetRead is the error of a read that the budget or the pool refuses. It
// is a read error, so net/http sends no reply and closes the connection.
var errBudgetRead error = &net.OpError{Op: "read", Net: "tcp", Err: errors.New("read budget used")}

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
// source. It wraps the raw TCP listener: the TLS layer goes on top of it, so a
// connection over a cap closes before the handshake and costs no TLS state.
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
			return &limitConn{Conn: c, sem: l.sem, src: l.src, key: key, rd: l.rd, left: l.rd.first}, nil
		default:
			l.src.give(key)
			_ = c.Close()
		}
	}
}

// inUse is the number of slots that are taken.
func (l *limitListener) inUse() int { return len(l.sem) }

// limitConn gives its source count and then its slot back on the first Close
// and only on the first. The key leaves the map before the slot is free.
//
// It also counts the bytes that Read takes from the socket. A period is the
// time from the start of the connection, or from the last idle state, to the
// next idle state. Read fails when the budget of the period is used. The bytes
// of a period above keepAliveBytes are charged to the pool of the Server. The
// charged bytes go back to the pool in Close. A connection with charged bytes
// read more than keepAliveBytes, so it also closes at its idle state.
type limitConn struct {
	net.Conn
	sem  chan struct{}
	src  *sourceCap
	key  netip.Addr
	once sync.Once
	rd   *readLimit

	mu      sync.Mutex
	left    int64 // budget left in this period
	used    int64 // bytes read in this period
	charged int64 // bytes of this period that the pool holds
	closed  bool
}

func (c *limitConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() {
		c.src.give(c.key)
		<-c.sem
	})
	c.mu.Lock()
	c.closed = true
	c.refund()
	c.mu.Unlock()
	return err
}

// refund gives the charged bytes back to the pool, one time. The caller holds mu.
func (c *limitConn) refund() {
	c.rd.pool.Add(-c.charged)
	c.charged = 0
}

// Read asks the socket for no more than the budget left and no more than
// keepAliveBytes. A read that the budget or the pool refuses closes the
// socket, so net/http cannot send a reply after the failed read.
func (c *limitConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	left := c.left
	c.mu.Unlock()
	if left <= 0 {
		_ = c.Close()
		return 0, errBudgetRead
	}
	p = p[:min(int64(len(p)), left, keepAliveBytes)]
	n, err := c.Conn.Read(p)
	if n == 0 {
		return 0, err
	}
	c.mu.Lock()
	c.left -= int64(n)
	before := c.used
	c.used += int64(n)
	refused := false
	if over := c.used - max(before, keepAliveBytes); over > 0 && !c.closed {
		if refused = !c.rd.take(over); refused {
			c.left = 0
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

// nextPeriod ends the period at an idle state. A connection that read more than
// keepAliveBytes closes, and Close gives its charged bytes back. Another one
// has no charged bytes, so the refund here gives back 0. It gets the budget of
// the next period. It does not wait on the network.
func (c *limitConn) nextPeriod() {
	c.mu.Lock()
	if c.used > keepAliveBytes {
		c.mu.Unlock()
		_ = c.Close()
		return
	}
	c.refund()
	c.used, c.left = 0, c.rd.next
	c.mu.Unlock()
}
