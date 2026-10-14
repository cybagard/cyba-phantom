package listener

import (
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
// all Serve calls of one Server, like the slot semaphore. It holds no String or
// Format method: nothing prints the map.
type sourceCap struct {
	mu     sync.Mutex
	count  map[netip.Addr]uint16
	closes atomic.Uint64 // connections closed at the source cap
}

// newSourceCap makes the map with room for maxConns keys: the slot cap bounds
// the number of keys, so the map never grows.
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

// limitListener caps the number of open connections, and the number for each
// source. It wraps the raw TCP listener: the TLS layer goes on top of it, so a
// connection over a cap closes before the handshake and costs no TLS state.
type limitListener struct {
	net.Listener
	sem chan struct{}
	src *sourceCap
}

// newLimitListener takes the semaphore and the source counts from the caller,
// so that more than one listener can share the same slots and counts.
func newLimitListener(ln net.Listener, sem chan struct{}, src *sourceCap) *limitListener {
	return &limitListener{Listener: ln, sem: sem, src: src}
}

// Accept returns a connection that has a free slot and is within the source
// cap. It closes a connection over a cap immediately and accepts the next one,
// so it never blocks.
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
			return &limitConn{Conn: c, sem: l.sem, src: l.src, key: key}, nil
		default:
			l.src.give(key)
			_ = c.Close()
		}
	}
}

// inUse is the number of slots that are taken.
func (l *limitListener) inUse() int { return len(l.sem) }

// limitConn gives its slot and its source count back on the first Close and
// only on the first.
type limitConn struct {
	net.Conn
	sem  chan struct{}
	src  *sourceCap
	key  netip.Addr
	once sync.Once
}

func (c *limitConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() {
		<-c.sem
		c.src.give(c.key)
	})
	return err
}
