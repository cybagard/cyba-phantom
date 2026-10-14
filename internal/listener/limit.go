package listener

import (
	"net"
	"sync"
)

// limitListener caps the number of open connections. It wraps the raw TCP
// listener: the TLS layer goes on top of it, so a connection over the cap
// closes before the handshake and costs no TLS state.
type limitListener struct {
	net.Listener
	sem chan struct{}
}

// newLimitListener takes the semaphore from the caller, so that more than one
// listener can share the same slots.
func newLimitListener(ln net.Listener, sem chan struct{}) *limitListener {
	return &limitListener{Listener: ln, sem: sem}
}

// Accept returns a connection that has a free slot. It closes a connection
// over the cap immediately and accepts the next one, so it never blocks on a full
// semaphore.
func (l *limitListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		select {
		case l.sem <- struct{}{}:
			return &limitConn{Conn: c, sem: l.sem}, nil
		default:
			_ = c.Close()
		}
	}
}

// inUse is the number of slots that are taken.
func (l *limitListener) inUse() int { return len(l.sem) }

// limitConn gives its slot back on the first Close and only on the first.
type limitConn struct {
	net.Conn
	sem  chan struct{}
	once sync.Once
}

func (c *limitConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { <-c.sem })
	return err
}
