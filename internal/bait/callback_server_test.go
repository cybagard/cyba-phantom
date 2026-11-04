package bait

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cybagard/cyba-phantom/internal/listener"
)

// countLn counts the bytes that the connections of its listener read.
type countLn struct {
	net.Listener
	n atomic.Int64
}

func (l *countLn) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &countConn{Conn: c, n: &l.n}, nil
}

type countConn struct {
	net.Conn
	n *atomic.Int64
}

func (c *countConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.n.Add(int64(n))
	return n, err
}

// readBudget is the read budget of the first period of a connection (SEC-22).
// It adds 16 384 bytes of hello budget, the header size and 1 024 bytes of
// slack.
const readBudget = 16384 + 8192 + 1024

// TestTS32CallbackServerBudget serves the handler through the listener. It
// sends a chunked body of 300 KiB to a route with a body position.
// The handler reads at most 4 097 body bytes. The connection must read no
// more than the read budget. net/http alone drains 270 501 bytes.
func TestTS32CallbackServerBudget(t *testing.T) {
	e := newCBEnv(t)
	srv, err := listener.New(listener.Config{
		TLS: &tls.Config{}, MaxConns: 8, HeaderBytes: 8192, Queue: e.q, Counters: e.q.Counters(),
	}, e.h)
	mustOK(t, err)
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	mustOK(t, err)
	ln := &countLn{Listener: raw}
	go func() { _ = srv.ServePlain(ln, e.h) }()
	t.Cleanup(func() { _ = srv.Close() })

	c, err := net.Dial("tcp", raw.Addr().String())
	mustOK(t, err)
	defer c.Close()
	mustOK(t, c.SetDeadline(time.Now().Add(10*time.Second)))
	body := strings.Repeat("x", 300<<10)
	_, err = io.WriteString(c, "POST "+cbRoutePath+" HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n")
	mustOK(t, err)
	// The server closes the connection at the budget. A later write can fail.
	for off := 0; off < len(body); off += 16 << 10 {
		if _, err := fmt.Fprintf(c, "%x\r\n%s\r\n", 16<<10, body[off:off+16<<10]); err != nil {
			break
		}
	}
	_, _ = io.Copy(io.Discard, c)
	got := ln.n.Load()
	t.Logf("connection-level bytes read: %d (budget %d, body %d)", got, readBudget, len(body))
	// The read that passes the budget takes one byte more, then the server
	// closes the connection.
	if got > readBudget+1 {
		t.Errorf("the connection read %d bytes, want at most %d", got, readBudget+1)
	}
	if reqs, _ := take(e.q); len(reqs) > 1 {
		t.Errorf("%d request events, want at most 1", len(reqs))
	}
}
