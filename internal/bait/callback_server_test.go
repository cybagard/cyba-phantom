package bait

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cybagard/cyba-phantom/internal/event"
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
// sends a chunked body of 300 KiB to a route with a body position, with and
// without "Connection: close". The request event must have status 200 and the
// route path. The connection must read at most the read budget plus one byte,
// which makes the server close. The test logs the byte counts. A small body
// first shows the 200 status line.
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

	// oneRequest sends a chunked POST with n body bytes, and the last chunk if
	// last is true. The request has the header "Connection: close" if closeHdr
	// is true. It gives the status line that the server sends, or 0 if it
	// sends none. It also gives the request events.
	oneRequest := func(n int, last, closeHdr bool) (status int, reqs []event.Record) {
		c, err := net.Dial("tcp", raw.Addr().String())
		mustOK(t, err)
		defer c.Close()
		mustOK(t, c.SetDeadline(time.Now().Add(10*time.Second)))
		hdr := ""
		if closeHdr {
			hdr = "Connection: close\r\n"
		}
		_, err = io.WriteString(c, "POST "+cbRoutePath+" HTTP/1.1\r\nHost: example.com\r\n"+hdr+"Transfer-Encoding: chunked\r\n\r\n")
		mustOK(t, err)
		body := strings.Repeat("x", n)
		// The server closes at the budget. Later writes can fail.
		const chunkSize = 16 << 10
		for off := 0; off < len(body); off += chunkSize {
			chunk := body[off:min(off+chunkSize, len(body))]
			if _, err := fmt.Fprintf(c, "%x\r\n%s\r\n", len(chunk), chunk); err != nil {
				break
			}
		}
		if last {
			_, _ = io.WriteString(c, "0\r\n\r\n")
		}
		if res, err := http.ReadResponse(bufio.NewReader(c), nil); err == nil {
			status = res.StatusCode
		}
		_, _ = io.Copy(io.Discard, c)
		// The server records the request after it closes the connection.
		for end := time.Now().Add(5 * time.Second); len(reqs) == 0 && time.Now().Before(end); time.Sleep(time.Millisecond) {
			reqs, _ = take(e.q)
		}
		return status, reqs
	}
	wantRequest := func(what string, reqs []event.Record) {
		t.Helper()
		if len(reqs) != 1 || reqs[0].Status == nil || *reqs[0].Status != http.StatusOK ||
			reqs[0].Path == nil || *reqs[0].Path != cbRoutePath {
			t.Errorf("%s: request events %+v, want 1 with status 200 and path %s", what, reqs, cbRoutePath)
		}
	}

	// A small body that ends in time shows that the request reaches the route.
	status, reqs := oneRequest(5<<10, true, true)
	if status != http.StatusOK {
		t.Errorf("small body: status line %d, want 200", status)
	}
	wantRequest("small body", reqs)

	// The read that passes the budget takes one byte more, then the server
	// closes the connection.
	wantBound := func(what string, got int64) {
		t.Helper()
		t.Logf("%s: connection-level bytes read: %d (budget %d, body %d)", what, got, readBudget, 300<<10)
		if got > readBudget+1 {
			t.Errorf("%s: the connection read %d bytes, want at most %d", what, got, readBudget+1)
		}
	}

	// Keep-alive is the default. net/http drains the unread body before it
	// writes the response. The read budget closes the connection first, so the
	// client gets no status line. The request event shows the route.
	before := ln.n.Load()
	status, reqs = oneRequest(300<<10, false, false)
	if status != 0 {
		t.Errorf("large body, keep-alive: status line %d, want none", status)
	}
	wantRequest("large body, keep-alive", reqs)
	wantBound("large body, keep-alive", ln.n.Load()-before)

	// With "Connection: close", net/http writes the response and drains the
	// body later. The client gets status 200. The byte bound is the same.
	before = ln.n.Load()
	status, reqs = oneRequest(300<<10, false, true)
	if status != http.StatusOK {
		t.Errorf("large body, close: status line %d, want 200", status)
	}
	wantRequest("large body, close", reqs)
	wantBound("large body, close", ln.n.Load()-before)
}
