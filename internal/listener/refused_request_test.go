package listener

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/cybagard/cyba-phantom/internal/event"
)

const (
	goodHead = "GET / HTTP/1.1\r\nHost: decoy.test\r\n\r\n"
	badHost  = "GET / HTTP/1.1\r\nHost: K\r\n\r\n" // U+212A, a malformed Host
	partial  = "GET / HTTP/1.1\r\nHost: a\r\n"
)

// watchClosed wraps the ConnState hook of hs. Call it before hs serves. The
// channel gets a value after the hook ran for a closed connection.
func watchClosed(hs *http.Server) <-chan struct{} {
	ch := make(chan struct{}, 8)
	hook := hs.ConnState
	hs.ConnState = func(c net.Conn, st http.ConnState) {
		hook(c, st)
		if st == http.StateClosed {
			ch <- struct{}{}
		}
	}
	return ch
}

func waitClosed(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(10 * time.Second):
		t.Fatal("the server did not close the connection")
	}
}

// newClosedRig returns a rig that signals each closed connection. The test
// serves it.
func newClosedRig(t *testing.T, tm timeouts, h http.Handler) (*rig, <-chan struct{}) {
	t.Helper()
	r := newRig(t, 8, testHeaderBytes, tm, h)
	return r, watchClosed(r.s.srv)
}

// wantRefused checks that the server queue holds n refused events with the
// reason refused_request and no status.
func wantRefused(t *testing.T, r *rig, n int) {
	t.Helper()
	evs := r.s.refused.q.Drain()
	if len(evs) != n {
		t.Fatalf("%d refused events, want %d", len(evs), n)
	}
	for _, e := range evs {
		rec := e.Record()
		if j, _ := rec.Detail.JSON(); e.Kind() != event.KindRefused || string(j) != `{"reason":"refused_request"}` || rec.Status != nil {
			t.Errorf("event kind %v, detail %s; want refused, refused_request, no status", e.Kind(), j)
		}
	}
}

// T-S-22: a request head that net/http refuses before the handler gives one
// refused event after the handshake. Five heads do this also after a served
// request, in a second write and in the same write. The sixth is above the read
// budget of that period.
func TestTS22RefusedRequestHeads(t *testing.T) {
	for _, tc := range []struct {
		name, req string
		code      int
		pipelined bool
	}{
		{"malformed host", badHost, 400, true},
		{"head over the cap", head(testHeaderBytes + 4096 + 200), 431, false},
		{"65 header values", "GET / HTTP/1.1\r\nHost: a\r\n" + strings.Repeat("X: v\r\n", 64) + "\r\n", 431, true},
		{"unknown transfer encoding", "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: foo\r\n\r\n", 501, true},
		{"HTTP/2.0 request line", "GET / HTTP/2.0\r\nHost: a\r\n\r\n", 505, true},
		{"unknown expectation", "GET / HTTP/1.1\r\nHost: a\r\nExpect: foo\r\n\r\n", 417, true},
	} {
		for _, mode := range []string{"alone", "one write", "second write"} {
			if mode != "alone" && !tc.pipelined {
				continue
			}
			t.Run(tc.name+", "+mode, func(t *testing.T) {
				h, q, _ := newHelloQueue(t, 16)
				r, closed := newClosedRig(t, defaultTimeouts, h)
				r.serve(t)
				c := r.dial(t)
				switch mode {
				case "one write":
					_, _ = io.WriteString(c, goodHead+tc.req)
					// The server can reset the connection before the client
					// reads the second reply. So the test reads the first.
					if resp, err := http.ReadResponse(bufio.NewReader(c), nil); err != nil || resp.StatusCode != 200 {
						t.Fatalf("first response %v, %v; want status 200", resp, err)
					}
				case "second write":
					if got := roundTrip(c, goodHead); got != 200 {
						t.Fatalf("first status %d, want 200", got)
					}
					fallthrough
				default:
					if got := roundTrip(c, tc.req); got != tc.code {
						t.Fatalf("status %d, want %d", got, tc.code)
					}
				}
				waitClosed(t, closed)
				wantRefused(t, r, 1)
				if n, want := len(q.Drain()), map[bool]int{false: 0, true: 1}[mode != "alone"]; n != want {
					t.Fatalf("%d request events, want %d", n, want)
				}
			})
		}
	}
}

// T-S-22: a request with a body that reaches the handler gives its request
// event and no refused event. The handler leaves the body unread, and the
// server closes the connection after the reply.
func TestTS22RequestWithBodyGivesNoRefused(t *testing.T) {
	h, q, _ := newHelloQueue(t, 16)
	r, closed := newClosedRig(t, defaultTimeouts, h)
	r.serve(t)
	req := "POST / HTTP/1.1\r\nHost: decoy.test\r\nConnection: close\r\nContent-Length: 5\r\n\r\nhello"
	if got := roundTrip(r.dial(t), req); got == 0 {
		t.Fatal("no reply")
	}
	waitClosed(t, closed)
	wantRefused(t, r, 0)
	if n := len(q.Drain()); n != 1 {
		t.Fatalf("%d request events, want 1", n)
	}
}

// holdConn keeps the writes of the client while hold is true. Close sends them
// in one write.
type holdConn struct {
	net.Conn
	hold bool
	buf  []byte
}

func (h *holdConn) Write(p []byte) (int, error) {
	if h.hold {
		h.buf = append(h.buf, p...)
		return len(p), nil
	}
	return h.Conn.Write(p)
}

func (h *holdConn) Close() error {
	_, _ = h.Conn.Write(h.buf)
	return h.Conn.Close()
}

// T-S-22: these closes give no refused event. A timeout, a client close and a
// client close_notify record are such closes. So are a close over the read
// budget, an acme-tls/1 connection and a close at shutdown. A refused head on
// the plain socket also gives no event. One row is a known limit.
func TestTS22NoEvent(t *testing.T) {
	served := func(t *testing.T, r *rig) *tls.Conn {
		t.Helper()
		c := r.dial(t)
		if got := roundTrip(c, goodHead); got != 200 {
			t.Fatalf("status %d, want 200", got)
		}
		return c
	}
	raw := func(t *testing.T, r *rig) net.Conn {
		t.Helper()
		c, err := dialTCP(r.addr)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		return c
	}
	dial13 := func(t *testing.T, r *rig) (*tls.Conn, *recordWriter, int) {
		c, w, cc := r.dialTLS13(t, raw(t, r))
		return c, w, cc.n
	}
	for _, tc := range []struct {
		name  string
		tm    timeouts
		setup func(t *testing.T, r *rig)
		act   func(t *testing.T, r *rig)
	}{
		{"read-header timeout", shortTimeouts(), nil, func(t *testing.T, r *rig) {
			c := r.dial(t)
			_, _ = io.WriteString(c, partial)
			closesWithin(t, c)
		}},
		{"partial head, client close", defaultTimeouts, nil, func(t *testing.T, r *rig) {
			c := r.dial(t)
			_, _ = io.WriteString(c, partial)
			_ = c.NetConn().Close()
		}},
		// Known limit. net/http answers a cut head with 400. The close_notify
		// record is data below TLS, and crypto/tls reads no more after it. So
		// nothing below TLS tells this close from a refused head.
		{"known limit: partial head, close_notify", defaultTimeouts, nil, func(t *testing.T, r *rig) {
			c := r.dial(t)
			_, _ = io.WriteString(c, partial)
			_ = c.Close()
		}},
		{"idle keep-alive timeout", shortTimeouts(), nil, func(t *testing.T, r *rig) {
			closesWithin(t, served(t, r))
		}},
		{"idle keep-alive, close_notify", defaultTimeouts, nil, func(t *testing.T, r *rig) {
			_ = served(t, r).Close()
		}},
		{"no request, close_notify", defaultTimeouts, nil, func(t *testing.T, r *rig) { _ = r.dial(t).Close() }},
		{"request and close_notify in one write", defaultTimeouts, nil, func(t *testing.T, r *rig) {
			hc := &holdConn{Conn: raw(t, r)}
			tc := tls.Client(hc, r.clientConfig())
			if err := tc.Handshake(); err != nil {
				t.Fatal(err)
			}
			hc.hold = true
			_, _ = io.WriteString(tc, goodHead)
			_ = tc.Close()
		}},
		// A KeyUpdate that asks for an update makes the server write a reply
		// inside a read. Then the read-header timeout closes the connection.
		{"KeyUpdate, then timeout", shortTimeouts(), nil, func(t *testing.T, r *rig) {
			c, w, _ := dial13(t, r)
			_, _ = c.NetConn().Write(w.handshake([]byte{24, 0, 0, 1, 1}))
			closesWithin(t, c.NetConn())
		}},
		{"read budget", defaultTimeouts, func(t *testing.T, r *rig) {
			probe := newRig(t, 4, testHeaderBytes, defaultTimeouts, okHandler)
			probe.serve(t)
			_, _, handshake := dial13(t, probe)
			r.s.rd.first = int64(handshake + recordOverhead + len(head(3000)))
		}, func(t *testing.T, r *rig) {
			c, _, _ := dial13(t, r)
			if got := roundTrip(c, head(3001)); got != 0 {
				t.Fatalf("status %d, want a close with no reply", got)
			}
		}},
		// The extra write gives the other parts of the condition.
		{"acme-tls/1", defaultTimeouts, func(t *testing.T, r *rig) {
			next := r.s.srv.TLSNextProto[challengeProto]
			r.s.srv.TLSNextProto[challengeProto] = func(s *http.Server, c *tls.Conn, h http.Handler) {
				_, _ = c.Write([]byte("x"))
				next(s, c, h)
			}
		}, func(t *testing.T, r *rig) {
			c, err := dialTLS(r.addr, r.clientConfig(challengeProto))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = c.Close() })
		}},
		// The test closes the server before the hook of the closed connection
		// runs, after the reply to a refused head.
		{"shutdown", defaultTimeouts, func(t *testing.T, r *rig) {
			hook := r.s.srv.ConnState
			r.s.srv.ConnState = func(c net.Conn, st http.ConnState) {
				if st == http.StateClosed {
					_ = r.s.Close()
				}
				hook(c, st)
			}
		}, func(t *testing.T, r *rig) {
			if got := roundTrip(r.dial(t), badHost); got != 400 {
				t.Fatalf("status %d, want 400", got)
			}
		}},
		{"plain socket", defaultTimeouts, nil, func(t *testing.T, r *rig) {
			_ = r.dial(t).Close() // the common wait needs a TLS connection
			hs := r.s.newHTTP(okHandler)
			plain := watchClosed(hs)
			ln := listenLoopback(t)
			go func() { _ = hs.Serve(newLimitListener(ln, r.s.sem, r.s.src, r.s.rd)) }()
			t.Cleanup(func() { _ = hs.Close() })
			if got := roundTrip(dialPlain(t, ln.Addr().String(), 1), badHost); got != 400 {
				t.Fatalf("status %d, want 400", got)
			}
			waitClosed(t, plain)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, closed := newClosedRig(t, tc.tm, okHandler)
			if tc.setup != nil {
				tc.setup(t, r)
			}
			r.serve(t)
			tc.act(t, r)
			waitClosed(t, closed)
			wantRefused(t, r, map[bool]int{false: 0, true: 1}[strings.HasPrefix(tc.name, "known limit")])
		})
	}
}

// peerConn gives a TCP peer address to the connection it wraps.
type peerConn struct{ net.Conn }

func (peerConn) RemoteAddr() net.Addr { return tcpAddr("192.0.2.1") }

// T-S-22: a connection that is not a *tls.Conn gives no refused event. A
// *tls.Conn with no complete handshake also gives none. Both have the other
// parts of the condition.
func TestTS22NeedsCompleteHandshake(t *testing.T) {
	r := newRig(t, 1, testHeaderBytes, defaultTimeouts, okHandler)
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	lc := &limitConn{Conn: peerConn{a}, writes: 2}
	r.s.refusedAtClose(lc, lc)
	r.s.refusedAtClose(tls.Server(lc, &tls.Config{}), lc)
	wantRefused(t, r, 0)
}

// T-S-22: each part of the refused-request condition is needed.
func TestTS22RefusedRequestCondition(t *testing.T) {
	for name, tc := range map[string]struct {
		mod  func(*limitConn)
		want bool
	}{
		"all parts":                        {func(*limitConn) {}, true},
		"read error":                       {func(c *limitConn) { c.lastEnd = true }, false},
		"budget close":                     {func(c *limitConn) { c.budget = true }, false},
		"timeout, first period":            {func(c *limitConn) { c.lastTimeout = true }, false},
		"timeout, bytes in the period":     {func(c *limitConn) { c.lastTimeout, c.served, c.used = true, true, 1 }, false},
		"timeout, no byte, earlier served": {func(c *limitConn) { c.lastTimeout, c.served = true, true }, true},
	} {
		c := &limitConn{writes: 2}
		tc.mod(c)
		if got := c.refusedRequest(); got != tc.want {
			t.Errorf("%s: %v, want %v", name, got, tc.want)
		}
	}
}
