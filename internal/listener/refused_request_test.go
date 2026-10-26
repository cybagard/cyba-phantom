package listener

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
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

// wantRefused checks that the server queue holds n refused events. Each has the
// reason refused_request, no status and the address of the TCP peer.
func wantRefused(t *testing.T, r *rig, n int) {
	t.Helper()
	evs := r.s.refused.q.Drain()
	if len(evs) != n {
		t.Fatalf("%d refused events, want %d", len(evs), n)
	}
	for _, e := range evs {
		rec := e.Record()
		if j, _ := rec.Detail.JSON(); e.Kind() != event.KindRefused || string(j) != `{"reason":"refused_request"}` || rec.Status != nil || e.IP() != "127.0.0.1" {
			t.Errorf("event kind %v, detail %s, address %s; want refused, refused_request, no status, 127.0.0.1", e.Kind(), j, e.IP())
		}
	}
}

// count is 1 for true and 0 for false.
func count(b bool) int {
	if b {
		return 1
	}
	return 0
}

// T-S-22: a request head that net/http refuses before the handler gives one
// refused event after the handshake. Six heads do this also after a served
// request, in a second write and in the same write. The head over the cap runs
// only alone: after a served request it is above the read budget.
func TestTS22RefusedRequestHeads(t *testing.T) {
	for _, tc := range []struct {
		name, req string
		code      int
		pipelined bool
	}{
		{"malformed host", badHost, 400, true},
		// The smallest reply of net/http is this bare 400.
		{"malformed request line", "GET /\r\n\r\n", 400, true},
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
				if n, want := len(q.Drain()), count(mode != "alone"); n != want {
					t.Fatalf("%d request events, want %d", n, want)
				}
			})
		}
	}
	t.Run("flushing handler, KeyUpdate in flight", testRefusedAfterFlush)
}

// tapListener gives each connection a tapConn.
type tapListener struct {
	net.Listener
	got chan struct{}
}

func (l tapListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	return tapConn{c, l.got}, err
}

// tapConn signals on got after each socket read that gives data.
type tapConn struct {
	net.Conn
	got chan struct{}
}

func (c tapConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		select {
		case c.got <- struct{}{}:
		default:
		}
	}
	return n, err
}

// testRefusedAfterFlush: the handler flushes its response and waits. The client
// sends a KeyUpdate that asks for no update while the response is in flight. A
// refused head in the same write as the request still gives one event.
func testRefusedAfterFlush(t *testing.T) {
	h, q, _ := newHelloQueue(t, 16)
	flushed, release := make(chan struct{}), make(chan struct{})
	r, closed := newClosedRig(t, defaultTimeouts, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		h.ServeHTTP(w, req)
		w.(http.Flusher).Flush()
		close(flushed)
		<-release
	}))
	var once sync.Once
	open := func() { once.Do(func() { close(release) }) }
	t.Cleanup(open)
	got, ln := make(chan struct{}, 16), listenLoopback(t)
	r.addr = ln.Addr().String()
	r.serveOn(t, tapListener{ln, got})
	raw, err := dialTCP(r.addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	_, w, _ := r.dialTLS13(t, raw)
	_, _ = raw.Write(w.data([]byte(goodHead + badHost)))
	waitSignal(t, flushed)
	for len(got) > 0 {
		<-got
	}
	_, _ = raw.Write(w.records([]byte{24, 0, 0, 1, 0}, 22))
	waitSignal(t, got)
	open()
	waitClosed(t, closed)
	wantRefused(t, r, 1)
	if n := len(q.Drain()); n != 1 {
		t.Fatalf("%d request events, want 1", n)
	}
}

// waitSignal waits for a value on ch.
func waitSignal(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(10 * time.Second):
		t.Fatal("no signal")
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

// badMAC is a TLS record of application data with a wrong MAC.
var badMAC = append([]byte{23, 3, 3, 0, 32}, make([]byte, 32)...)

// T-S-22: these closes give no refused event. A timeout, a client close and a
// client close_notify record are such closes. So are a close over the read
// budget, an acme-tls/1 connection and a close at shutdown. A record that makes
// crypto/tls write an alert or a key update also gives no event. A refused head
// on the plain socket gives no event. A row named known limit gives one.
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
	// served13 sends a request in a record of the writer, so that the writer
	// keeps its sequence number. Then it reads the reply.
	served13 := func(t *testing.T, r *rig) (*tls.Conn, *recordWriter) {
		t.Helper()
		c, w, _ := dial13(t, r)
		if _, err := c.NetConn().Write(w.data([]byte(goodHead))); err != nil {
			t.Fatal(err)
		}
		if resp, err := http.ReadResponse(bufio.NewReader(c), nil); err != nil || resp.StatusCode != 200 {
			t.Fatalf("response %v, %v; want status 200", resp, err)
		}
		return c, w
	}
	// rec13 writes the records of build to a TLS 1.3 connection, in the first
	// period or after a served request.
	rec13 := func(after bool, build func(*testing.T, *recordWriter) []byte) func(*testing.T, *rig) {
		return func(t *testing.T, r *rig) {
			var c *tls.Conn
			var w *recordWriter
			if after {
				c, w = served13(t, r)
			} else {
				c, w, _ = dial13(t, r)
			}
			_, _ = c.NetConn().Write(build(t, w))
		}
	}
	dial12 := func(t *testing.T, r *rig, protos ...string) *tls.Conn {
		t.Helper()
		cfg := r.clientConfig(protos...)
		cfg.MaxVersion = tls.VersionTLS12
		c, err := dialTLS(r.addr, cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		return c
	}
	// cached offers session tickets: the server writes a ticket flight.
	cached := func(t *testing.T, r *rig, ver uint16) *tls.Conn {
		t.Helper()
		cfg := r.clientConfig()
		cfg.MaxVersion = ver
		cfg.ClientSessionCache = tls.NewLRUClientSessionCache(2)
		c, err := dialTLS(r.addr, cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		return c
	}
	mac := func(*testing.T, *recordWriter) []byte { return badMAC }
	keyUpdateClose := func(t *testing.T, w *recordWriter) []byte {
		return append(w.keyUpdate(t), w.records([]byte{1, 0}, 21)...)
	}
	clientHello := func(_ *testing.T, w *recordWriter) []byte { return w.handshake([]byte{1, 0, 0, 0}) }
	type24 := func(_ *testing.T, w *recordWriter) []byte { return w.records([]byte{1}, 24) }
	alert := func(_ *testing.T, w *recordWriter) []byte { return w.records([]byte{2, 40}, 21) }
	warning := func(_ *testing.T, w *recordWriter) []byte { return w.records([]byte{1, 42}, 21) }
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
		// nothing below TLS shows a difference from a refused head.
		{"known limit: partial head, close_notify", defaultTimeouts, nil, func(t *testing.T, r *rig) {
			c := r.dial(t)
			_, _ = io.WriteString(c, partial)
			_ = c.Close()
		}},
		// Known limit. The same, for a fatal alert from the client.
		{"known limit: partial head, fatal alert", defaultTimeouts, nil, func(t *testing.T, r *rig) {
			c, w, _ := dial13(t, r)
			_, _ = c.NetConn().Write(append(w.data([]byte(partial)), alert(t, w)...))
		}},
		// Known limit. net/http answers a client alert with 400.
		{"known limit: client warning alert as the first record", defaultTimeouts, nil, rec13(false, warning)},
		{"known limit: client fatal alert as the first record", defaultTimeouts, nil, rec13(false, alert)},
		{"bad MAC", defaultTimeouts, nil, rec13(false, mac)},
		{"bad MAC after a request", defaultTimeouts, nil, rec13(true, mac)},
		{"KeyUpdate and close_notify", defaultTimeouts, nil, rec13(false, keyUpdateClose)},
		{"KeyUpdate and close_notify after a request", defaultTimeouts, nil, rec13(true, keyUpdateClose)},
		{"post-handshake ClientHello", defaultTimeouts, nil, rec13(false, clientHello)},
		{"ClientHello after a served request", defaultTimeouts, nil, rec13(true, clientHello)},
		{"record of inner type 24", defaultTimeouts, nil, rec13(false, type24)},
		{"TLS 1.2, bad record, close", defaultTimeouts, nil, func(t *testing.T, r *rig) {
			c := dial12(t, r)
			_, _ = c.NetConn().Write(badMAC)
			_ = c.Close()
		}},
		{"TLS 1.2, timeout", shortTimeouts(), nil, func(t *testing.T, r *rig) { closesWithin(t, dial12(t, r)) }},
		// TLS 1.2: a ticket flight follows the client Finished.
		{"TLS 1.2 with a session cache, timeout", shortTimeouts(), nil, func(t *testing.T, r *rig) {
			closesWithin(t, cached(t, r, tls.VersionTLS12))
		}},
		{"TLS 1.3 with a session cache, timeout", shortTimeouts(), nil, func(t *testing.T, r *rig) {
			closesWithin(t, cached(t, r, tls.VersionTLS13))
		}},
		{"TLS 1.3, timeout", shortTimeouts(), nil, func(t *testing.T, r *rig) {
			c, _, _ := dial13(t, r)
			closesWithin(t, c.NetConn())
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
		{"acme-tls/1, TLS 1.2", defaultTimeouts, nil, func(t *testing.T, r *rig) { dial12(t, r, challengeProto) }},
		// The injected write is a counted write. So only the acme check stops
		// the event.
		{"acme-tls/1", defaultTimeouts, func(t *testing.T, r *rig) {
			next := r.s.srv.TLSNextProto[challengeProto]
			r.s.srv.TLSNextProto[challengeProto] = func(s *http.Server, c *tls.Conn, h http.Handler) {
				_, _ = c.Write(appData(uncountedWriteMax + 1))
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
			wantRefused(t, r, count(strings.HasPrefix(tc.name, "known limit")))
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

// stubConn gives n bytes and err to each Read, and takes each Write.
type stubConn struct {
	net.Conn
	n   int
	err error
}

func (f stubConn) Read([]byte) (int, error)    { return f.n, f.err }
func (f stubConn) Write(p []byte) (int, error) { return len(p), nil }

// failWrite is a stubConn whose Write gives err.
type failWrite struct {
	stubConn
	err error
}

func (f failWrite) Write([]byte) (int, error) { return 0, f.err }

// T-S-22: a write that fails after the last read with data clears the data
// mark, so there is no bad_hello. A write that works keeps it.
func TestTS22FailedWriteClearsHelloData(t *testing.T) {
	for name, tc := range map[string]struct {
		conn net.Conn
		want bool
	}{
		"write fails":     {failWrite{stubConn{n: 5}, net.ErrClosed}, false},
		"write times out": {failWrite{stubConn{n: 5}, os.ErrDeadlineExceeded}, false},
		"write works":     {stubConn{n: 5}, true},
	} {
		t.Run(name, func(t *testing.T) {
			lc := &limitConn{Conn: tc.conn, left: 100}
			_, err := lc.Read(make([]byte, 10))
			mustNil(t, err)
			_, _ = lc.Write([]byte("flight"))
			r, ok := lc.handshakeReason()
			if ok != tc.want || (ok && r != event.ReasonBadHello) {
				t.Errorf("reason %v, ok %v; want ok %v", r, ok, tc.want)
			}
		})
	}
}

// appData returns n bytes that start with the record type application_data.
func appData(n int) []byte {
	p := make([]byte, n)
	if n > 0 {
		p[0] = recordApplicationData
	}
	return p
}

// T-S-22: each part of the refused-request condition is needed. A write counts
// when it has more than uncountedWriteMax bytes and starts with an
// application-data record type.
func TestTS22RefusedRequestCondition(t *testing.T) {
	counted := appData(uncountedWriteMax + 1)
	handshake := append([]byte{22}, counted[1:]...)
	for name, tc := range map[string]struct {
		write []byte
		mod   func(*limitConn)
		want  bool
	}{
		"all parts":         {counted, func(*limitConn) {}, true},
		"handler mark":      {counted, func(c *limitConn) { c.handled = true }, false},
		"acme-tls/1":        {counted, func(c *limitConn) { c.acme = true }, false},
		"budget closed":     {counted, func(c *limitConn) { c.budgetClosed = true }, false},
		"read error":        {counted, func(c *limitConn) { c.lastReadErr = true }, false},
		"no write":          {nil, func(*limitConn) {}, false},
		"write at limit":    {appData(uncountedWriteMax), func(*limitConn) {}, false},
		"other record type": {handshake, func(*limitConn) {}, false},
		"read with data":    {counted, func(c *limitConn) { _, _ = c.Read(make([]byte, 1)) }, false},
	} {
		c := newLimitConn(stubConn{n: 1}, nil, newSourceCap(1), netip.Addr{}, newReadLimit(testHeaderBytes))
		_, _ = c.Write(tc.write)
		tc.mod(c)
		if got := c.refusedRequest(); got != tc.want {
			t.Errorf("%s: %v, want %v", name, got, tc.want)
		}
	}
}

// T-S-22: limitConn.Read allocates nothing, on a read with data and on a read
// that times out.
func TestLimitConnReadAllocatesNothing(t *testing.T) {
	timeout := &net.OpError{Op: "read", Net: "tcp", Err: os.ErrDeadlineExceeded}
	for name, f := range map[string]stubConn{"data": {n: 1}, "timeout": {err: timeout}} {
		c := newLimitConn(f, nil, newSourceCap(1), netip.Addr{}, newReadLimit(testHeaderBytes))
		buf := make([]byte, 64)
		if got := testing.AllocsPerRun(100, func() { _, _ = c.Read(buf) }); got != 0 {
			t.Errorf("%s: %v allocations for each Read, want 0", name, got)
		}
	}
}
