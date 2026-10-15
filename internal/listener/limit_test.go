package listener

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// loopbackDialer binds the source address 127.0.0.<host>. A test that opens
// more than maxConnsPerSource connections spreads them over several hosts of
// 127.0.0.0/8, with at most maxConnsPerSource for each host.
func loopbackDialer(host byte) *net.Dialer {
	return &net.Dialer{Timeout: 3 * time.Second, LocalAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, host)}}
}

// dialTLSFrom opens a TLS connection to addr from 127.0.0.<host>. The test
// closes it at the end.
func (r *rig) dialTLSFrom(t *testing.T, addr string, host byte) net.Conn {
	t.Helper()
	d := tls.Dialer{NetDialer: loopbackDialer(host), Config: r.clientConfig()}
	c, err := d.DialContext(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// expectCapClose opens a connection to addr from 127.0.0.<host>, sends a
// ClientHello and fails the test unless the server ends the connection within
// closeBound.
func expectCapClose(t *testing.T, r *rig, addr string, host byte) {
	t.Helper()
	raw, err := loopbackDialer(host).Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	start := time.Now()
	_ = raw.SetDeadline(time.Now().Add(3 * time.Second))
	if err := tls.Client(raw, r.clientConfig()).Handshake(); !isClosed(err) {
		t.Fatalf("connection over the cap: handshake error %v; want an end of stream or a reset", err)
	}
	if d := time.Since(start); d > closeBound {
		t.Fatalf("close took %v, want at most %v", d, closeBound)
	}
}

// waitFor polls cond for 5 s.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timeout: %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// T-S-17: the key is the IPv4 address or the /64 prefix of an IPv6 address.
func TestTS17SourceKey(t *testing.T) {
	tcp := func(s string) net.Addr {
		return net.TCPAddrFromAddrPort(netip.AddrPortFrom(netip.MustParseAddr(s), 443))
	}
	key := func(s string) netip.Addr { return netip.MustParseAddr(s) }
	same := []struct{ a, b string }{
		{"192.0.2.7", "192.0.2.7"},
		{"::ffff:192.0.2.7", "192.0.2.7"},
		{"2001:db8:1:2:3:4:5:6", "2001:db8:1:2::"},
		{"2001:db8:1:2:ffff::1", "2001:db8:1:2::"},
		{"fe80::1%eth0", "fe80::"},
	}
	for _, c := range same {
		if got := sourceKey(tcp(c.a)); got != key(c.b) {
			t.Errorf("sourceKey(%s) = %v, want %v", c.a, got, c.b)
		}
	}
	if sourceKey(tcp("2001:db8:1:2::1")) == sourceKey(tcp("2001:db8:1:3::1")) {
		t.Error("two /64 prefixes share a key")
	}
	if sourceKey(tcp("192.0.2.7")) == sourceKey(tcp("192.0.2.8")) {
		t.Error("two IPv4 addresses share a key")
	}
	for name, a := range map[string]net.Addr{
		"udp":     &net.UDPAddr{IP: net.IPv4(192, 0, 2, 7), Port: 1},
		"unix":    &net.UnixAddr{Name: "x", Net: "unix"},
		"invalid": &net.TCPAddr{},
		"nil":     nil,
	} {
		if got := sourceKey(a); got.IsValid() {
			t.Errorf("%s: key %v, want the zero key", name, got)
		}
	}
}

// T-S-17: connection 33 from one source closes before the handshake and no
// ClientHello is captured for it. A client from another source gets 200. The
// close counter goes up by one, and the error log gets no line.
func TestTS17SourceCap(t *testing.T) {
	r := newRig(t, 40, testHeaderBytes, defaultTimeouts, okHandler)
	var calls atomic.Int32
	r.s.tls.GetConfigForClient = func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
		calls.Add(1)
		return captureHello(chi)
	}
	r.serve(t)
	var conns []net.Conn
	for range maxConnsPerSource {
		conns = append(conns, r.dialTLSFrom(t, r.addr, 2))
	}
	lines := r.s.ErrorLines()
	expectCapClose(t, r, r.addr, 2)
	if calls.Load() != maxConnsPerSource {
		t.Fatalf("capture ran %d times, want %d", calls.Load(), maxConnsPerSource)
	}
	if got := status(r.dialTLSFrom(t, r.addr, 3), 0); got != 200 {
		t.Fatalf("other source: status %d, want 200", got)
	}
	if got := r.s.SourceCapCloses(); got != 1 {
		t.Fatalf("source cap closes %d, want 1", got)
	}
	// The 32 open connections still serve.
	for i, c := range conns {
		if got := status(c, 0); got != 200 {
			t.Fatalf("open connection %d: status %d", i, got)
		}
	}
	if got := r.s.ErrorLines(); got != lines {
		t.Fatalf("error lines %d, want %d", got, lines)
	}
}

// T-S-17: the cap is for the whole server: 16 connections on each of two
// listeners are 32 from one source, and connection 33 closes on either one.
func TestTS17SourceCapSharedByServeCalls(t *testing.T) {
	r := newRig(t, 40, testHeaderBytes, defaultTimeouts, okHandler)
	r.serve(t)
	first := r.addr
	r.serve(t)
	second := r.addr
	for range maxConnsPerSource / 2 {
		r.dialTLSFrom(t, first, 2)
		r.dialTLSFrom(t, second, 2)
	}
	expectCapClose(t, r, second, 2)
	expectCapClose(t, r, first, 2)
	if got := r.s.SourceCapCloses(); got != 2 {
		t.Fatalf("source cap closes %d, want 2", got)
	}
}

// T-S-17: a close gives the source count back with the slot, and the map keeps
// no key for a source that has no connection. A connection that gets no slot
// gives its count back at once.
func TestTS17SourceCountReleased(t *testing.T) {
	r := newRig(t, 3, testHeaderBytes, defaultTimeouts, okHandler)
	r.serve(t)
	lines := r.s.ErrorLines()
	a, b := r.dialTLSFrom(t, r.addr, 2), r.dialTLSFrom(t, r.addr, 3)
	c := r.dialTLSFrom(t, r.addr, 3)
	if n := r.s.src.keys(); n != 2 {
		t.Fatalf("keys %d, want 2", n)
	}
	// The slots are full: this source gets no slot and keeps no key.
	expectCapClose(t, r, r.addr, 4)
	if n := r.s.src.keys(); n != 2 {
		t.Fatalf("keys %d after the slot cap close, want 2", n)
	}
	if got := r.s.SourceCapCloses(); got != 0 {
		t.Fatalf("source cap closes %d for a slot cap close, want 0", got)
	}
	for _, x := range []net.Conn{a, b, c} {
		_ = x.Close()
	}
	waitFor(t, "map empty and slots free", func() bool { return r.s.src.keys() == 0 && len(r.s.sem) == 0 })
	if got := r.s.ErrorLines(); got != lines {
		t.Fatalf("error lines %d, want %d", got, lines)
	}
}

// T-S-17: the map that newServer makes has room for MaxConns keys: n distinct
// keys take no allocation. A map without a size hint allocates on the same
// steps, so the measure sees growth. The measure is the average over many
// fills, because the counter is for the whole process and a goroutine of
// another test can allocate during a run.
func TestTS17SourceMapCapacity(t *testing.T) {
	const (
		n    = 256
		runs = 50
	)
	keys := make([]netip.Addr, n)
	for i := range keys {
		keys[i] = netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)})
	}
	// AllocsPerRun calls f one more time before it measures, so runs+1 maps.
	average := func(caps []*sourceCap) float64 {
		next := 0
		return testing.AllocsPerRun(runs, func() {
			s := caps[next]
			next++
			for _, k := range keys {
				s.take(k)
			}
		})
	}
	servers := make([]*sourceCap, runs+1)
	plain := make([]*sourceCap, runs+1)
	for i := range servers {
		servers[i] = newRig(t, n, testHeaderBytes, defaultTimeouts, okHandler).s.src
		plain[i] = &sourceCap{count: make(map[netip.Addr]uint16)}
	}
	if got := average(servers); got != 0 {
		t.Errorf("server map: %v allocations on average for %d keys, want 0", got, n)
	}
	for i, s := range servers {
		if got := s.keys(); got != n {
			t.Errorf("server map %d holds %d keys, want %d", i, got, n)
		}
	}
	if got := average(plain); got == 0 {
		t.Error("map without a size hint took 0 allocations on average: the measure does not see growth")
	}
}

// T-S-17: no log line holds a source address during closes at the source cap.
func TestTS17SourceCapNotLogged(t *testing.T) {
	var std, structured bytes.Buffer
	prevOut, prevSlog := log.Writer(), slog.Default()
	t.Cleanup(func() { slog.SetDefault(prevSlog); log.SetOutput(prevOut) })
	slog.SetDefault(slog.New(slog.NewTextHandler(&structured, nil)))
	log.SetOutput(&std)

	r := newRig(t, 40, testHeaderBytes, defaultTimeouts, okHandler)
	r.serve(t)
	for range maxConnsPerSource {
		r.dialTLSFrom(t, r.addr, 5)
	}
	lines := r.s.ErrorLines()
	expectCapClose(t, r, r.addr, 5)
	expectCapClose(t, r, r.addr, 5)
	if got := r.s.SourceCapCloses(); got != 2 {
		t.Fatalf("source cap closes %d, want 2", got)
	}
	if got := r.s.ErrorLines(); got != lines {
		t.Fatalf("error lines %d, want %d", got, lines)
	}
	for _, out := range []string{std.String(), structured.String()} {
		if strings.Contains(out, "127.0.0.5") {
			t.Errorf("log output holds the source address: %q", out)
		}
	}
}

// fakeConn is a pipe end with a chosen peer and local address. It records Close.
type fakeConn struct {
	net.Conn
	remote, local net.Addr
	closed        atomic.Bool
}

func (c *fakeConn) RemoteAddr() net.Addr { return c.remote }
func (c *fakeConn) LocalAddr() net.Addr  { return c.local }
func (c *fakeConn) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

// fakeListener returns its connections in order, then err.
type fakeListener struct {
	conns []*fakeConn
	err   error
}

func (l *fakeListener) Accept() (net.Conn, error) {
	if len(l.conns) == 0 {
		return nil, l.err
	}
	c := l.conns[0]
	l.conns = l.conns[1:]
	return c, nil
}
func (l *fakeListener) Close() error   { return nil }
func (l *fakeListener) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 443} }

func newFakeConn(t *testing.T, remote, local string) *fakeConn {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	return &fakeConn{
		Conn:   a,
		remote: net.TCPAddrFromAddrPort(netip.MustParseAddrPort(remote)),
		local:  net.TCPAddrFromAddrPort(netip.MustParseAddrPort(local)),
	}
}

// T-S-17: the key comes from RemoteAddr only, and Accept makes no error text of
// its own. All connections have the same peer host and different local
// addresses. Connection 33 closes inside Accept, and Accept returns the next
// connection, which has another peer host. The error of the listener below
// passes through unchanged.
func TestTS17SourceKeyFromRemoteAddrOnly(t *testing.T) {
	fake := &fakeListener{err: errors.New("fake accept error")}
	for i := range maxConnsPerSource {
		fake.conns = append(fake.conns, newFakeConn(t, fmt.Sprintf("192.0.2.7:%d", 1000+i), fmt.Sprintf("198.51.100.%d:443", i+1)))
	}
	over := newFakeConn(t, "192.0.2.7:2000", "198.51.100.200:443")
	other := newFakeConn(t, "192.0.2.8:1000", "198.51.100.1:443")
	fake.conns = append(fake.conns, over, other)

	l := newLimitListener(fake, make(chan struct{}, 2*maxConnsPerSource), newSourceCap(2*maxConnsPerSource), newReadLimit(testHeaderBytes))
	for i := range maxConnsPerSource {
		if _, err := l.Accept(); err != nil {
			t.Fatalf("accept %d: %v", i, err)
		}
	}
	got, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	if !over.closed.Load() {
		t.Error("connection 33 from the same peer host is not closed")
	}
	if lc, ok := got.(*limitConn); !ok || lc.Conn != net.Conn(other) {
		t.Errorf("Accept returned %v, want the connection from the other peer host", got)
	}
	if other.closed.Load() {
		t.Error("connection from the other peer host is closed")
	}
	if n := l.src.closes.Load(); n != 1 {
		t.Errorf("source cap closes %d, want 1", n)
	}
	if _, err := l.Accept(); err != fake.err {
		t.Errorf("Accept error %v, want the error of the listener", err)
	}
}

// T-S-17: the source check comes before the slot. The slots are full and the
// source is at the cap: Accept closes the connection at the source cap, takes
// no slot and leaves the count of the key unchanged.
func TestTS17SourceCheckBeforeSlot(t *testing.T) {
	over := newFakeConn(t, "192.0.2.7:2000", "198.51.100.1:443")
	fake := &fakeListener{conns: []*fakeConn{over}, err: errors.New("end of fake listener")}
	sem := make(chan struct{}, 1)
	sem <- struct{}{}
	src := newSourceCap(1)
	key := netip.MustParseAddr("192.0.2.7")
	for range maxConnsPerSource {
		src.take(key)
	}
	l := newLimitListener(fake, sem, src, newReadLimit(testHeaderBytes))
	if _, err := l.Accept(); err != fake.err {
		t.Fatalf("Accept error %v, want the error of the listener", err)
	}
	if !over.closed.Load() {
		t.Error("connection over the source cap is not closed")
	}
	if n := src.closes.Load(); n != 1 {
		t.Errorf("source cap closes %d, want 1", n)
	}
	if n := len(sem); n != 1 {
		t.Errorf("slots in use %d, want 1", n)
	}
	if n := src.count[key]; n != maxConnsPerSource {
		t.Errorf("count of the key %d, want %d", n, maxConnsPerSource)
	}
}

// benchConn is a pipe end with a TCP peer address. Close does nothing, so the
// benchmark makes the connection once and measures only the listener.
type benchConn struct {
	net.Conn
	remote net.Addr
}

func (c *benchConn) RemoteAddr() net.Addr { return c.remote }
func (c *benchConn) Close() error         { return nil }

// benchListener returns the same connection on each Accept.
type benchListener struct{ conn net.Conn }

func (l *benchListener) Accept() (net.Conn, error) { return l.conn, nil }
func (l *benchListener) Close() error              { return nil }
func (l *benchListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 443}
}

// BenchmarkLimitAccept measures one Accept of limitListener and one Close of
// the limitConn that it returns.
func BenchmarkLimitAccept(b *testing.B) {
	a, p := net.Pipe()
	defer a.Close()
	defer p.Close()
	conn := &benchConn{Conn: a, remote: net.TCPAddrFromAddrPort(netip.MustParseAddrPort("192.0.2.7:1000"))}
	const slots = 64
	l := newLimitListener(&benchListener{conn: conn}, make(chan struct{}, slots), newSourceCap(slots), newReadLimit(testHeaderBytes))
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		c, err := l.Accept()
		if err != nil {
			b.Fatal(err)
		}
		_ = c.Close()
	}
}

// newSourceListener returns a new source address on each Accept.
type newSourceListener struct{ n atomic.Uint32 }

func (l *newSourceListener) Accept() (net.Conn, error) {
	i := l.n.Add(1)
	a := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
	return &benchConn{remote: net.TCPAddrFromAddrPort(netip.AddrPortFrom(a, 1))}, nil
}
func (l *newSourceListener) Close() error { return nil }
func (l *newSourceListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 443}
}

// T-S-17: with one Accept loop and connections that close in their own
// goroutines, the map never holds more than slots+1 keys.
func TestTS17SourceKeysWithinBound(t *testing.T) {
	const slots, accepts = 4, 30_000
	src := newSourceCap(slots)
	l := newLimitListener(&newSourceListener{}, make(chan struct{}, slots), src, newReadLimit(testHeaderBytes))
	var done atomic.Bool
	var max int
	var sampler sync.WaitGroup
	sampler.Add(1)
	go func() {
		defer sampler.Done()
		for !done.Load() {
			if k := src.keys(); k > max {
				max = k
			}
		}
	}()
	var closers sync.WaitGroup
	for range accepts {
		c, err := l.Accept()
		if err != nil {
			t.Fatal(err)
		}
		closers.Add(1)
		go func() { defer closers.Done(); _ = c.Close() }()
	}
	closers.Wait()
	done.Store(true)
	sampler.Wait()
	if max > slots+1 {
		t.Errorf("map held %d keys, want at most %d", max, slots+1)
	}
}

// T-S-17: one step of the accept path takes no heap allocation, for an IPv4 and
// an IPv6 peer address.
func TestTS17SourceCapStepNoAllocs(t *testing.T) {
	s := newSourceCap(8)
	for _, ip := range []string{"192.0.2.7", "2001:db8:1:2::7"} {
		addr := net.TCPAddrFromAddrPort(netip.AddrPortFrom(netip.MustParseAddr(ip), 1000))
		if n := testing.AllocsPerRun(100, func() {
			k := sourceKey(addr)
			s.take(k)
			s.give(k)
		}); n != 0 {
			t.Errorf("%s: %v allocations, want 0", ip, n)
		}
	}
}

// T-S-18: a normal client reads less than 4096 bytes in each period, so the pool
// charges nothing, the connection stays open and a second request gets 200. The
// pool and the slots are free after the client closes.
func TestTS18NormalClient(t *testing.T) {
	r := newRig(t, 4, testHeaderBytes, defaultTimeouts, okHandler)
	l := r.watchPeriods()
	r.serve(t)
	c := r.dial(t)
	for i := range 2 {
		if got := status(c, 0); got != 200 {
			t.Fatalf("request %d: status %d, want 200", i, got)
		}
	}
	idle, _ := l.wait(t, 2, 0)
	for i, p := range idle {
		if p.used == 0 || p.used > keepAliveBytes || p.charged != 0 {
			t.Errorf("period %d: read %d bytes, charged %d", i, p.used, p.charged)
		}
	}
	_ = c.Close()
	waitFor(t, "pool and slots free", func() bool { return r.s.rd.pool.Load() == 0 && len(r.s.sem) == 0 })
}

// T-S-18: the budget of the next period is header_bytes + 1024. After a first
// request, a head of header_bytes bytes gets 200. A period that reads more than
// the budget closes the connection with no response, and the wrapper counted
// exactly the budget.
func TestTS18NextPeriodBudget(t *testing.T) {
	r := newRig(t, 4, testHeaderBytes, defaultTimeouts, okHandler)
	l := r.watchPeriods()
	r.serve(t)
	c := r.dialWhole(t)
	if got := status(c, 0); got != 200 {
		t.Fatalf("first request: status %d", got)
	}
	if got := status(c, testHeaderBytes); got != 200 {
		t.Fatalf("head of header_bytes bytes: status %d, want 200", got)
	}
	over := r.dialWhole(t)
	if got := status(over, 0); got != 200 {
		t.Fatalf("first request: status %d", got)
	}
	if got := status(over, testHeaderBytes+2000); got != 0 {
		t.Fatalf("head over the budget: status %d, want a close", got)
	}
	_, closed := l.wait(t, 0, 2)
	var most int64
	for _, p := range closed {
		most = max(most, p.used)
	}
	if most != r.s.rd.next {
		t.Fatalf("the most bytes of a period: %d, want the budget %d", most, r.s.rd.next)
	}
}

// T-S-18: the keep-alive limit. The test calibrates the TLS overhead of one
// request, then sends a request that makes the wrapper count 4096 bytes in the
// period (the connection stays open) and one that makes it count 4097 (the
// connection closes after the response).
func TestTS18KeepAliveLimit(t *testing.T) {
	r := newRig(t, 8, testHeaderBytes, defaultTimeouts, okHandler)
	l := r.watchPeriods()
	r.serve(t)
	c := r.dialWhole(t)
	status(c, 0)
	status(c, 100)
	idle, _ := l.wait(t, 2, 0)
	overhead := idle[1].used - 100
	base := 2
	for _, tc := range []struct {
		used int64
		open bool
	}{{keepAliveBytes, true}, {keepAliveBytes + 1, false}} {
		c := r.dialWhole(t)
		if got := status(c, 0); got != 200 {
			t.Fatalf("first request: status %d", got)
		}
		if got := status(c, int(tc.used-overhead)); got != 200 {
			t.Fatalf("period of %d bytes: status %d, want 200", tc.used, got)
		}
		base += 2
		idle, _ := l.wait(t, base, 0)
		if idle[base-1].used != tc.used {
			t.Fatalf("the wrapper counted %d bytes, want %d", idle[base-1].used, tc.used)
		}
		if open := status(c, 0) == 200; open != tc.open {
			t.Errorf("period of %d bytes: connection open %v, want %v", tc.used, open, tc.open)
		}
		if tc.open {
			base++
		}
	}
}

// T-S-18: the pool arithmetic on the wrapper. The first 4096 bytes of a period
// are free. The charged bytes go back at idle and at close one time. A read
// that takes the pool over poolBytes fails and charges nothing.
func TestTS18PoolArithmetic(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	rd := newReadLimit(testHeaderBytes)
	l := newLimitListener(ln, make(chan struct{}, 8), newSourceCap(8), rd)
	defer l.Close()
	// open returns a wrapper whose client sent n bytes, and the wrapper has read k.
	open := func(n, k int) *limitConn {
		cc, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cc.Close() })
		c, err := l.Accept()
		if err != nil {
			t.Fatal(err)
		}
		_, _ = cc.Write(make([]byte, n))
		lc := c.(*limitConn)
		buf := make([]byte, k)
		for got := 0; got < k; {
			m, err := lc.Read(buf[:k-got])
			if err != nil {
				t.Fatal(err)
			}
			got += m
		}
		return lc
	}
	want := func(what string, pool int64) {
		t.Helper()
		if got := rd.pool.Load(); got != pool {
			t.Fatalf("%s: pool %d, want %d", what, got, pool)
		}
	}
	a, b := open(10000, 10000), open(10000, 10000)
	if s := a.snapshot(); s != (periodRec{10000, 10000 - keepAliveBytes}) {
		t.Fatalf("snapshot %+v", s)
	}
	want("two large periods", 2*(10000-keepAliveBytes))
	a.nextPeriod() // a read more than 4096 bytes: it closes and gives its bytes back
	_ = a.Close()
	want("a closed at idle, then closed again", 10000-keepAliveBytes)
	_ = b.Close()
	_ = b.Close()
	want("b closed two times", 0)

	n := open(3000, 3000)
	n.nextPeriod() // within 4096 bytes: it stays open with the next budget
	if s := n.snapshot(); s != (periodRec{}) || n.left != rd.next {
		t.Fatalf("after idle: %+v, left %d", s, n.left)
	}
	want("idle within the allowance", 0)

	rd.pool.Store(poolBytes - 100)
	f := open(keepAliveBytes+300, keepAliveBytes)
	if _, err := f.Read(make([]byte, 8192)); err == nil {
		t.Fatal("a read over the pool worked")
	}
	if _, err := f.Read(make([]byte, 8)); err == nil {
		t.Fatal("a read after the refusal worked")
	}
	_ = f.Close()
	want("refused read", poolBytes-100)

	rd.pool.Store(poolBytes - 500)
	e := open(keepAliveBytes+501, keepAliveBytes+500)
	want("pool filled to the limit", poolBytes)
	if _, err := e.Read(make([]byte, 8)); err == nil {
		t.Fatal("a charged read at a full pool worked")
	}
	_ = e.Close()
	want("close of the holder", poolBytes-500)
}

// T-S-18: with the pool full, a normal client completes its handshake and
// request and gets 200. A ClientHello that reads above the allowance has a
// charged read, and the connection closes. The pool does not change.
func TestTS18PoolFull(t *testing.T) {
	r := newRig(t, 4, testHeaderBytes, defaultTimeouts, okHandler)
	l := r.watchPeriods()
	r.serve(t)
	r.s.rd.pool.Store(poolBytes)
	if got := status(r.dial(t), 0); got != 200 {
		t.Fatalf("normal client with a full pool: status %d, want 200", got)
	}
	raw, err := net.Dial("tcp", r.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
	if err := tls.Client(raw, r.clientConfig(manyProtos(20)...)).Handshake(); err == nil {
		t.Fatal("a ClientHello over the allowance worked with a full pool")
	}
	if _, closed := l.wait(t, 0, 1); closed[0].used <= keepAliveBytes {
		t.Fatalf("the closed connection read %d bytes", closed[0].used)
	}
	if got := r.s.rd.pool.Load(); got != poolBytes {
		t.Fatalf("pool %d, want %d", got, poolBytes)
	}
}

// T-S-18: connections that read above the allowance hold charged bytes, and the
// pool is 0 again after they close.
func TestTS18PoolReleasedAfterClose(t *testing.T) {
	r := newRig(t, 8, testHeaderBytes, defaultTimeouts, okHandler)
	l := r.watchPeriods()
	r.serve(t)
	const n = 5
	for range n {
		c, err := tls.Dial("tcp", r.addr, r.clientConfig(manyProtos(40)...))
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		if got := status(c, 0); got != 200 {
			t.Fatalf("status %d, want 200", got)
		}
	}
	idle, _ := l.wait(t, n, 0)
	for i, p := range idle {
		if p.charged <= 0 {
			t.Errorf("connection %d: charged %d, want more than 0", i, p.charged)
		}
	}
	waitFor(t, "pool and slots free", func() bool { return r.s.rd.pool.Load() == 0 && len(r.s.sem) == 0 })
}
