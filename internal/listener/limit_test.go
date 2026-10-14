package listener

import (
	"context"
	"crypto/tls"
	"net"
	"net/netip"
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

// T-S-17: the map is made with room for MaxConns keys. Making the map and
// inserting MaxConns keys allocates less than the same steps with a map that
// has no size hint. newServer makes its map with newSourceCap(cfg.MaxConns).
func TestTS17SourceMapCapacity(t *testing.T) {
	const n = 256
	keys := make([]netip.Addr, n)
	for i := range keys {
		keys[i] = netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)})
	}
	allocs := func(mk func() *sourceCap) float64 {
		return testing.AllocsPerRun(20, func() {
			s := mk()
			for _, k := range keys {
				s.take(k)
			}
		})
	}
	sized := allocs(func() *sourceCap { return newSourceCap(n) })
	unsized := allocs(func() *sourceCap { return &sourceCap{count: make(map[netip.Addr]uint16)} })
	if sized >= unsized {
		t.Fatalf("sized map: %v allocations, unsized map: %v", sized, unsized)
	}
}
