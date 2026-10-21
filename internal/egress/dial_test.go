package egress_test

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/cybagard/cyba-phantom/internal/egress"
	"github.com/cybagard/cyba-phantom/internal/egress/egresstest"
)

const testTimeout = 5 * time.Second

var (
	loop4 = netip.MustParseAddr("127.0.0.1")
	loop6 = netip.MustParseAddr("::1")
)

// listen opens a TCP listener on the loopback address a. It skips the test
// when the host has no such address.
func listen(t *testing.T, a netip.Addr) *net.TCPListener {
	t.Helper()
	ln, err := net.ListenTCP("tcp", net.TCPAddrFromAddrPort(netip.AddrPortFrom(a, 0)))
	if err != nil {
		t.Skipf("no listener on %s: %v", a, err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln
}

// listenUDP opens a UDP socket on the loopback address a.
func listenUDP(t *testing.T, a netip.Addr) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(a, 0)))
	if err != nil {
		t.Skipf("no UDP socket on %s: %v", a, err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// noAccept fails t when ln has a connection that the dialer under test made.
// A plain dial queues a probe after any earlier connection, so the first
// accepted connection must be the probe.
func noAccept(t *testing.T, ln *net.TCPListener) {
	t.Helper()
	probe, err := net.DialTimeout("tcp", ln.Addr().String(), testTimeout)
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	ln.SetDeadline(time.Now().Add(testTimeout))
	c, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if c.RemoteAddr().String() != probe.LocalAddr().String() {
		t.Errorf("listener accepted %s before the probe", c.RemoteAddr())
	}
}

// noDatagram fails t when c holds a datagram that is not the probe.
func noDatagram(t *testing.T, c *net.UDPConn) {
	t.Helper()
	probe, err := net.Dial("udp", c.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	if _, err := probe.Write([]byte("probe")); err != nil {
		t.Fatal(err)
	}
	c.SetReadDeadline(time.Now().Add(testTimeout))
	buf := make([]byte, 64)
	n, _, err := c.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "probe" {
		t.Errorf("socket got %q before the probe", buf[:n])
	}
}

func dial(d *net.Dialer, network, address string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	return d.DialContext(ctx, network, address)
}

func mustRefuse(t *testing.T, d *net.Dialer, network, address string) {
	t.Helper()
	c, err := dial(d, network, address)
	if err == nil {
		c.Close()
		t.Errorf("%s %s: dial worked", network, address)
	} else if !errors.Is(err, egress.ErrRefused) {
		t.Errorf("%s %s: got %v", network, address, err)
	}
}

func TestTS21DialerFields(t *testing.T) {
	d := egress.Dialer(3 * time.Second)
	if d.Timeout != 3*time.Second {
		t.Errorf("Timeout is %v", d.Timeout)
	}
	if d.ControlContext == nil {
		t.Error("no ControlContext")
	}
	if d.Control != nil || d.LocalAddr != nil || d.Resolver != nil ||
		d.FallbackDelay != 0 {
		t.Errorf("unexpected field set: %+v", d)
	}
}

func TestTS21DialerSendsNothingToLoopback(t *testing.T) {
	d := egress.Dialer(testTimeout)
	for _, a := range []netip.Addr{loop4, loop6} {
		ln := listen(t, a)
		mustRefuse(t, d, "tcp", ln.Addr().String())
		noAccept(t, ln)
		uc := listenUDP(t, a)
		mustRefuse(t, d, "udp", uc.LocalAddr().String())
		noDatagram(t, uc)
	}
}

func TestTS21DialerRefusesEachRange(t *testing.T) {
	d := egress.Dialer(testTimeout)
	for _, addr := range []string{
		"0.0.0.1", "10.0.0.1", "100.64.0.1", "127.0.0.1", "169.254.169.254",
		"172.16.0.1", "192.0.0.1", "192.0.2.1", "192.88.99.1", "192.168.0.1",
		"198.18.0.1", "198.51.100.1", "203.0.113.1", "224.0.0.1", "240.0.0.1",
		"255.255.255.255", "[::]", "[::1]", "[fe80::1]", "[fc00::1]",
		"[2001::1]", "[2001:db8::1]", "[2002::1]", "[3fff::1]", "[ff02::1]",
		"[64:ff9b::a9fe:a9fe]", "[::ffff:10.0.0.1]", "[::ffff:127.0.0.1]",
		"[::ffff:a9fe:a9fe]", "[fe80::1%eth0]", "[2606:4700::1111%eth0]",
	} {
		mustRefuse(t, d, "tcp", addr+":443")
		mustRefuse(t, d, "udp", addr+":53")
	}
}

func TestTS21DialerRefusesName(t *testing.T) {
	ln := listen(t, loop4)
	names := egresstest.NewNames(t)
	names.Set("refused.test.", loop4)
	d := egress.Dialer(testTimeout)
	d.Resolver = names.Resolver()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	mustRefuse(t, d, "tcp", "refused.test.:"+port)
	noAccept(t, ln)
}

func TestTS21NameWithRefusedAndStandIn(t *testing.T) {
	ln := listen(t, loop4)
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	names := egresstest.NewNames(t)
	d := egresstest.Dialer(t, testTimeout, loop4)
	d.Resolver = names.Resolver()
	for _, refused := range []string{"10.0.0.1", "2001:db8::1", "::ffff:10.0.0.1"} {
		names.Set("mixed.test.", netip.MustParseAddr(refused), loop4)
		c, err := dial(d, "tcp", "mixed.test.:"+port)
		if err != nil {
			t.Fatalf("answers %s and 127.0.0.1: %v", refused, err)
		}
		if got := c.RemoteAddr().String(); got != ln.Addr().String() {
			t.Errorf("connected to %s", got)
		}
		c.Close()
		s, err := ln.Accept()
		if err != nil {
			t.Fatal(err)
		}
		s.Close()
	}
}

func TestTS21NameChangesBetweenDials(t *testing.T) {
	ln := listen(t, loop4)
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	names := egresstest.NewNames(t)
	names.Set("rebind.test.", loop4)
	d := egresstest.Dialer(t, testTimeout, loop4)
	d.Resolver = names.Resolver()
	c, err := dial(d, "tcp", "rebind.test.:"+port)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	names.Set("rebind.test.", netip.MustParseAddr("169.254.169.254"))
	mustRefuse(t, d, "tcp", "rebind.test.:"+port)
}

// fakeTB records a fatal call. Fatalf stops the goroutine as testing.T does.
type fakeTB struct {
	testing.TB
	failed bool
}

func (f *fakeTB) Helper()               {}
func (f *fakeTB) Cleanup(func())        {}
func (f *fakeTB) Fatalf(string, ...any) { f.failed = true; panic(f) }

// failsOn tells if fn calls Fatalf on f.
func failsOn(f *fakeTB, fn func()) (failed bool) {
	defer func() {
		if r := recover(); r != nil && r != any(f) {
			panic(r)
		}
		failed = f.failed
	}()
	fn()
	return false
}

// The Testing check of egresstest cannot fail in a test binary. This test
// covers the other Fatalf path of the same helper.
func TestTS21EgresstestRefusesNonLoopback(t *testing.T) {
	for _, a := range []string{"10.0.0.1", "8.8.8.8", "::ffff:127.0.0.1"} {
		f := &fakeTB{TB: t}
		if !failsOn(f, func() {
			egresstest.Dialer(f, time.Second, netip.MustParseAddr(a))
		}) {
			t.Errorf("egresstest permits %s", a)
		}
	}
	f := &fakeTB{TB: t}
	if failsOn(f, func() { egresstest.Dialer(f, time.Second, loop4, loop6) }) {
		t.Error("egresstest refuses a loopback address")
	}
}

func TestTS21TestDialerPermitsOnlyNamedLoopback(t *testing.T) {
	ln := listen(t, loop4)
	prod := egress.Dialer(testTimeout)
	mustRefuse(t, prod, "tcp", ln.Addr().String())
	noAccept(t, ln)

	test := egresstest.Dialer(t, testTimeout, loop4)
	c, err := dial(test, "tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	mustRefuse(t, test, "tcp", "[::1]:1")
	mustRefuse(t, test, "tcp", "10.0.0.1:1")
	mustRefuse(t, prod, "tcp", ln.Addr().String())
}
