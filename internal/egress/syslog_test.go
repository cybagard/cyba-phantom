package egress_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/cybagard/cyba-phantom/internal/egress"
)

func TestTS21SyslogDialerRefusesBadInput(t *testing.T) {
	tests := []struct {
		scheme, addr string
	}{
		{"tls", "127.0.0.1:514"},
		{"", "127.0.0.1:514"},
		{"http", "127.0.0.1:514"},
		{"udp", "10.0.0.1:514"},
		{"udp", "8.8.8.8:514"},
		{"tcp", "[::ffff:127.0.0.1]:514"},
		{"tcp", "[::1%lo]:514"},
		{"tcp", "[fe80::1]:514"},
		{"udp", "127.0.0.1:0"},
	}
	for _, tc := range tests {
		d, err := egress.SyslogDialer(tc.scheme, netip.MustParseAddrPort(tc.addr), time.Second)
		if err == nil || d != nil {
			t.Errorf("%s %s: got %v, %v", tc.scheme, tc.addr, d, err)
		}
	}
	d, err := egress.SyslogDialer("udp", netip.AddrPort{}, time.Second)
	if err == nil || d != nil {
		t.Errorf("invalid address: got %v, %v", d, err)
	}
}

func TestTS21SyslogDialerFields(t *testing.T) {
	d, err := egress.SyslogDialer("udp", netip.MustParseAddrPort("127.0.0.2:514"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if d.Timeout != time.Second || d.ControlContext == nil || d.Control != nil ||
		d.LocalAddr != nil || d.Resolver != nil || d.FallbackDelay != 0 {
		t.Errorf("unexpected fields: %+v", d)
	}
}

func TestTS21SyslogUDPException(t *testing.T) {
	uc := listenUDP(t, loop4)
	ap := uc.LocalAddr().(*net.UDPAddr).AddrPort()
	d, err := egress.SyslogDialer("udp", ap, testTimeout)
	if err != nil {
		t.Fatal(err)
	}
	c, err := dial(d, "udp4", ap.String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	uc.SetReadDeadline(time.Now().Add(testTimeout))
	n, _, err := uc.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "hello" {
		t.Errorf("datagram: %q, %v", buf[:n], err)
	}
	other := netip.AddrPortFrom(loop4, ap.Port()+1)
	mustRefuse(t, d, "udp4", other.String())
	mustRefuse(t, d, "udp6", netip.AddrPortFrom(loop6, ap.Port()).String())
	mustRefuse(t, d, "tcp4", ap.String())
	mustRefuse(t, d, "tcp6", netip.AddrPortFrom(loop6, ap.Port()).String())
	mustRefuse(t, d, "udp4", netip.AddrPortFrom(loop4b, ap.Port()).String())
	mapped := fmt.Sprintf("[::ffff:127.0.0.1%%lo]:%d", ap.Port())
	mustRefuse(t, d, "udp", mapped)
	mustHookRefuse(t, d, "udp6", mapped)

	prod := egress.Dialer(testTimeout)
	mustRefuse(t, prod, "udp4", ap.String())
	noDatagram(t, uc)
}

func TestTS21SyslogTCPExceptionOnIPv4(t *testing.T) {
	ln := listen(t, loop4)
	ap := ln.Addr().(*net.TCPAddr).AddrPort()
	d, err := egress.SyslogDialer("tcp", ap, testTimeout)
	if err != nil {
		t.Fatal(err)
	}
	c, err := dial(d, "tcp4", ap.String())
	if err != nil {
		t.Fatal(err)
	}
	s, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	c.Close()
	mustRefuse(t, d, "tcp4", netip.AddrPortFrom(loop4b, ap.Port()).String())
	mustRefuse(t, d, "tcp6", netip.AddrPortFrom(loop6, ap.Port()).String())
	mapped := fmt.Sprintf("[::ffff:127.0.0.1%%lo]:%d", ap.Port())
	mustRefuse(t, d, "tcp", mapped)
	mustHookRefuse(t, d, "tcp6", mapped)
}

// mustHookRefuse calls the hook of d with no dial. On Linux, a dial does not
// give the hook an IPv4-mapped address with a zone. Network udp6 fails before
// the hook. Network udp gives an IPv4 address with a zone, and that address
// does not parse.
func mustHookRefuse(t *testing.T, d *net.Dialer, network, address string) {
	t.Helper()
	err := d.ControlContext(context.Background(), network, address, nil)
	if !errors.Is(err, egress.ErrRefused) {
		t.Errorf("hook %s %s: got %v", network, address, err)
	}
}

func TestTS21SyslogTCPException(t *testing.T) {
	ln := listen(t, loop6)
	ap := ln.Addr().(*net.TCPAddr).AddrPort()
	d, err := egress.SyslogDialer("tcp", ap, testTimeout)
	if err != nil {
		t.Fatal(err)
	}
	c, err := dial(d, "tcp6", ap.String())
	if err != nil {
		t.Fatal(err)
	}
	s, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	c.Close()
	mustRefuse(t, d, "udp6", ap.String())
	mustRefuse(t, d, "tcp4", netip.AddrPortFrom(loop4, ap.Port()).String())
	mustRefuse(t, d, "tcp6", netip.AddrPortFrom(loop6, ap.Port()+1).String())
	mustRefuse(t, d, "tcp6", fmt.Sprintf("[::1%%eth0]:%d", ap.Port()))

	prod := egress.Dialer(testTimeout)
	mustRefuse(t, prod, "tcp6", ap.String())
	noAccept(t, ln)
}

func TestTS21SyslogExceptionIsForItsDialerOnly(t *testing.T) {
	ln := listen(t, loop4)
	ap := ln.Addr().(*net.TCPAddr).AddrPort()
	if _, err := egress.SyslogDialer("tcp", ap, testTimeout); err != nil {
		t.Fatal(err)
	}
	mustRefuse(t, egress.Dialer(testTimeout), "tcp", ap.String())
	noAccept(t, ln)
}
