package egress

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"syscall"
	"time"
)

// loopback4 is the IPv4 range that a syslog sink can use.
var loopback4 = netip.MustParsePrefix("127.0.0.0/8")

// Dialer gives a dialer that applies the address rule to each address, before
// the dialer connects. The dialer resolves a name again for each dial and
// keeps no result. It has no local address, and it uses the default resolver
// and the default fallback delay.
func Dialer(timeout time.Duration) *net.Dialer {
	return &net.Dialer{Timeout: timeout, ControlContext: control}
}

// errSyslogInput is the error for a bad input to SyslogDialer.
var errSyslogInput = errors.New("egress: syslog exception needs a udp or tcp " +
	"scheme and a loopback address with a port")

// SyslogDialer gives a dialer for one syslog sink. The dialer permits the one
// address and port of the sink only on the networks of scheme. Every other
// dial gets the address rule. The scheme is "udp" or "tcp". The address is in
// 127.0.0.0/8 or is ::1, with no zone and no IPv4-mapped form.
func SyslogDialer(
	scheme string, addr netip.AddrPort, timeout time.Duration,
) (*net.Dialer, error) {
	a := addr.Addr()
	loopback := a.Is4() && loopback4.Contains(a) || a == netip.IPv6Loopback()
	if (scheme != "udp" && scheme != "tcp") || !loopback || addr.Port() == 0 {
		return nil, errSyslogInput
	}
	d := Dialer(timeout)
	rule := d.ControlContext
	d.ControlContext = func(
		ctx context.Context, network, address string, c syscall.RawConn,
	) error {
		if proto, ok := protocol(network); ok && proto == scheme {
			if ap, err := netip.ParseAddrPort(address); err == nil && ap == addr {
				return nil
			}
		}
		return rule(ctx, network, address, c)
	}
	return d, nil
}
