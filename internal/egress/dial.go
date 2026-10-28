package egress

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
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

// errItemInput is the error for a bad port or protocol in ItemDialer.
var errItemInput = errors.New("egress: item dialer needs a port that is not 0 " +
	"and a tcp or udp protocol")

// ItemDialer gives a dialer for one endpoint item. Besides the address rule,
// the dialer permits an address in list. It does so only on the port and the
// protocol of the item. The list is a part of this dialer only. The protocol
// is "tcp" or "udp". ItemDialer refuses a list with an entry that fails the
// entry rule of ParsePrivateEntry. It gives the error of that rule. The
// dialer keeps a copy of the list. The never-list wins over an entry.
func ItemDialer(
	list []netip.Prefix, port uint16, proto string, timeout time.Duration,
) (*net.Dialer, error) {
	if port == 0 || (proto != "tcp" && proto != "udp") {
		return nil, errItemInput
	}
	for _, p := range list {
		if err := checkEntry(p); err != nil {
			return nil, err
		}
	}
	list = slices.Clone(list)
	d := Dialer(timeout)
	d.ControlContext = func(
		_ context.Context, network, address string, _ syscall.RawConn,
	) error {
		np, ap, ok := parseDial(network, address)
		if !ok {
			return errRefused
		}
		if !itemPermits(list, ap.Addr(), ap.Port() == port && np == proto) {
			return errRefused
		}
		return nil
	}
	return d, nil
}
