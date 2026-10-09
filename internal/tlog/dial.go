package tlog

import (
	"net"
	"net/netip"
	"syscall"
	"time"
)

const dialTimeout = 10 * time.Second

// newDialer makes the dialer of the publisher. Control runs after the name is
// resolved and before the connect, so a name that resolves to a refused address
// is refused too (C4).
func newDialer() *net.Dialer {
	return &net.Dialer{Timeout: dialTimeout, Control: refuseAddress}
}

// refuseAddress is the Control function of the dialer. It refuses an address that
// is unspecified, link-local unicast, or multicast. This is the rule of 04
// section 5 for a resolved address. Loopback is allowed.
func refuseAddress(_, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return errPublishAddress
	}
	if a := ap.Addr().Unmap(); a.IsUnspecified() || a.IsLinkLocalUnicast() || a.IsMulticast() {
		return errPublishAddress
	}
	return nil
}
