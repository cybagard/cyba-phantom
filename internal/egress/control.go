package egress

import (
	"context"
	"net/netip"
	"syscall"
)

// control has the signature of net.Dialer.ControlContext. The dialer calls it
// for each address, before the connect. It reads no environment, file or
// config. Each refusal is errRefused itself, with no address added.
func control(
	_ context.Context, network, address string, _ syscall.RawConn,
) error {
	switch network {
	case "tcp4", "tcp6", "udp4", "udp6":
	default:
		return errRefused
	}
	ap, err := netip.ParseAddrPort(address)
	if err != nil || !Permitted(ap.Addr()) {
		return errRefused
	}
	return nil
}
