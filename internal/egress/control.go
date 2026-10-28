package egress

import (
	"context"
	"net/netip"
	"syscall"
)

// control has the signature of net.Dialer.ControlContext. The dialer calls it
// for each address, before it connects. It reads no environment, file or
// config. Each refusal returns errRefused. This function adds no address to it.
func control(
	_ context.Context, network, address string, _ syscall.RawConn,
) error {
	_, ap, ok := parseDial(network, address)
	if !ok || !Permitted(ap.Addr()) {
		return errRefused
	}
	return nil
}

// parseDial maps the network with protocol and parses the address. It gives
// false when the network is not permitted or the address has no port. The
// caller must test the boolean: the address is set when only the network fails.
func parseDial(network, address string) (string, netip.AddrPort, bool) {
	proto, ok := protocol(network)
	ap, err := netip.ParseAddrPort(address)
	return proto, ap, ok && err == nil
}

// protocol gives "tcp" or "udp" for the four networks that the rule permits:
// tcp4, tcp6, udp4 and udp6. For each other network it gives false.
func protocol(network string) (string, bool) {
	switch network {
	case "tcp4", "tcp6":
		return "tcp", true
	case "udp4", "udp6":
		return "udp", true
	}
	return "", false
}
