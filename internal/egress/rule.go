// Package egress decides if the sensor can connect to an address (SEC-26).
// The rule is a fixed table in the code. No config key, environment variable
// or flag changes it.
package egress

import (
	"errors"
	"net/netip"
)

// ErrRefused is the error for each refused address. Its text has no address,
// name or port, so a client can log it.
var ErrRefused = errors.New("connection refused by the address rule")

// refused4 are the refused IPv4 prefixes. Each other IPv4 address is
// permitted.
var refused4 = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

// permitted6 is the only permitted IPv6 range. Every other IPv6 address is
// refused, which includes IPv4-compatible and NAT64 addresses.
var permitted6 = netip.MustParsePrefix("2000::/3")

// refused6 are the refused prefixes inside permitted6.
var refused6 = []netip.Prefix{
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("3fff::/20"),
}

// Permitted tells if the sensor can connect to a. It refuses an invalid
// address and an address with a zone. Then it reads an IPv4-mapped address
// as IPv4. The zone check comes first, because Unmap drops the zone.
func Permitted(a netip.Addr) bool {
	if !a.IsValid() || a.Zone() != "" {
		return false
	}
	a = a.Unmap()
	if a.Is4() {
		return !inAny(refused4, a)
	}
	return permitted6.Contains(a) && !inAny(refused6, a)
}

// inAny tells if a is in one of the prefixes.
func inAny(prefixes []netip.Prefix, a netip.Addr) bool {
	for _, p := range prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
