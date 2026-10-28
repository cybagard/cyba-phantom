package egress

import (
	"errors"
	"net/netip"
)

// The errors for a bad list entry. No error text holds the entry text. Thus, a
// loader can add the key of the entry and log the error.
var (
	errEntryParse    = errors.New("egress: list entry is not an address or a prefix")
	errEntryZone     = errors.New("egress: list entry has a zone")
	errEntryMapped   = errors.New("egress: list entry is an IPv4-mapped address")
	errEntryHostBits = errors.New("egress: list entry has host bits that are not 0")
	errEntryClass    = errors.New("egress: list entry is not in a private class")
)

// privateClasses are the ranges that a list entry can be in (SEC-30).
var privateClasses = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("fc00::/7"),
}

// neverList are the ranges that the guard refuses, also when a list entry
// holds them. Only the two metadata addresses are in a private class.
var neverList = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("fd00:ec2::254/128"),
	netip.MustParsePrefix("100.100.100.200/32"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("ff00::/8"),
	netip.MustParsePrefix("0.0.0.0/32"),
	netip.MustParsePrefix("::/128"),
}

// ParsePrivateEntry parses one entry of a private list (SEC-30). The entry is
// a prefix, or one address that becomes a /32 or /128 prefix. The function
// refuses a zone, an IPv4-mapped entry and host bits that are not 0. It also
// refuses a prefix that is not fully inside one of the five private classes.
func ParsePrivateEntry(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		a, aerr := netip.ParseAddr(s)
		if aerr != nil {
			return netip.Prefix{}, errEntryParse
		}
		if a.Zone() != "" {
			return netip.Prefix{}, errEntryZone
		}
		p = netip.PrefixFrom(a, a.BitLen())
	}
	if err := checkEntry(p); err != nil {
		return netip.Prefix{}, err
	}
	return p, nil
}

// checkEntry applies the entry rule to p. A Prefix has no zone.
func checkEntry(p netip.Prefix) error {
	if !p.IsValid() {
		return errEntryParse
	}
	if p.Addr().Is4In6() {
		return errEntryMapped
	}
	if p.Masked() != p {
		return errEntryHostBits
	}
	for _, class := range privateClasses {
		if class.Bits() <= p.Bits() && class.Contains(p.Addr()) {
			return nil
		}
	}
	return errEntryClass
}

// ItemPermitted tells if the guard of an item with the private list lets the
// item connect to the address a. The order is the order of the item dialer:
// zone, unmap, never-list, the rule, then the list. The list applies for any
// port and protocol, so a caller uses it only for the endpoint of the item.
// An entry that the entry rule refuses makes the result false. The loader uses
// it for an IP-literal host, so that it has the same never-list as the dialer.
func ItemPermitted(list []netip.Prefix, a netip.Addr) bool {
	for _, p := range list {
		if checkEntry(p) != nil {
			return false
		}
	}
	return itemPermits(list, a, true)
}

// itemPermits applies the guard order of an item dialer to the address a.
// The caller sets portAndProtoMatch when the port and the protocol of the dial
// are those of the item. The zone check comes before the unmap, because Unmap
// drops the zone. The never-list comes before the rule and the list.
func itemPermits(
	list []netip.Prefix, a netip.Addr, portAndProtoMatch bool,
) bool {
	if a.Zone() != "" {
		return false
	}
	a = a.Unmap()
	if inAny(neverList, a) {
		return false
	}
	if Permitted(a) {
		return true
	}
	return portAndProtoMatch && inAny(list, a)
}
