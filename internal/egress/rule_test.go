package egress

import (
	"net/netip"
	"testing"
)

// refusedPrefixes repeats the refused prefixes of the rule on purpose. The
// test does not read the table of the code.
var refusedPrefixes = []string{
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
	"169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
	"192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
	"203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
	"2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20",
}

// lastAddr returns the last address of a prefix.
func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().AsSlice()
	for i := p.Bits(); i < len(b)*8; i++ {
		b[i/8] |= 0x80 >> (i % 8)
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

// wantNeighbor tells if the rule permits an address outside a prefix.
func wantNeighbor(a netip.Addr) bool {
	if a.Is6() && !netip.MustParsePrefix("2000::/3").Contains(a) {
		return false
	}
	for _, s := range refusedPrefixes {
		if netip.MustParsePrefix(s).Contains(a) {
			return false
		}
	}
	return true
}

func TestTS21RuleRefusesEachPrefixAtItsEdges(t *testing.T) {
	for _, s := range refusedPrefixes {
		p := netip.MustParsePrefix(s)
		first, last := p.Masked().Addr(), lastAddr(p)
		for _, a := range []netip.Addr{first, last} {
			if Permitted(a) {
				t.Errorf("%s: edge %s is permitted", s, a)
			}
		}
		if below := first.Prev(); below.IsValid() {
			if got := Permitted(below); got != wantNeighbor(below) {
				t.Errorf("%s: below %s: got %v", s, below, got)
			}
		}
		if above := last.Next(); above.IsValid() {
			if got := Permitted(above); got != wantNeighbor(above) {
				t.Errorf("%s: above %s: got %v", s, above, got)
			}
		}
	}
}

func TestTS21RuleAddresses(t *testing.T) {
	permitted := []string{
		"8.8.8.8", "2606:4700::1111", "9.255.255.255", "11.0.0.0",
		"100.63.255.255", "100.128.0.0", "223.255.255.255",
		"2001:200::", "2001:db9::", "2003::", "3fff:1000::", "3ffe::1",
		"2000::", "3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
		"::ffff:8.8.8.8",
	}
	refused := []string{
		"1fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "4000::", "::", "::1",
		"255.255.255.255", "100.100.100.200", "169.254.169.254",
		"169.254.0.23", "fd00:ec2::254", "fe80::1", "fec0::1", "ff02::1",
		"::ffff:169.254.169.254", "::ffff:10.0.0.1", "::a9fe:a9fe",
		"64:ff9b::a9fe:a9fe", "64:ff9b:1::1", "2002:a9fe:a9fe::1",
		"2001:0:4136:e378::1", "100:0:0:1::1", "100::1",
		"fe80::1%eth0", "2606:4700::1111%eth0", "::ffff:8.8.8.8%eth0",
		"::ffff:10.0.0.1%eth0",
	}
	for _, s := range permitted {
		if !Permitted(netip.MustParseAddr(s)) {
			t.Errorf("%s: refused", s)
		}
	}
	for _, s := range refused {
		if Permitted(netip.MustParseAddr(s)) {
			t.Errorf("%s: permitted", s)
		}
	}
	if Permitted(netip.Addr{}) {
		t.Error("invalid address: permitted")
	}
}
