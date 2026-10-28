package egress

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestTS26EntryRefusesLoadCases(t *testing.T) {
	tests := []struct {
		entry string
		err   error
	}{
		{"0.0.0.0/0", errEntryClass},
		{"::/0", errEntryClass},
		{"198.18.0.0/15", errEntryClass},
		{"192.0.2.1", errEntryClass},
		{"64:ff9b::/96", errEntryClass},
		{"2002::/16", errEntryClass},
		{"fec0::/10", errEntryClass},
		{"::ffff:10.0.0.0/104", errEntryMapped},
		{"::ffff:10.1.2.3", errEntryMapped},
		{"fe80::1%eth0", errEntryZone},
		{"fd00::1%eth0", errEntryZone},
		{"10.0.0.1/8", errEntryHostBits},
		{"fd00::1/8", errEntryHostBits},
		{"fd00::1/64", errEntryHostBits},
		{"10.0.0.0/7", errEntryClass},
		{"fc00::/6", errEntryClass},
		{"172.0.0.0/11", errEntryClass},
		{"192.168.0.0/15", errEntryClass},
		{"100.0.0.0/9", errEntryClass},
		{"", errEntryParse},
		{"example.com", errEntryParse},
		{"10.0.0.1:443", errEntryParse},
		{"10.0.0.0/33", errEntryParse},
	}
	for _, tc := range tests {
		p, err := ParsePrivateEntry(tc.entry)
		if !errors.Is(err, tc.err) {
			t.Errorf("entry %q: got %v, want %v", tc.entry, err, tc.err)
		}
		if p.IsValid() {
			t.Errorf("entry %q: refused entry gave prefix %v", tc.entry, p)
		}
		if err != nil && strings.Contains(err.Error(), tc.entry) && tc.entry != "" {
			t.Errorf("entry %q: error text holds the entry", tc.entry)
		}
	}
}

func TestTS26EntryPassesEachClass(t *testing.T) {
	for _, entry := range []string{
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
		"fc00::/7", "10.1.2.3", "10.0.0.0/9", "172.31.255.255", "172.16.0.0/16",
		"192.168.255.255", "100.127.255.255", "100.64.0.0/10", "fd00::/8",
		"fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "fc00::1",
		"10.0.0.0", "10.255.255.255", "172.16.0.0", "192.168.0.0", "100.64.0.0",
	} {
		if _, err := ParsePrivateEntry(entry); err != nil {
			t.Errorf("entry %q: %v", entry, err)
		}
	}
}

// The first address below and the first address above each class are refused.
func TestTS26EntryClassEdges(t *testing.T) {
	for _, entry := range []string{
		"9.255.255.255", "11.0.0.0", "172.15.255.255", "172.32.0.0",
		"192.167.255.255", "192.169.0.0", "100.63.255.255", "100.128.0.0",
		"fbff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "fe00::",
	} {
		if _, err := ParsePrivateEntry(entry); !errors.Is(err, errEntryClass) {
			t.Errorf("entry %q: got %v", entry, err)
		}
	}
}

func TestTS26EntryForms(t *testing.T) {
	for _, tc := range []struct{ bare, prefix string }{
		{"10.1.2.3", "10.1.2.3/32"},
		{"fd00::1", "fd00::1/128"},
	} {
		a, err := ParsePrivateEntry(tc.bare)
		if err != nil {
			t.Fatal(err)
		}
		b, err := ParsePrivateEntry(tc.prefix)
		if err != nil {
			t.Fatal(err)
		}
		if a != b || a != netip.MustParsePrefix(tc.prefix) {
			t.Errorf("%q gives %v and %q gives %v", tc.bare, a, tc.prefix, b)
		}
	}
}

func TestTS26NeverListEdges(t *testing.T) {
	for _, a := range []string{
		"127.0.0.0", "127.255.255.255", "::1", "169.254.0.0", "169.254.255.255",
		"fe80::", "febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "fd00:ec2::254",
		"100.100.100.200", "224.0.0.0", "239.255.255.255", "ff00::",
		"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "0.0.0.0", "::",
	} {
		if !inAny(neverList, netip.MustParseAddr(a)) {
			t.Errorf("never-list lacks %s", a)
		}
	}
	for _, a := range []string{
		"126.255.255.255", "128.0.0.0", "::2", "169.253.255.255", "169.255.0.0",
		"fe7f::", "fec0::", "fd00:ec2::253", "fd00:ec2::255", "100.100.100.199",
		"100.100.100.201", "223.255.255.255", "240.0.0.0", "feff::", "0.0.0.1",
		"::3", "10.1.2.3", "fd00::1",
	} {
		if inAny(neverList, netip.MustParseAddr(a)) {
			t.Errorf("never-list holds %s", a)
		}
	}
}

// TestTS26ItemPermitted checks the order of ItemPermitted: zone, unmap,
// never-list, the rule, then the list.
func TestTS26ItemPermitted(t *testing.T) {
	list := func(s ...string) []netip.Prefix {
		var out []netip.Prefix
		for _, e := range s {
			p, err := ParsePrivateEntry(e)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, p)
		}
		return out
	}
	tests := []struct {
		name string
		list []netip.Prefix
		addr string
		want bool
	}{
		{"in list", list("10.0.0.0/8"), "10.1.2.3", true},
		{"mapped in list", list("10.0.0.0/8"), "::ffff:10.1.2.3", true},
		{"not in list", list("192.168.0.0/16"), "10.1.2.3", false},
		{"no list", nil, "10.1.2.3", false},
		{"global without list", nil, "8.8.8.8", true},
		{"never-list beats the list", list("100.100.100.200"), "100.100.100.200", false},
		{"never-list v6", list("fd00::/8"), "fd00:ec2::254", false},
		{"zone", list("fd00::/8"), "fd00::1%eth0", false},
		{"outside every class", list("10.0.0.0/8"), "198.18.0.1", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ItemPermitted(tt.list, netip.MustParseAddr(tt.addr)); got != tt.want {
				t.Errorf("ItemPermitted(%s) = %v, want %v", tt.addr, got, tt.want)
			}
		})
	}
}

// itemDialer makes an item dialer from the entries. It fails t on an error.
func itemDialer(t *testing.T, port uint16, proto string, list ...string) *net.Dialer {
	t.Helper()
	var prefixes []netip.Prefix
	for _, e := range list {
		p, err := ParsePrivateEntry(e)
		if err != nil {
			t.Fatal(err)
		}
		prefixes = append(prefixes, p)
	}
	d, err := ItemDialer(prefixes, port, proto, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// step runs the control step of d.
func step(d *net.Dialer, network, address string) error {
	return d.ControlContext(context.Background(), network, address, nil)
}

func TestTS26ItemControlPortAndProtocol(t *testing.T) {
	d := itemDialer(t, 443, "tcp", "10.0.0.0/8")
	for _, tc := range []struct {
		network, address string
		permitted        bool
	}{
		{"tcp4", "10.1.2.3:443", true},
		{"tcp4", "10.1.2.3:444", false},
		{"tcp4", "10.1.2.3:80", false},
		{"udp4", "10.1.2.3:443", false},
		{"udp6", "[::ffff:10.1.2.3]:443", false},
		{"tcp4", "172.16.0.1:443", false},
		{"tcp4", "11.0.0.1:443", true}, // global unicast: the rule permits it
		{"tcp4", "11.0.0.1:444", true},
		{"tcp6", "[::ffff:10.1.2.3]:443", true},
		{"tcp6", "[::ffff:10.1.2.3]:444", false},
		{"tcp", "10.1.2.3:443", false},
		{"ip4", "10.1.2.3:443", false},
		{"tcp", "11.0.0.1:443", false},
		{"ip4", "11.0.0.1:443", false},
		{"udp", "11.0.0.1:443", false},
		{"", "11.0.0.1:443", false},
		{"tcp4", "11.0.0.1", false},
		{"tcp4", "10.1.2.3", false},
		{"tcp4", "", false},
	} {
		err := step(d, tc.network, tc.address)
		if tc.permitted && err != nil || !tc.permitted && err != ErrRefused {
			t.Errorf("%s %s: got %v, permitted %t", tc.network, tc.address, err, tc.permitted)
		}
	}
	u := itemDialer(t, 53, "udp", "fd00::/8")
	if err := step(u, "udp6", "[fd00::1]:53"); err != nil {
		t.Errorf("udp item: %v", err)
	}
	if err := step(u, "tcp6", "[fd00::1]:53"); err != ErrRefused {
		t.Errorf("udp item on tcp: %v", err)
	}
}

func TestTS26ItemControlNeverListWins(t *testing.T) {
	for _, tc := range []struct{ entry, address string }{
		{"100.64.0.0/10", "100.100.100.200:443"},
		{"100.100.100.200", "100.100.100.200:443"},
		{"fd00::/8", "[fd00:ec2::254]:443"},
		{"fc00::/7", "[fd00:ec2::254]:443"},
		{"fd00:ec2::254", "[fd00:ec2::254]:443"},
		{"100.64.0.0/10", "[::ffff:100.100.100.200]:443"},
		{"fc00::/7", "[::ffff:a9fe:a9fe]:443"},
	} {
		d := itemDialer(t, 443, "tcp", tc.entry)
		network := "tcp6"
		if !strings.Contains(tc.address, "[") {
			network = "tcp4"
		}
		if err := step(d, network, tc.address); err != ErrRefused {
			t.Errorf("entry %s, %s: got %v", tc.entry, tc.address, err)
		}
	}
	// No private class holds these, so the rule alone refuses them. The
	// item dialer must keep that.
	d := itemDialer(t, 443, "tcp", "10.0.0.0/8")
	for _, a := range []string{
		"169.254.169.254:443", "127.0.0.1:443", "[::1]:443", "[fe80::1]:443",
		"224.0.0.1:443", "[ff02::1]:443", "0.0.0.0:443", "[::]:443",
	} {
		network := "tcp6"
		if !strings.Contains(a, "[") {
			network = "tcp4"
		}
		if err := step(d, network, a); err != ErrRefused {
			t.Errorf("%s: got %v", a, err)
		}
	}
}

func TestTS26ItemControlMappedAndZone(t *testing.T) {
	d := itemDialer(t, 443, "tcp", "10.0.0.0/8", "fd00::/8")
	if err := step(d, "tcp6", "[::ffff:10.1.2.3]:443"); err != nil {
		t.Errorf("mapped listed address: %v", err)
	}
	for _, a := range []string{
		"[fd00::1%eth0]:443", "[::ffff:10.1.2.3%eth0]:443",
		"[::ffff:100.100.100.200%eth0]:443", "[2606:4700::1111%eth0]:443",
	} {
		if err := step(d, "tcp6", a); err != ErrRefused {
			t.Errorf("%s: got %v", a, err)
		}
	}
	if err := step(d, "tcp6", "[fd00::1]:443"); err != nil {
		t.Errorf("listed IPv6 address: %v", err)
	}
}

func TestTS26ItemWithoutListRefusesPrivate(t *testing.T) {
	d := itemDialer(t, 443, "tcp")
	for _, a := range []string{
		"10.1.2.3:443", "172.16.0.1:443", "192.168.1.1:443",
		"100.64.0.1:443", "[fd00::1]:443", "[::ffff:10.1.2.3]:443",
	} {
		network := "tcp6"
		if !strings.Contains(a, "[") {
			network = "tcp4"
		}
		if err := step(d, network, a); err != ErrRefused {
			t.Errorf("%s: got %v", a, err)
		}
	}
}

func TestTS26ItemListIsPartOfOneDialer(t *testing.T) {
	a := itemDialer(t, 443, "tcp", "10.0.0.0/8")
	b := itemDialer(t, 443, "tcp", "192.168.0.0/16")
	if err := step(b, "tcp4", "10.1.2.3:443"); err != ErrRefused {
		t.Errorf("second item: got %v", err)
	}
	if err := step(a, "tcp4", "192.168.1.1:443"); err != ErrRefused {
		t.Errorf("first item: got %v", err)
	}
	if err := step(Dialer(time.Second), "tcp4", "10.1.2.3:443"); err != ErrRefused {
		t.Errorf("Dialer: got %v", err)
	}
	if err := step(a, "tcp4", "10.1.2.3:443"); err != nil {
		t.Errorf("first item, own address: %v", err)
	}
}

func TestTS26ItemDialerKeepsACopy(t *testing.T) {
	list := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	d, err := ItemDialer(list, 443, "tcp", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	list[0] = netip.MustParsePrefix("192.168.0.0/16")
	if err := step(d, "tcp4", "10.1.2.3:443"); err != nil {
		t.Errorf("after a change of the caller list: %v", err)
	}
}

func TestTS26ItemDialerRefusesBadInput(t *testing.T) {
	ok := netip.MustParsePrefix("10.0.0.0/8")
	for name, tc := range map[string]struct {
		list  []netip.Prefix
		port  uint16
		proto string
		err   error
	}{
		"port 0":         {[]netip.Prefix{ok}, 0, "tcp", errItemInput},
		"protocol":       {[]netip.Prefix{ok}, 443, "sctp", errItemInput},
		"empty protocol": {[]netip.Prefix{ok}, 443, "", errItemInput},
		"network name":   {[]netip.Prefix{ok}, 443, "tcp4", errItemInput},
		"everything":     {[]netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}, 443, "tcp", errEntryClass},
		"wide class":     {[]netip.Prefix{netip.MustParsePrefix("10.0.0.0/7")}, 443, "tcp", errEntryClass},
		"host bits":      {[]netip.Prefix{ok, netip.MustParsePrefix("10.0.0.1/8")}, 443, "tcp", errEntryHostBits},
		"mapped":         {[]netip.Prefix{netip.MustParsePrefix("::ffff:10.0.0.0/104")}, 443, "tcp", errEntryMapped},
		"zero prefix":    {[]netip.Prefix{{}}, 443, "tcp", errEntryParse},
	} {
		d, err := ItemDialer(tc.list, tc.port, tc.proto, time.Second)
		if !errors.Is(err, tc.err) || d != nil {
			t.Errorf("%s: got %v and %v", name, d, err)
		}
	}
}
