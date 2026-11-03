package session

import (
	"encoding/hex"
	"net/netip"
	"regexp"
	"strings"
	"testing"
	"time"
)

const ja4 = "t13d1516h2_8daaf6152771_b186095e22b6"

// seqKey is the key with the bytes 0x00, 0x01, ..., 0x1f.
func seqKey() Key {
	s := &state{date: "2026-03-01"}
	for i := range s.key {
		s.key[i] = byte(i)
	}
	return keyOf(s)
}

func idHex(t *testing.T, id *string) string {
	t.Helper()
	if id == nil {
		t.Fatal("no id")
	}
	b, err := sessionEncoding.DecodeString(strings.ToUpper(*id))
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

// T-U-24: known answers from an HMAC-SHA256 tool outside Go.
func TestTU24KnownAnswers(t *testing.T) {
	k := seqKey()
	for _, c := range []struct{ ip, ja4, want string }{
		{"198.51.100.23", ja4, "9f5eae7d953e15154ade0a558546405d"},
		{"2001:db8:abcd:1234::1", "", "2476f3bc714f2f5606deac0d6d26b5e1"},
		{"198.51.100.23", "", "ef9adff2fbaba4068b3beb5d3e73a89a"},
	} {
		if got := idHex(t, k.SessionID(c.ip, c.ja4)); got != c.want {
			t.Errorf("SessionID(%q, %q) = %s, want %s", c.ip, c.ja4, got, c.want)
		}
	}
	for _, c := range []struct{ ip, want string }{
		{"2001:db8:abcd:1234::", "4ff51d11fd449b46527592dcdb030e5da99d8d10a889ab725754c2631720d5b8"},
		{"198.51.100.23", "55f9a91f887826a0569aa50da3f71a541c542da9a3d4441ad0eca0a921d9b312"},
	} {
		if got := k.IPHMAC(netip.MustParseAddr(c.ip)); got != c.want {
			t.Errorf("IPHMAC(%q) = %s, want %s", c.ip, got, c.want)
		}
	}
}

// T-U-24: the vectors of the store tests. A mapped IPv4 address has the id of
// its IPv4 form. Two IPv6 addresses in one /64 have one id.
func TestTU24SessionIDVectors(t *testing.T) {
	k := NewDayKey().At(at(t, "2026-03-01T10:00:00Z"))
	shape := regexp.MustCompile(`^[a-z2-7]{26}$`)
	id := func(ip, j string) string {
		t.Helper()
		s := k.SessionID(ip, j)
		if s == nil {
			t.Fatalf("no id for %q", ip)
		}
		if !shape.MatchString(*s) {
			t.Errorf("id %q is not 26 lower-case base32 characters", *s)
		}
		return *s
	}
	v4, mapped := id("198.51.100.23", ja4), id("::ffff:198.51.100.23", ja4)
	v6a, v6b := id("2001:db8:abcd:1234::1", ja4), id("2001:db8:abcd:1234:ffff::9", ja4)
	if v4 != mapped {
		t.Error("a mapped IPv4 address has another id")
	}
	if v6a != v6b {
		t.Error("two addresses of one /64 have two ids")
	}
	if v4 == v6a {
		t.Error("an IPv4 key and an IPv6 key have one id")
	}
	if id("198.51.100.23", "") == v4 {
		t.Error("the JA4 text does not change the id")
	}
	if id("fe80::1%eth0", "") != id("fe80::1", "") {
		t.Error("the zone changes the id")
	}
}

// T-U-24: the id differs from the first 16 bytes of ip_hmac of the same key,
// also with an empty JA4. A bad or empty address has no id.
func TestTU24SessionIDDiffersFromIPHMAC(t *testing.T) {
	k := NewDayKey().At(at(t, "2026-03-01T10:00:00Z"))
	const ip = "192.0.2.77"
	got, err := hex.DecodeString(k.IPHMAC(netip.MustParseAddr(ip)))
	if err != nil || len(got) != 32 {
		t.Fatalf("ip_hmac is not 32 bytes of hex: %v", err)
	}
	if a, b := idHex(t, k.SessionID(ip, "")), hex.EncodeToString(got[:16]); a == b {
		t.Error("the id equals the first 16 bytes of ip_hmac")
	}
	for _, bad := range []string{"", "not an ip", "198.51.100.23\n"} {
		if k.SessionID(bad, ja4) != nil {
			t.Errorf("an id for %q", bad)
		}
	}
}

func BenchmarkSessionID(b *testing.B) {
	k := seqKey()
	b.ReportAllocs()
	for b.Loop() {
		_ = k.SessionID("198.51.100.23", ja4)
	}
}

func BenchmarkAt(b *testing.B) {
	d := NewDayKey()
	when := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	d.At(when)
	b.ReportAllocs()
	for b.Loop() {
		_ = d.At(when)
	}
}

func BenchmarkIPHMAC(b *testing.B) {
	k := seqKey()
	a := netip.MustParseAddr("2001:db8:abcd:1234::")
	b.ReportAllocs()
	for b.Loop() {
		_ = k.IPHMAC(a)
	}
}
