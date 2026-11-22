package session

import (
	"encoding/hex"
	"net/netip"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/cybagard/cyba-phantom/internal/event"
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
		{"198.51.100.23", ja4, "fb93b50613e54015f5ffa1a7aec6f158"},
		{"2001:db8:abcd:1234::1", "", "e2ac800c9eb321d4f59acb734c16e991"},
		{"198.51.100.23", "", "79218a485663e84422081e7d9ff4e964"},
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

// T-S-22: the session id input has the key length byte. Without it, two inputs
// are equal bytes. One is the IPv4 key 32.1.13.184 and a JA4 text of 12 NUL
// bytes and "x". The other is the IPv6 key 2001:db8:: and the JA4 text "x".
func TestTS22SessionIDKeyLengthByte(t *testing.T) {
	k := seqKey()
	v4, v6 := "32.1.13.184", "2001:db8::1"
	ja4v4, ja4v6 := strings.Repeat("\x00", 12)+"x", "x"
	flat := func(ip, j string) string {
		c, ok := event.CounterKey(netip.MustParseAddr(ip))
		if !ok {
			t.Fatalf("no counter key for %q", ip)
		}
		return sessionPrefix + "\x00" + string(c.AsSlice()) + j
	}
	if flat(v4, ja4v4) != flat(v6, ja4v6) {
		t.Fatal("the two inputs without the length byte are not equal bytes")
	}
	a, b := idHex(t, k.SessionID(v4, ja4v4)), idHex(t, k.SessionID(v6, ja4v6))
	if a == b {
		t.Errorf("one id %s for an IPv4 key and an IPv6 key", a)
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
