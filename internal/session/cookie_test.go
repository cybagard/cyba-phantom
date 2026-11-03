package session

import (
	"net/http"
	"strings"
	"testing"
)

// testID is the id with the bytes 0x00, 0x01, ..., 0x0f.
func testID() [idLen]byte {
	var id [idLen]byte
	for i := range id {
		id[i] = byte(i)
	}
	return id
}

// Known answer from openssl and Python, with seqKey and testID.
const (
	knownValue = "aaaqeayeaudaocajbifqydiob5e62j77n4ppjuwk3e"
	knownID    = "aaaqeayeaudaocajbifqydiob4"
)

func hdr(lines ...string) http.Header {
	return http.Header{"Cookie": lines}
}

// T-U-24: round trip, and the known answer.
func TestTU24RoundTrip(t *testing.T) {
	k := seqKey()
	v := k.CookieValue(testID())
	if v != knownValue {
		t.Fatalf("CookieValue = %q, want %q", v, knownValue)
	}
	got, ok := k.CheckCookie(v)
	if !ok || got != knownID {
		t.Fatalf("CheckCookie = %q, %v, want %q", got, ok, knownID)
	}
	// The id text is the form that SessionID gives.
	k2 := NewDayKey().At(at(t, "2026-03-01T10:00:00Z"))
	want := k2.SessionID("198.51.100.23", ja4)
	var id [idLen]byte
	b, err := sessionEncoding.DecodeString(strings.ToUpper(*want))
	if err != nil {
		t.Fatal(err)
	}
	copy(id[:], b)
	got, ok = k2.CheckCookie(k2.CookieValue(id))
	if !ok || got != *want {
		t.Errorf("round trip = %q, %v, want %q", got, ok, *want)
	}
}

// T-U-24: each 1-bit flip of each of the 42 bytes is refused.
func TestTU24BitFlips(t *testing.T) {
	k := seqKey()
	v := []byte(k.CookieValue(testID()))
	for i := range v {
		for bit := 0; bit < 8; bit++ {
			m := append([]byte(nil), v...)
			m[i] ^= 1 << bit
			if _, ok := k.CheckCookie(string(m)); ok {
				t.Errorf("flip of bit %d of byte %d accepted", bit, i)
			}
		}
	}
}

// T-U-24: the last character has 2 low bits that a decoder ignores. A value
// whose last character differs there must be refused.
func TestTU24LastCharacterBits(t *testing.T) {
	k := seqKey()
	v := k.CookieValue(testID())
	if v[41] != 'e' {
		t.Fatalf("last character %q, test needs e", v[41])
	}
	for _, c := range []string{"f", "g", "h"} {
		if _, ok := k.CheckCookie(v[:41] + c); ok {
			t.Errorf("last character %q accepted", c)
		}
	}
}

// T-U-24: the other refusals.
func TestTU24Refused(t *testing.T) {
	k := seqKey()
	v := k.CookieValue(testID())
	other := NewDayKey().At(at(t, "2026-03-01T10:00:00Z"))
	cases := map[string]string{
		"upper case":    strings.ToUpper(v),
		"41 bytes":      v[:41],
		"43 bytes":      v + "a",
		"empty":         "",
		"equals inside": v[:10] + "=" + v[11:],
		"equals at 43":  v + "=",
		"byte 0x80":     v[:10] + "\x80" + v[11:],
		"byte 0xff":     v[:10] + "\xff" + v[11:],
		"newline":       v[:10] + "\n" + v[11:],
		"newline at 43": v + "\n",
		"quoted":        `"` + v + `"`,
		"quote inside":  v[:10] + `"` + v[11:],
		"digit 1":       v[:10] + "1" + v[11:],
		"another key":   other.CookieValue(testID()),
	}
	for name, c := range cases {
		if _, ok := k.CheckCookie(c); ok {
			t.Errorf("%s: accepted", name)
		}
		if name == "another key" {
			continue
		}
		if _, ok := CookieFromHeader(hdr("sid=" + c)); ok {
			t.Errorf("%s: parse accepted", name)
		}
	}
	// The value of the other key is well formed, so the parse takes it.
	if _, ok := CookieFromHeader(hdr("sid=" + cases["another key"])); !ok {
		t.Error("parse refused a well formed value")
	}
}

// T-U-24: the zero Key makes no value and accepts no value.
func TestTU24ZeroKey(t *testing.T) {
	var z Key
	if v := z.CookieValue(testID()); v != "" {
		t.Errorf("zero Key made %q", v)
	}
	if _, ok := z.CheckCookie(knownValue); ok {
		t.Error("zero Key accepted a value")
	}
}

// T-S-31: exactly one part with the name gives the value.
func TestTS31Parse(t *testing.T) {
	v := knownValue
	bad := "sid=x"
	cases := []struct {
		name  string
		lines []string
		ok    bool
	}{
		{"one", []string{"sid=" + v}, true},
		{"others around", []string{"a=b; sid=" + v + "; c=d"}, true},
		{"other lines", []string{"a=b", "sid=" + v, "c=d"}, true},
		{"space and tab", []string{" \t sid=" + v + " \t ;a=b"}, true},
		{"tab only", []string{"a=b;\tsid=" + v + "\t"}, true},
		{"no header", nil, false},
		{"no part with the name", []string{"a=b; c=d"}, false},
		{"empty line", []string{""}, false},
		{"upper name", []string{"SID=" + v}, false},
		{"space before equals", []string{"sid =" + v}, false},
		{"name prefix", []string{"sid2=" + v, "xsid=" + v}, false},
		{"no equals", []string{"sid"}, false},
		{"empty value", []string{"sid="}, false},
		{"quoted", []string{`sid="` + v + `"`}, false},
		{"two in a line", []string{"sid=" + v + "; sid=" + v}, false},
		{"valid then bad", []string{"sid=" + v + "; " + bad}, false},
		{"bad then valid", []string{bad + "; sid=" + v}, false},
		{"two lines", []string{"sid=" + v, "sid=" + v}, false},
		{"two lines, one bad", []string{"sid=" + v, bad}, false},
		{"CR at the end", []string{"sid=" + v + "\r"}, false},
		{"value with a second equals", []string{"sid=" + v + "="}, false},
		{"empty parts", []string{";;sid=" + v + ";;"}, true},
	}
	for _, c := range cases {
		got, ok := CookieFromHeader(hdr(c.lines...))
		if ok != c.ok || (ok && got != v) {
			t.Errorf("%s: got %q, %v, want ok %v", c.name, got, ok, c.ok)
		}
	}
}

func oneHeader() http.Header { return hdr("sid=" + knownValue) }

func manyHeader() http.Header {
	var b strings.Builder
	for i := 0; i < 39; i++ {
		b.WriteString("c")
		b.WriteString(string(rune('a' + i%26)))
		b.WriteString("=v; ")
	}
	b.WriteString("sid=" + knownValue)
	return hdr(b.String())
}

func floodHeader() http.Header {
	return hdr(strings.Repeat("sid=x; ", 2998) + "sid=x")
}

// T-S-31: the parse allocates nothing.
func TestTS31NoAllocations(t *testing.T) {
	for _, c := range []struct {
		name string
		h    http.Header
		ok   bool
	}{
		{"1 cookie", oneHeader(), true},
		{"40 cookies", manyHeader(), true},
		{"2999 parts with the name", floodHeader(), false},
	} {
		if _, ok := CookieFromHeader(c.h); ok != c.ok {
			t.Errorf("%s: ok = %v, want %v", c.name, ok, c.ok)
		}
		n := testing.AllocsPerRun(100, func() { CookieFromHeader(c.h) })
		if n != 0 {
			t.Errorf("%s: %v allocations, want 0", c.name, n)
		}
	}
}

var benchHeaders = []struct {
	name string
	h    func() http.Header
}{
	{"1", oneHeader},
	{"40", manyHeader},
	{"2999", floodHeader},
}

func BenchmarkCookieFromHeader(b *testing.B) {
	for _, c := range benchHeaders {
		h := c.h()
		b.Run(c.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				CookieFromHeader(h)
			}
		})
	}
}

// BenchmarkRequestCookie is the before line: the net/http parse.
func BenchmarkRequestCookie(b *testing.B) {
	for _, c := range benchHeaders {
		r := &http.Request{Header: c.h()}
		b.Run(c.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				r.Cookie("sid")
			}
		})
	}
}

func BenchmarkCheckCookie(b *testing.B) {
	k := seqKey()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		k.CheckCookie(knownValue)
	}
}
