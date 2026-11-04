package bait

import (
	"bufio"
	"fmt"
	"math/rand/v2"
	"net/http"
	"strings"
	"testing"

	"github.com/cybagard/cyba-phantom/internal/token"
)

// tokText is a candidate. The other texts are near misses.
const tokText = "abcdefghijklmnopqrstuvwxyz"

var nearMiss = map[string]string{
	"upper":    strings.ToUpper(tokText),
	"25 bytes": tokText[:25],
	"27 bytes": tokText + "a",
	"escaped":  "%61" + tokText[1:24],
	"digit 0":  tokText[:25] + "0",
	"empty":    "",
}

// TestTS32AlphabetTie ties the local alphabet to the token package. Each
// text of a token has only bytes of the set. All 32 bytes occur. Parse
// refuses a text with one byte outside the set.
func TestTS32AlphabetTie(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	seen := map[byte]bool{}
	for range 4000 {
		var tok [token.Size]byte
		for i := range tok {
			tok[i] = byte(rng.Uint32())
		}
		text := token.Text(tok)
		if !isCandidate(text) {
			t.Fatalf("token text %q is not a candidate", text)
		}
		for i := 0; i < len(text); i++ {
			seen[text[i]] = true
		}
	}
	if len(seen) != len(candidateAlphabet) {
		t.Errorf("%d bytes occur in token texts, set has %d", len(seen), len(candidateAlphabet))
	}
	text := token.Text([token.Size]byte{1, 2, 3})
	for b := 0; b < 256; b++ {
		if inAlphabet[b] {
			continue
		}
		for _, pos := range []int{0, 12, 25} {
			bad := text[:pos] + string([]byte{byte(b)}) + text[pos+1:]
			if _, ok := token.Parse(bad); ok {
				t.Fatalf("Parse accepts byte %#x at %d", b, pos)
			}
			if isCandidate(bad) {
				t.Fatalf("candidate accepts byte %#x at %d", b, pos)
			}
		}
	}
}

// TestTS32PathCandidate checks the segment after the route path.
func TestTS32PathCandidate(t *testing.T) {
	cases := []struct{ name, route, path, want string }{
		{"segment", "/api", "/api/" + tokText, tokText},
		{"deep route", "/a/b", "/a/b/" + tokText, tokText},
		{"root", "/", "/" + tokText, tokText},
		{"route path", "/api", "/api", ""},
		{"empty segment", "/api", "/api/", ""},
		{"two segments", "/api", "/api/" + tokText + "/x", ""},
		{"trailing slash", "/api", "/api/" + tokText + "/", ""},
		{"double slash", "/api", "/api//" + tokText, ""},
		{"longer route name", "/api", "/apix/" + tokText, ""},
		{"other route", "/api", "/other/" + tokText, ""},
		{"root path", "/", "/", ""},
		{"root two segments", "/", "/a/" + tokText, ""},
		{"above route", "/a/b", "/a/" + tokText, ""},
		{"escaped slash", "/api", "/api%2F" + tokText, ""},
	}
	for n, v := range nearMiss {
		cases = append(cases, struct{ name, route, path, want string }{n, "/api", "/api/" + v, ""})
	}
	for _, c := range cases {
		if got := PathCandidate(c.path, c.route); got != c.want {
			t.Errorf("%s: PathCandidate(%q, %q) = %q, want %q", c.name, c.path, c.route, got, c.want)
		}
	}
}

// TestTS32QueryCandidate checks the raw value of the one part with the name.
func TestTS32QueryCandidate(t *testing.T) {
	cases := []struct{ name, q, want string }{
		{"one part", "token=" + tokText, tokText},
		{"middle", "a=1&token=" + tokText + "&b=2", tokText},
		{"empty parts", "&&token=" + tokText + "&&", tokText},
		{"two parts", "token=" + tokText + "&token=" + tokText, ""},
		{"second empty", "token=" + tokText + "&token=", ""},
		{"second no equal", "token=" + tokText + "&token", ""},
		{"semicolon", "a=1;token=" + tokText, ""},
		{"semicolon after", "token=" + tokText + ";a=1", ""},
		{"case", "Token=" + tokText, ""},
		{"longer name", "tokenx=" + tokText, ""},
		{"name in value", "a=token=" + tokText, ""},
		{"two equal signs", "token==" + tokText, ""},
		{"no equal sign", "token", ""},
		{"empty query", "", ""},
	}
	for n, v := range nearMiss {
		cases = append(cases, struct{ name, q, want string }{n, "token=" + v, ""})
	}
	for _, c := range cases {
		if got := QueryCandidate(c.q, "token"); got != c.want {
			t.Errorf("%s: QueryCandidate(%q) = %q, want %q", c.name, c.q, got, c.want)
		}
	}
}

// queryForms are the hostile queries. The name is in the last part.
func queryForms() map[string]string {
	last := "token=" + tokText
	return map[string]string{
		"1 part":       last,
		"4000 pairs":   strings.Repeat("a=b&", 4000) + last,
		"10001 pairs":  strings.Repeat("a&", 10000) + last,
		"two names":    strings.Repeat("a=b&", 4000) + last + "&" + last,
		"long semicol": strings.Repeat("a=b;", 4000) + last,
	}
}

// TestTS32QueryNoAllocs checks that the query scan does not allocate.
func TestTS32QueryNoAllocs(t *testing.T) {
	for name, q := range queryForms() {
		want := tokText
		if strings.HasPrefix(name, "two") || strings.HasPrefix(name, "long") {
			want = ""
		}
		if got := QueryCandidate(q, "token"); got != want {
			t.Errorf("%s: candidate %q, want %q", name, got, want)
		}
		if n := testing.AllocsPerRun(1000, func() { _ = QueryCandidate(q, "token") }); n != 0 {
			t.Errorf("%s: %v allocations", name, n)
		}
	}
	for name, p := range map[string]string{"path": "/api/" + tokText, "none": "/api/x/y"} {
		if n := testing.AllocsPerRun(1000, func() { _ = PathCandidate(p, "/api") }); n != 0 {
			t.Errorf("%s: %v allocations", name, n)
		}
	}
}

// parseRequest parses the raw head with net/http, as the server does.
func parseRequest(tb testing.TB, head string) *http.Request {
	tb.Helper()
	r, err := http.ReadRequest(bufio.NewReader(strings.NewReader(head)))
	if err != nil {
		tb.Fatal(err)
	}
	return r
}

// TestTS32HeaderCandidate checks the header value after a real request parse.
func TestTS32HeaderCandidate(t *testing.T) {
	canon := HeaderName("x-request-token")
	if canon != "X-Request-Token" {
		t.Fatalf("HeaderName = %q", canon)
	}
	cases := []struct{ name, lines, want string }{
		{"one line", "X-Request-Token: " + tokText, tokText},
		{"lower case name", "x-request-token: " + tokText, tokText},
		{"spaces around", "X-Request-Token:   " + tokText + " \t ", tokText},
		{"two lines", "X-Request-Token: " + tokText + "\r\nx-request-token: " + tokText, ""},
		{"second line empty", "X-Request-Token: " + tokText + "\r\nX-Request-Token:", ""},
		{"other name", "X-Request-Tokens: " + tokText, ""},
		{"absent", "X-Other: 1", ""},
	}
	for n, v := range nearMiss {
		cases = append(cases, struct{ name, lines, want string }{n, "X-Request-Token: " + v, ""})
	}
	for _, c := range cases {
		r := parseRequest(t, "GET / HTTP/1.1\r\nHost: x\r\n"+c.lines+"\r\n\r\n")
		if got := HeaderCandidate(r.Header, canon); got != c.want {
			t.Errorf("%s: HeaderCandidate = %q, want %q", c.name, got, c.want)
		}
	}
}

// TestTS32HeaderNoAllocs checks the read of a request with 64 headers.
func TestTS32HeaderNoAllocs(t *testing.T) {
	var b strings.Builder
	b.WriteString("GET / HTTP/1.1\r\nHost: x\r\n")
	for i := 0; i < 62; i++ {
		fmt.Fprintf(&b, "X-H%d: v\r\n", i)
	}
	b.WriteString("X-Request-Token: " + tokText + "\r\n\r\n")
	r := parseRequest(t, b.String())
	if len(r.Header) != 63 {
		t.Fatalf("%d header names", len(r.Header))
	}
	canon := HeaderName("X-REQUEST-TOKEN")
	if got := HeaderCandidate(r.Header, canon); got != tokText {
		t.Fatalf("candidate %q", got)
	}
	if n := testing.AllocsPerRun(1000, func() { _ = HeaderCandidate(r.Header, canon) }); n != 0 {
		t.Errorf("%v allocations", n)
	}
}

// BenchmarkQueryCandidate scans a query of 16 KB.
func BenchmarkQueryCandidate(b *testing.B) {
	q := queryForms()["4000 pairs"]
	b.ReportAllocs()
	for b.Loop() {
		_ = QueryCandidate(q, "token")
	}
}
