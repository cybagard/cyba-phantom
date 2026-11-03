package event

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"fmt"
	"maps"
	"math"
	"math/rand/v2"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// largestRecord is the length of the largest canonical record, as measured by
// TestTS12_LargestEvent. That test builds the record.
const largestRecord = 11428

func sp(s string) *string { return &s }

func fixedClock(ms int64) Clock { return func() time.Time { return time.UnixMilli(ms) } }

func mustEvent(t *testing.T, in Input) *Event {
	t.Helper()
	e, err := NewEvent(fixedClock(1758300000123), in)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// T-U-06: the pinned vectors give the exact bytes and hash, also from a
// stored row.
func TestTU06_RecordVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/events.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Name      string `json:"name"`
		Row       Row    `json:"row"`
		Canonical string `json:"canonical"`
		SHA256    string `json:"sha256"`
	}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		r, err := RecordFromRow(c.Row)
		if err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		b, err := EvidenceBytes(r)
		sum := sha256.Sum256([]byte(c.Canonical))
		h, herr := HashEvidence(r)
		if err != nil || herr != nil || string(b) != c.Canonical || hex.EncodeToString(sum[:]) != c.SHA256 || h != sum {
			t.Errorf("%s: bytes %s, errors %v, %v, hash %x", c.Name, b, err, herr, h)
		}
	}
}

// T-U-06: a field without a value is not in the record, and a system kind has
// no session.
func TestTU06_AbsentFields(t *testing.T) {
	for _, k := range allKinds {
		in := Input{Kind: k, Session: "s-1", Vhost: "h", Path: "/\xff"}
		e, err := NewEvent(fixedClock(5), in)
		if k.isSystem() {
			if err == nil {
				t.Errorf("%v: a session is accepted", k)
			}
			in.Session = ""
			e = mustEvent(t, in)
		} else if err != nil {
			t.Fatal(err)
		}
		b, err := e.record.canonical()
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(b, []byte("null")) || bytes.Contains(b, []byte(`""`)) {
			t.Errorf("%v: null or empty string in %s", k, b)
		}
		if has := bytes.Contains(b, []byte(`"session"`)); has == k.isSystem() {
			t.Errorf("%v: session presence is %v in %s", k, has, b)
		}
		for _, m := range []string{"method", "status", "trap_id", "token_id", "surface", "fp", "detail"} {
			if bytes.Contains(b, []byte(`"`+m+`"`)) {
				t.Errorf("%v: absent %s is in %s", k, m, b)
			}
		}
	}
	// A hand-built record is checked as well.
	for _, r := range []Record{
		{TS: 1, Kind: KindCallback, Path: sp("")},
		{TS: 1, Kind: KindCallback, FP: &FP{}},
		{TS: 1, Kind: KindRetention, Session: sp("s")},
		{TS: 1, Kind: KindCallback, Path: sp("\xff")},
		{TS: 1, Kind: KindCallback, Surface: new(Surface)},
	} {
		if _, err := HashEvidence(r); err == nil {
			t.Errorf("record %+v is accepted", r)
		}
	}
	// A status of 0 is a value and stays in the record.
	zero := int64(0)
	if b, _ := (Record{TS: 1, Kind: KindCallback, Status: &zero}).canonical(); !bytes.Contains(b, []byte(`"status":0`)) {
		t.Errorf("status 0 is lost: %s", b)
	}
}

// T-U-06: the same record gives the same bytes and hash for any field order,
// detail insertion order and member order of the source JSON.
func TestTU06_InsertionOrder(t *testing.T) {
	st := int64(200)
	surf := SurfaceQuery
	var want []byte
	for i := 0; i < 20; i++ {
		d := Detail{}
		names := []string{"n", "a", "z", "m", "b"}
		rand.Shuffle(len(names), func(i, j int) { names[i], names[j] = names[j], names[i] })
		for _, n := range names {
			d[n] = Int(int64(len(n)) + 7)
		}
		var r Record
		if i%2 == 0 {
			r = Record{TS: 9, Kind: KindScoreChange, Session: sp("s"), Status: &st, Surface: &surf,
				FP: &FP{Hdr: sp("c"), JA4: sp("a"), H2: sp("b")}, Detail: d, Path: sp("/p"), Vhost: sp("v")}
		} else {
			r = Record{Vhost: sp("v"), Path: sp("/p"), Detail: d, FP: &FP{JA4: sp("a"), H2: sp("b"), Hdr: sp("c")},
				Surface: &surf, Status: &st, Session: sp("s"), Kind: KindScoreChange, TS: 9}
		}
		b, err := EvidenceBytes(r)
		if err != nil {
			t.Fatal(err)
		}
		if want == nil {
			want = b
		}
		if !bytes.Equal(b, want) {
			t.Fatalf("bytes differ: %s and %s", b, want)
		}
	}
	for _, src := range []string{
		`{"v":1,"ts":9,"session":"s","kind":"score_change","vhost":"v","path":"/p","status":200,"surface":"query","fp":{"hdr":"c","h2":"b","ja4":"a"},"detail":{"z":8,"a":8,"b":8,"m":8,"n":8}}`,
		`{"detail":{"n":8,"m":8,"b":8,"a":8,"z":8},"fp":{"ja4":"a","h2":"b","hdr":"c"},"surface":"query","status":200,"path":"/p","vhost":"v","kind":"score_change","session":"s","ts":9,"v":1}`,
	} {
		if b, err := Canonical([]byte(src)); err != nil || !bytes.Equal(b, want) {
			t.Errorf("permuted JSON gives %s, %v", b, err)
		}
	}
}

// T-U-06: a record rebuilt from the stored values of the event gives the same
// hash as the record of the constructor.
func TestTU06_StoredRowRebuild(t *testing.T) {
	st := int64(404)
	for _, k := range []Kind{KindCallback, KindAlertSent, KindBundleRejected} {
		in := Input{Kind: k, Vhost: "decoy.\xffexample", Method: "GET", Path: "/a\xc3(b", Status: &st, TrapID: "t",
			TokenID: "k", Surface: SurfaceHeader, JA4: "j", Detail: Detail{"b": Bool(true), "n": Int(-5), "s": Str("é<>&\U00002028")}}
		if !k.isSystem() {
			in.Session = "s-9"
		}
		e := mustEvent(t, in)
		rec := e.Record()
		dj, err := rec.Detail.JSON()
		if err != nil {
			t.Fatal(err)
		}
		row := Row{TS: rec.TS, SessionID: rec.Session, Kind: k.String(), Vhost: rec.Vhost,
			Method: rec.Method, Path: rec.Path, Status: rec.Status, TrapID: rec.TrapID,
			TokenID: rec.TokenID, Surface: rec.Surface, FP: rec.FP, Detail: sp(string(dj))}
		back, err := RecordFromRow(row)
		if err != nil {
			t.Fatal(err)
		}
		h1, err1 := HashEvidence(rec)
		h2, err2 := HashEvidence(back)
		if err1 != nil || err2 != nil || h1 != h2 {
			t.Errorf("%v: hashes %x and %x, errors %v, %v", k, h1, h2, err1, err2)
		}
	}
	if _, err := RecordFromRow(Row{Kind: "Callback"}); err == nil {
		t.Error("a row with an unknown kind is accepted")
	}
}

// T-S-12: construction makes request-derived strings valid and cuts them at a
// character boundary; one value goes to the DB row and the record; ts comes
// from the sensor clock.
func TestTS12_StringConstruction(t *testing.T) {
	if got := *text("a\xff\xc3(\xed\xa0\x80z", 99, false); got != "a%FF%C3(%ED%A0%80z" {
		t.Errorf("escape: %q", got)
	}
	if got := *text("é€😀", 4, false); got != "é" { // the cut is inside €
		t.Errorf("cut: %q", got)
	}
	if got := *text("é€😀", 5, false); got != "é€" {
		t.Errorf("cut: %q", got)
	}
	if text("", 5, false) != nil {
		t.Error("an empty string is not absent")
	}
	caps := map[string]int{"vhost": capVhost, "method": capMethod, "path": capPath, "id": capID, "fp": capFP}
	long := strings.Repeat("\xff", 5000)
	for name, c := range caps {
		got := *text(long, c, false)
		if len(got) > c || len(got) < c-2 || !strings.HasPrefix(got, "%FF") {
			t.Errorf("%s: length %d", name, len(got))
		}
	}
	long = strings.Repeat("😀", 5000)
	for name, c := range caps {
		if got := *text(long, c, false); len(got) != c/4*4 {
			t.Errorf("%s: length %d", name, len(got))
		}
	}
	e := mustEvent(t, Input{Kind: KindRequest, Vhost: long, Path: long, Surface: SurfaceBody, JA4: long})
	if rec := e.Record(); len(*rec.Vhost) != 252 || len(*rec.Path) != 2048 || len(*rec.FP.JA4) != 128 {
		t.Error("caps are not applied in the constructor")
	}
	if ts := e.Record().TS; ts != 1758300000123 {
		t.Errorf("ts %d is not from the clock", ts)
	}
	if e, err := NewEvent(nil, Input{Kind: KindRequest}); err != nil || e.Record().TS < 1e12 {
		t.Errorf("nil clock does not use the time of the sensor: %v", err)
	}
	if _, err := NewEvent(nil, Input{Kind: KindRequest, Surface: "cookie"}); err == nil {
		t.Error("an unknown surface is accepted")
	}
	if _, err := NewEvent(nil, Input{Kind: 0}); err == nil {
		t.Error("an unknown kind is accepted")
	}
}

// T-U-21: RequestPath keeps each escape of the raw path with upper-case hex
// digits and never decodes it. A '%' that starts no escape gives %25, and so
// does each '%' of a path with no raw path.
func TestTU21RequestPath(t *testing.T) {
	for _, c := range []struct{ raw, path, want string }{
		{"/a%2Fb<c", "/a/b<c", "/a%2Fb%3Cc"},
		{"/a%0ab", "/a\nb", "/a%0Ab"},
		{"/a%7f", "/a\x7f", "/a%7F"},
		{"/%zz", "/%zz", "/%25zz"},
		{"/a%", "/a%", "/a%25"},
		{"/a%4", "/a%4", "/a%254"},
		{"", "/%41", "/%2541"},
		{"/%2541", "/%41", "/%2541"},
		{"", "*", "%2A"},
		{"", "", ""},
	} {
		if got := RequestPath(c.raw, c.path); got != c.want {
			t.Errorf("RequestPath(%q, %q) = %q, want %q", c.raw, c.path, got, c.want)
		}
	}
}

// T-U-21: after "/", each byte 0x00-0x1F, 0x7F and 0x80-0xFF gives %XX with
// upper-case hex. '/' is copied, '%' gives %25, and each other byte gives what
// url.PathEscape gives for that byte alone.
func TestTU21RequestPathEachByte(t *testing.T) {
	for c := range 256 {
		s := "/" + string([]byte{byte(c)})
		want := "/" + url.PathEscape(s[1:])
		switch c {
		case '/':
			want = "//"
		case '%':
			want = "/%25"
		}
		if got := RequestPath("", s); got != want {
			t.Errorf("byte %d: path gives %q, want %q", c, got, want)
		}
		if got := RequestPath(s, ""); got != want {
			t.Errorf("byte %d: raw path gives %q, want %q", c, got, want)
		}
	}
}

// T-U-21: a path over 2048 bytes is cut before the first token that does not
// fit. The code writes no later token, and the cut is never inside an escape.
func TestTU21RequestPathCut(t *testing.T) {
	for _, unit := range []string{"%2F", "<", "a"} {
		for pad := range 4 {
			raw := "/" + strings.Repeat("a", pad) + strings.Repeat(unit, 3000)
			got := RequestPath(raw, "")
			n := 1 + pad
			want := n + (capPath-n)/3*3
			if unit == "a" {
				want = capPath
			}
			if len(got) != want || len(got) < 2046 || strings.Contains(got[len(got)-2:], "%") {
				t.Errorf("unit %q, pad %d: length %d, want %d", unit, pad, len(got), want)
			}
		}
	}
	// The token "<" needs 3 bytes and does not fit. The later "b" would fit.
	long := "/" + strings.Repeat("a", 2046) + "<bb"
	if got := RequestPath("", long); len(got) != 2047 || strings.Contains(got, "%") {
		t.Errorf("length %d, want 2047 and no escape", len(got))
	}
}

// T-U-21: NewEvent writes each byte 0x00-0x1F and 0x7F of the path as %XX with
// upper-case hex. The cut never splits such an escape.
func TestTU21ConstructionEscapesControlBytes(t *testing.T) {
	path := func(s string) string { return *mustEvent(t, Input{Kind: KindRequest, Path: s}).Record().Path }
	for c := range 0x80 {
		want := "a" + string(rune(c)) + "b"
		if c < 0x20 || c == 0x7F {
			want = fmt.Sprintf("a%%%02Xb", c)
		}
		if got := path("a" + string(rune(c)) + "b"); got != want {
			t.Errorf("byte %d: stored %q, want %q", c, got, want)
		}
	}
	if got, want := path(strings.Repeat("a", 2046)+"\x01b"), strings.Repeat("a", 2046); got != want {
		t.Errorf("cut: stored %d bytes, want %d", len(got), len(want))
	}
	if got, want := path(strings.Repeat("\x01", 2100)), strings.Repeat("%01", 682); got != want {
		t.Errorf("long: stored %d bytes, want %d", len(got), len(want))
	}
}

// T-U-21: for any Path, the stored path has no control byte, has at most 2048
// bytes and is valid UTF-8. The row of the event is accepted.
func FuzzTU21Path(f *testing.F) {
	for _, s := range []string{"/a%2Fb%3Cc", "/a%0Ab", "/a%7F", "/%2541", "/é", "/a\x01b", "\x7f\xff",
		strings.Repeat("\x01", 2100), strings.Repeat("a", 2046) + "\x01b"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		rec := mustEvent(t, Input{Kind: KindRequest, Path: s}).Record()
		if rec.Path == nil {
			return
		}
		p := *rec.Path
		if len(p) > capPath || !utf8.ValidString(p) || strings.IndexFunc(p, func(r rune) bool { return r < 0x20 || r == 0x7F }) >= 0 {
			t.Errorf("stored path %q breaks a rule", p)
		}
		if _, err := RecordFromRow(Row{TS: rec.TS, Kind: rec.Kind.String(), Path: rec.Path}); err != nil {
			t.Errorf("RecordFromRow: %v", err)
		}
	})
}

// T-U-21: one url.PathUnescape of the stored value gives the decoded request
// path, also when the cut shortens the value.
func TestTU21PathDecodes(t *testing.T) {
	for _, c := range []struct{ raw, path, want string }{
		{"/a%2Fb<c", "/a/b<c", "/a/b<c"},
		{"/a%0ab", "/a\nb", "/a\nb"},
		{"/a%7f", "/a\x7f", "/a\x7f"},
		{"/%zz", "/%zz", "/%zz"},
		{"/a%", "/a%", "/a%"},
		{"", "/%41", "/%41"},
		{"/%2541", "/%41", "/%41"},
		{"/\xc3\xa9", "/é", "/é"},
	} {
		stored := *mustEvent(t, Input{Kind: KindRequest, Path: RequestPath(c.raw, c.path)}).Record().Path
		if got, err := url.PathUnescape(stored); err != nil || got != c.want {
			t.Errorf("%q: decode of %q gives %q, %v, want %q", c.raw, stored, got, err, c.want)
		}
	}
	stored := *mustEvent(t, Input{Kind: KindRequest, Path: RequestPath("/"+strings.Repeat("%2F", 1000), "")}).Record().Path
	if got, err := url.PathUnescape(stored); err != nil || got != strings.Repeat("/", 683) {
		t.Errorf("cut value: decode gives %d bytes, %v", len(got), err)
	}
}

// T-S-12: no form of an IP or ip_hmac marker given as client address,
// forwarded value or body prefix is in the canonical bytes, for each kind. An
// ip_hmac is not an address, so the constructor refuses it as a client address.
func TestTS12_IPMarkers(t *testing.T) {
	const hmac = "9f2c4a7be1d3058c6a1f77aa"
	addrs := []string{"203.0.113.7", "2001:db8::7", "::ffff:203.0.113.7"}
	forms := append([]string{"2001:0db8:0000:0000:0000:0000:0000:0007", "::ffff:cb00:7107", "cb007107", hmac}, addrs...)
	all := strings.Join(forms, ", ")
	for _, k := range allKinds {
		inputs := []Input{{Forwarded: all, BodyPrefix: []byte(all)}}
		for _, a := range addrs {
			inputs = append(inputs, Input{ClientIP: a, Forwarded: "for=" + all, BodyPrefix: []byte(all)})
		}
		for _, in := range inputs {
			in.Kind, in.Vhost, in.Detail = k, "decoy.example", Detail{"n": Int(1)}
			e, err := NewEvent(fixedClock(1758300000123), in)
			if err != nil {
				t.Fatal(err)
			}
			b, err := e.record.canonical()
			if err != nil {
				t.Fatal(err)
			}
			if in.ClientIP != "" && e.IP() == "" {
				t.Errorf("%v: the address is not in the DB part", k)
			}
			for _, f := range forms {
				if bytes.Contains(bytes.ToLower(b), []byte(strings.ToLower(f))) {
					t.Errorf("%v: %q is in %s", k, f, b)
				}
			}
		}
		if _, err := NewEvent(nil, Input{Kind: k, ClientIP: hmac}); err == nil {
			t.Errorf("%v: an ip_hmac is accepted as client address", k)
		}
	}
}

// T-S-12: text in the request-content fields and in a Detail string is copied
// as given, after repair and cut. It is request content, not the connection
// address, so it is hashed by design. The producer owns that rule.
func TestTS12_RequestContentCopied(t *testing.T) {
	const m = "203.0.113.7"
	e := mustEvent(t, Input{Kind: KindCallback, Session: m, Vhost: m, Method: m, Path: "/" + m, TrapID: m,
		TokenID: m, JA4: m, H2: m, Hdr: m, Detail: Detail{"src": Str(m)}})
	b, err := e.record.canonical()
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(b), m); n != 10 {
		t.Errorf("marker is %d times in %s, want 10", n, b)
	}
}

// watchEncoder records the length of each input of the encoder until the end
// of the test.
func watchEncoder(t *testing.T) *[]int {
	var seen []int
	orig := canonicalize
	canonicalize = func(raw []byte) ([]byte, error) {
		seen = append(seen, len(raw))
		return orig(raw)
	}
	t.Cleanup(func() { canonicalize = orig })
	return &seen
}

// manyMembers makes a Detail of n members that have the value v. The names are
// the names in first, then each printable name of 1 byte, then of 2 bytes.
func manyMembers(n int, v Value, first ...string) Detail {
	d := Detail{}
	add := func(s string) {
		if len(d) < n {
			d[s] = v
		}
	}
	for _, s := range first {
		add(s)
	}
	for a := 0x20; a <= 0x7e; a++ {
		add(string(rune(a)))
	}
	for a := 0x20; a <= 0x7e; a++ {
		for b := 0x20; b <= 0x7e; b++ {
			add(string(rune(a)) + string(rune(b)))
		}
	}
	return d
}

// T-S-12: a Detail of 1071 short members is an error before the encoder runs.
// The test counts the encoder inputs and expects none. It covers int, bool and
// empty string values, and names that need a JSON escape.
func TestTS12_ManyDetailMembers(t *testing.T) {
	seen := watchEncoder(t)
	quotes := []string{`"`, `\`, `""`, `\\`, `"\`, `\"`}
	for name, d := range map[string]Detail{
		"int":       manyMembers(1071, Int(-(1<<53 - 1))),
		"int quote": manyMembers(1071, Int(-(1<<53 - 1)), quotes...),
		"min int64": manyMembers(1071, Int(math.MinInt64)),
		"bool":      manyMembers(1071, Bool(false)),
		"empty str": manyMembers(1071, Str("")),
	} {
		if len(d) != 1071 {
			t.Fatalf("%s: %d members", name, len(d))
		}
		if _, err := d.JSON(); err == nil {
			t.Errorf("%s: JSON accepts the detail", name)
		}
		if _, err := HashEvidence(Record{TS: 1, Kind: KindCallback, Detail: d}); err == nil {
			t.Errorf("%s: HashEvidence accepts the detail", name)
		}
		if _, err := NewEvent(nil, Input{Kind: KindCallback, Detail: d}); err == nil {
			t.Errorf("%s: NewEvent accepts the detail", name)
		}
	}
	if len(*seen) != 0 {
		t.Errorf("the encoder got input of lengths %v", *seen)
	}
}

// T-S-12: Detail.check reads the string length of each value for the size
// bound. The long value is on the second sorted name. The marshaled text is
// also too large, so the test calls check directly. The encoder gets no input.
func TestTS12_DetailSizeBoundReadsValue(t *testing.T) {
	seen := watchEncoder(t)
	const want = "event: detail is too large"
	d := Detail{"a": Int(0), "b": Str(strings.Repeat("x", 2045))}
	if err := d.check(); err == nil || err.Error() != want {
		t.Errorf("check: error %v, want %q", err, want)
	}
	if _, err := d.JSON(); err == nil || err.Error() != want {
		t.Errorf("JSON: error %v, want %q", err, want)
	}
	if len(*seen) != 0 {
		t.Errorf("the encoder got input of lengths %v", *seen)
	}
}

const errDetailTooLarge = "event: detail is too large"

// T-S-12: a value of quotes passes check, but each quote needs 2 bytes in the
// marshaled text. JSON refuses the text before the encoder gets it.
func TestTS12_DetailMarshaledSizeBound(t *testing.T) {
	seen := watchEncoder(t)
	d := Detail{"a": Str(strings.Repeat(`"`, 1100))}
	if err := d.check(); err != nil {
		t.Errorf("check: %v", err)
	}
	if _, err := d.JSON(); err == nil || err.Error() != errDetailTooLarge {
		t.Errorf("JSON: error %q, want %q", err, errDetailTooLarge)
	}
	if len(*seen) != 0 {
		t.Errorf("the encoder got input of lengths %v", *seen)
	}
}

// T-S-12: check adds the lower bounds of all members. A sum equal to the cap
// passes check, and a sum past the cap does not.
func TestTS12_DetailSumBound(t *testing.T) {
	x := func(n int) Value { return Str(strings.Repeat("x", n)) }
	d := Detail{"a": x(1100), "b": x(1100)}
	if err := d.check(); err == nil || err.Error() != errDetailTooLarge {
		t.Errorf("two members: error %q, want %q", err, errDetailTooLarge)
	}
	d = Detail{"a": x(2043)}
	if err := d.check(); err != nil {
		t.Errorf("sum 2048: %v", err)
	}
	if _, err := d.JSON(); err == nil || err.Error() != errDetailTooLarge {
		t.Errorf("JSON of 2051 bytes: error %q, want %q", err, errDetailTooLarge)
	}
	d = Detail{"a": x(2044)}
	if err := d.check(); err == nil || err.Error() != errDetailTooLarge {
		t.Errorf("sum 2049: error %q, want %q", err, errDetailTooLarge)
	}
}

// T-S-12: a name of 64 bytes and the names " " and "~" are the bounds.
// JSON accepts them, and ParseDetail reads the text back. The names "\x1f" and
// "\x7f" are one past the bounds, and JSON refuses them.
func TestTS12_DetailNameBounds(t *testing.T) {
	for _, n := range []string{"\x1f", "\x7f"} {
		_, err := Detail{n: Int(1)}.JSON()
		if want := "event: detail name is not printable ASCII"; err == nil || err.Error() != want {
			t.Errorf("name %q: error %q, want %q", n, err, want)
		}
	}
	d := Detail{strings.Repeat("n", 64): Int(1), " ": Int(1), "~": Int(1)}
	b, err := d.JSON()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseDetail(string(b))
	if err != nil || !maps.Equal(got, d) {
		t.Errorf("ParseDetail: %v, %v, want %v", got, err, d)
	}
}

// T-S-12: the largest event has a fixed size; the encoder input is bounded by
// the record caps.
func TestTS12_LargestEvent(t *testing.T) {
	seen := watchEncoder(t)
	ctl := strings.Repeat("\x01", 300) // a control byte is 6 bytes in canonical form
	// The longest ts and status are the negative integers -(2^53-1). The kind
	// score_change is the longest name of a kind that can have a session.
	st := int64(-maxInt)
	// The documentation prefix has the group db8 with 3 digits, so the first
	// address has 38 bytes, one less than maxIPText. The second address has the
	// longest text that an address can have.
	for _, c := range []struct {
		ip     string
		length int
	}{
		{"2001:db8:1234:5678:9abc:def0:1234:5678", maxIPText - 1},
		{"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", maxIPText},
	} {
		e, err := NewEvent(fixedClock(-maxInt), Input{Kind: KindScoreChange, Session: ctl, Vhost: ctl + strings.Repeat("a", 253),
			Method: ctl, Path: strings.Repeat("\"", 2100), TrapID: ctl, TokenID: ctl, Status: &st,
			Surface: SurfaceHeader, JA4: ctl, H2: ctl, Hdr: ctl,
			Detail:   Detail{"a": Str(strings.Repeat("\x01", 340))},
			ClientIP: c.ip, BodyPrefix: make([]byte, 9000)})
		if err != nil {
			t.Fatal(err)
		}
		b, err := e.record.canonical()
		if err != nil {
			t.Fatal(err)
		}
		ip := e.IP()
		if len(b) > MaxRecordBytes || len(e.BodyPrefix()) != MaxBodyPrefix || len(ip) != c.length || e.Size() > MaxEventBytes {
			t.Fatalf("ip %q: record %d, prefix %d, size %d", c.ip, len(b), len(e.BodyPrefix()), e.Size())
		}
		// The pinned size is the length of the canonical bytes of the record above.
		// Each text field is as long as its cap allows. Each control byte is a
		// 6-byte escape, and each quote of the path is 2 bytes. The test
		// measured the value; a change of a cap changes it.
		if len(b) != largestRecord || e.Size() != len(b)+MaxBodyPrefix+len(ip) {
			t.Errorf("ip %q: largest record is %d bytes, event is %d", c.ip, len(b), e.Size())
		}
	}
	// Input past a cap is an error before it reaches the encoder.
	over := strings.Repeat("a", 5000)
	for i, r := range []Record{
		{Kind: KindCallback, Path: sp(over)}, {Kind: KindCallback, Vhost: sp(over[:254])},
		{Kind: KindCallback, FP: &FP{H2: sp(over[:129])}}, {Kind: KindCallback, Session: sp(over[:65])},
		{Kind: KindCallback, Detail: Detail{"a": Str(strings.Repeat("a", 2*MaxDetailBytes))}},
		{Kind: KindCallback, Detail: Detail{"a": Str(strings.Repeat("\x01", 400))}}, // 2.4 KB canonical
		{Kind: KindCallback, Detail: Detail{strings.Repeat("n", 65): Int(1)}},
		{Kind: KindCallback, Detail: Detail{"é": Int(1)}},
		{Kind: KindCallback, Detail: Detail{"a": {}}},
	} {
		if _, err := HashEvidence(r); err == nil {
			t.Errorf("record %d is accepted", i)
		}
	}
	for _, n := range *seen {
		if n > MaxRecordBytes {
			t.Errorf("the encoder got %d bytes, more than %d", n, MaxRecordBytes)
		}
	}
	if len(*seen) == 0 {
		t.Error("the encoder was not called")
	}
}

// T-S-12: no field of a record or a detail value is a float, and nothing in
// the record can hold an address, a body, a header or a cookie.
func TestTS12_NoFloatAndShape(t *testing.T) {
	var walk func(reflect.Type)
	walk = func(ty reflect.Type) {
		switch ty.Kind() {
		case reflect.Float32, reflect.Float64, reflect.Interface, reflect.Complex64, reflect.Complex128:
			t.Errorf("type %v is not allowed", ty)
		case reflect.Pointer, reflect.Slice, reflect.Array:
			walk(ty.Elem())
		case reflect.Map:
			if ty != reflect.TypeOf(Detail{}) {
				t.Errorf("map type %v is not allowed", ty)
			}
			walk(ty.Elem())
		case reflect.Struct:
			for i := 0; i < ty.NumField(); i++ {
				f := ty.Field(i)
				for _, bad := range []string{"ip", "hmac", "body", "agent", "header", "cookie", "forward"} {
					if ty == reflect.TypeOf(Record{}) && strings.Contains(strings.ToLower(f.Name), bad) {
						t.Errorf("Record has field %s", f.Name)
					}
				}
				walk(f.Type)
			}
		}
	}
	walk(reflect.TypeOf(Record{}))
	walk(reflect.TypeOf(Row{}))
	for _, bad := range []string{`{"a":2.0}`, `{"a":1.5}`, `{"a":1e0}`, `{"a":-0}`, `{"a":9007199254740992}`,
		`{"a":{"b":1}}`, `{"a":[1]}`, `{"a":null}`, `{"a":1,"a":2}`, `{"a":1} x`, `{"a":1`, `[1]`, ``, "{\"\xff\":1}"} {
		if _, err := ParseDetail(bad); err == nil {
			t.Errorf("detail text %q is accepted", bad)
		}
	}
	d, err := ParseDetail(`{"b":true,"i":-3,"s":"x"}`)
	if err != nil || d["i"] != Int(-3) || d["b"] != Bool(true) || d["s"] != Str("x") {
		t.Errorf("flat detail: %v, %v", d, err)
	}
}
