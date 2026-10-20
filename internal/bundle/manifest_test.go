package bundle

import (
	"bytes"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"
	"time"
)

var baseMembers = [][2]string{
	{"version", `"2026.09.19-1"`},
	{"min_engine", `"1.0.0"`},
	{"created", `"2026-09-19T00:00:00Z"`},
	{"expires", `"2027-09-19T00:00:00Z"`},
	{"key_id", `"k1"`},
}

// testNow is a clock value for the tests, between created and expires of good.
var testNow = time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)

// with builds the base manifest with the raw JSON value of one member changed.
// An empty value leaves the member out. If the base has no such member, with
// adds it.
func with(name, raw string) string {
	var ms []string
	found := false
	for _, kv := range baseMembers {
		v := kv[1]
		if kv[0] == name {
			found, v = true, raw
		}
		if v != "" {
			ms = append(ms, strconv.Quote(kv[0])+":"+v)
		}
	}
	if !found && raw != "" {
		ms = append(ms, strconv.Quote(name)+":"+raw)
	}
	return "{" + strings.Join(ms, ",") + "}"
}

var good = with("", "")

// plus adds the text of one member after the members of the base manifest.
func plus(member string) string { return strings.TrimSuffix(good, "}") + "," + member + "}" }

func q(s string) string { return `"` + s + `"` }

type mcase struct{ name, in string }

func key32(f func(i int) byte) string {
	b := make([]byte, 32)
	for i := range b {
		b[i] = f(i)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func rot(from, key string) string { return `{"from":` + q(from) + `,"key":` + q(key) + `}` }

func validManifests() []mcase {
	k := key32(func(i int) byte { return byte(i) })
	cs := []mcase{
		{"base", good},
		{"white space around", " \n" + good + "\r\n\t "},
		{"rotation", with("rotation", rot("k0", k))},
		{"version last of day", with("version", q("2026.09.19-999"))},
		{"version leap day", with("version", q("2024.02.29-10"))},
		{"min_engine zero", with("min_engine", q("0.0.0"))},
		{"min_engine largest", with("min_engine", q("9999.9999.9999"))},
		{"key_id 16 bytes", with("key_id", q("abcdefghij012345"))},
		{"key_id digit", with("key_id", q("0"))},
		{"366 days", with("expires", q("2027-09-20T00:00:00Z"))},
		{"one second", with("expires", q("2026-09-19T00:00:01Z"))},
		{"members in other order", `{"key_id":"k1","expires":"2027-09-19T00:00:00Z","created":"2026-09-19T00:00:00Z","min_engine":"1.0.0","version":"2026.09.19-1"}`},
	}
	for _, n := range []int{0, 1, 4096 - len(good)} {
		cs = append(cs, mcase{"padded to " + strconv.Itoa(len(good)+n), good + strings.Repeat(" ", n)})
	}
	return cs
}

func refusedManifests() []mcase {
	zeroKey := strings.Repeat("A", 43) + "="
	cs := []mcase{
		{"empty", ""}, {"open brace", "{"}, {"no member", "{}"}, {"array", "[]"}, {"null", "null"},
		{"string", `"x"`}, {"number", "1"}, {"cut off", `{"version":`},
		{"trailing comma", strings.TrimSuffix(good, "}") + ",}"},
		{"second object", good + "{}"}, {"two objects", good + good}, {"text after", good + " x"},
		{"NUL after", good + "\x00"}, {"text before", "x" + good},
		{"duplicate version", plus(`"version":"2026.09.19-2"`)},
		{"duplicate with same value", plus(`"key_id":"k1"`)},
		{"duplicate by escape", plus("\"\x5cu0076ersion\":\"2026.09.19-2\"")},
		{"duplicate in rotation", with("rotation", `{"from":"k0","from":"k0","key":`+q(zeroKey)+`}`)},
		{"unknown", plus(`"extra":"x"`)},
		{"unknown with marker", plus(`"MARKER-7f3a":"MARKER-7f3a"`)},
		{"case variant added", plus(`"Version":"2026.09.19-1"`)},
		{"invalid UTF-8 in name", plus("\"\xff\":1")},
		{"invalid UTF-8 in value", plus("\"a\":\"\xff\"")},
		{"invalid UTF-8 in key_id", with("key_id", "\"k\xff\"")},
	}
	for _, kv := range baseMembers {
		n := kv[0]
		cs = append(cs,
			mcase{"missing " + n, with(n, "")},
			mcase{"null " + n, with(n, "null")},
			mcase{"case variant " + n, strings.Replace(good, strconv.Quote(n), strconv.Quote(strings.ToUpper(n)), 1)},
			mcase{"capital first " + n, strings.Replace(good, strconv.Quote(n), strconv.Quote(strings.ToUpper(n[:1])+n[1:]), 1)})
		for _, v := range []string{"5", "true", `["x"]`, `{}`, `{"a":"b"}`} {
			cs = append(cs, mcase{n + " type " + v, with(n, v)})
		}
	}
	for _, v := range []string{"2026.09.19", "2026.09.19-", "2026.09.19-0", "2026.09.19-1000", "2026.09.19-01",
		"2026.09.19--1", "2026.09.19-+1", "2026.09.19-1 ", " 2026.09.19-1", "2026.09.19-1\x5cn", "2026.9.19-1",
		"26.09.19-1", "2026-09-19-1", "2026.09.19.1", "2026.13.01-1", "2026.00.19-1", "2026.09.00-1",
		"2026.09.31-1", "2026.02.30-1", "2025.02.29-1", "2026.09.19-a", "v2026.09.19-1", "",
		"٢٠٢٦.09.19-1"} {
		cs = append(cs, mcase{"version " + v, with("version", q(v))})
	}
	for _, v := range []string{"1.0", "1", "1.0.0.0", "1.0.", ".1.0", "01.0.0", "1.00.0", "1.0.00", "1.0.01",
		"10000.0.0", "1.10000.0", "1.0.10000", "-1.0.0", "+1.0.0", "1.0.+1", "a.b.c", "", "v1.0.0",
		"1.0.0-rc1", " 1.0.0", "1.0.0 ", "1,0,0", "1.0.0\x5cn"} {
		cs = append(cs, mcase{"min_engine " + v, with("min_engine", q(v))})
	}
	// Each case of expires is an instant after created and within 366 days of
	// it, so that only the form rule refuses it.
	for _, n := range []struct{ name, day, prev, year string }{
		{"created", "2026-09-19", "2026-09-18", "2026"},
		{"expires", "2027-01-01", "2026-12-31", "2027"},
	} {
		at := func(day, sep, clock string) string { return day + sep + clock }
		d, p, y := n.day, n.prev, n.year
		for _, v := range []string{"", d, at(d, "T", "00:00Z"), at(d, "T", "00:00:00"),
			at(d, "T", "00:00:00z"), at(d, "t", "00:00:00Z"), at(d, " ", "00:00:00Z"),
			at(d, "T", "00:00:00.5Z"), at(d, "T", "00:00:00.000Z"), at(d, "T", "00:00:00+00:00"),
			at(d, "T", "00:00:00-00:00"), at(d, "T", "01:00:00+01:00"), at(p, "T", "23:00:00-01:00"),
			at(y+"-02-30", "T", "00:00:00Z"), at(d, "T", "24:00:00Z"), at(d, "T", "23:59:60Z"),
			at(y+"-9-19", "T", "00:00:00Z"), " " + at(d, "T", "00:00:00Z"),
			at(d, "T", "00:00:00Z "), at(d, "T", "00:00:00Z\x5cn"), "1789012345"} {
			cs = append(cs, mcase{n.name + " " + v, with(n.name, q(v))})
		}
	}
	for _, v := range []string{"", "k1k1k1k1k1k1k1k1k", "K1", "k_1", "k-1", "k 1", "k.1", "é", "k1\x5cn", `k\u0000`} {
		cs = append(cs, mcase{"key_id " + v, with("key_id", `"`+v+`"`)})
	}
	exp := func(v string) string { return with("expires", q(v)) }
	cs = append(cs,
		mcase{"created equals expires", exp("2026-09-19T00:00:00Z")},
		mcase{"created after expires", exp("2026-09-18T23:59:59Z")},
		mcase{"366 days and one second", exp("2027-09-20T00:00:01Z")},
		mcase{"367 days", exp("2027-09-21T00:00:00Z")},
		mcase{"many years", strings.Replace(exp("9999-12-31T23:59:59Z"), "2026-09-19T00:00:00Z", "0001-01-01T00:00:00Z", 1)})
	std := base64.StdEncoding
	url32 := base64.URLEncoding.EncodeToString(bytes.Repeat([]byte{0xfb, 0xff}, 16))
	for _, v := range []string{"null", "{}", `"x"`, "[]", "5", "true", `{"from":"k0"}`, `{"key":` + q(zeroKey) + `}`,
		`{"from":null,"key":` + q(zeroKey) + `}`, `{"from":"k0","key":null}`, `{"from":5,"key":` + q(zeroKey) + `}`,
		`{"from":"k0","key":5}`,
		rot("k0", zeroKey)[:len(rot("k0", zeroKey))-1] + `,"extra":1}`,
		`{"From":"k0","key":` + q(zeroKey) + `}`, `{"from":"k0","Key":` + q(zeroKey) + `}`,
		rot("", zeroKey), rot("K0", zeroKey), rot("k_0", zeroKey), rot("k1k1k1k1k1k1k1k1k", zeroKey),
		rot("k0", ""), rot("k0", "!!!!"), rot("k0", strings.TrimSuffix(zeroKey, "=")),
		rot("k0", strings.Repeat("A", 42)+"B="), rot("k0", strings.Repeat("A", 43)+"A"),
		rot("k0", std.EncodeToString(make([]byte, 31))), rot("k0", std.EncodeToString(make([]byte, 33))),
		rot("k0", std.EncodeToString(make([]byte, 16))), rot("k0", url32),
		rot("k0", strings.ReplaceAll(url32, "-", "+")), rot("k0", zeroKey[:20]+`\n`+zeroKey[20:])} {
		cs = append(cs, mcase{"rotation " + v, with("rotation", v)})
	}
	cs = append(cs, mcase{"larger than 4096", good + strings.Repeat(" ", 4097-len(good))})
	return cs
}

// T-U-08: a valid manifest parses.
func TestTU08ValidManifest(t *testing.T) {
	m, err := ParseManifest([]byte(good))
	if err != nil {
		t.Fatal(err)
	}
	want := time.Date(2026, 9, 19, 0, 0, 0, 0, time.UTC)
	if m.Version != "2026.09.19-1" || m.MinEngine != [3]int{1, 0, 0} || m.KeyID != "k1" || m.Rotation != nil ||
		!m.Created.Equal(want) || !m.Expires.Equal(want.AddDate(1, 0, 0)) {
		t.Errorf("manifest %+v", m)
	}
	for _, c := range validManifests() {
		if _, err := ParseManifest([]byte(c.in)); err != nil {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

// T-U-08: the rotation member gives its two values.
func TestTU08ValidRotation(t *testing.T) {
	m, err := ParseManifest([]byte(with("rotation", rot("k0", key32(func(i int) byte { return byte(i + 1) })))))
	if err != nil || m.Rotation == nil {
		t.Fatalf("manifest %+v, error %v", m, err)
	}
	if m.Rotation.From != "k0" || m.Rotation.Key[0] != 1 || m.Rotation.Key[31] != 32 {
		t.Errorf("rotation %+v", m.Rotation)
	}
}

// T-U-08, T-S-19: each bad manifest gives manifest_invalid, no manifest, and an
// error with fixed text.
func TestTS19ManifestInvalid(t *testing.T) {
	for _, c := range refusedManifests() {
		m, err := ParseManifest([]byte(c.in))
		if m != nil || err != ErrManifestInvalid {
			t.Errorf("%s: manifest %v, error %v", c.name, m, err)
			continue
		}
		if code, ok := CodeOf(err); !ok || code != CodeManifestInvalid || err.Error() != "bundle: manifest_invalid" {
			t.Errorf("%s: code %v, text %q", c.name, code, err)
		}
	}
}

// T-S-19: a value with a JSON escape for a new line is valid JSON. The decoder
// accepts it, so the form rule of the member is the rule that refuses it.
func TestTS19EscapedNewLineIsJSON(t *testing.T) {
	n := 0
	for _, c := range refusedManifests() {
		if !strings.HasSuffix(c.name, "\x5cn") {
			continue
		}
		n++
		var raw rawManifest
		if err := json.Unmarshal([]byte(c.in), &raw, parseOpts...); err != nil {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	if n != 5 {
		t.Errorf("%d cases", n)
	}
}

// T-S-19: a manifest of 4096 bytes passes. The parser refuses one of 4097
// bytes, although it is valid JSON with only white space added.
func TestTS19ManifestSizeCap(t *testing.T) {
	for _, c := range validManifests() {
		if len(c.in) > MaxManifestBytes {
			t.Errorf("%s: %d bytes", c.name, len(c.in))
		}
	}
	if _, err := ParseManifest([]byte(good + strings.Repeat(" ", 4096-len(good)))); err != nil {
		t.Errorf("4096 bytes: %v", err)
	}
	if _, err := ParseManifest([]byte(good + strings.Repeat(" ", 4097-len(good)))); err != ErrManifestInvalid {
		t.Errorf("4097 bytes: %v", err)
	}
}

// T-U-08: EngineVersion has the form of min_engine.
func TestTU08EngineVersionForm(t *testing.T) {
	if _, ok := parseEngine(EngineVersion); !ok {
		t.Fatalf("EngineVersion %q", EngineVersion)
	}
}

// T-U-08: min_engine above the engine version gives min_engine. An equal or
// lower one passes. The compare goes part by part, as numbers.
func TestTU08MinEngine(t *testing.T) {
	engine := [3]int{2, 3, 4}
	for _, c := range []struct {
		min  [3]int
		fail bool
	}{
		{[3]int{2, 3, 4}, false},
		{[3]int{1, 3, 4}, false}, {[3]int{2, 2, 4}, false}, {[3]int{2, 3, 3}, false},
		{[3]int{1, 9999, 9999}, false}, {[3]int{2, 2, 9999}, false}, {[3]int{0, 0, 0}, false},
		{[3]int{3, 3, 4}, true}, {[3]int{2, 4, 4}, true}, {[3]int{2, 3, 5}, true},
		{[3]int{3, 0, 0}, true}, {[3]int{2, 4, 0}, true}, {[3]int{2, 10, 0}, true},
	} {
		err := checkEngine(c.min, engine)
		if c.fail != (err == ErrMinEngine) || (err != nil && err != ErrMinEngine) {
			t.Errorf("min_engine %v, engine %v: %v", c.min, engine, err)
		}
	}
	for _, c := range []struct {
		min  string
		fail bool
	}{
		{"1.0.0", false}, {"0.0.0", false}, {"0.9999.9999", false},
		{"2.0.0", true}, {"1.1.0", true}, {"1.0.1", true}, {"9999.9999.9999", true},
	} {
		m, err := ParseManifest([]byte(with("min_engine", q(c.min))))
		if err != nil {
			t.Fatalf("%s: %v", c.min, err)
		}
		if err := m.CheckEngine(); c.fail != (err == ErrMinEngine) || (err != nil && err != ErrMinEngine) {
			t.Errorf("min_engine %s, engine %s: %v", c.min, EngineVersion, err)
		}
	}
}

// T-U-08: expires <= now gives expired. One second before expires passes.
func TestTU08Expiry(t *testing.T) {
	m, err := ParseManifest([]byte(good))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		now  time.Time
		fail bool
	}{
		{m.Expires.Add(-time.Second), false}, {m.Created, false}, {testNow, false},
		{m.Expires, true}, {m.Expires.Add(time.Second), true}, {m.Expires.AddDate(10, 0, 0), true},
	} {
		if err := m.CheckExpiry(c.now); c.fail != (err == ErrExpired) || (err != nil && err != ErrExpired) {
			t.Errorf("expires %v, now %v: %v", m.Expires, c.now, err)
		}
	}
}

// check runs the steps in the order of the loader: format, engine, expiry.
func check(b string, now time.Time) error {
	m, err := ParseManifest([]byte(b))
	if err != nil {
		return err
	}
	if err := m.CheckEngine(); err != nil {
		return err
	}
	return m.CheckExpiry(now)
}

// T-U-08: each failure gives exactly one code. A format failure gives
// manifest_invalid and nothing else. This holds also when min_engine is above
// the engine version and the manifest has expired.
func TestTU08OneCodeForEachFailure(t *testing.T) {
	bad := strings.Replace(with("min_engine", q("9.0.0")), "2027-09-19", "2026-09-20", 1)
	bad = strings.Replace(bad, "2026.09.19-1", "2026.09.31-1", 1)
	for _, c := range []struct {
		name, in string
		want     error
		code     Code
	}{
		{"valid", good, nil, 0},
		{"format", with("key_id", q("K1")), ErrManifestInvalid, CodeManifestInvalid},
		{"format, engine and expiry", bad, ErrManifestInvalid, CodeManifestInvalid},
		{"engine", with("min_engine", q("1.0.1")), ErrMinEngine, CodeMinEngine},
		{"expiry", with("expires", q("2026-09-20T00:00:00Z")), ErrExpired, CodeExpired},
	} {
		err := check(c.in, testNow)
		if err != c.want {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if code, ok := CodeOf(err); ok != (err != nil) || code != c.code {
			t.Errorf("%s: code %v, %v", c.name, code, ok)
		}
	}
	m, err := ParseManifest([]byte(bad))
	if m != nil || err != ErrManifestInvalid {
		t.Errorf("format failure: manifest %v, error %v", m, err)
	}
}

// T-U-08: the eight codes, with their text.
func TestTU08CodeText(t *testing.T) {
	want := []string{"archive_invalid", "bad_sig", "manifest_invalid", "min_engine", "expired", "rollback",
		"template_parse", "seed_invalid"}
	codes := []Code{CodeArchiveInvalid, CodeBadSig, CodeManifestInvalid, CodeMinEngine, CodeExpired,
		CodeRollback, CodeTemplateParse, CodeSeedInvalid}
	for i, c := range codes {
		if c.String() != want[i] {
			t.Errorf("code %d: %q, want %q", c, c.String(), want[i])
		}
	}
	for _, c := range []Code{0, Code(len(codes) + 1), 255} {
		if c.String() != "unknown" {
			t.Errorf("code %d: %q", c, c.String())
		}
	}
}

// T-U-08: the errors of the manifest steps are distinct and each has one code.
func TestTU08CodeOf(t *testing.T) {
	errs := []error{ErrArchiveInvalid, ErrManifestInvalid, ErrMinEngine, ErrExpired}
	want := []Code{CodeArchiveInvalid, CodeManifestInvalid, CodeMinEngine, CodeExpired}
	for i, err := range errs {
		if code, ok := CodeOf(err); !ok || code != want[i] {
			t.Errorf("%v: code %v, %v", err, code, ok)
		}
		for j, other := range errs {
			if (i == j) != errors.Is(err, other) {
				t.Errorf("%v and %v", err, other)
			}
		}
	}
	if code, ok := CodeOf(errors.New("other")); ok || code != 0 {
		t.Errorf("other error: code %v, %v", code, ok)
	}
}

// T-U-08: the code of the manifest steps does not read the clock. The caller
// gives now.
func TestTU08NoWallClock(t *testing.T) {
	for _, name := range []string{"manifest.go", "engine.go", "code.go"} {
		f, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if s, ok := n.(*ast.SelectorExpr); ok {
				if x, ok := s.X.(*ast.Ident); ok && x.Name == "time" && (s.Sel.Name == "Now" || s.Sel.Name == "Since" || s.Sel.Name == "Until") {
					t.Errorf("%s uses time.%s", name, s.Sel.Name)
				}
			}
			return true
		})
	}
}
