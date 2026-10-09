package event

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"math/rand/v2"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

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
		h, _ := HashEvidence(r)
		if err != nil || string(b) != c.Canonical || hex.EncodeToString(sum[:]) != c.SHA256 || h != sum {
			t.Errorf("%s: bytes %s, error %v, hash %x", c.Name, b, err, h)
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
		b, err := e.Record.canonical()
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
			TokenID: "k", Surface: SurfaceHeader, JA4: "j", Detail: Detail{"b": Bool(true), "n": Int(-5), "s": Str("é<>& ")}}
		if !k.isSystem() {
			in.Session = "s-9"
		}
		e := mustEvent(t, in)
		dj, err := e.Record.Detail.JSON()
		if err != nil {
			t.Fatal(err)
		}
		row := Row{TS: e.Record.TS, SessionID: e.Record.Session, Kind: k.String(), Vhost: e.Record.Vhost,
			Method: e.Record.Method, Path: e.Record.Path, Status: e.Record.Status, TrapID: e.Record.TrapID,
			TokenID: e.Record.TokenID, Surface: e.Record.Surface, FP: e.Record.FP, Detail: sp(string(dj))}
		back, err := RecordFromRow(row)
		if err != nil {
			t.Fatal(err)
		}
		h1, err1 := HashEvidence(e.Record)
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
	if got := *text("a\xff\xc3(\xed\xa0\x80z", 99); got != "a%FF%C3(%ED%A0%80z" {
		t.Errorf("escape: %q", got)
	}
	if got := *text("é€😀", 4); got != "é" { // the cut at 4 falls inside €
		t.Errorf("cut: %q", got)
	}
	if got := *text("é€😀", 5); got != "é€" {
		t.Errorf("cut: %q", got)
	}
	if text("", 5) != nil {
		t.Error("an empty string is not absent")
	}
	caps := map[string]int{"vhost": capVhost, "method": capMethod, "path": capPath, "id": capID, "fp": capFP}
	long := strings.Repeat("\xff", 5000)
	for name, c := range caps {
		got := *text(long, c)
		if len(got) > c || len(got) < c-2 || !strings.HasPrefix(got, "%FF") {
			t.Errorf("%s: length %d", name, len(got))
		}
	}
	long = strings.Repeat("😀", 5000)
	for name, c := range caps {
		if got := *text(long, c); len(got) != c/4*4 {
			t.Errorf("%s: length %d", name, len(got))
		}
	}
	e := mustEvent(t, Input{Kind: KindRequest, Vhost: long, Path: long, Surface: SurfaceBody, JA4: long})
	if len(*e.Record.Vhost) != 252 || len(*e.Record.Path) != 2048 || len(*e.Record.FP.JA4) != 128 {
		t.Error("caps are not applied in the constructor")
	}
	if e.Record.TS != 1758300000123 {
		t.Errorf("ts %d is not from the clock", e.Record.TS)
	}
	if e, _ := NewEvent(nil, Input{Kind: KindRequest}); e == nil || e.Record.TS < 1e12 {
		t.Error("nil clock does not use the time of the sensor")
	}
	if _, err := NewEvent(nil, Input{Kind: KindRequest, Surface: "cookie"}); err == nil {
		t.Error("an unknown surface is accepted")
	}
	if _, err := NewEvent(nil, Input{Kind: 0}); err == nil {
		t.Error("an unknown kind is accepted")
	}
}

// T-S-12: no form of an IP or ip_hmac marker given to the constructor is in
// the canonical bytes, for each kind. Detail values are typed by the producer:
// a producer must not put an address in a string, and review checks that.
func TestTS12_IPMarkers(t *testing.T) {
	markers := []string{"203.0.113.7", "2001:db8::7", "::ffff:203.0.113.7", "9f2c4a7be1d3058c6a1f77aa"}
	forms := append([]string{"2001:0db8:0000:0000:0000:0000:0000:0007", "::ffff:cb00:7107",
		"cb007107", "203", "0113"}, markers...)
	all := strings.Join(markers, ", ")
	for _, k := range allKinds {
		inputs := []Input{{Forwarded: all, BodyPrefix: []byte(all)}}
		for _, m := range markers {
			inputs = append(inputs, Input{ClientIP: m, Forwarded: "for=" + m, BodyPrefix: []byte(m)})
		}
		for _, in := range inputs {
			in.Kind, in.Vhost, in.Detail = k, "decoy.example", Detail{"n": Int(1)}
			e, err := NewEvent(nil, in)
			if err != nil {
				if in.ClientIP == markers[3] {
					continue // an ip_hmac is not an address
				}
				t.Fatal(err)
			}
			b, err := e.Record.canonical()
			if err != nil {
				t.Fatal(err)
			}
			if in.ClientIP != "" && e.DB.IP == "" {
				t.Errorf("%v: the address is not in the DB part", k)
			}
			for _, f := range forms[2:] {
				// "203" and "0113" can be part of a time stamp; skip short forms.
				if len(f) > 4 && bytes.Contains(bytes.ToLower(b), []byte(strings.ToLower(f))) {
					t.Errorf("%v: %q is in %s", k, f, b)
				}
			}
		}
	}
}

// T-S-12: the largest event has a fixed size; the encoder input is bounded by
// the record caps.
func TestTS12_LargestEvent(t *testing.T) {
	ctl := strings.Repeat("\x01", 300) // a control byte is 6 bytes in canonical form
	st := int64(1<<53 - 1)
	e, err := NewEvent(fixedClock(1<<53-1), Input{Kind: KindCallback, Session: ctl, Vhost: ctl + strings.Repeat("a", 253),
		Method: ctl, Path: strings.Repeat("\x01", 2100), TrapID: ctl, TokenID: ctl, Status: &st,
		Surface: SurfaceHeader, JA4: ctl, H2: ctl, Hdr: ctl,
		Detail:   Detail{"a": Str(strings.Repeat("\x01", 340))},
		ClientIP: "2a01:fb8f:1234:5678:9abc:def0:1234:5678", BodyPrefix: make([]byte, 9000)})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := e.Record.canonical()
	if len(b) > MaxRecordBytes || len(e.DB.BodyPrefix) != MaxBodyPrefix || e.Size() > MaxEventBytes {
		t.Fatalf("record %d, prefix %d, size %d", len(b), len(e.DB.BodyPrefix), e.Size())
	}
	if len(b) != 19614 || e.Size() != len(b)+MaxBodyPrefix+39 {
		t.Errorf("largest record is %d bytes, event is %d", len(b), e.Size())
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
