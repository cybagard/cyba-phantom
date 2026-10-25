package event

import (
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

const errMemberCap = "event: detail has more than 8 members"

var sinkRecord Record

// members returns a Detail of n short members.
func members(n int) Detail {
	d := Detail{}
	for i := range n {
		d[fmt.Sprintf("m%d", i)] = Int(int64(i))
	}
	return d
}

// membersText returns the JSON text of n short members, made by hand because
// Detail.JSON refuses more than 8.
func membersText(n int) string {
	return membersTextOf(n, func(i int) string { return strconv.Itoa(i) })
}

// membersTextOf is membersText with the JSON text of each value from val.
func membersTextOf(n int, val func(i int) string) string {
	parts := make([]string, n)
	for i := range parts {
		parts[i] = fmt.Sprintf(`"m%d":%s`, i, val(i))
	}
	return "{" + strings.Join(parts, ",") + "}"
}

// recordBytes returns the heap bytes of one Record copy of e: the average of
// a fixed number of copies.
func recordBytes(e *Event) int64 {
	const runs = 1000
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for range runs {
		sinkRecord = e.Record()
	}
	runtime.ReadMemStats(&after)
	return int64(after.TotalAlloc-before.TotalAlloc) / runs
}

// T-S-24: a detail has at most 8 members. NewEvent, Detail.JSON and ParseDetail
// accept 8. They refuse 9 with the same error, also when the text of the 9
// members is less than 2 KB.
func TestTS24_DetailMemberCap(t *testing.T) {
	if _, err := NewEvent(fixedClock(1), Input{Kind: KindCallback, Detail: members(8)}); err != nil {
		t.Errorf("NewEvent refuses 8 members: %v", err)
	}
	if _, err := members(8).JSON(); err != nil {
		t.Errorf("JSON refuses 8 members: %v", err)
	}
	if d, err := ParseDetail(membersText(8)); err != nil || len(d) != 8 {
		t.Errorf("ParseDetail of 8 members: %d members, %v", len(d), err)
	}
	text := membersText(9)
	if len(text) >= 2<<10 {
		t.Fatalf("the text of 9 members has %d bytes", len(text))
	}
	_, errNew := NewEvent(fixedClock(1), Input{Kind: KindCallback, Detail: members(9)})
	_, errJSON := members(9).JSON()
	_, errParse := ParseDetail(text)
	for name, err := range map[string]error{"NewEvent": errNew, "JSON": errJSON, "ParseDetail": errParse} {
		if err == nil || err.Error() != errMemberCap {
			t.Errorf("%s of 9 members: error %v, want %q", name, err, errMemberCap)
		}
	}
	if _, err := NewEvent(fixedClock(1), Input{Kind: KindCallback, Detail: members(1000)}); err == nil || err.Error() != errMemberCap {
		t.Errorf("NewEvent of 1000 members: error %v", err)
	}
}

// T-S-24: the event keeps a new map with only its members. A caller map that
// held 1 000 members and now holds 1 is the first case. A detail of 8 members
// is the second. In both, a Record copy takes at most 512 bytes more heap.
// The test compares each copy with the Record copy of an event with no
// detail. A change to the caller map does not change the event.
func TestTS24_RecordCopyBound(t *testing.T) {
	base := recordBytes(mustEvent(t, Input{Kind: KindCallback}))
	shrunk := members(1000)
	for n := range shrunk {
		if len(shrunk) == 1 {
			break
		}
		delete(shrunk, n)
	}
	for name, d := range map[string]Detail{"1000 to 1": shrunk, "8 members": members(8)} {
		e := mustEvent(t, Input{Kind: KindCallback, Detail: d})
		got := recordBytes(e)
		t.Logf("%s: Record copy %d B, no detail %d B, extra %d B", name, got, base, got-base)
		if got-base > 512 {
			t.Errorf("%s: a Record copy takes %d bytes more than with no detail, want at most 512", name, got-base)
		}
		want := len(e.Record().Detail)
		d["added"] = Int(1)
		for k := range d {
			delete(d, k)
		}
		if e.Record().Detail == nil || len(e.Record().Detail) != want {
			t.Errorf("%s: a change to the caller map changed the event", name)
		}
	}
}

// T-S-24: ParseDetail tests the 2 KB cap of the text first. The text is a
// valid flat object of more than 8 members. Only the text check gives the text
// error.
func TestTS24_ParseDetailTextCapFirst(t *testing.T) {
	text := membersText(300)
	if len(text) <= MaxDetailBytes {
		t.Fatalf("the text has %d bytes, want more than %d", len(text), MaxDetailBytes)
	}
	const want = "event: detail text is not a flat object"
	if _, err := ParseDetail(text); err == nil || err.Error() != want {
		t.Errorf("ParseDetail of a text of %d bytes: error %v, want %q", len(text), err, want)
	}
}

// T-S-24: Detail.JSON tests the number of members before the names. A detail of
// 9 members, one with an empty name, gives the member error.
func TestTS24_DetailCountBeforeNames(t *testing.T) {
	d := members(8)
	d[""] = Int(1)
	if _, err := d.JSON(); err == nil || err.Error() != errMemberCap {
		t.Errorf("JSON of 9 members with an empty name: error %v, want %q", err, errMemberCap)
	}
}

// T-S-24: a detail with two bad names gives one error each time. The names are
// tested in sorted order, so the empty name comes first. ParseDetail and
// Detail.JSON are called 1 000 times, because map order is random. The check
// makes no allocation.
func TestTS24_DetailNameErrorOrder(t *testing.T) {
	const want = "event: detail name is empty or too long"
	d := Detail{"": Int(0), "胁0": Int(0)}
	for range 1000 {
		if _, err := ParseDetail(`{"":0,"胁0":0}`); err == nil || err.Error() != want {
			t.Fatalf("ParseDetail: error %v, want %q", err, want)
		}
		if _, err := d.JSON(); err == nil || err.Error() != want {
			t.Fatalf("JSON: error %v, want %q", err, want)
		}
	}
	eight := members(8)
	if allocs := testing.AllocsPerRun(100, func() { _ = eight.check() }); allocs != 0 {
		t.Errorf("check made %v allocations, want 0", allocs)
	}
}

// T-S-24: NewEvent tests the number of members before it copies the map. For a
// caller map of 9 or of 1 000 members it makes no allocation.
func TestTS24_NewEventNoCopyAboveCap(t *testing.T) {
	for _, n := range []int{9, 1000} {
		in := Input{Kind: KindCallback, Detail: members(n)}
		allocs := testing.AllocsPerRun(10, func() {
			if _, err := NewEvent(fixedClock(1), in); err == nil {
				t.Errorf("NewEvent accepted %d members", n)
			}
		})
		if allocs != 0 {
			t.Errorf("NewEvent of %d members made %v allocations, want 0", n, allocs)
		}
	}
}

// T-S-24: ParseDetail refuses the ninth member while it decodes. The test
// compares two flat texts under 2 KB: 9 members and 150 members. The second
// makes no more allocations than the first. The test runs with int, string and
// bool values. The stop does not depend on the type of the ninth value.
func TestTS24_ParseDetailStopsAtNinthMember(t *testing.T) {
	for kind, val := range map[string]func(int) string{
		"int":    strconv.Itoa,
		"string": func(i int) string { return `"v` + strconv.Itoa(i) + `"` },
		"bool":   func(i int) string { return strconv.FormatBool(i%2 == 0) },
	} {
		long := membersTextOf(150, val)
		if len(long) >= MaxDetailBytes {
			t.Fatalf("%s: the text has %d bytes, want less than %d", kind, len(long), MaxDetailBytes)
		}
		run := func(text string) float64 {
			return testing.AllocsPerRun(10, func() {
				if _, err := ParseDetail(text); err == nil || err.Error() != errMemberCap {
					t.Errorf("%s: ParseDetail: error %v, want %q", kind, err, errMemberCap)
				}
			})
		}
		nine, many := run(membersTextOf(9, val)), run(long)
		t.Logf("%s: allocations: 9 members %v, 150 members %v", kind, nine, many)
		if many > nine {
			t.Errorf("%s: 150 members made %v allocations, 9 members made %v", kind, many, nine)
		}
	}
}

// T-S-24: ParseDetail gives the member error only when it reads a ninth name
// that the decoder accepts. A text of 8 members and then a fault gets the
// text error. A text of 9 valid members gets the member error.
func TestTS24_ParseDetailNinthNameOnly(t *testing.T) {
	const errText = "event: detail text is not a flat object"
	eight := strings.TrimSuffix(membersText(8), "}")
	for name, tc := range map[string]struct{ text, want string }{
		"8 members and trailing comma": {eight + ",}", errText},
		"8 members and no brace":       {eight, errText},
		"8 members and garbage":        {eight + " x}", errText},
		"8 members and repeated name":  {eight + `,"m0":1}`, errText},
		"8 members and closing brace":  {eight + "}", ""},
		"9 valid members":              {membersText(9), errMemberCap},
		"empty ninth name":             {eight + `,"":1}`, errMemberCap},
		"empty ninth name and garbage": {eight + `,"":1 x}`, errMemberCap},
	} {
		d, err := ParseDetail(tc.text)
		switch {
		case tc.want == "" && (err != nil || len(d) != 8):
			t.Errorf("%s: %d members, %v, want 8 members", name, len(d), err)
		case tc.want != "" && (err == nil || err.Error() != tc.want):
			t.Errorf("%s: error %v, want %q", name, err, tc.want)
		}
	}
}

// T-S-24: a text of 2 048 bytes passes the text cap. A text of 2 049 bytes gets
// the text error. Both are one member with a long string value.
func TestTS24_ParseDetailTextCapBoundary(t *testing.T) {
	text := func(n int) string {
		return `{"a":"` + strings.Repeat("x", n-len(`{"a":""}`)) + `"}`
	}
	at, over := text(MaxDetailBytes), text(MaxDetailBytes+1)
	if len(at) != MaxDetailBytes || len(over) != MaxDetailBytes+1 {
		t.Fatalf("text lengths are %d and %d", len(at), len(over))
	}
	if d, err := ParseDetail(at); err != nil || len(d) != 1 {
		t.Errorf("ParseDetail of %d bytes: %d members, %v", len(at), len(d), err)
	}
	const want = "event: detail text is not a flat object"
	if _, err := ParseDetail(over); err == nil || err.Error() != want {
		t.Errorf("ParseDetail of %d bytes: error %v, want %q", len(over), err, want)
	}
}

// T-S-24: an event made with no detail has no detail map in its Record.
func TestTS24_NoDetailStaysNil(t *testing.T) {
	if d := mustEvent(t, Input{Kind: KindCallback}).Record().Detail; d != nil {
		t.Errorf("Record().Detail is %v, want nil", d)
	}
}
