package event

import (
	"fmt"
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
	parts := make([]string, n)
	for i := range parts {
		parts[i] = fmt.Sprintf(`"m%d":%d`, i, i)
	}
	return "{" + strings.Join(parts, ",") + "}"
}

// recordBytes returns the heap bytes of one Record copy of e.
func recordBytes(e *Event) int64 {
	r := testing.Benchmark(func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			sinkRecord = e.Record()
		}
	})
	return r.AllocedBytesPerOp()
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

// T-S-24: NewEvent tests the number of members before it copies the map. For a
// caller map of 1 000 members it makes no allocation.
func TestTS24_NewEventNoCopyAboveCap(t *testing.T) {
	in := Input{Kind: KindCallback, Detail: members(1000)}
	allocs := testing.AllocsPerRun(10, func() {
		if _, err := NewEvent(fixedClock(1), in); err == nil {
			t.Error("NewEvent accepted 1000 members")
		}
	})
	if allocs != 0 {
		t.Errorf("NewEvent of 1000 members made %v allocations, want 0", allocs)
	}
}

// T-S-24: an event made with no detail has no detail map in its Record.
func TestTS24_NoDetailStaysNil(t *testing.T) {
	if d := mustEvent(t, Input{Kind: KindCallback}).Record().Detail; d != nil {
		t.Errorf("Record().Detail is %v, want nil", d)
	}
}
