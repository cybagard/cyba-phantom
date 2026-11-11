package event

import (
	"math"
	"testing"
)

// T-U-11: a retention event has no session. Its detail has the eight integer
// members, each with its count.
func TestTU11_RetentionEvent(t *testing.T) {
	c := RetentionCounts{IP: 1, Fields: 2, Rolled: 3, Deleted: 4, Evicted: 5, Vacuumed: 6, CutoffIP: 7, CutoffRaw: 8}
	e, err := NewRetentionEvent(fixedClock(5), c)
	if err != nil {
		t.Fatal(err)
	}
	r := e.Record()
	if r.Kind != KindRetention || r.Session != nil {
		t.Fatalf("kind %v, session %v", r.Kind, r.Session)
	}
	want := map[string]int64{"ip": 1, "fields": 2, "rolled": 3, "deleted": 4, "evicted": 5, "vacuumed": 6, "cutoff_ip": 7, "cutoff_raw": 8}
	if len(r.Detail) != len(want) {
		t.Fatalf("detail %v", r.Detail)
	}
	for k, n := range want {
		if v := r.Detail[k]; v.tag != 'i' || v.i != n {
			t.Errorf("member %s = %+v, want %d", k, v, n)
		}
	}
}

// T-U-11: NewEvent refuses a retention detail with a text member, an unknown
// member, or an integer outside +-(2^53-1). The constructor refuses a count
// outside the range too.
func TestTU11_RetentionRefusals(t *testing.T) {
	for name, d := range map[string]Detail{
		"text member":    {"ip": Str("1")},
		"unknown member": {"rows": Int(1)},
		"too large":      {"ip": Int(maxInt + 1)},
		"too small":      {"cutoff_raw": Int(-maxInt - 1)},
	} {
		if _, err := NewEvent(nil, Input{Kind: KindRetention, Detail: d}); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	if _, err := NewEvent(nil, Input{Kind: KindRetention, Detail: Detail{"ip": Int(maxInt), "fields": Int(-maxInt)}}); err != nil {
		t.Errorf("limit values: %v", err)
	}
	if _, err := NewRetentionEvent(nil, RetentionCounts{Deleted: math.MaxInt64}); err == nil {
		t.Error("constructor accepted a count above the range")
	}
	if _, err := NewEvent(nil, Input{Kind: KindRetention, Session: "s"}); err == nil {
		t.Error("session accepted")
	}
	if _, err := NewEvent(nil, Input{Kind: KindBeacon, Detail: Detail{"rows": Int(1)}}); err != nil {
		t.Errorf("another kind has the check: %v", err)
	}
}
