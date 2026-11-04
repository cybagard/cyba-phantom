package event

import (
	"bytes"
	"reflect"
	"slices"
	"testing"
	"unsafe"

	"github.com/cybagard/cyba-phantom/internal/token"
)

func mintRange() *MintRange {
	return &MintRange{SetID: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}, Unit: 77, First: 1234, Count: 68, IssuedAt: 1758300000123}
}

func mintInput(m *MintRange) Input {
	return Input{Kind: KindRequest, Session: "abc", Vhost: "example.com", Method: "GET", Path: "/x", ClientIP: "192.0.2.1", Mint: m}
}

func mintEvent(t *testing.T, m *MintRange) *Event {
	t.Helper()
	e, err := NewEvent(fixedClock(5), mintInput(m))
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// T-S-31: the limits are copies of the values of internal/token. This test file
// is the only place where internal/event names internal/token.
func TestTS31MintLimitsEqualTokenValues(t *testing.T) {
	if MintMaxCount != token.MaxRange {
		t.Errorf("MintMaxCount %d, token.MaxRange %d", MintMaxCount, token.MaxRange)
	}
	if MintCounterLimit != 1<<42 || MintUnitLimit != 1<<20 {
		t.Errorf("counter limit %d, unit limit %d, want 2^42 and 2^20", uint64(MintCounterLimit), uint64(MintUnitLimit))
	}
}

// T-S-31: the accessor gives the range by value. A change to the copy does not
// change the event.
func TestTS31MintAccessorGivesACopy(t *testing.T) {
	in := mintRange()
	e := mintEvent(t, in)
	m, ok := e.Mint()
	if !ok || m != *in {
		t.Fatalf("range %+v %v, want %+v", m, ok, *in)
	}
	m.First, m.SetID[0] = 9, 9
	in.First = 10
	if got, _ := e.Mint(); got.First != 1234 || got.SetID[0] != 1 {
		t.Fatalf("the event range changed: %+v", got)
	}
	if _, ok := mintEvent(t, nil).Mint(); ok {
		t.Fatal("an event with no range has one")
	}
}

// T-S-31: a request event has the same canonical bytes with and without a
// range. The record has no field for the range.
func TestTS31MintIsNotInTheRecord(t *testing.T) {
	with, without := mintEvent(t, mintRange()), mintEvent(t, nil)
	a, err := with.record.canonical()
	if err != nil {
		t.Fatal(err)
	}
	b, err := without.record.canonical()
	if err != nil || !bytes.Equal(a, b) {
		t.Fatalf("canonical bytes differ: %s and %s (%v)", a, b, err)
	}
	if !reflect.DeepEqual(with.Record(), without.Record()) {
		t.Fatal("the records differ")
	}
	var names []string
	for f := range reflect.TypeFor[Record]().Fields() {
		names = append(names, f.Name)
	}
	want := []string{"TS", "Session", "Kind", "Vhost", "Method", "Path", "Status", "TrapID", "TokenID", "Surface", "FP", "Detail"}
	if !slices.Equal(names, want) {
		t.Fatalf("record fields %v, want %v", names, want)
	}
}

// T-S-31: Size grows by the fixed size of the range, and the cap grows by the
// same size.
func TestTS31MintSize(t *testing.T) {
	with, without := mintEvent(t, mintRange()), mintEvent(t, nil)
	if d := with.Size() - without.Size(); d != 40 {
		t.Fatalf("Size grows by %d, want 40", d)
	}
	if n := unsafe.Sizeof(MintRange{}); n != 32 {
		t.Fatalf("MintRange takes %d bytes in memory, want 32", n)
	}
	if MaxEventBytes != MaxRecordBytes+MaxBodyPrefix+maxIPText+40 {
		t.Fatalf("MaxEventBytes %d", MaxEventBytes)
	}
	big := mintInput(mintRange())
	big.BodyPrefix = make([]byte, 2*MaxBodyPrefix)
	e, err := NewEvent(fixedClock(5), big)
	if err != nil {
		t.Fatal(err)
	}
	if e.Size() > MaxEventBytes {
		t.Fatalf("size %d, cap %d", e.Size(), MaxEventBytes)
	}
}

// T-S-31: NewEvent refuses a range on another kind and a range out of bounds.
func TestTS31MintRangeIsChecked(t *testing.T) {
	good := *mintRange()
	for _, k := range []Kind{KindRefused, KindCallback, KindBeacon, KindScoreChange, KindAlertSent, KindBundleLoad, KindBundleRejected, KindRetention} {
		in := Input{Kind: k, Mint: &good}
		if k == KindRefused {
			in.Reason = ReasonUnknownName
		}
		if _, err := NewEvent(fixedClock(5), in); err == nil {
			t.Errorf("kind %v takes a range", k)
		}
	}
	bad := map[string]func(*MintRange){
		"count 0":      func(m *MintRange) { m.Count = 0 },
		"count 69":     func(m *MintRange) { m.Count = 69 },
		"first 2^42":   func(m *MintRange) { m.First = 1 << 42 },
		"unit 2^20":    func(m *MintRange) { m.Unit = 1 << 20 },
		"first max":    func(m *MintRange) { m.First = ^uint64(0) },
		"unit max":     func(m *MintRange) { m.Unit = ^uint32(0) },
		"count 255":    func(m *MintRange) { m.Count = 255 },
		"first 2^42-1": nil,
	}
	for name, mut := range bad {
		m := good
		if mut == nil {
			m.First, m.Unit, m.Count = 1<<42-1, 1<<20-1, 1 // the largest values
			if _, err := NewEvent(fixedClock(5), mintInput(&m)); err != nil {
				t.Errorf("%s: %v", name, err)
			}
			continue
		}
		mut(&m)
		if _, err := NewEvent(fixedClock(5), mintInput(&m)); err == nil {
			t.Errorf("%s is accepted", name)
		}
	}
	m := good
	m.Count = 1
	m.First = 0
	if _, err := NewEvent(fixedClock(5), mintInput(&m)); err != nil {
		t.Errorf("smallest range: %v", err)
	}
}

// T-S-31: a full bulk lane drops an event with a range and counts one drop.
func TestTS31FullBulkLaneDropsTheRange(t *testing.T) {
	plain := mintEvent(t, nil)
	s := int64(plain.Size())
	q, err := newQueue(8, 2*s+39, 1<<20, NewCounters())
	if err != nil {
		t.Fatal(err)
	}
	// Two events with no range fit in the cap. Two events with a range do not.
	if !q.Enqueue(mintEvent(t, mintRange())) {
		t.Fatal("the first event with a range is dropped")
	}
	if q.Enqueue(mintEvent(t, mintRange())) {
		t.Fatal("the second event with a range is queued")
	}
	if d := q.Dropped(); d.Bulk != 1 || d.Evidence != 0 || d.Invalid != 0 {
		t.Fatalf("drops %+v, want one bulk drop", d)
	}
}
