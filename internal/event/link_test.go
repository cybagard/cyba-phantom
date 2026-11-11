package event

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

func linkValue() *CallbackLink {
	return &CallbackLink{SetID: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}, Unit: 77, Counter: 1234}
}

func linkInput(l *CallbackLink) Input {
	return Input{Kind: KindCallback, Session: "abc", Vhost: "example.com", Method: "GET", Path: "/x",
		TrapID: "trap-a", TokenID: "0123456789abcdef0123456789abcdef", Surface: SurfacePath,
		ClientIP: "192.0.2.1", Link: l}
}

func linkEvent(t *testing.T, l *CallbackLink) *Event {
	t.Helper()
	e, err := NewEvent(fixedClock(5), linkInput(l))
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// T-S-32: a callback event has the same canonical bytes and record with and
// without a link. Size grows by the fixed size of the link. Link gives the
// value back, and false when the event has none.
func TestTS32LinkIsNotInTheRecord(t *testing.T) {
	in := linkValue()
	with, without := linkEvent(t, in), linkEvent(t, nil)
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
	if d := with.Size() - without.Size(); d != 8+4+8 {
		t.Fatalf("Size grows by %d, want 20", d)
	}
	if l, ok := with.Link(); !ok || l != *in {
		t.Fatalf("Link gives %+v %v, want %+v true", l, ok, *in)
	}
	if _, ok := without.Link(); ok {
		t.Fatal("an event with no link has one")
	}
	if _, ok := with.Mint(); ok {
		t.Fatal("a link makes a range")
	}
}

// T-S-32: a zero link is a link.
func TestTS32ZeroLinkIsPresent(t *testing.T) {
	if l, ok := linkEvent(t, &CallbackLink{}).Link(); !ok || l != (CallbackLink{}) {
		t.Fatalf("Link gives %+v %v", l, ok)
	}
}

// T-S-32: NewEvent refuses a link on a kind other than callback. It refuses a
// link out of bounds. It refuses a link with no trap id or no token id. It
// accepts the largest unit and counter.
func TestTS32LinkIsChecked(t *testing.T) {
	for _, k := range []Kind{KindRequest, KindRefused, KindBeacon, KindScoreChange, KindAlertSent, KindBundleLoad, KindBundleRejected, KindRetention} {
		in := linkInput(nil)
		in.Kind = k
		if k.isSystem() {
			in.Session = ""
		}
		if k == KindRetention {
			// A retention event has only a kind and a detail.
			in = Input{Kind: k}
		}
		if k == KindRefused {
			// A refused record has only a reason and an address.
			in = Input{Kind: k, Reason: ReasonUnknownName, ClientIP: "192.0.2.1"}
		}
		if _, err := NewEvent(fixedClock(5), in); err != nil {
			t.Errorf("kind %v with no link: %v", k, err)
			continue
		}
		in.Link = linkValue()
		if _, err := NewEvent(fixedClock(5), in); err == nil || !strings.Contains(err.Error(), "only a callback event has a link") {
			t.Errorf("kind %v with a link: %v", k, err)
		}
	}
	bad := map[string]func(*CallbackLink){
		"unit 2^20":    func(l *CallbackLink) { l.Unit = 1 << 20 },
		"unit max":     func(l *CallbackLink) { l.Unit = ^uint32(0) },
		"counter 2^42": func(l *CallbackLink) { l.Counter = 1 << 42 },
		"counter max":  func(l *CallbackLink) { l.Counter = ^uint64(0) },
	}
	for name, mut := range bad {
		l := *linkValue()
		mut(&l)
		if _, err := NewEvent(fixedClock(5), linkInput(&l)); err == nil {
			t.Errorf("%s is accepted", name)
		}
	}
	for name, mut := range map[string]func(*Input){
		"no trap id":  func(in *Input) { in.TrapID = "" },
		"no token id": func(in *Input) { in.TokenID = "" },
	} {
		in := linkInput(linkValue())
		mut(&in)
		if _, err := NewEvent(fixedClock(5), in); err == nil {
			t.Errorf("%s is accepted", name)
		}
		in.Link = nil
		if _, err := NewEvent(fixedClock(5), in); err != nil {
			t.Errorf("%s with no link: %v", name, err)
		}
	}
	max := CallbackLink{Unit: 1<<20 - 1, Counter: 1<<42 - 1}
	if l, ok := linkEvent(t, &max).Link(); !ok || l != max {
		t.Errorf("largest link gives %+v %v", l, ok)
	}
}

// T-S-32: a change to *in.Link after NewEvent does not change the event.
func TestTS32LinkIsCopied(t *testing.T) {
	in := linkValue()
	e := linkEvent(t, in)
	in.Counter, in.SetID[0] = 9, 9
	l, _ := e.Link()
	l.Unit = 5
	if got, _ := e.Link(); got.Counter != 1234 || got.SetID[0] != 1 || got.Unit != 77 {
		t.Fatalf("the event link changed: %+v", got)
	}
}

// T-S-32: the largest callback event with a link is within MaxEventBytes. The
// link is not more than a range, because an event has one of them.
func TestTS32LinkEventStaysInMaxEventBytes(t *testing.T) {
	if linkSize > mintRangeSize {
		t.Fatalf("linkSize %d is more than mintRangeSize %d", linkSize, mintRangeSize)
	}
	ctl := strings.Repeat("\x01", 300)
	st := int64(-maxInt)
	in := Input{Kind: KindCallback, Session: ctl, Vhost: ctl + strings.Repeat("a", 253),
		Method: ctl, Path: strings.Repeat("\"", 2100), TrapID: ctl, TokenID: ctl, Status: &st,
		Surface: SurfaceHeader, JA4: ctl, H2: ctl, Hdr: ctl,
		Detail:   Detail{"a": Str(strings.Repeat("\x01", 340))},
		ClientIP: "2001:db8:1234:5678:9abc:def0:1234:5678", BodyPrefix: make([]byte, 9000),
		Link: linkValue()}
	e, err := NewEvent(fixedClock(-maxInt), in)
	if err != nil {
		t.Fatal(err)
	}
	if e.Size() > MaxEventBytes || e.Size() < MaxEventBytes/2 {
		t.Fatalf("size %d is not in [%d, %d]", e.Size(), MaxEventBytes/2, MaxEventBytes)
	}
}

// T-S-32: a full evidence lane drops a callback event with its link and counts
// one drop.
func TestTS32FullEvidenceLaneDropsTheLink(t *testing.T) {
	plain := linkEvent(t, nil)
	q, _ := mustQueue(t, 8, 1<<20, int64(2*plain.Size())+linkSize)
	if !q.Enqueue(linkEvent(t, linkValue())) {
		t.Fatal("the first event with a link is dropped")
	}
	if q.Enqueue(linkEvent(t, linkValue())) {
		t.Fatal("the second event with a link is queued")
	}
	if d := q.Dropped(); d.Evidence != 1 || d.Bulk != 0 || d.Invalid != 0 {
		t.Fatalf("drops %+v, want one evidence drop", d)
	}
	if !q.Enqueue(linkEvent(t, nil)) {
		t.Fatal("an event with no link does not fit")
	}
}
