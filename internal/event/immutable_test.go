package event_test

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/cybagard/cyba-phantom/internal/event"
)

// These tests use only the public API. A caller outside the package can do
// nothing else with an Event.

var allKinds = []event.Kind{
	event.KindRequest, event.KindCallback, event.KindBeacon, event.KindScoreChange,
	event.KindBundleLoad, event.KindBundleRejected, event.KindAlertSent, event.KindRetention,
}

// hasSession tells if an event of kind k can have a session. The three system
// kinds cannot.
func hasSession(k event.Kind) bool {
	switch k {
	case event.KindBundleLoad, event.KindBundleRejected, event.KindRetention:
		return false
	}
	return true
}

func at(ms int64) event.Clock { return func() time.Time { return time.UnixMilli(ms) } }

// fullInput sets every field of an event.
func fullInput(k event.Kind) event.Input {
	status := int64(404)
	in := event.Input{
		Kind: k, Vhost: "decoy.example", Method: "POST", Path: "/p?x=1", TrapID: "trap-1",
		TokenID: "tok-1", Status: &status, Surface: event.SurfaceBody,
		JA4: "ja4-value", H2: "h2-value", Hdr: "hdr-value",
		Detail:   event.Detail{"count": event.Int(7), "flag": event.Bool(true), "note": event.Str("n")},
		ClientIP: "2001:db8::7", BodyPrefix: []byte("body prefix bytes"),
	}
	if hasSession(k) {
		in.Session = "sess-1"
	}
	return in
}

// bigInput sets every field to the longest value that the caps allow.
func bigInput(k event.Kind) event.Input {
	ctl := strings.Repeat("\x01", 300) // a control byte is 6 bytes in canonical form
	status := int64(-(1<<53 - 1))
	in := event.Input{
		Kind: k, Vhost: ctl + strings.Repeat("a", 253), Method: ctl, Path: strings.Repeat("\x01", 2100),
		TrapID: ctl, TokenID: ctl, Status: &status, Surface: event.SurfaceHeader,
		JA4: ctl, H2: ctl, Hdr: ctl, Detail: event.Detail{"a": event.Str(strings.Repeat("\x01", 340))},
		ClientIP: "2001:db8:1234:5678:9abc:def0:1234:5678", BodyPrefix: make([]byte, 9000),
	}
	if hasSession(k) {
		in.Session = ctl
	}
	return in
}

func mustEvent(t testing.TB, now event.Clock, in event.Input) *event.Event {
	t.Helper()
	e, err := event.NewEvent(now, in)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// recordBytes returns the canonical record bytes of r from the public API. The
// record encoder writes the members of the record and the version member v with
// the value 1. Encode of r alone has no v member. So recordBytes encodes a
// struct with the same two parts. For an evidence kind, take checks that these
// bytes equal EvidenceBytes. For request and beacon, no public function gives
// the bytes of a record, and Encode of this struct is the only source.
func recordBytes(t testing.TB, r event.Record) []byte {
	t.Helper()
	b, err := event.Encode(struct {
		V int64 `json:"v"`
		event.Record
	}{1, r})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// snapshot holds the values that the accessors return. It holds copies, so a
// change to the event cannot change the snapshot.
type snapshot struct {
	record, prefix []byte
	ip             string
	kind           event.Kind
	size           int
}

// take reads the event through its accessors. It fails if Size is not the
// length of the record bytes plus len(IP()) plus len(BodyPrefix()), or if an
// evidence record has other bytes than EvidenceBytes gives.
func take(t testing.TB, e *event.Event) snapshot {
	t.Helper()
	rec := e.Record()
	s := snapshot{record: recordBytes(t, rec), prefix: bytes.Clone(e.BodyPrefix()), ip: e.IP(), kind: e.Kind(), size: e.Size()}
	if want := len(s.record) + len(s.ip) + len(s.prefix); s.size != want {
		t.Fatalf("Size is %d, the record is %d bytes, IP %d, body prefix %d: want %d", s.size, len(s.record), len(s.ip), len(s.prefix), want)
	}
	if ok, err := s.kind.IsEvidence(); err == nil && ok {
		if eb, err := event.EvidenceBytes(rec); err != nil || !bytes.Equal(eb, s.record) {
			t.Fatalf("EvidenceBytes %s, %v differs from the encoded record %s", eb, err, s.record)
		}
	}
	return s
}

// same fails if the event does not return the values of the snapshot.
func (s snapshot) same(t testing.TB, e *event.Event) {
	t.Helper()
	got := take(t, e)
	if !bytes.Equal(got.record, s.record) {
		t.Errorf("Record changed: %s, want %s", got.record, s.record)
	}
	if !bytes.Equal(got.prefix, s.prefix) || (got.prefix == nil) != (s.prefix == nil) {
		t.Errorf("BodyPrefix changed: %d bytes, want %d bytes (first bytes %.16q, want %.16q)", len(got.prefix), len(s.prefix), got.prefix, s.prefix)
	}
	if got.ip != s.ip || got.kind != s.kind || got.size != s.size {
		t.Errorf("IP, Kind or Size changed: %q %v %d, want %q %v %d", got.ip, got.kind, got.size, s.ip, s.kind, s.size)
	}
}

type tamper struct {
	name string
	run  func(e *event.Event)
}

// tampers change every value that an accessor returns. Kind and IP return plain
// values, so only Record and BodyPrefix have something to change. A tamper must
// not panic for an event with absent fields. The last tamper runs all others.
var tampers = withAll(parts)

func withAll(parts []tamper) []tamper {
	all := func(e *event.Event) {
		for _, tp := range parts {
			tp.run(e)
		}
	}
	return append(parts[:len(parts):len(parts)], tamper{"all", all})
}

var parts = []tamper{
	{"record pointees", func(e *event.Event) {
		r := e.Record()
		r.TS++
		r.Kind = event.KindRetention
		for _, p := range []*string{r.Session, r.Vhost, r.Method, r.Path, r.TrapID, r.TokenID} {
			if p != nil {
				*p += "-changed"
			}
		}
		if r.Status != nil {
			*r.Status = -1
		}
		if r.Surface != nil {
			*r.Surface = "changed"
		}
	}},
	{"record fp", func(e *event.Event) {
		r := e.Record()
		if r.FP == nil {
			return
		}
		for _, p := range []*string{r.FP.JA4, r.FP.H2, r.FP.Hdr} {
			if p != nil {
				*p = "changed"
			}
		}
		r.FP.JA4, r.FP.H2, r.FP.Hdr = nil, new(string), new(string)
		r.FP = nil
	}},
	{"record detail", func(e *event.Event) {
		r := e.Record()
		if r.Detail == nil {
			return
		}
		for n := range r.Detail {
			r.Detail[n] = event.Str("changed")
		}
		r.Detail["added"] = event.Int(1)
		clear(r.Detail)
	}},
	{"body prefix bytes", func(e *event.Event) {
		b := e.BodyPrefix()
		for i := range b {
			b[i] = 0xAA // not a byte of any body prefix in these tests
		}
	}},
	{"body prefix append", func(e *event.Event) {
		b := append(e.BodyPrefix(), "tail"...)
		for i := range b {
			b[i] = 'X'
		}
	}},
}

// T-U-06, T-S-12: no use of the accessors changes an event. For each kind, an
// event with no optional field and an event with every field set go through
// each change in tampers. After each change, a second call of every accessor
// returns the first values, and Size is still the size computed from the public
// API.
func TestTS12_AccessorsShareNoMemory(t *testing.T) {
	variants := []struct {
		name string
		in   func(event.Kind) event.Input
	}{
		{"minimal", func(k event.Kind) event.Input { return event.Input{Kind: k} }},
		{"full", fullInput},
	}
	for _, k := range allKinds {
		for _, v := range variants {
			for _, tp := range tampers {
				t.Run(k.String()+"/"+v.name+"/"+tp.name, func(t *testing.T) {
					e := mustEvent(t, at(1758300000123), v.in(k))
					before := take(t, e)
					if v.name == "full" {
						rec := e.Record()
						if rec.Path == nil || *rec.Path != "/p?x=1" || rec.FP == nil || *rec.FP.JA4 != "ja4-value" ||
							rec.Detail["count"] != event.Int(7) || e.IP() != "2001:db8::7" || string(e.BodyPrefix()) != "body prefix bytes" {
							t.Fatalf("the event lacks a value of its input: %+v", rec)
						}
					} else if e.BodyPrefix() != nil || e.IP() != "" {
						t.Fatalf("a minimal event has a body prefix or an IP")
					}
					tp.run(e)
					before.same(t, e)
				})
			}
		}
	}
}

// T-S-12: a queue of a small depth holds events of the largest size. A caller
// tries to change each event after the enqueue. The byte sum of the queue stays
// the sum of Size over the accepted events, and it never passes the byte caps of
// the lanes. These caps are 24 MiB for the bulk lane and 8 MiB for the evidence
// lane, as the Queue documentation says. The second case uses the largest depth,
// so that the byte caps and not the lane lengths drop the events.
func TestTS12_QueueBytesWithChangedEvents(t *testing.T) {
	const bulkCap, evidenceCap = 24 << 20, 8 << 20
	for _, c := range []struct {
		name    string
		depth   int
		offered int
		byBytes bool
	}{
		{"small depth", 4, 12, false},
		{"byte cap drops", event.MaxQueueDepth, 1100, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			q, err := event.NewQueue(c.depth, event.NewCounters())
			if err != nil {
				t.Fatal(err)
			}
			snaps := map[*event.Event]snapshot{} // the values at the enqueue, for each accepted event
			var sum event.Bytes                  // the sum of Size over the accepted events
			var accepted [2]int
			check := func(when string) {
				t.Helper()
				if got := q.Bytes(); got != sum {
					t.Fatalf("%s: queue bytes %+v, sum of Size %+v", when, got, sum)
				}
				if sum.Bulk > bulkCap || sum.Evidence > evidenceCap {
					t.Fatalf("%s: byte sums %+v pass the caps %d and %d", when, sum, bulkCap, evidenceCap)
				}
			}
			for range c.offered {
				for i, k := range []event.Kind{event.KindRequest, event.KindCallback} {
					e := mustEvent(t, at(1), bigInput(k))
					size := e.Size()
					if size < event.MaxEventBytes*4/5 || size > event.MaxEventBytes {
						t.Fatalf("size %d is not near %d", size, event.MaxEventBytes)
					}
					if q.Enqueue(e) {
						snaps[e] = take(t, e)
						accepted[i]++
						if i == 0 {
							sum.Bulk += int64(size)
						} else {
							sum.Evidence += int64(size)
						}
					}
					check("after the enqueue")
					for _, tp := range tampers {
						tp.run(e)
					}
					check("after the changes")
					if e.Size() != size {
						t.Fatalf("Size is %d after the changes, was %d", e.Size(), size)
					}
				}
			}
			d := q.Dropped()
			if d.Bulk == 0 || d.Evidence == 0 || d.Invalid != 0 {
				t.Fatalf("dropped %+v: the test must drop bulk and evidence events", d)
			}
			if c.byBytes && (accepted[0] >= c.depth || accepted[1] >= c.depth/4) {
				t.Fatalf("accepted %v events: the lane lengths, not the byte caps, dropped them", accepted)
			}
			for {
				e, ok := q.TryTake()
				if !ok {
					break
				}
				snap, found := snaps[e]
				if !found || e.Size() != snap.size {
					t.Fatalf("taken event: accepted %v, Size %d, was %d", found, e.Size(), snap.size)
				}
				snap.same(t, e) // also checks Size against the size computed from the public API
				size := int64(snap.size)
				delete(snaps, e)
				if ev, _ := e.Kind().IsEvidence(); ev {
					sum.Evidence -= size
				} else {
					sum.Bulk -= size
				}
				check("after a take")
			}
			if len(snaps) != 0 || sum != (event.Bytes{}) {
				t.Errorf("%d accepted events were not taken, sum %+v", len(snaps), sum)
			}
		})
	}
}
