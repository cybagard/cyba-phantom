package event

import (
	"errors"
	"strings"
	"testing"
)

var allReasons = []RefusedReason{
	ReasonNoServerName, ReasonUnknownName, ReasonBadHello, ReasonClientAbort, ReasonRefusedRequest,
}

var reasonText = []string{"no_server_name", "unknown_name", "bad_hello", "client_abort", "refused_request"}

func refusedInput(mod func(*Input)) Input {
	in := Input{Kind: KindRefused, Reason: ReasonBadHello}
	if mod != nil {
		mod(&in)
	}
	return in
}

// T-U-06: refused is a ninth kind that is not evidence and not a system kind.
// The eight other kinds keep their names and results.
func TestTU06_RefusedKind(t *testing.T) {
	k, err := ParseKind("refused")
	if err != nil || k != KindRefused || !k.valid() || k.String() != "refused" {
		t.Fatalf("ParseKind(refused) = %v, %v", k, err)
	}
	if b, err := k.MarshalText(); err != nil || string(b) != "refused" {
		t.Errorf("MarshalText = %q, %v", b, err)
	}
	if ev, err := k.IsEvidence(); ev || err != nil {
		t.Errorf("IsEvidence = %v, %v", ev, err)
	}
	if k.isSystem() {
		t.Error("refused is a system kind")
	}
	if KindRefused != KindRetention+1 {
		t.Errorf("refused is %d, want the value after retention", KindRefused)
	}
	old := []struct {
		k        Kind
		name     string
		evidence bool
		system   bool
	}{
		{KindRequest, "request", false, false}, {KindCallback, "callback", true, false},
		{KindBeacon, "beacon", false, false}, {KindScoreChange, "score_change", true, false},
		{KindBundleLoad, "bundle_load", true, true}, {KindBundleRejected, "bundle_rejected", true, true},
		{KindAlertSent, "alert_sent", true, false}, {KindRetention, "retention", true, true},
	}
	for i, c := range old {
		ev, err := c.k.IsEvidence()
		if int(c.k) != i+1 || c.k.String() != c.name || ev != c.evidence || err != nil || c.k.isSystem() != c.system {
			t.Errorf("kind %d (%s) changed", c.k, c.name)
		}
	}
}

// T-U-06: each input that a refused event cannot have is refused, one case for
// each input.
func TestTU06_RefusedInputs(t *testing.T) {
	st := int64(400)
	for _, c := range []struct {
		name string
		mod  func(*Input)
		want error
	}{
		{"status", func(in *Input) { in.Status = &st }, errRefusedField},
		{"vhost", func(in *Input) { in.Vhost = "a.example" }, errRefusedField},
		{"method", func(in *Input) { in.Method = "GET" }, errRefusedField},
		{"path", func(in *Input) { in.Path = "/" }, errRefusedField},
		{"trap_id", func(in *Input) { in.TrapID = "t-1" }, errRefusedField},
		{"token_id", func(in *Input) { in.TokenID = "k-1" }, errRefusedField},
		{"surface", func(in *Input) { in.Surface = SurfacePath }, errRefusedField},
		{"session", func(in *Input) { in.Session = "s-1" }, errRefusedField},
		{"h2", func(in *Input) { in.H2 = "x" }, errRefusedField},
		{"hdr", func(in *Input) { in.Hdr = "y" }, errRefusedField},
		{"body prefix", func(in *Input) { in.BodyPrefix = []byte("x") }, errRefusedInput},
		{"reason zero", func(in *Input) { in.Reason = 0 }, errRefusedReason},
		{"reason past the last", func(in *Input) { in.Reason = ReasonRefusedRequest + 1 }, errRefusedReason},
		{"caller detail", func(in *Input) { in.Detail = Detail{"reason": Str("bad_hello")} }, errRefusedInput},
		{"empty caller detail", func(in *Input) { in.Detail = Detail{} }, errRefusedInput},
	} {
		t.Run(c.name, func(t *testing.T) {
			if e, err := NewEvent(fixedClock(1), refusedInput(c.mod)); !errors.Is(err, c.want) || e != nil {
				t.Errorf("event %v, error %v, want %v", e, err, c.want)
			}
		})
	}
	t.Run("reason on another kind", func(t *testing.T) {
		if _, err := NewEvent(fixedClock(1), Input{Kind: KindRequest, Reason: ReasonBadHello}); !errors.Is(err, errReasonKind) {
			t.Errorf("error %v, want %v", err, errReasonKind)
		}
	})
}

// T-U-06: each of the five reasons gives the detail with one member, and the
// client address and the JA4 text are allowed.
func TestTU06_RefusedReasons(t *testing.T) {
	for i, r := range allReasons {
		if r.String() != reasonText[i] {
			t.Errorf("reason %d is %q", r, r.String())
		}
		e, err := NewEvent(fixedClock(1), refusedInput(func(in *Input) { in.Reason = r }))
		if err != nil {
			t.Fatal(err)
		}
		d := e.Record().Detail
		if v, ok := d["reason"]; len(d) != 1 || !ok || v != Str(reasonText[i]) {
			t.Errorf("reason %q: detail %v", reasonText[i], d)
		}
	}
	if ReasonRefusedRequest+1 != 6 || (ReasonRefusedRequest+1).String() != "unknown" || RefusedReason(0).String() != "unknown" {
		t.Error("the reason set is not closed")
	}
	e, err := NewEvent(fixedClock(1), refusedInput(func(in *Input) { in.ClientIP = "192.0.2.7"; in.JA4 = "t13d" }))
	if err != nil {
		t.Fatal(err)
	}
	if r := e.Record(); e.IP() != "192.0.2.7" || r.FP == nil || *r.FP.JA4 != "t13d" || r.Session != nil {
		t.Errorf("ip %q, record %+v", e.IP(), r)
	}
}

// T-U-06: the record rule of the kind holds for a stored row and for the
// encoder, not only for NewEvent.
func TestTU06_RefusedRecordRules(t *testing.T) {
	good := func() Record { return Record{TS: 1, Kind: KindRefused, Detail: Detail{"reason": Str("client_abort")}} }
	if _, err := good().canonical(); err != nil {
		t.Fatal(err)
	}
	withJA4 := good()
	withJA4.FP = &FP{JA4: sp("t13d")}
	if _, err := withJA4.canonical(); err != nil {
		t.Errorf("a record with only fp.ja4: %v", err)
	}
	st, s := int64(400), Surface("path")
	for _, c := range []struct {
		name string
		mod  func(*Record)
		want error
	}{
		{"second member", func(r *Record) { r.Detail["x"] = Int(1) }, errRefusedDetail},
		{"reason outside the five", func(r *Record) { r.Detail["reason"] = Str("other") }, errRefusedReason},
		{"empty reason", func(r *Record) { r.Detail["reason"] = Str("") }, errRefusedReason},
		{"reason not a string", func(r *Record) { r.Detail["reason"] = Int(1) }, errRefusedDetail},
		{"other member name", func(r *Record) { r.Detail = Detail{"why": Str("bad_hello")} }, errRefusedDetail},
		{"no detail", func(r *Record) { r.Detail = nil }, errRefusedDetail},
		{"empty detail", func(r *Record) { r.Detail = Detail{} }, errRefusedDetail},
		{"status", func(r *Record) { r.Status = &st }, errRefusedField},
		{"vhost", func(r *Record) { r.Vhost = sp("a") }, errRefusedField},
		{"method", func(r *Record) { r.Method = sp("GET") }, errRefusedField},
		{"path", func(r *Record) { r.Path = sp("/") }, errRefusedField},
		{"trap_id", func(r *Record) { r.TrapID = sp("t") }, errRefusedField},
		{"token_id", func(r *Record) { r.TokenID = sp("k") }, errRefusedField},
		{"surface", func(r *Record) { r.Surface = (*Surface)(&s) }, errRefusedField},
		{"session", func(r *Record) { r.Session = sp("s") }, errRefusedField},
		{"fp.h2", func(r *Record) { r.FP = &FP{H2: sp("x")} }, errRefusedField},
		{"fp.hdr", func(r *Record) { r.FP = &FP{Hdr: sp("y")} }, errRefusedField},
		{"bad reason and status", func(r *Record) { r.Detail["reason"] = Str("other"); r.Status = &st }, errRefusedField},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := good()
			c.mod(&r)
			if _, err := r.canonical(); !errors.Is(err, c.want) {
				t.Errorf("error %v, want %v", err, c.want)
			}
		})
	}
	row := func(detail *string) Row { return Row{TS: 1, Kind: "refused", Detail: detail} }
	for _, d := range []string{`{"reason":"bad_hello"}`, `{"reason":"refused_request"}`} {
		if _, err := RecordFromRow(row(&d)); err != nil {
			t.Errorf("row %s: %v", d, err)
		}
	}
	// The session column of a refused row is not part of the record.
	stored := row(sp(`{"reason":"bad_hello"}`))
	stored.SessionID = sp("abcdefghijklmnopqrstuvwxyz")
	stored.FP = &FP{JA4: sp("t13d")}
	if r, err := RecordFromRow(stored); err != nil || r.Session != nil {
		t.Errorf("row with a session id: session %v, error %v", r.Session, err)
	}
	if r, err := RecordFromRow(Row{TS: 1, Kind: "request", SessionID: sp("s-1")}); err != nil || r.Session == nil || *r.Session != "s-1" {
		t.Errorf("request row: session %v, error %v", r.Session, err)
	}
	for _, c := range []struct {
		name string
		row  Row
		want error
	}{
		{"reason outside the five", row(sp(`{"reason":"x"}`)), errRefusedReason},
		{"second member", row(sp(`{"reason":"bad_hello","a":1}`)), errRefusedDetail},
		{"reason not a string", row(sp(`{"reason":1}`)), errRefusedDetail},
		{"no detail", row(nil), errRefusedDetail},
		{"status", func() Row { r := row(sp(`{"reason":"bad_hello"}`)); r.Status = &st; return r }(), errRefusedField},
		{"fp.h2", func() Row { r := row(sp(`{"reason":"bad_hello"}`)); r.FP = &FP{H2: sp("x")}; return r }(), errRefusedField},
		{"fp.hdr", func() Row { r := row(sp(`{"reason":"bad_hello"}`)); r.FP = &FP{Hdr: sp("y")}; return r }(), errRefusedField},
	} {
		t.Run("row "+c.name, func(t *testing.T) {
			if _, err := RecordFromRow(c.row); !errors.Is(err, c.want) {
				t.Errorf("error %v, want %v", err, c.want)
			}
		})
	}
	// ParseDetail has its own error for a text that is not an object: the test
	// checks only that the row is refused.
	if _, err := RecordFromRow(row(sp(`{"reason":`))); err == nil {
		t.Error("row with a detail text that does not parse accepted")
	}
}

// refusedBig makes the largest refused event: the longest JA4 text and the
// longest client address.
func refusedBig(t testing.TB) *Event {
	t.Helper()
	e, err := NewEvent(fixedClock(1), refusedInput(func(in *Input) {
		in.JA4 = strings.Repeat("a", capFP)
		in.ClientIP = "2001:db8:1234:5678:9abc:def0:1234:5678"
	}))
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// T-U-17: a refused event uses the bulk lane. It is accepted while the evidence
// lane is full. It is dropped while the bulk lane is full by count. The evidence
// hash and the evidence bytes refuse it.
func TestTU17_RefusedLane(t *testing.T) {
	const depth = 4
	q, c := mustQueue(t, depth, maxBulkBytes, maxEvidenceBytes)
	for i := 0; i < cap(q.evidence); i++ {
		q.Enqueue(qEvent(t, KindCallback, "192.0.2.2"))
	}
	if q.Enqueue(qEvent(t, KindCallback, "192.0.2.2")) {
		t.Fatal("the evidence lane is not full")
	}
	for i := 0; i < depth; i++ {
		if !q.Enqueue(refusedBig(t)) {
			t.Fatalf("refused event %d was dropped while the evidence lane is full", i)
		}
	}
	if len(q.bulk) != depth || len(q.evidence) != cap(q.evidence) {
		t.Fatalf("lanes hold %d bulk and %d evidence events", len(q.bulk), len(q.evidence))
	}
	extra, err := NewEvent(fixedClock(1), refusedInput(func(in *Input) { in.ClientIP = "192.0.2.3" }))
	if err != nil {
		t.Fatal(err)
	}
	if q.Enqueue(extra) {
		t.Fatal("a refused event passed a bulk lane that is full by count")
	}
	if d := q.Dropped(); d != (Dropped{Bulk: 1, Evidence: 1}) {
		t.Errorf("dropped %+v, want 1 bulk and 1 evidence", d)
	}
	if m, overflow := c.Snapshot(); m[mustAddr(t, "192.0.2.3")] != 1 || total(m, overflow) != 2 {
		t.Errorf("counters: %v, overflow %d", m, overflow)
	}
	r := refusedBig(t).Record()
	if h, err := HashEvidence(r); err == nil || h != [32]byte{} {
		t.Errorf("HashEvidence = %x, %v", h, err)
	}
	if b, err := EvidenceBytes(r); err == nil || b != nil {
		t.Errorf("EvidenceBytes = %q, %v", b, err)
	}
}

// T-U-17: the size of a refused event of near-maximum size counts in the byte
// cap of the bulk lane and not in the evidence lane. The consumer gives the
// bytes back.
func TestTU17_RefusedByteCap(t *testing.T) {
	big := refusedBig(t)
	if big.Size() <= capFP || big.Size() > MaxEventBytes {
		t.Fatalf("size %d", big.Size())
	}
	q, _ := mustQueue(t, 100, int64(2*big.Size()), maxEvidenceBytes)
	if !q.Enqueue(big) {
		t.Fatal("the first refused event is dropped")
	}
	if !q.Enqueue(big) {
		t.Fatal("the second refused event is dropped")
	}
	if q.Bytes() != (Bytes{Bulk: int64(2 * big.Size())}) {
		t.Errorf("sums %+v, want the size of two events in the bulk lane", q.Bytes())
	}
	if q.Enqueue(big) || q.Dropped().Bulk != 1 || q.Dropped().Evidence != 0 {
		t.Errorf("a third event passed the cap: dropped %+v", q.Dropped())
	}
	if !q.Enqueue(qEvent(t, KindCallback, "192.0.2.1")) {
		t.Error("an evidence event was dropped while the bulk byte cap is full")
	}
	if _, ok := q.TryTake(); !ok || q.Bytes().Bulk != int64(2*big.Size()) {
		t.Errorf("the evidence take changed the bulk sum: %+v", q.Bytes())
	}
	if _, ok := q.TryTake(); !ok || q.Bytes().Bulk != int64(big.Size()) {
		t.Errorf("take did not give the bytes back: %+v", q.Bytes())
	}
}
