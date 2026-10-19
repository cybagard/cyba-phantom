package event

import (
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
	}{
		{"status", func(in *Input) { in.Status = &st }},
		{"vhost", func(in *Input) { in.Vhost = "a.example" }},
		{"method", func(in *Input) { in.Method = "GET" }},
		{"path", func(in *Input) { in.Path = "/" }},
		{"trap_id", func(in *Input) { in.TrapID = "t-1" }},
		{"token_id", func(in *Input) { in.TokenID = "k-1" }},
		{"surface", func(in *Input) { in.Surface = SurfacePath }},
		{"session", func(in *Input) { in.Session = "s-1" }},
		{"body prefix", func(in *Input) { in.BodyPrefix = []byte("x") }},
		{"reason zero", func(in *Input) { in.Reason = 0 }},
		{"reason past the last", func(in *Input) { in.Reason = ReasonRefusedRequest + 1 }},
		{"caller detail", func(in *Input) { in.Detail = Detail{"reason": Str("bad_hello")} }},
		{"empty caller detail", func(in *Input) { in.Detail = Detail{} }},
	} {
		t.Run(c.name, func(t *testing.T) {
			if e, err := NewEvent(fixedClock(1), refusedInput(c.mod)); err == nil || e != nil {
				t.Errorf("accepted: %v", e)
			}
		})
	}
	t.Run("reason on another kind", func(t *testing.T) {
		if _, err := NewEvent(fixedClock(1), Input{Kind: KindRequest, Reason: ReasonBadHello}); err == nil {
			t.Error("accepted")
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
	st, s := int64(400), Surface("path")
	for _, c := range []struct {
		name string
		mod  func(*Record)
	}{
		{"second member", func(r *Record) { r.Detail["x"] = Int(1) }},
		{"reason outside the five", func(r *Record) { r.Detail["reason"] = Str("other") }},
		{"empty reason", func(r *Record) { r.Detail["reason"] = Str("") }},
		{"reason not a string", func(r *Record) { r.Detail["reason"] = Int(1) }},
		{"other member name", func(r *Record) { r.Detail = Detail{"why": Str("bad_hello")} }},
		{"no detail", func(r *Record) { r.Detail = nil }},
		{"status", func(r *Record) { r.Status = &st }},
		{"vhost", func(r *Record) { r.Vhost = sp("a") }},
		{"method", func(r *Record) { r.Method = sp("GET") }},
		{"path", func(r *Record) { r.Path = sp("/") }},
		{"trap_id", func(r *Record) { r.TrapID = sp("t") }},
		{"token_id", func(r *Record) { r.TokenID = sp("k") }},
		{"surface", func(r *Record) { r.Surface = (*Surface)(&s) }},
		{"session", func(r *Record) { r.Session = sp("s") }},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := good()
			c.mod(&r)
			if _, err := r.canonical(); err == nil {
				t.Error("canonical accepted the record")
			}
		})
	}
	row := func(detail *string) Row { return Row{TS: 1, Kind: "refused", Detail: detail} }
	for _, d := range []string{`{"reason":"bad_hello"}`, `{"reason":"refused_request"}`} {
		if _, err := RecordFromRow(row(&d)); err != nil {
			t.Errorf("row %s: %v", d, err)
		}
	}
	for _, d := range []string{`{"reason":"x"}`, `{"reason":"bad_hello","a":1}`, `{"reason":1}`} {
		if _, err := RecordFromRow(row(&d)); err == nil {
			t.Errorf("row %s accepted", d)
		}
	}
	if _, err := RecordFromRow(row(nil)); err == nil {
		t.Error("row with no detail accepted")
	}
	withStatus := row(sp(`{"reason":"bad_hello"}`))
	withStatus.Status = &st
	if _, err := RecordFromRow(withStatus); err == nil {
		t.Error("row with a status accepted")
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
	if !q.Enqueue(big) || !q.Enqueue(big) {
		t.Fatal("the cap holds two refused events")
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
