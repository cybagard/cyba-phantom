package event

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// qEvent makes an event of kind k for the client address ip. An empty ip gives
// an event with no client address.
func qEvent(t testing.TB, k Kind, ip string) *Event {
	t.Helper()
	e, err := NewEvent(fixedClock(1), Input{Kind: k, ClientIP: ip})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// qBigEvent makes an event of kind k with the longest fields that a record
// allows. Its size is near MaxEventBytes.
func qBigEvent(t testing.TB, k Kind) *Event {
	t.Helper()
	ctl := strings.Repeat("\x01", 300)
	st := int64(-maxInt)
	e, err := NewEvent(fixedClock(-maxInt), Input{Kind: k, Session: ctl, Vhost: ctl + strings.Repeat("a", 253),
		Method: ctl, Path: strings.Repeat("\x01", 2100), TrapID: ctl, TokenID: ctl, Status: &st,
		Surface: SurfaceHeader, JA4: ctl, H2: ctl, Hdr: ctl,
		Detail:   Detail{"a": Str(strings.Repeat("\x01", 340))},
		ClientIP: "2001:db8:1234:5678:9abc:def0:1234:5678", BodyPrefix: make([]byte, 9000)})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func mustQueue(t testing.TB, depth int, bulkCap, evidenceCap int64) (*Queue, *Counters) {
	t.Helper()
	c := NewCounters()
	q, err := newQueue(depth, bulkCap, evidenceCap, c)
	if err != nil {
		t.Fatal(err)
	}
	return q, c
}

// T-U-17: the depth is 1 to 8192, the counters value must be ready, and the
// lanes have the capacities of the rule.
func TestTU17_QueueConstructor(t *testing.T) {
	for _, d := range []int{-1, 0, MaxQueueDepth + 1} {
		if _, err := NewQueue(d, NewCounters()); err == nil {
			t.Errorf("depth %d: want an error", d)
		}
	}
	if _, err := NewQueue(4, nil); err == nil {
		t.Error("nil counters: want an error")
	}
	if _, err := NewQueue(4, &Counters{}); err == nil {
		t.Error("zero counters: want an error")
	}
	for _, c := range []struct{ depth, evidence int }{
		{1, 1}, {3, 1}, {4, 1}, {7, 1}, {8, 2}, {100, 25}, {4096, 1024}, {MaxQueueDepth, 2048},
	} {
		q, err := NewQueue(c.depth, NewCounters())
		if err != nil {
			t.Fatal(err)
		}
		if cap(q.bulk) != c.depth || cap(q.evidence) != c.evidence {
			t.Errorf("depth %d: caps %d and %d, want %d and %d", c.depth, cap(q.bulk), cap(q.evidence), c.depth, c.evidence)
		}
	}
}

// T-U-17: many producers and a stopped consumer. The enqueues finish in
// bounded time, the byte sum of each lane stays in its cap, and the queue counts
// each drop one time, for its lane and for its client key. The capacity of a
// channel is the count bound of the lane, so the test does not check it.
func TestTU17_QueueConcurrentBounds(t *testing.T) {
	const depth, producers = 16, 8
	// The caps are less than the lanes can hold: 10 of 16 bulk events and 3 of 4
	// evidence events.
	bulkCap := int64(qEvent(t, KindRequest, "192.0.2.1").Size()) * 10
	evidenceCap := int64(qEvent(t, KindCallback, "192.0.2.1").Size()) * 3
	q, c := mustQueue(t, depth, bulkCap, evidenceCap)

	kinds := []Kind{KindRequest, KindBeacon, KindCallback, KindScoreChange, KindAlertSent, KindBundleLoad}
	var evs []*Event
	for i, k := range kinds {
		ip := fmt.Sprintf("192.0.2.%d", i+1)
		if k == KindBundleLoad {
			ip = "" // a system event has no client
		}
		evs = append(evs, qEvent(t, k, ip))
	}
	evidence := func(i int) bool { return i >= 2 }

	var offered, accepted [2]atomic.Uint64
	stop := make(chan struct{})
	var watcher sync.WaitGroup
	watcher.Add(1)
	go func() {
		defer watcher.Done()
		for {
			if b := q.Bytes(); b.Bulk > bulkCap || b.Evidence > evidenceCap {
				t.Errorf("byte cap passed: bulk %d of %d, evidence %d of %d", b.Bulk, bulkCap, b.Evidence, evidenceCap)
				return
			}
			select {
			case <-stop:
				return
			default:
			}
		}
	}()

	done := make(chan struct{})
	var wg sync.WaitGroup
	for p := 0; p < producers; p++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 10*depth; i++ {
				idx := (i + p) % len(evs)
				lane := 0
				if evidence(idx) {
					lane = 1
				}
				offered[lane].Add(1)
				if q.Enqueue(evs[idx]) {
					accepted[lane].Add(1)
				}
			}
		}()
	}
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("enqueue did not finish: a producer blocks")
	}
	close(stop)
	watcher.Wait()

	d := q.Dropped()
	if want := offered[0].Load() - accepted[0].Load(); d.Bulk != want {
		t.Errorf("bulk dropped %d, want offered-accepted %d", d.Bulk, want)
	}
	if want := offered[1].Load() - accepted[1].Load(); d.Evidence != want {
		t.Errorf("evidence dropped %d, want offered-accepted %d", d.Evidence, want)
	}
	if d.Invalid != 0 {
		t.Errorf("invalid dropped %d, want 0", d.Invalid)
	}
	if d.Bulk+d.Evidence == 0 {
		t.Fatal("the test dropped nothing")
	}
	m, overflow := c.Snapshot()
	if got := total(m, overflow); got != d.Bulk+d.Evidence {
		t.Errorf("counters hold %d drops, want %d", got, d.Bulk+d.Evidence)
	}
	var queued Bytes
	for _, e := range q.Drain() {
		if isEv, _ := e.Record.Kind.IsEvidence(); isEv {
			queued.Evidence += int64(e.Size())
		} else {
			queued.Bulk += int64(e.Size())
		}
	}
	if queued.Bulk > bulkCap || queued.Evidence > evidenceCap || q.Bytes() != (Bytes{}) {
		t.Errorf("queued %+v (caps %d and %d), sums after drain %+v", queued, bulkCap, evidenceCap, q.Bytes())
	}
}

// T-U-17: the evidence lane accepts events while the bulk lane is full, and
// the consumer takes the evidence lane first.
func TestTU17_QueueEvidenceFirst(t *testing.T) {
	const depth = 8
	q, c := mustQueue(t, depth, maxBulkBytes, maxEvidenceBytes)
	for i := 0; i < depth; i++ {
		if !q.Enqueue(qEvent(t, KindRequest, "192.0.2.1")) {
			t.Fatalf("bulk event %d was dropped", i)
		}
	}
	if q.Enqueue(qEvent(t, KindBeacon, "192.0.2.1")) {
		t.Fatal("bulk lane accepted an event when full")
	}
	for i := 0; i < cap(q.evidence); i++ {
		if !q.Enqueue(qEvent(t, KindCallback, "192.0.2.2")) {
			t.Fatalf("evidence event %d was dropped while the bulk lane is full", i)
		}
	}
	if q.Enqueue(qEvent(t, KindCallback, "192.0.2.2")) {
		t.Fatal("evidence lane accepted an event when full")
	}
	d := q.Dropped()
	if d.Bulk != 1 || d.Evidence != 1 {
		t.Errorf("dropped %+v, want 1 bulk and 1 evidence", d)
	}
	var kinds []Kind
	for {
		e, ok := q.TryTake()
		if !ok {
			break
		}
		kinds = append(kinds, e.Record.Kind)
	}
	if len(kinds) != depth+cap(q.evidence) {
		t.Fatalf("took %d events", len(kinds))
	}
	for i, k := range kinds {
		if want := i < cap(q.evidence); want != (k == KindCallback) {
			t.Fatalf("take %d is %v: the evidence lane is not first", i, k)
		}
	}
	m, overflow := c.Snapshot()
	if m[mustAddr(t, "192.0.2.1")] != 1 || m[mustAddr(t, "192.0.2.2")] != 1 || overflow != 0 {
		t.Errorf("counters: %d keys, overflow %d; want one drop for each key", len(m), overflow)
	}
}

// T-U-17: the byte cap of the bulk lane drops a large event when the lane has
// room. The consumer gives the bytes back.
func TestTU17_QueueByteBudget(t *testing.T) {
	big := qBigEvent(t, KindRequest)
	// MaxEventBytes is a bound with room above the longest real event.
	if big.Size() < MaxEventBytes*4/5 || big.Size() > MaxEventBytes {
		t.Fatalf("size %d is not near %d", big.Size(), MaxEventBytes)
	}
	small := qEvent(t, KindBeacon, "192.0.2.9")
	budget := int64(2*big.Size() + small.Size())
	q, c := mustQueue(t, 100, budget, maxEvidenceBytes)
	if !q.Enqueue(big) || !q.Enqueue(big) {
		t.Fatal("the budget holds two large events")
	}
	if q.Enqueue(big) {
		t.Fatal("a third large event passed the budget")
	}
	if len(q.bulk) != 2 || q.Dropped().Bulk != 1 {
		t.Fatalf("lane has %d events, dropped %+v", len(q.bulk), q.Dropped())
	}
	if !q.Enqueue(small) || q.Bytes().Bulk != budget {
		t.Fatalf("small event dropped or sum %d, want %d", q.Bytes().Bulk, budget)
	}
	if q.Enqueue(small) {
		t.Fatal("an event passed a full budget")
	}
	if _, ok := q.TryTake(); !ok || q.Bytes().Bulk != budget-int64(big.Size()) {
		t.Fatalf("take did not give the bytes back: sum %d", q.Bytes().Bulk)
	}
	if !q.Enqueue(big) {
		t.Fatal("a large event is dropped after the take")
	}
	m, overflow := c.Snapshot()
	if got := total(m, overflow); got != 2 {
		t.Errorf("counters hold %d drops, want 2", got)
	}
}

// T-U-17: producers together never push the byte sum of a lane past its cap.
func TestTU17_QueueByteBudgetConcurrent(t *testing.T) {
	e := qEvent(t, KindRequest, "192.0.2.1")
	const fit = 5
	q, _ := mustQueue(t, MaxQueueDepth, int64(fit*e.Size()), maxEvidenceBytes)
	var accepted atomic.Int64
	var wg sync.WaitGroup
	for p := 0; p < 8; p++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				if q.Enqueue(e) {
					accepted.Add(1)
				}
				if q.Bytes().Bulk > int64(fit*e.Size()) {
					t.Error("the byte sum passed the cap")
					return
				}
			}
		}()
	}
	wg.Wait()
	if accepted.Load() != fit || q.Dropped().Bulk != 8*200-fit {
		t.Errorf("accepted %d, dropped %+v: want %d accepted", accepted.Load(), q.Dropped(), fit)
	}
}

// T-U-17: maximum-size bulk events fill the byte cap of the bulk lane, and the
// evidence lane still accepts every callback event (SEC-15, ADR-019). The bulk
// lane has room by count, so the byte cap causes the drops. The test runs at
// the default depth and at the largest depth.
func TestTU17_QueueLaneByteCaps(t *testing.T) {
	big := qBigEvent(t, KindRequest)
	small := qEvent(t, KindBeacon, "192.0.2.1")
	for _, depth := range []int{4096, 8192} {
		t.Run(fmt.Sprint(depth), func(t *testing.T) {
			q, _ := mustQueue(t, depth, maxBulkBytes, maxEvidenceBytes)
			for q.Dropped().Bulk == 0 && q.Enqueue(big) {
			}
			// Small events use the bytes that a large event cannot use.
			for q.Dropped().Bulk == 1 && q.Enqueue(small) {
			}
			if q.Dropped().Bulk != 2 || len(q.bulk) >= depth {
				t.Fatalf("depth %d: dropped %+v with %d of %d bulk events; want the byte cap to drop them", depth, q.Dropped(), len(q.bulk), depth)
			}
			accepted := 0
			for i := 0; i < 10; i++ {
				if q.Enqueue(qEvent(t, KindCallback, "192.0.2.2")) {
					accepted++
				}
			}
			b := q.Bytes()
			if accepted != 10 || q.Dropped().Evidence != 0 {
				t.Errorf("depth %d: %d of 10 callback events accepted, dropped %+v", depth, accepted, q.Dropped())
			}
			if b.Bulk > maxBulkBytes || b.Evidence > maxEvidenceBytes {
				t.Errorf("depth %d: byte sums %+v pass the caps %d and %d", depth, b, maxBulkBytes, maxEvidenceBytes)
			}
		})
	}
}

// T-U-17: the shutdown order of Close. All producers return, then Close, then
// Drain takes every event that Enqueue accepted, in both lanes.
func TestTU17_QueueShutdown(t *testing.T) {
	const depth, producers, rounds = 64, 8, 500
	q, _ := mustQueue(t, depth, maxBulkBytes, maxEvidenceBytes)
	kinds := []Kind{KindRequest, KindBeacon, KindCallback, KindScoreChange}
	var evs []*Event
	for _, k := range kinds {
		evs = append(evs, qEvent(t, k, "192.0.2.1"))
	}
	var accepted [2]atomic.Uint64 // bulk, evidence
	var wg sync.WaitGroup
	for p := 0; p < producers; p++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < rounds; i++ {
				idx := (i + p) % len(evs)
				if q.Enqueue(evs[idx]) {
					accepted[idx/2].Add(1)
				}
			}
		}()
	}
	wg.Wait()
	q.Close()
	var drained [2]uint64
	for _, e := range q.Drain() {
		if isEv, _ := e.Record.Kind.IsEvidence(); isEv {
			drained[1]++
		} else {
			drained[0]++
		}
	}
	if drained[0] != accepted[0].Load() || drained[1] != accepted[1].Load() {
		t.Errorf("drained %d bulk and %d evidence events, accepted %d and %d", drained[0], drained[1], accepted[0].Load(), accepted[1].Load())
	}
	if drained[0] == 0 || drained[1] == 0 || q.Dropped().Bulk == 0 || q.Dropped().Evidence == 0 {
		t.Errorf("the test must accept and drop events in both lanes: drained %v, dropped %+v", drained, q.Dropped())
	}
	if len(q.Drain()) != 0 || q.Bytes() != (Bytes{}) {
		t.Error("queue is not empty after drain")
	}
}

// T-U-17: Enqueue after Close counts a drop and does not panic. The consumer
// drains the events that were queued before Close.
func TestTU17_QueueClose(t *testing.T) {
	q, c := mustQueue(t, 4, maxBulkBytes, maxEvidenceBytes)
	q.Enqueue(qEvent(t, KindRequest, "192.0.2.1"))
	q.Enqueue(qEvent(t, KindCallback, "192.0.2.1"))
	if q.Closed() {
		t.Fatal("new queue is closed")
	}
	q.Close()
	q.Close()
	if !q.Closed() {
		t.Fatal("Close did not close")
	}
	if q.Enqueue(qEvent(t, KindRequest, "2001:db8::1")) || q.Enqueue(qEvent(t, KindCallback, "")) {
		t.Fatal("closed queue accepted an event")
	}
	if d := q.Dropped(); d.Bulk != 1 || d.Evidence != 1 {
		t.Errorf("dropped %+v, want 1 bulk and 1 evidence", d)
	}
	m, overflow := c.Snapshot()
	if m[mustAddr(t, "2001:db8::")] != 1 || overflow != 1 {
		t.Errorf("counters: %d keys, overflow %d; want the /64 key and one no-address drop", len(m), overflow)
	}
	select {
	case <-q.Ready():
	default:
		t.Error("Ready has no value after Close")
	}
	got := q.Drain()
	if len(got) != 2 || got[0].Record.Kind != KindCallback || got[1].Record.Kind != KindRequest {
		t.Errorf("drain gave %d events, want the evidence event then the bulk event", len(got))
	}
	if len(q.Drain()) != 0 || q.Bytes() != (Bytes{}) {
		t.Error("queue is not empty after drain")
	}
}

// T-U-17: Ready tells the consumer about an accepted event. A nil event, a kind
// that is not known, and an event that NewEvent did not make (Size 0) are never
// queued.
func TestTU17_QueueReadyAndInvalid(t *testing.T) {
	q, c := mustQueue(t, 4, maxBulkBytes, maxEvidenceBytes)
	select {
	case <-q.Ready():
		t.Fatal("Ready has a value in an empty queue")
	default:
	}
	q.Enqueue(qEvent(t, KindRequest, ""))
	select {
	case <-q.Ready():
	default:
		t.Fatal("Ready has no value after an accepted event")
	}
	q.TryTake()
	literal := func(k Kind, ip string) *Event {
		return &Event{Record: Record{Kind: k}, DB: DBOnly{IP: ip, BodyPrefix: make([]byte, 1<<20)}}
	}
	if q.Enqueue(nil) || q.Enqueue(&Event{Record: Record{Kind: 0}}) || q.Enqueue(literal(99, "198.51.100.1")) ||
		q.Enqueue(literal(KindRequest, "198.51.100.2")) || q.Enqueue(literal(KindCallback, "")) {
		t.Fatal("an invalid event was accepted")
	}
	if d := q.Dropped(); d != (Dropped{Invalid: 5}) {
		t.Errorf("dropped %+v, want 5 invalid", d)
	}
	if len(q.bulk) != 0 || len(q.evidence) != 0 || q.Bytes() != (Bytes{}) {
		t.Error("an invalid event is in a lane")
	}
	m, overflow := c.Snapshot()
	if len(m) != 2 || m[mustAddr(t, "198.51.100.1")] != 1 || m[mustAddr(t, "198.51.100.2")] != 1 || overflow != 3 {
		t.Errorf("counters: %d keys, overflow %d; want 2 keys and overflow 3", len(m), overflow)
	}
}

// T-U-17: an IP text that is not an address goes to the overflow bucket.
func TestTU17_QueueBadAddress(t *testing.T) {
	q, c := mustQueue(t, 1, maxBulkBytes, maxEvidenceBytes)
	q.Enqueue(qEvent(t, KindRequest, ""))
	// NewEvent rejects this text, so the test sets it after NewEvent.
	e := qEvent(t, KindRequest, "")
	e.DB.IP = "not-an-address"
	q.Enqueue(e)
	m, overflow := c.Snapshot()
	if len(m) != 0 || overflow != 1 {
		t.Errorf("counters: %d keys, overflow %d; want overflow 1", len(m), overflow)
	}
}
