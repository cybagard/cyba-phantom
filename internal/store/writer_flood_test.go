package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cybagard/cyba-phantom/internal/event"
)

// refill adds n request events. A hook on the writer goroutine calls it, so it
// reports with Error and not with Fatal.
func (r *rig) refill(n int) {
	for range n {
		e, err := event.NewEvent(time.Now, event.Input{Kind: event.KindRequest})
		if err != nil || !r.q.Enqueue(e) {
			r.t.Error("refill failed")
			return
		}
	}
}

// flood puts 1 000 events in the lanes. After each commit, the writer adds 500
// events from its own goroutine until stop is set, so the next TryTake finds
// events and the lanes never run empty. At the first commit it calls first. It
// returns the number of commits.
func (r *rig) flood(stop *atomic.Bool, first func()) *atomic.Int64 {
	for i := range 1000 {
		r.add(event.KindRequest, int64(i))
	}
	var n atomic.Int64
	r.w.onCommit = func(int) {
		if n.Add(1) == 1 {
			first()
		}
		if !stop.Load() {
			r.refill(maxBatch)
		}
	}
	return &n
}

// T-U-18: under a flood that keeps the lanes full, a row request that waits gets
// its row between two batches, in less time than the sink timeout. The test
// sends the request through the sink at the first commit and keeps the flood
// until the sink has its reply, so a writer that serves the row only when the
// lanes are empty gives no reply in time.
func TestTU18RowRequestIsServedUnderAFlood(t *testing.T) {
	r := newSinkRigDepth(t, 4000)
	var stop atomic.Bool
	t.Cleanup(func() { stop.Store(true) })
	type result struct {
		err  error
		took time.Duration
	}
	done := make(chan result, 1)
	msg := r.note(7, 3)
	n := r.flood(&stop, func() {
		go func() {
			begin := time.Now()
			err := r.sink.Add(7, msg)
			stop.Store(true)
			done <- result{err, time.Since(begin)}
		}()
		// The next flush finds the request in the channel.
		for end := time.Now().Add(waitFor); len(r.w.rows) == 0 && time.Now().Before(end); runtime.Gosched() {
		}
	})
	var afterCommits int64
	var lanesFull bool
	r.w.beforeRowCommit = func(*sql.Tx) error {
		afterCommits, lanesFull = n.Load(), r.q.Bytes() != (event.Bytes{})
		return nil
	}
	stopRun := r.start()
	var res result
	select {
	case res = <-done:
	case <-time.After(2 * rowTimeout):
		t.Fatal("no reply of the sink")
	}
	if err := stopRun(); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if res.err != nil || res.took > rowTimeout || r.rowCount() != 1 {
		t.Fatalf("reply %v after %v, %d rows", res.err, res.took, r.rowCount())
	}
	if afterCommits < 1 || !lanesFull {
		t.Fatalf("the row was stored after %d commits, lanes not empty: %v", afterCommits, lanesFull)
	}
}

// T-U-18: under a flood that keeps the lanes full, the writer takes a tick
// between two batches. The tick channel has no buffer, so a completed send
// proves that the writer read it. The flood goes on until the send is done.
func TestTU18TickIsTakenUnderAFlood(t *testing.T) {
	r := newRig(t, 4000)
	var stop atomic.Bool
	t.Cleanup(func() { stop.Store(true) })
	sent := make(chan bool, 1)
	r.flood(&stop, func() {
		go func() {
			select {
			case r.tick <- time.Now():
				sent <- true
			case <-time.After(waitFor):
				sent <- false
			}
			stop.Store(true)
		}()
	})
	stopRun := r.start()
	if ok := <-sent; !ok {
		t.Fatal("the writer did not take the tick during the flood")
	}
	if err := stopRun(); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

// T-U-18: a writer that a flush has stopped serves no waiting row request: the
// request stays in the channel and the table has no row.
func TestTU18StoppedWriterServesNoWaitingRow(t *testing.T) {
	r := newSinkRig(t)
	r.w.rows <- rowRequest{size: 7, msg: r.note(7, 3), reply: make(chan error, 1)}
	r.w.stop(fail(writerName, ruleDatabase))
	r.w.serveWaiting(nil, nil)
	if len(r.w.rows) != 1 || r.rowCount() != 0 {
		t.Fatalf("%d requests wait (want 1), %d rows (want 0)", len(r.w.rows), r.rowCount())
	}
}

// T-U-18: a database error rolls the batch back and counts each event of the
// batch as a drop for its lane. The batch has three bulk and two evidence
// events. The first event of each case commits before the error.
func TestTU18RolledBackBatchIsCountedForItsLanes(t *testing.T) {
	failCommit := func(*sql.Tx) error { return errors.New("commit failed") }
	cases := []struct {
		name string
		late func(r *rig)
	}{
		{"error before BEGIN", func(r *rig) { r.db.Close() }},
		{"insert error", func(r *rig) { r.app.next = -1 }},
		{"COMMIT error", func(r *rig) { r.w.beforeCommit = failCommit }},
		{"COMMIT error after a failed append", func(r *rig) {
			r.app.err = errors.New("log is stopped")
			r.w.beforeCommit = failCommit
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t, 100)
			err := r.runAfterStart(func() { c.late(r) }, func() {
				for i, k := range []event.Kind{event.KindRequest, event.KindCallback, event.KindBeacon, event.KindAlertSent, event.KindRequest} {
					r.add(k, int64(i+1))
				}
			})
			if err != nil {
				t.Fatal(err)
			}
			if got := r.w.Stats().Dropped; got != (Drops{Bulk: 3, Evidence: 2}) || r.w.Healthy() || len(r.commits) != 0 {
				t.Fatalf("dropped %+v (want bulk 3, evidence 2), healthy %v, %d commits of the batch", got, r.w.Healthy(), len(r.commits))
			}
		})
	}
}

// T-U-18: a record error (an event whose kind is not a kind) stops the writer.
// Err holds the record class, and the batch stores no row. The events that come
// later are taken out of the lanes and counted. Enqueue refuses an event with
// kind 0 or Size 0. A later assignment can give a queued event kind 0. The
// test gives the writer a batch with the zero Event (kind 0) through flush.
// Run calls flush with each batch. The stopped writer then takes the later
// events from the lanes.
func TestTU18RecordErrorStopsTheWriter(t *testing.T) {
	r := newRig(t, 100)
	mk := func(k event.Kind, ts int64) *event.Event {
		e, err := event.NewEvent(func() time.Time { return time.UnixMilli(ts) }, event.Input{Kind: k})
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	batch := []*event.Event{{}, mk(event.KindRequest, 1), mk(event.KindCallback, 2)}
	r.w.flush(batch)
	wantRule(t, r.w.Err(), writerName, ruleRecord)
	if got := r.rows(); got != 0 {
		t.Fatalf("%d rows after the record error", got)
	}
	r.add(event.KindRequest, 3)
	r.add(event.KindAlertSent, 4)
	stop := r.start()
	r.fire() // one tick of the stopped state
	want := Drops{Bulk: 3, Evidence: 2}
	eventually(t, func() bool { return r.w.Stats().Dropped == want })
	if err := stop(); !errors.Is(err, context.Canceled) || r.rows() != 0 {
		t.Fatalf("Run returned %v, %d rows", err, r.rows())
	}
}

// T-U-18: the writer reads Record one time for each event. An assignment to
// the event after that read changes neither the hash nor the record bytes of
// the row. So sha256(record) equals hash, and the record is the bytes of the
// first value. One case assigns in w.clock, after the copy and before the hash.
// The other case assigns in beforeAppend, after the hash.
func TestTU18RecordIsReadOnceForHashAndRow(t *testing.T) {
	seams := []struct {
		name   string
		assign func(w *Writer, f func())
	}{
		{"clock", func(w *Writer, f func()) { w.clock = func() time.Time { f(); return time.Now() } }},
		{"beforeAppend", func(w *Writer, f func()) { w.beforeAppend = f }},
	}
	for _, s := range seams {
		t.Run(s.name, func(t *testing.T) {
			r := newRig(t, 100)
			first, other := rowEvent(t, event.KindCallback, true, 1), rowEvent(t, event.KindCallback, false, 2)
			want, err := event.EvidenceBytes(first.Record())
			if err != nil {
				t.Fatal(err)
			}
			s.assign(r.w, func() { *first = *other })
			if err := r.w.write([]*event.Event{first}); err != nil {
				t.Fatal(err)
			}
			rows := r.stored()
			if len(rows) != 1 {
				t.Fatalf("%d rows, want 1", len(rows))
			}
			if sum := sha256.Sum256(rows[0].record); !bytes.Equal(sum[:], rows[0].hash) {
				t.Errorf("sha256(record) %x is not hash %x", sum, rows[0].hash)
			}
			if !bytes.Equal(rows[0].record, want) {
				t.Errorf("record is %s, want the bytes of the first value %s", rows[0].record, want)
			}
		})
	}
}

// T-U-18: an assignment to an event in the transaction does not change its kind
// for the writer. The batch has one evidence and one bulk event. The assignment
// gives one of them the kind of the other. Each row keeps the kind of the first
// value. Only the evidence row has a hash, a leaf and a record. If the COMMIT
// fails, the drops count one bulk and one evidence event.
func TestTU18AssignedKindDoesNotChangeTheLane(t *testing.T) {
	cases := []struct {
		name    string
		target  int // index of the event that gets the new value
		newKind event.Kind
	}{
		{"bulk event gets an evidence value", 1, event.KindCallback},
		{"evidence event gets a bulk value", 0, event.KindRequest},
	}
	for _, c := range cases {
		for _, commitFails := range []bool{false, true} {
			for _, viaClock := range []bool{false, true} {
				// The clock runs after the copy, before the evidence decision.
				// beforeAppend runs after the hash.
				t.Run(fmt.Sprintf("%s, COMMIT fails %v, clock %v", c.name, commitFails, viaClock), func(t *testing.T) {
					testAssignedKind(t, c.target, c.newKind, commitFails, viaClock)
				})
			}
		}
	}
}

func testAssignedKind(t *testing.T, target int, newKind event.Kind, commitFails, viaClock bool) {
	r := newRig(t, 100)
	batch := []*event.Event{rowEvent(t, event.KindCallback, true, 1), rowEvent(t, event.KindRequest, true, 2)}
	newValue := rowEvent(t, newKind, false, 3)
	assign := func() { *batch[target] = *newValue }
	if viaClock {
		r.w.clock = func() time.Time { assign(); return time.Now() }
	} else {
		r.w.beforeAppend = assign
	}
	if commitFails {
		r.w.beforeCommit = func(*sql.Tx) error { return errors.New("commit failed") }
	}
	err := r.w.write(batch)
	if commitFails {
		if err == nil || r.w.Stats().Dropped != (Drops{Bulk: 1, Evidence: 1}) {
			t.Fatalf("error %v, dropped %+v (want bulk 1, evidence 1)", err, r.w.Stats().Dropped)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	rows := r.stored()
	if len(rows) != 2 || rows[0].kind != "callback" || rows[1].kind != "request" {
		t.Fatalf("rows %+v, want kinds callback and request", rows)
	}
	if rows[0].hash == nil || rows[0].leaf == nil || rows[0].record == nil {
		t.Errorf("the evidence row lacks hash, leaf_index or record")
	}
	if rows[1].hash != nil || rows[1].leaf != nil || rows[1].record != nil {
		t.Errorf("the bulk row has hash, leaf_index or record")
	}
}
