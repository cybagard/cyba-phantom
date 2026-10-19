package store

import (
	"context"
	"database/sql"
	"errors"
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
// Err holds the record class, the batch stores no row, and the events that come
// later are taken out of the lanes and counted. Enqueue refuses an event that
// NewEvent did not make, and an event cannot change after NewEvent. So the test
// gives the writer a batch with the zero Event (kind 0) through flush, as Run
// does. The stopped writer then takes the later events from the lanes.
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
