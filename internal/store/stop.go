package store

import (
	"context"
	"errors"
	"sync/atomic"
	"time"

	"github.com/cybagard/cyba-phantom/internal/event"
)

// Drops holds the numbers of dropped events for each lane. These are the
// events that the stopped state dropped and the events of a rolled-back batch.
// They are the values of the lane label of the metric
// phantom_store_dropped_events_total.
type Drops struct {
	Bulk, Evidence uint64
}

// DropCount counts the events that Discard drops, and the events of a
// rolled-back batch, for each lane. The zero value is ready for use. It is safe
// for concurrent use.
type DropCount struct {
	bulk, evidence atomic.Uint64
}

// Load returns the counts now.
func (d *DropCount) Load() Drops {
	return Drops{Bulk: d.bulk.Load(), Evidence: d.evidence.Load()}
}

// add counts one dropped event of kind k. An evidence kind counts for the
// evidence lane. Each other value of k counts for the bulk lane, also a kind
// that is not known.
func (d *DropCount) add(k event.Kind) {
	if ok, err := k.IsEvidence(); err == nil && ok {
		d.evidence.Add(1)
		return
	}
	d.bulk.Add(1)
}

// Stats holds the counts of the writer.
type Stats struct {
	// WriteFailed counts the evidence events of a batch whose AppendBatch call
	// failed. It is for phantom_tlog_write_failed_total.
	WriteFailed uint64
	// OrphanLeaves counts the leaves of a batch whose COMMIT failed after a good
	// AppendBatch call. It is for phantom_tlog_orphan_leaves_total.
	OrphanLeaves uint64
	// Dropped counts the dropped events for each lane. These are the events
	// that the stopped writer took out of the lanes. They also include the
	// events of a rolled-back batch. It is for
	// phantom_store_dropped_events_total.
	Dropped Drops
}

// Stats returns the counts of the writer. It is safe to call from any goroutine.
func (w *Writer) Stats() Stats {
	return Stats{WriteFailed: w.writeFailed.Load(), OrphanLeaves: w.orphans.Load(), Dropped: w.drops.Load()}
}

// Healthy tells if the writer has not stopped. It is safe to call from any
// goroutine.
func (w *Writer) Healthy() bool { return w.Err() == nil }

// Err returns the first error that stopped the writer, or nil. The error is an
// *Error with a fixed rule. It holds no driver text and no row value. It is safe
// to call from any goroutine.
func (w *Writer) Err() error {
	if p := w.stopErr.Load(); p != nil {
		return *p
	}
	return nil
}

// stop records err as the reason of the stop, writes one log line, and makes the
// stop marker (see ensureMarker). A later call changes nothing and logs nothing.
// There is no reopen of the log or of the database, and no exit of the process.
func (w *Writer) stop(err error) {
	var e *Error
	if !errors.As(err, &e) {
		err = fail(writerName, ruleDatabase)
	}
	if w.stopErr.CompareAndSwap(nil, &err) {
		w.log.Error("store writer stopped", "class", err.Error())
		w.ensureMarker()
	}
}

// Discard is the loop of the stopped state. At each tick (250 ms) it takes each
// event out of both lanes with TryTake and drops it. It counts each drop in d for
// the lane of the event. It writes no row and calls no appender. It is not
// Queue.Drain: it gives the events to nobody. Discard needs no store and no
// writer. The argument d must not be nil.
//
// Discard returns nil after Close of the queue, when it has dropped the events
// that are left. It returns ctx.Err() when ctx ends first.
func Discard(ctx context.Context, q *event.Queue, d *DropCount) error {
	t := time.NewTicker(flushEvery)
	defer t.Stop()
	return discardLoop(ctx, q, d, t.C, func() {})
}

// discardLoop is discard with a function that runs at each tick, before the
// drop. The writer uses it to try again to make the stop marker.
func discardLoop(ctx context.Context, q *event.Queue, d *DropCount, tick <-chan time.Time, onTick func()) error {
	for {
		select {
		case <-ctx.Done():
			if q.Closed() {
				discardAll(q, d)
				return nil
			}
			return ctx.Err()
		case <-tick:
			onTick()
			discardAll(q, d)
		case <-q.Ready():
			// The wake value must be taken, or this select would not wait. Only
			// the tick and Close make the loop take events.
			if q.Closed() {
				discardAll(q, d)
				return nil
			}
		}
	}
}

// discardAll drops the events that are in the lanes now.
func discardAll(q *event.Queue, d *DropCount) {
	for {
		e, ok := q.TryTake()
		if !ok {
			return
		}
		d.add(e.Kind())
	}
}
