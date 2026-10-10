package store

import (
	"context"
	"database/sql"
	"time"

	"github.com/cybagard/cyba-phantom/internal/event"
	"github.com/cybagard/cyba-phantom/internal/tlog"
)

const (
	// maxBatch and flushEvery are the batch limits (SEC-15, NFR-02): the writer
	// commits at 500 events or after 250 ms.
	maxBatch   = 500
	flushEvery = 250 * time.Millisecond

	writerName   = "writer"
	ruleDatabase = "database write failed"
	ruleAppend   = "log append failed"
	ruleRecord   = "evidence record cannot be made"

	insertEvent = "INSERT INTO event (ts, kind, hash, leaf_index, record) VALUES (?, ?, ?, ?, ?)"
)

// Writer is the one writer of the event table. It owns the database pool from
// Open and Migrate, the queue, and the appender. This step writes only the
// columns ts, kind, hash, leaf_index and record.
type Writer struct {
	db  *sql.DB
	q   *event.Queue
	app appender

	tick     <-chan time.Time // a test sets it; nil means a ticker of flushEvery
	onCommit func(rows int)   // a test sets it; nil in production
}

// NewWriter returns a writer for db, taking events from q and putting evidence
// hashes in app.
func NewWriter(db *sql.DB, q *event.Queue, app appender) *Writer {
	return &Writer{db: db, q: q, app: app}
}

// Run is the one writer goroutine. The caller starts it with go and starts no
// other writer. Run takes events with TryTake, evidence lane first, into one
// batch. It writes the batch in one transaction when the batch has 500 events,
// and at each tick when the batch is not empty. It holds one batch at a time and
// starts no goroutine for an event.
//
// Normal shutdown: the caller stops the producers and calls Close on the queue.
// Run then writes its batch, takes the events that are left with Drain, writes
// them in batches of at most 500, and returns nil.
//
// If ctx ends first, Run writes the batch that it already has and returns
// ctx.Err(). The events that Run did not take stay in the lanes.
//
// A database error or an append error rolls back the batch. Run then returns
// the error, an *Error that holds no driver text and no row value.
func (w *Writer) Run(ctx context.Context) error {
	tick := w.tick
	if tick == nil {
		t := time.NewTicker(flushEvery)
		defer t.Stop()
		tick = t.C
	}
	batch := make([]*event.Event, 0, maxBatch)
	var err error
	for {
		select {
		case <-ctx.Done():
			if _, err = w.flush(batch); err != nil {
				return err
			}
			return ctx.Err()
		case <-tick:
			batch, err = w.flush(batch)
		case <-w.q.Ready():
			// Take events until the lanes are empty, then look at Closed.
			for {
				e, ok := w.q.TryTake()
				if !ok {
					break
				}
				if batch = append(batch, e); len(batch) == maxBatch {
					if batch, err = w.flush(batch); err != nil {
						return err
					}
				}
			}
			if w.q.Closed() {
				return w.shutdown(batch)
			}
		}
		if err != nil {
			return err
		}
	}
}

// shutdown writes the last batch and the events that Drain returns.
func (w *Writer) shutdown(batch []*event.Event) error {
	if _, err := w.flush(batch); err != nil {
		return err
	}
	for rest := w.q.Drain(); len(rest) > 0; {
		n := min(len(rest), maxBatch)
		if err := w.write(rest[:n]); err != nil {
			return err
		}
		rest = rest[n:]
	}
	return nil
}

// flush writes the batch and returns it empty. It clears the pointers, so the
// events of the written batch can be freed.
func (w *Writer) flush(batch []*event.Event) ([]*event.Event, error) {
	err := w.write(batch)
	clear(batch)
	return batch[:0], err
}

// write stores one batch in one transaction. The evidence hashes go to the
// appender in one call before COMMIT. Row i of the evidence events gets
// leaf_index first+i. The transaction does not use the context of Run: the
// last write must work after ctx ends.
func (w *Writer) write(batch []*event.Event) error {
	if len(batch) == 0 {
		return nil
	}
	ctx := context.Background()
	tx, err := w.db.BeginTx(ctx, nil)
	if err != nil {
		return fail(writerName, ruleDatabase)
	}
	defer tx.Rollback() // no effect after COMMIT

	hs := make([]tlog.EventHash, 0, len(batch))
	for _, e := range batch {
		ok, err := e.Record.Kind.IsEvidence()
		if err != nil {
			return fail(writerName, ruleRecord)
		}
		if !ok {
			continue
		}
		h, err := event.HashEvidence(e.Record)
		if err != nil {
			return fail(writerName, ruleRecord)
		}
		hs = append(hs, tlog.EventHash(h))
	}
	var first int64
	if len(hs) > 0 {
		if first, err = w.app.AppendBatch(hs); err != nil {
			return fail(writerName, ruleAppend)
		}
	}

	stmt, err := tx.PrepareContext(ctx, insertEvent)
	if err != nil {
		return fail(writerName, ruleDatabase)
	}
	defer stmt.Close()
	i := 0
	for _, e := range batch {
		var hash, leaf, record any // nil is NULL
		if ok, _ := e.Record.Kind.IsEvidence(); ok {
			b, err := event.EvidenceBytes(e.Record)
			if err != nil {
				return fail(writerName, ruleRecord)
			}
			hash, leaf, record = hs[i][:], first+int64(i), b
			i++
		}
		if _, err := stmt.ExecContext(ctx, e.Record.TS, e.Record.Kind.String(), hash, leaf, record); err != nil {
			return fail(writerName, ruleDatabase)
		}
	}
	if tx.Commit() != nil {
		return fail(writerName, ruleDatabase)
	}
	if w.onCommit != nil {
		w.onCommit(len(batch))
	}
	return nil
}
