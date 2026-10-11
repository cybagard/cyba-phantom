package store

import (
	"context"
	"database/sql"
	"log/slog"
	"sync/atomic"
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
)

// Writer is the one writer of the event table. It uses the database pool from
// Open and Migrate, the queue, and the appender. The caller closes them after
// Run returns. It also adds the drop counts of the queue to ip_counter.
//
// After a database error or an append error the writer stops (see Run). Healthy,
// Err and Stats are safe to call from any goroutine.
type Writer struct {
	db         *sql.DB
	q          *event.Queue
	app        appender
	counters   *event.Counters
	bodyPrefix bool // privacy.store_body_prefix
	dk         dayKey
	log        *slog.Logger

	stopErr              atomic.Pointer[error] // the first error; nil while the writer runs
	writeFailed, orphans atomic.Uint64
	drops                DropCount

	tick     <-chan time.Time // a test sets it; nil means a ticker of flushEvery
	onCommit func(rows int)   // a test sets it; nil in production
	clock    func() time.Time // a test sets it; nil means time.Now
	// timing gets the time of a batch and of its commit. A test sets it; nil in
	// production.
	timing func(batch, commit time.Duration)
	// beforeCommit runs on the transaction before COMMIT. An error from it is a
	// failed COMMIT. A test sets it; nil in production.
	beforeCommit func(tx *sql.Tx) error
}

// NewWriter returns a writer for db, taking events from q and putting evidence
// hashes in app. The writer adds the drop counts of c to ip_counter. It stores
// the body prefix of an event only when bodyPrefix is true. It writes one line to
// log when it stops; a nil log writes nothing. The other pointer arguments must
// not be nil.
func NewWriter(db *sql.DB, q *event.Queue, app appender, c *event.Counters, bodyPrefix bool, log *slog.Logger) *Writer {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Writer{db: db, q: q, app: app, counters: c, bodyPrefix: bodyPrefix, log: log}
}

// Run is the one writer goroutine. The caller starts it with go and starts no
// other writer. Run takes events with TryTake, evidence lane first, into one
// batch. It writes the batch in one transaction when the batch has 500 events,
// and at each tick when the batch is not empty. It holds one batch at a time and
// starts no goroutine for an event. While the lanes stay non-empty, Run writes
// at 500 events and the tick case can wait.
//
// Normal shutdown: the caller stops the producers and calls Close on the queue.
// Run then writes its batch, takes the events that are left with Drain, writes
// them in batches of at most 500, and returns nil. The caller does not cancel
// ctx until Run returns. If the queue is closed when ctx ends, Run does the same
// shutdown.
//
// If ctx ends and the queue is not closed, Run writes the batch that it already
// has and returns ctx.Err(). The events that Run did not take stay in the lanes.
// Thus a cancel without Close can leave events in the lanes.
//
// A database error or an append error stops the writer. A failed BEGIN starts no
// transaction, and a later database error rolls the transaction back. The writer
// keeps the first error (Err), is not healthy (Healthy), and writes one log line
// with the fixed class of the error. It does not open the log or the database
// again, and it does not end the process. Run does not return the error. It goes
// on in the stopped state: it writes no row, calls no appender, and runs
// Discard, so that the lanes do not stay full. It returns nil after Close and
// ctx.Err() after a cancel, as it does when it has not stopped.
func (w *Writer) Run(ctx context.Context) error {
	tick := w.tick
	if tick == nil {
		t := time.NewTicker(flushEvery)
		defer t.Stop()
		tick = t.C
	}
	batch := make([]*event.Event, 0, maxBatch)
	for {
		select {
		case <-ctx.Done():
			if w.q.Closed() {
				w.shutdown(batch)
				return nil
			}
			w.flush(batch)
			return ctx.Err()
		case <-tick:
			batch = w.flush(batch)
		case <-w.q.Ready():
			// Take events until the lanes are empty, then examine Closed. After
			// a flush at 500 events, leave the loop if ctx has ended or the
			// writer has stopped, so that the select can take ctx.Done.
			for {
				e, ok := w.q.TryTake()
				if !ok {
					break
				}
				if batch = append(batch, e); len(batch) == maxBatch {
					batch = w.flush(batch)
					if ctx.Err() != nil || !w.Healthy() {
						break
					}
				}
			}
			if w.q.Closed() {
				w.shutdown(batch)
				return nil
			}
		}
		if !w.Healthy() {
			return discard(ctx, w.q, &w.drops, tick)
		}
	}
}

// shutdown writes the last batch and the events that Drain returns. If the
// writer has stopped, flush drops the events that are left, and counts them.
func (w *Writer) shutdown(batch []*event.Event) {
	w.flush(batch)
	for rest := w.q.Drain(); len(rest) > 0; {
		n := min(len(rest), maxBatch)
		w.flush(rest[:n])
		rest = rest[n:]
	}
}

// flush writes the batch and returns it empty. It clears the pointers, so the
// events of the written batch can be freed. An error stops the writer. A stopped
// writer writes nothing: flush drops the events and counts the drops.
func (w *Writer) flush(batch []*event.Event) []*event.Event {
	if !w.Healthy() {
		for _, e := range batch {
			w.drops.add(e)
		}
	} else if err := w.write(batch); err != nil {
		w.stop(err)
	}
	clear(batch)
	return batch[:0]
}

// write stores one batch in one transaction. It hashes the evidence events
// first. For a batch with evidence it takes the one pool connection and sets
// synchronous=FULL on it before BEGIN. It sets NORMAL again when the transaction
// has ended, after a commit and after a rollback. A failure to set either value
// is a database error.
//
// In the transaction, the evidence hashes go to the appender in one call before
// COMMIT. Row i of the evidence events gets leaf_index first+i. The insert loop
// makes the record bytes for each row, binds them, and drops them after the
// insert. Thus the writer keeps no second copy of the record bytes of the batch.
// The transaction does not use the context of Run: the last write must work after
// ctx ends.
//
// If AppendBatch fails, the transaction stores only the bulk rows of the batch.
// It stores no evidence row. Each evidence event of the batch counts as a failed
// log write, and write returns the append error after the commit. If COMMIT
// fails after a good AppendBatch call, the leaves of the batch are in the log
// and have no row. Each of them counts as an orphan leaf.
//
// At its start the batch reads the clock one time and takes the UTC date and
// the day key for it. The ip_counter rows of the batch use them, also when the
// batch ends after midnight.
func (w *Writer) write(batch []*event.Event) (err error) {
	if len(batch) == 0 {
		return nil
	}
	var begin time.Time
	if w.timing != nil {
		begin = time.Now()
	}
	now := time.Now
	if w.clock != nil {
		now = w.clock
	}
	day := now().UTC().Format(dayLayout)
	w.dk.use(day)
	hs := make([]tlog.EventHash, 0, len(batch))
	evidence := make([]bool, len(batch))
	for j, e := range batch {
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
		evidence[j] = true
		hs = append(hs, tlog.EventHash(h))
	}

	ctx := context.Background()
	conn, err := w.db.Conn(ctx)
	if err != nil {
		return fail(writerName, ruleDatabase)
	}
	defer conn.Close()
	if len(hs) > 0 {
		if _, err := conn.ExecContext(ctx, "PRAGMA synchronous=FULL"); err != nil {
			return fail(writerName, ruleDatabase)
		}
		defer func() {
			if _, e := conn.ExecContext(ctx, "PRAGMA synchronous=NORMAL"); e != nil && err == nil {
				err = fail(writerName, ruleDatabase)
			}
		}()
	}
	return w.transact(ctx, conn, batch, hs, evidence, day, begin)
}

// transact is the transaction of write.
func (w *Writer) transact(ctx context.Context, conn *sql.Conn, batch []*event.Event, hs []tlog.EventHash, evidence []bool, day string, begin time.Time) error {
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return fail(writerName, ruleDatabase)
	}
	defer tx.Rollback() // no effect after COMMIT
	stmt, err := tx.PrepareContext(ctx, insertEvent)
	if err != nil {
		return fail(writerName, ruleDatabase)
	}
	defer stmt.Close()

	var first int64
	var appendErr error
	if len(hs) > 0 {
		if first, err = w.app.AppendBatch(hs); err != nil {
			appendErr = fail(writerName, ruleAppend)
			w.writeFailed.Add(uint64(len(hs)))
		}
	}
	i, rows := 0, 0
	for j, e := range batch {
		var hash, leaf, record any // nil is NULL
		if evidence[j] {
			if appendErr != nil {
				continue
			}
			b, err := event.EvidenceBytes(e.Record)
			if err != nil {
				return fail(writerName, ruleRecord)
			}
			hash, leaf, record = hs[i][:], first+int64(i), b
			i++
		}
		if err := w.insertRow(ctx, stmt, e, hash, leaf, record); err != nil {
			return err
		}
		rows++
	}
	if err := w.countDrops(ctx, tx, day); err != nil {
		return err
	}
	var commitAt time.Time
	if w.timing != nil {
		commitAt = time.Now()
	}
	err = nil
	if w.beforeCommit != nil {
		err = w.beforeCommit(tx)
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		if appendErr != nil {
			return appendErr
		}
		w.orphans.Add(uint64(len(hs)))
		return fail(writerName, ruleDatabase)
	}
	if w.timing != nil {
		w.timing(time.Since(begin), time.Since(commitAt))
	}
	if w.onCommit != nil {
		w.onCommit(rows)
	}
	return appendErr
}
