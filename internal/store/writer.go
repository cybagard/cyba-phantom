package store

import (
	"context"
	"database/sql"
	"errors"
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
	ruleFork     = "checkpoint fork signal"
)

// Writer is the one writer of the event table. It uses the database pool from
// Open and Migrate, the queue, and the appender. The caller closes them after
// Run returns. It also adds the drop counts of the queue to ip_counter.
//
// The writer stops for one of five causes: an append error, a database error, a
// record error (the kind, the event hash or the record bytes of an event cannot
// be made), a failed start check, or a fork signal of the checkpoint row (see
// Run). Healthy, Err and Stats are safe to call from any goroutine.
type Writer struct {
	db         *sql.DB
	q          *event.Queue
	app        appender
	rec        Recovery
	counters   *event.Counters
	bodyPrefix bool // privacy.store_body_prefix
	dk         dayKey
	log        *slog.Logger

	stopErr              atomic.Pointer[error] // the first error; nil while the writer runs
	writeFailed, orphans atomic.Uint64
	drops                DropCount
	markerMade           atomic.Bool // writer.stop exists
	markerLogged         atomic.Bool // the failed create has a log line

	tick     <-chan time.Time // a test sets it; nil means a ticker of flushEvery
	onCommit func(rows int)   // a test sets it; nil in production
	clock    func() time.Time // a test sets it; nil means time.Now
	// timing gets the time of a batch and of its commit. A transaction with only
	// drop counts and no event does not call it. A test sets it; nil in
	// production.
	timing func(batch, commit time.Duration)
	// beforeCommit runs on the transaction before COMMIT. An error from it is a
	// failed COMMIT. A test sets it; nil in production.
	beforeCommit func(tx *sql.Tx) error
	// beforeAppend runs in the transaction before AppendBatch. A test sets it;
	// nil in production.
	beforeAppend func()
	// evidenceBytes makes the record bytes of an evidence row. A test sets it, to
	// make an error that no real record gives after HashEvidence worked. Nil in
	// production: the writer then calls event.EvidenceBytes.
	evidenceBytes func(event.Record) ([]byte, error)

	// beforeRowCommit runs on the transaction of a checkpoint row before COMMIT.
	// An error from it is a failed COMMIT. A test sets it; nil in production.
	beforeRowCommit func(tx *sql.Tx) error

	// rows takes the requests of the checkpoint sink. Only Run reads it.
	rows chan rowRequest
}

// NewWriter returns a writer for db, taking events from q and putting evidence
// hashes in app. The writer adds the drop counts of c to ip_counter. It stores
// the body prefix of an event only when bodyPrefix is true. It writes one line to
// log when it stops; a nil log writes nothing. rec gives the state directory, the
// origin, and the log for the start check and the stop marker. rec.State and
// rec.Log must not be nil: a nil one stops the writer at the start of Run. The
// other pointer arguments must not be nil.
func NewWriter(db *sql.DB, q *event.Queue, app appender, c *event.Counters, bodyPrefix bool, log *slog.Logger, rec Recovery) *Writer {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Writer{db: db, q: q, app: app, rec: rec, counters: c, bodyPrefix: bodyPrefix, log: log, rows: make(chan rowRequest, 1)}
}

// Run is the one writer goroutine. The caller starts it with go and starts no
// other writer. Run takes events with TryTake, evidence lane first, into one
// batch. It writes the batch in one transaction when the batch has 500 events,
// and at each tick when the batch is not empty. It holds one batch at a time and
// starts no goroutine for an event. While the lanes stay non-empty, Run writes
// at 500 events. After each such write it serves a waiting row request and a
// waiting tick, with no wait, so a flood does not hold them.
//
// Before the first write, Run does the start check (see start). A stop marker or
// a failed check stops the writer, and Run goes to the stopped state at once.
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
// Each of these stops the writer: an append error, a database error, a record
// error (the kind, the event hash or the record bytes of an event cannot be made),
// a failed start check, and a fork signal of the checkpoint row. A failed BEGIN
// starts no transaction, and a later database error rolls the transaction back.
// The events of a batch that ends with an error and no COMMIT count as drops for
// their lane. The writer keeps the first error (Err), is not healthy (Healthy),
// and writes one log line with the fixed class of the error. It does not open
// the log or the database again, and it does not end the process. Run does not
// return the error. It
// continues in the stopped state: it writes no row, calls no appender, and runs
// the Discard loop, so that the lanes do not stay full. It returns nil after Close and
// ctx.Err() after a cancel, as it does when it has not stopped.
//
// At each tick, also when the batch is empty, the writer checks the drop counts
// of the queue. If there are any, it adds them to ip_counter (see write).
func (w *Writer) Run(ctx context.Context) error {
	tick := w.tick
	if tick == nil {
		t := time.NewTicker(flushEvery)
		defer t.Stop()
		tick = t.C
	}
	if err := w.start(); err != nil {
		w.stop(err)
		return discardLoop(ctx, w.q, &w.drops, tick, w.ensureMarker)
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
		case rq := <-w.rows:
			w.serveRow(rq)
		case <-w.q.Ready():
			// Take events until the lanes are empty, then examine Closed. After
			// a flush at 500 events, serve a waiting row request and a waiting
			// tick, so that a flood does not hold them. Then leave the loop if
			// ctx has ended or the writer has stopped, so that the select can
			// take ctx.Done.
			for {
				e, ok := w.q.TryTake()
				if !ok {
					break
				}
				if batch = append(batch, e); len(batch) == maxBatch {
					batch = w.flush(batch)
					batch = w.serveWaiting(tick, batch)
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
			// A row request can stop the writer while the batch holds events that
			// Run took. Flush drops and counts them, as discardLoop does for the lanes.
			w.flush(batch)
			return discardLoop(ctx, w.q, &w.drops, tick, w.ensureMarker)
		}
	}
}

// serveWaiting serves a row request and a tick that wait now. Each select has a
// default case, so it never blocks. A tick goes through flush, as in the select
// of Run. A stopped writer serves nothing: the flush before can have stopped it,
// and a stopped writer writes no row.
func (w *Writer) serveWaiting(tick <-chan time.Time, batch []*event.Event) []*event.Event {
	if !w.Healthy() {
		return batch
	}
	select {
	case rq := <-w.rows:
		w.serveRow(rq)
	default:
	}
	select {
	case <-tick:
		batch = w.flush(batch)
	default:
	}
	return batch
}

// shutdown writes the last batch and the events that Drain returns. If the
// writer has stopped, flush drops the events that are left, and counts them.
// It ends with one flush of an empty batch, so that the drop counts that are
// still in memory go to ip_counter. Thus a healthy writer keeps no count in
// memory after shutdown.
func (w *Writer) shutdown(batch []*event.Event) {
	w.flush(batch)
	for rest := w.q.Drain(); len(rest) > 0; {
		n := min(len(rest), maxBatch)
		w.flush(rest[:n])
		rest = rest[n:]
	}
	w.flush(nil)
}

// flush writes the batch and returns it empty. It clears the pointers, so the
// events of the written batch can be freed. An error stops the writer. A stopped
// writer writes nothing: flush drops the events and counts the drops. A batch
// that ends with an error and no COMMIT is lost: flush counts each of its events
// as a drop for its lane. It does not count a batch whose COMMIT succeeded.
func (w *Writer) flush(batch []*event.Event) []*event.Event {
	if !w.Healthy() {
		for _, e := range batch {
			w.drops.add(e.Kind())
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
// is a database error. If write returns an error and the COMMIT did not succeed,
// write counts each event of the batch as a drop for its lane. A failed NORMAL
// after a good COMMIT counts none, because the rows exist.
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
// log write, and write returns the append error after the commit. Suppose the
// error matches tlog.ErrHeadOnDisk. Then the head of the log on disk can cover
// the batch, and each leaf of the batch also counts as an orphan leaf. This
// count is made when the append fails, so a later COMMIT, good or not, does not
// change it.
//
// Suppose AppendBatch works and the transaction then ends without a COMMIT.
// Then the leaves of the batch are in the log and have no row. Each of them
// counts as an orphan leaf. This holds for each error after the append: the
// record bytes, an insert, the drop counts and the COMMIT. An error before the
// append, for example of the prepare, counts none, because no leaf reached the
// log.
//
// At its start the batch reads the clock one time and takes the UTC date and
// the day key for it. The ip_counter rows of the batch use them, also when the
// batch ends after midnight.
//
// An empty batch writes nothing if the queue has no drop count. If it has, write
// runs the transaction with no row and no AppendBatch call, and no evidence, so
// synchronous stays NORMAL. The transaction adds the counts to ip_counter and
// takes the date and the day key at its start, as for a batch.
func (w *Writer) write(batch []*event.Event) (err error) {
	if len(batch) == 0 && !w.counters.Pending() {
		return nil
	}
	// One copy of each event. The evidence decision, the hash, the row and the
	// drop lane use it. A later change to an event has no effect.
	recs := make([]event.Record, len(batch))
	for j, e := range batch {
		recs[j] = e.Record()
	}
	committed := false
	defer func() {
		if err != nil && !committed {
			for _, rec := range recs {
				w.drops.add(rec.Kind)
			}
		}
	}()
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
	for j, rec := range recs {
		ok, err := rec.Kind.IsEvidence()
		if err != nil {
			return fail(writerName, ruleRecord)
		}
		if !ok {
			continue
		}
		h, err := event.HashEvidence(rec)
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
	committed, err = w.transact(ctx, conn, batch, recs, hs, evidence, day, begin)
	return err
}

// transact is the transaction of write. It returns true when the COMMIT worked.
// Suppose AppendBatch returned nil and the transaction ends without a COMMIT.
// Then the deferred function counts each leaf of the batch as an orphan leaf,
// one time.
func (w *Writer) transact(ctx context.Context, conn *sql.Conn, batch []*event.Event, recs []event.Record, hs []tlog.EventHash, evidence []bool, day string, begin time.Time) (committed bool, err error) {
	appended := false
	defer func() {
		if appended && !committed {
			w.orphans.Add(uint64(len(hs)))
		}
	}()
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return false, fail(writerName, ruleDatabase)
	}
	defer tx.Rollback() // no effect after COMMIT
	stmt, err := tx.PrepareContext(ctx, insertEvent)
	if err != nil {
		return false, fail(writerName, ruleDatabase)
	}
	defer stmt.Close()

	var first int64
	var appendErr error
	if len(hs) > 0 {
		if w.beforeAppend != nil {
			w.beforeAppend()
		}
		if first, err = w.app.AppendBatch(hs); err != nil {
			appendErr = fail(writerName, ruleAppend)
			w.writeFailed.Add(uint64(len(hs)))
			if errors.Is(err, tlog.ErrHeadOnDisk) {
				w.orphans.Add(uint64(len(hs)))
			}
		} else {
			appended = true
		}
	}
	i, rows := 0, 0
	for j, e := range batch {
		var hash, leaf, record any // nil is NULL
		if evidence[j] && appendErr != nil {
			continue
		}
		rec := recs[j] // the copy that write hashed
		if rec.Kind == event.KindRefused {
			// The row of a refused event gets a session id from the batch day
			// key. The address and the JA4 text go to no column.
			var ja4 string
			if rec.FP != nil && rec.FP.JA4 != nil {
				ja4 = *rec.FP.JA4
			}
			rec.Session = w.dk.sessionID(e.IP(), ja4)
		}
		if evidence[j] {
			evBytes := event.EvidenceBytes
			if w.evidenceBytes != nil {
				evBytes = w.evidenceBytes
			}
			b, err := evBytes(rec)
			if err != nil {
				return false, fail(writerName, ruleRecord)
			}
			hash, leaf, record = hs[i][:], first+int64(i), b
			i++
		}
		if err := w.insertRow(ctx, stmt, e, rec, hash, leaf, record); err != nil {
			return false, err
		}
		rows++
	}
	if err := w.countDrops(ctx, tx, day); err != nil {
		return false, err
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
			return false, appendErr
		}
		return false, fail(writerName, ruleDatabase)
	}
	if w.timing != nil && len(batch) > 0 {
		w.timing(time.Since(begin), time.Since(commitAt))
	}
	if w.onCommit != nil {
		w.onCommit(rows)
	}
	return true, appendErr
}

// rowRequest asks the writer goroutine to store one checkpoint row. The reply
// channel has room for one value, so the writer never waits for the sink.
type rowRequest struct {
	size  uint64
	root  [32]byte
	msg   []byte
	reply chan error
}

// serveRow answers a request of the checkpoint sink. storeRow returns only a
// database error or a fork signal. Each such error stops the writer, as the
// other stop causes do, before the reply goes to the sink. The reply is the same
// error.
func (w *Writer) serveRow(rq rowRequest) {
	err := w.storeRow(rq)
	if err != nil {
		w.stop(err)
	}
	rq.reply <- err
}

// storeRow stores the row in its own transaction, with synchronous=FULL set
// before BEGIN and NORMAL again after the transaction has ended. A row for the
// size with the same note is a success and changes nothing. A row with another
// note is a fork signal. The transaction does not use the context of Run.
func (w *Writer) storeRow(rq rowRequest) (err error) {
	ctx := context.Background()
	conn, err := w.db.Conn(ctx)
	if err != nil {
		return fail(writerName, ruleDatabase)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "PRAGMA synchronous=FULL"); err != nil {
		return fail(writerName, ruleDatabase)
	}
	defer func() {
		if _, e := conn.ExecContext(ctx, "PRAGMA synchronous=NORMAL"); e != nil && err == nil {
			err = fail(writerName, ruleDatabase)
		}
	}()
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return fail(writerName, ruleDatabase)
	}
	defer tx.Rollback() // no effect after COMMIT
	var have string
	switch err := tx.QueryRowContext(ctx, "SELECT signed_note FROM checkpoint WHERE tree_size = ?", rq.size).Scan(&have); {
	case err == nil:
		if have != string(rq.msg) {
			return fail(writerName, ruleFork)
		}
		return nil
	case !errors.Is(err, sql.ErrNoRows):
		return fail(writerName, ruleDatabase)
	}
	now := time.Now
	if w.clock != nil {
		now = w.clock
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO checkpoint (tree_size, root_hash, signed_note, created_at) VALUES (?, ?, ?, ?)",
		rq.size, rq.root[:], string(rq.msg), now().UnixMilli()); err != nil {
		return fail(writerName, ruleDatabase)
	}
	err = nil
	if w.beforeRowCommit != nil {
		err = w.beforeRowCommit(tx)
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		return fail(writerName, ruleDatabase)
	}
	return nil
}
