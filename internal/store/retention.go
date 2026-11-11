package store

import (
	"context"
	"database/sql"
	"time"

	"github.com/cybagard/cyba-phantom/internal/event"
)

const (
	// chunkRows and chunkBudget are the limits of one retention chunk (SEC-39).
	// A chunk changes at most 1 000 rows. It ends after the first statement
	// that reaches 100 ms of statement time, or when no row is left. BEGIN and
	// COMMIT are not in the statement time.
	chunkRows   = 1000
	chunkBudget = 100 * time.Millisecond

	// The checkpoint waits for no reader. The writer counts a busy result, and
	// the next run tries again. After the checkpoint, busy_timeout gets the
	// pool value of the pragma list in open.go.
	checkpointSQL = "PRAGMA wal_checkpoint(TRUNCATE)"
	busyOff       = "PRAGMA busy_timeout=0"
	busyPool      = "PRAGMA busy_timeout=" + busyTimeout

	ruleRetention = "retention run ended early"
)

// A retentionStep runs its statements in the transaction of a chunk. It changes
// at most limit rows. It returns a count that is an upper bound of the rows
// that it changed, and at most limit. A count below limit means that the step
// has no row left. A count above limit, or below 0, is a database error of the
// chunk.
type retentionStep func(ctx context.Context, tx *sql.Tx, limit int) (int, error)

// retentionSteps are the steps of a run that RunRetention starts, in order. The
// list is empty. The schedule does not use this list. It sends its own list
// for each run. A test sets its own list and restores this one.
var retentionSteps []retentionStep

// A member is one count of the retention event. A step adds the rows that its
// statements changed to a member, never the cost that it returns.
type member uint8

const (
	memIP member = iota
	memFields
	memRolled
	memDeleted
	memEvicted
	memVacuumed
	numMembers // the number of members, not a member
)

// tally holds the rows that the steps of one chunk changed.
type tally [numMembers]int64

type tallyKey struct{}

// tallyRows adds n rows to a member of the tally of the chunk. A chunk with no
// run record has no tally, and the call does nothing.
func tallyRows(ctx context.Context, m member, n int) {
	if t, ok := ctx.Value(tallyKey{}).(*tally); ok {
		t[m] += int64(n)
	}
}

// execCount is execN, and it counts the rows that the statement changed.
func execCount(ctx context.Context, tx *sql.Tx, m member, q string, args ...any) (int, error) {
	n, err := execN(ctx, tx, q, args...)
	tallyRows(ctx, m, n)
	return n, err
}

// retentionRun is the record of one schedule run: the counts of the chunks that
// committed, and the two cutoffs. The schedule goroutine sets the cutoffs
// before it sends the request. After that, only the writer goroutine uses it.
type retentionRun struct {
	counts event.RetentionCounts

	// capAt is 1 plus the index of the first cap step. 0 means no cap step.
	// Before that step, the run ends its chunk and settles the WAL, once.
	capAt   int
	settled bool
}

// settleDue tells if the run must settle the WAL before the step at index i.
func (r *retentionRun) settleDue(i int) bool {
	return r != nil && r.capAt == i+1 && !r.settled
}

type runKey struct{}

// withRun gives ctx a run record. runSteps reads it from the context, so the
// signature of the run function of the schedule does not change.
func withRun(ctx context.Context, run *retentionRun) context.Context {
	return context.WithValue(ctx, runKey{}, run)
}

// add puts the rows of a committed chunk in the run total.
func (r *retentionRun) add(t *tally) {
	r.counts.IP += t[memIP]
	r.counts.Fields += t[memFields]
	r.counts.Rolled += t[memRolled]
	r.counts.Deleted += t[memDeleted]
	r.counts.Evicted += t[memEvicted]
	r.counts.Vacuumed += t[memVacuumed]
}

// retentionRequest asks the writer goroutine for one retention run. The reply
// channel has room for one value, so the writer never waits for the caller.
// The gone channel is the done channel of the context of the caller.
type retentionRequest struct {
	reply chan error
	gone  <-chan struct{}
	steps []retentionStep // nil means the package list retentionSteps
	run   *retentionRun   // nil means that the run makes no event
}

// left tells if the caller has left. The writer then skips the run.
func (rq retentionRequest) left() bool {
	select {
	case <-rq.gone:
		return true
	default:
		return false
	}
}

// RunRetention asks the writer to run the retention steps and waits for the
// end of the run or of ctx. The reply is nil when the run ended with its
// checkpoint. It is an error when the run ended early or the writer stopped.
// A stopped writer, or a ctx that has ended, gives its error at once and sends
// no request. A call that returns on its ctx can leave a request. When the
// writer takes a request whose caller has left, the writer replies with an
// error and runs nothing. A call also waits until its ctx ends when Run is not
// running. Run can be not started, or it can return after Close or a cancel.
// The request then stays in the buffer, or the call waits to send it. The same
// holds when the writer stops while the request waits. Any goroutine can make
// the call.
func (w *Writer) RunRetention(ctx context.Context) error {
	return w.runSteps(ctx, nil)
}

// runSteps is RunRetention with its own step list. The schedule builds a list
// for each run, because the cutoffs come from the time of the run. A nil list
// means the package list retentionSteps.
func (w *Writer) runSteps(ctx context.Context, steps []retentionStep) error {
	if err := w.Err(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	run, _ := ctx.Value(runKey{}).(*retentionRun)
	rq := retentionRequest{reply: make(chan error, 1), gone: ctx.Done(), steps: steps, run: run}
	select {
	case w.retention <- rq:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case err := <-rq.reply:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// RetentionCheckpointBusy returns the number of runs whose TRUNCATE checkpoint
// found a reader and so did not finish. It is for the metric
// phantom_retention_checkpoint_busy_total. A busy result is not an error. It is
// safe to call from any goroutine.
func (w *Writer) RetentionCheckpointBusy() uint64 { return w.checkpointBusy.Load() }

// serveRetention runs one retention run and sends the result to rq. It runs one
// chunk for each pass. Between two chunks the writer serves what waits (see
// betweenChunks). An ended ctx, a stopped writer, or a caller that has left
// gets no chunk and no checkpoint. The run also ends early, with an error, in
// four cases. These are: ctx has ended, the caller has left, the queue is
// closed, or the writer has stopped. Each chunk is a transaction, so no partial
// chunk stays. A database error stops the writer. The run ends with the
// checkpoint.
func (w *Writer) serveRetention(ctx context.Context, tick <-chan time.Time, batch []*event.Event, rq retentionRequest) []*event.Event {
	if !w.Healthy() || ctx.Err() != nil || rq.left() {
		rq.reply <- fail(writerName, ruleRetention)
		return batch
	}
	steps := rq.steps
	if steps == nil {
		steps = retentionSteps
	}
	for cur := 0; cur < len(steps); {
		if rq.run.settleDue(cur) {
			rq.run.settled = true
			if err := w.truncateWAL(false); err != nil {
				w.stop(err)
				rq.reply <- err
				return batch
			}
		}
		if _, err := w.chunkRun(steps, &cur, rq.run); err != nil {
			w.stop(err)
			rq.reply <- err
			return batch
		}
		if cur == len(steps) {
			break
		}
		batch = w.betweenChunks(tick, batch)
		if ctx.Err() != nil || rq.left() || w.q.Closed() || !w.Healthy() {
			rq.reply <- w.endRun(rq.run, fail(writerName, ruleRetention))
			return batch
		}
	}
	err := w.checkpoint()
	if err != nil {
		w.stop(err)
	} else {
		err = w.endRun(rq.run, nil)
	}
	rq.reply <- err
	return batch
}

// endRun writes the retention event of a run that has a run record. The caller
// calls it after a chunk has committed. The event goes to flush as a batch of
// its own. It does not use the queue, so a full evidence lane cannot drop it. A
// paused writer drops it with a count, as flush does. A stopped writer makes no
// event and counts no drop. endRun returns err. If the write stops the writer,
// it returns the error of the stop.
func (w *Writer) endRun(run *retentionRun, err error) error {
	if run == nil || !w.Healthy() {
		return err
	}
	e, eerr := event.NewRetentionEvent(w.now, run.counts)
	if eerr != nil {
		eerr = fail(writerName, ruleRecord)
		w.stop(eerr)
		return eerr
	}
	w.flush([]*event.Event{e})
	if !w.Healthy() {
		return w.Err()
	}
	return err
}

// chunk runs the steps from *cur in one transaction on one pool connection. The
// transaction does not use the context of Run, as write does not. The statement
// limit is 1 000 minus the rows that the chunk changed. The chunk ends at the
// first of three conditions. These are 1 000 rows, the first statement that
// reaches the budget, and the end of the last step. BEGIN and COMMIT are not in
// the budget. A step with no row left lets the chunk go on with the next step.
// The time comes from w.now. It returns the rows that the chunk changed. Any
// failure is a database error, also a step count above the limit or below 0.
// Then the transaction rolls back.
func (w *Writer) chunk(steps []retentionStep, cur *int) (rows int, err error) {
	return w.chunkRun(steps, cur, nil)
}

// chunkRun is chunk for a run with a run record. The steps count the rows that
// they change in a tally of the chunk. The tally goes into the run total after
// the COMMIT, so a chunk that rolls back adds nothing.
func (w *Writer) chunkRun(steps []retentionStep, cur *int, run *retentionRun) (rows int, err error) {
	var t tally
	ctx := context.WithValue(context.Background(), tallyKey{}, &t)
	conn, err := w.db.Conn(ctx)
	if err != nil {
		return 0, fail(writerName, ruleDatabase)
	}
	defer conn.Close()
	var tx *sql.Tx
	if w.beforeBegin != nil {
		err = w.beforeBegin()
	}
	if err == nil {
		tx, err = conn.BeginTx(ctx, nil)
	}
	if err != nil {
		return 0, fail(writerName, ruleDatabase)
	}
	defer tx.Rollback() // no effect after COMMIT
	start := w.now()
	for *cur < len(steps) && rows < chunkRows && !run.settleDue(*cur) {
		limit := chunkRows - rows
		n, err := steps[*cur](ctx, tx, limit)
		if err != nil || n < 0 || n > limit {
			return 0, fail(writerName, ruleDatabase)
		}
		rows += n
		if n < limit {
			*cur++
		}
		if w.now().Sub(start) >= chunkBudget {
			break
		}
	}
	err = nil
	if w.beforeCommit != nil {
		err = w.beforeCommit(tx)
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		return 0, fail(writerName, ruleDatabase)
	}
	if run != nil {
		run.add(&t)
	}
	return rows, nil
}

// betweenChunks serves what waits between two chunks, never blocking. The order
// is: one row request. Then the events in the lanes, at most one batch of 500.
// The writer writes the batch when the batch is not empty. Then one tick. The
// take has a bound, so a flood cannot hold the run. A stopped writer drops the
// batch, as flush does.
func (w *Writer) betweenChunks(tick <-chan time.Time, batch []*event.Event) []*event.Event {
	select {
	case rq := <-w.rows:
		w.serveRow(rq)
	default:
	}
	for len(batch) < maxBatch {
		e, ok := w.q.TryTake()
		if !ok {
			break
		}
		batch = append(batch, e)
	}
	if len(batch) > 0 {
		batch = w.flush(batch)
	}
	select {
	case <-tick:
		batch = w.flush(batch)
	default:
	}
	return batch
}

// checkpoint runs the TRUNCATE checkpoint on the pool connection with
// busy_timeout 0. Then it sets busy_timeout to the pool value again. A busy
// result adds 1 to the busy count and is not an error. A failed pragma or
// checkpoint statement is a database error.
func (w *Writer) checkpoint() (err error) { return w.truncateWAL(true) }

// truncateWAL is checkpoint. The settle before the cap step calls it with count
// false. Its busy result is not in the busy count. That count has one value for
// each run.
func (w *Writer) truncateWAL(count bool) (err error) {
	ctx := context.Background()
	conn, err := w.db.Conn(ctx)
	if err != nil {
		return fail(writerName, ruleDatabase)
	}
	defer conn.Close()
	if err := w.pragma(ctx, conn, busyOff); err != nil {
		return fail(writerName, ruleDatabase)
	}
	defer func() {
		if e := w.pragma(ctx, conn, busyPool); e != nil && err == nil {
			err = fail(writerName, ruleDatabase)
		}
	}()
	if w.beforePragma != nil {
		if err := w.beforePragma(checkpointSQL); err != nil {
			return fail(writerName, ruleDatabase)
		}
	}
	var busy, logFrames, moved int
	if err := conn.QueryRowContext(ctx, checkpointSQL).Scan(&busy, &logFrames, &moved); err != nil {
		return fail(writerName, ruleDatabase)
	}
	if busy == 1 && count {
		w.checkpointBusy.Add(1)
	}
	return nil
}
