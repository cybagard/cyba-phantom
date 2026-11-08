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
	// the next run tries again. After it, busy_timeout gets the pool value of
	// the pragma list in open.go.
	checkpointSQL = "PRAGMA wal_checkpoint(TRUNCATE)"
	busyOff       = "PRAGMA busy_timeout=0"
	busyPool      = "PRAGMA busy_timeout=" + busyTimeout

	ruleRetention = "retention run ended early"
)

// A retentionStep runs one statement in the transaction of a chunk. It changes
// at most limit rows. It returns the count of rows that it changed. A count
// below limit means that the step has no row left. A count above limit, or
// below 0, is a database error of the chunk.
type retentionStep func(ctx context.Context, tx *sql.Tx, limit int) (int, error)

// retentionSteps are the steps of a run, in order. The list is empty: the steps
// come in later changes. A test sets its own list and restores this one.
var retentionSteps []retentionStep

// retentionRequest asks the writer goroutine for one retention run. The reply
// channel has room for one value, so the writer never waits for the caller.
// The gone channel is the done channel of the context of the caller.
type retentionRequest struct {
	reply chan error
	gone  <-chan struct{}
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
// no request. A call that returns on its ctx can leave a request. The writer
// drops it. A call can wait until its ctx ends, when the writer stops while the
// request waits. It is safe to call from any goroutine.
func (w *Writer) RunRetention(ctx context.Context) error {
	if err := w.Err(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	rq := retentionRequest{reply: make(chan error, 1), gone: ctx.Done()}
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
// betweenChunks). A stopped writer, or a caller that has left, gets no chunk
// and no checkpoint. Then the run ends early, with an error, in four cases.
// These are: ctx has ended, the caller has left, the queue is closed, or the
// writer has stopped. Each chunk is a transaction, so no partial chunk stays. A
// database error stops the writer. After the last chunk the run ends with the
// TRUNCATE checkpoint.
func (w *Writer) serveRetention(ctx context.Context, tick <-chan time.Time, batch []*event.Event, rq retentionRequest) []*event.Event {
	if !w.Healthy() || rq.left() {
		rq.reply <- fail(writerName, ruleRetention)
		return batch
	}
	steps := retentionSteps
	for cur := 0; cur < len(steps); {
		if _, err := w.chunk(steps, &cur); err != nil {
			w.stop(err)
			rq.reply <- err
			return batch
		}
		if cur == len(steps) {
			break
		}
		batch = w.betweenChunks(tick, batch)
		if ctx.Err() != nil || rq.left() || w.q.Closed() || !w.Healthy() {
			rq.reply <- fail(writerName, ruleRetention)
			return batch
		}
	}
	err := w.checkpoint()
	if err != nil {
		w.stop(err)
	}
	rq.reply <- err
	return batch
}

// chunk runs the steps from *cur in one transaction on one pool connection. The
// transaction does not use the context of Run, as write does not. The statement
// limit is 1 000 minus the rows that the chunk changed. The chunk ends at the
// first of three events. These are 1 000 rows, the first statement that
// reaches the budget, and the end of the last step. BEGIN and COMMIT are not in
// the budget. A step with no row left lets the chunk go on with the next step.
// The time comes from w.now. It returns the rows that the chunk changed. Any
// failure is a database error, also a step count above the limit or below 0.
// Then the transaction rolls back.
func (w *Writer) chunk(steps []retentionStep, cur *int) (rows int, err error) {
	ctx := context.Background()
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
	for *cur < len(steps) && rows < chunkRows {
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
	return rows, nil
}

// betweenChunks serves what waits between two chunks, never blocking. The order
// is: one row request. Then the events in the lanes, at most one batch of 500.
// It writes the batch when the batch is not empty. Then one tick. The take has
// a bound, so a flood cannot stop the run. A stopped writer drops the batch, as
// flush does.
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
func (w *Writer) checkpoint() (err error) {
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
	if busy == 1 {
		w.checkpointBusy.Add(1)
	}
	return nil
}
