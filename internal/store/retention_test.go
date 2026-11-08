package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cybagard/cyba-phantom/internal/event"
)

// seedTS is the ts of the first seeded row. The ts of rig.add is lower.
const seedTS = 1_000_000

// seedEvents inserts n request rows with ts = base + i*step. A wide row has a
// detail text of 300 characters. Only the benchmark asks for wide rows. The
// seed turns the CHECK constraints off: under the race detector they cost most
// of the time. It turns them on again and reads the setting back.
func seedEvents(tb testing.TB, db *sql.DB, n int, base, step int64, wide bool) {
	tb.Helper()
	detail := "NULL"
	if wide {
		detail = "hex(randomblob(150))"
	}
	if _, err := db.Exec("PRAGMA ignore_check_constraints=ON"); err != nil {
		tb.Fatal(err)
	}
	defer func() {
		var v int
		if _, err := db.Exec("PRAGMA ignore_check_constraints=OFF"); err != nil {
			tb.Fatal(err)
		}
		if err := db.QueryRow("PRAGMA ignore_check_constraints").Scan(&v); err != nil || v != 0 {
			tb.Fatalf("ignore_check_constraints is %d after the seed: %v", v, err)
		}
	}()
	for off := 0; off < n; off += 100_000 {
		last := off + min(100_000, n-off) - 1
		if _, err := db.Exec(`WITH RECURSIVE c(i) AS (SELECT ? UNION ALL SELECT i+1 FROM c WHERE i < ?)
			INSERT INTO event (ts, kind, detail) SELECT ? + i*?, 'request', `+detail+` FROM c`,
			off, last, base, step); err != nil {
			tb.Fatal(err)
		}
	}
}

// deleteRange is a test step: it deletes the oldest rows with lo <= ts < hi.
func deleteRange(lo, hi int64) retentionStep {
	return func(ctx context.Context, tx *sql.Tx, limit int) (int, error) {
		res, err := tx.ExecContext(ctx, "DELETE FROM event WHERE rowid IN (SELECT rowid FROM event WHERE ts >= ? AND ts < ? ORDER BY ts LIMIT ?)", lo, hi, limit)
		if err != nil {
			return 0, err
		}
		n, err := res.RowsAffected()
		return int(n), err
	}
}

// onCall wraps step: f gets the index of the call, before the step runs.
func onCall(step retentionStep, f func(i int, tx *sql.Tx)) retentionStep {
	i := 0
	return func(ctx context.Context, tx *sql.Tx, limit int) (int, error) {
		i++
		f(i-1, tx)
		return step(ctx, tx, limit)
	}
}

// retentionRig makes a rig with rows seeded rows and the given steps.
func retentionRig(t *testing.T, rows int, steps ...retentionStep) *rig {
	t.Helper()
	r := newRig(t, 4000)
	seedEvents(t, r.db, rows, seedTS, 1, false)
	setHook(t, &retentionSteps, steps)
	return r
}

// retain starts the writer, asks for one run and returns its result.
func (r *rig) retain(limit time.Duration) error {
	r.t.Helper()
	r.launchCancelable(context.Background())
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	defer cancel()
	return r.w.RunRetention(ctx)
}

// tryAdd is rig.add without Fatal. A step callback runs on the writer
// goroutine, where FailNow must not run. The test checks the error.
func (r *rig) tryAdd(kind event.Kind, ts int64) error {
	e, err := event.NewEvent(func() time.Time { return time.UnixMilli(ts) }, event.Input{Kind: kind})
	if err == nil && !r.q.Enqueue(e) {
		err = errors.New("the queue refused the event")
	}
	return err
}

// wantCheckpoint is the statement list of a checkpoint, as literal text.
var wantCheckpoint = []string{"PRAGMA busy_timeout=0", "PRAGMA wal_checkpoint(TRUNCATE)", "PRAGMA busy_timeout=5000"}

// recordPragmas makes the writer note each PRAGMA statement that it runs.
func (r *rig) recordPragmas() *[]string {
	var s []string
	r.w.beforePragma = func(stmt string) error { s = append(s, stmt); return nil }
	return &s
}

// reply waits for the reply of a request that the test queued itself.
func (r *rig) reply(rq retentionRequest) error {
	r.t.Helper()
	select {
	case err := <-rq.reply:
		return err
	case <-time.After(waitFor):
		r.t.Fatal("no reply to the retention request")
		return nil
	}
}

func (r *rig) events() (n int) {
	r.t.Helper()
	if err := r.db.QueryRow("SELECT count(*) FROM event").Scan(&n); err != nil {
		r.t.Fatal(err)
	}
	return n
}

// T-U-26: a run over 10 000 rows gives at least 10 chunks. No chunk changes
// more than 1 000 rows.
func TestTU26RunGivesChunksOfAtMost1000Rows(t *testing.T) {
	cur, step := 0, deleteRange(seedTS, math.MaxInt64)
	r := retentionRig(t, 10_000, func(ctx context.Context, tx *sql.Tx, limit int) (int, error) {
		n, err := step(ctx, tx, limit)
		cur += n
		return n, err
	})
	var chunks []int
	r.w.beforeCommit = func(*sql.Tx) error { chunks, cur = append(chunks, cur), 0; return nil }
	if err := r.retain(waitFor); err != nil {
		t.Fatal(err)
	}
	if len(chunks) < 10 || slices.Max(chunks) > 1000 || r.events() != 0 {
		t.Fatalf("chunks %v, %d rows left", chunks, r.events())
	}
}

// T-U-26: the limit of a statement is 1 000 minus the rows that the chunk
// changed. Two steps have 600 rows each. The first chunk changes 1 000 rows, so
// its second statement gets the limit 400. The next chunk changes the rest.
func TestTU26SecondStatementGetsTheRestOfTheLimit(t *testing.T) {
	var limits, chunks []int
	cur := 0
	wrap := func(step retentionStep) retentionStep {
		return func(ctx context.Context, tx *sql.Tx, limit int) (int, error) {
			n, err := step(ctx, tx, limit)
			limits, cur = append(limits, limit), cur+n
			return n, err
		}
	}
	r := retentionRig(t, 1200, wrap(deleteRange(seedTS, seedTS+600)),
		wrap(deleteRange(seedTS+600, seedTS+1200)))
	r.w.beforeCommit = func(*sql.Tx) error { chunks, cur = append(chunks, cur), 0; return nil }
	if err := r.retain(waitFor); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(limits, []int{1000, 400, 1000}) || !slices.Equal(chunks, []int{1000, 200}) || r.events() != 0 {
		t.Fatalf("limits %v, chunks %v, %d rows left", limits, chunks, r.events())
	}
}

// T-U-26: a run with no step runs no chunk, so no BEGIN. It still ends with the
// checkpoint. The list of production steps is empty in this change.
func TestTU26EmptyStepListRunsOnlyTheCheckpoint(t *testing.T) {
	r := retentionRig(t, 0)
	begins := 0
	r.w.beforeBegin = func() error { begins++; return nil }
	stmts := r.recordPragmas()
	if err := r.retain(waitFor); err != nil {
		t.Fatal(err)
	}
	if begins != 0 || !slices.Equal(*stmts, wantCheckpoint) {
		t.Fatalf("%d BEGIN, statements %v, want %v", begins, *stmts, wantCheckpoint)
	}
}

// T-U-26: between two chunks the writer writes a batch only when it has one.
// The drop counts wait for the tick: no tick comes, so they stay in memory.
func TestTU26DropCountsWaitForTheTick(t *testing.T) {
	var r *rig
	r = retentionRig(t, 3000, onCall(deleteRange(seedTS, math.MaxInt64), func(i int, _ *sql.Tx) {
		if i == 0 {
			r.c.DropNoAddr()
		}
	}))
	if err := r.retain(waitFor); err != nil {
		t.Fatal(err)
	}
	if !r.c.Pending() {
		t.Fatal("a run with no batch and no tick wrote the drop counts")
	}
}

// T-U-26: a chunk ends after the first statement that reaches the 100 ms
// budget. The statements add 49, 50 and 1 ms to the clock of the writer, in
// this order. The first two reach 99 ms, which is not enough. The third reaches
// 100 ms exactly, so each chunk has 3 statements.
func TestTU26ChunkEndsAtTheTimeBudget(t *testing.T) {
	now := time.Unix(0, 0)
	costs := []time.Duration{49, 50, 1}
	var steps []retentionStep
	calls, perChunk := 0, []int{}
	for k := range 9 {
		step := deleteRange(seedTS+int64(10*k), seedTS+int64(10*k+10))
		steps = append(steps, func(ctx context.Context, tx *sql.Tx, limit int) (int, error) {
			now, calls = now.Add(costs[calls%len(costs)]*time.Millisecond), calls+1
			return step(ctx, tx, limit)
		})
	}
	r := retentionRig(t, 90, steps...)
	r.w.clock = func() time.Time { return now }
	r.w.beforeCommit = func(*sql.Tx) error { perChunk, calls = append(perChunk, calls), 0; return nil }
	if err := r.retain(waitFor); err != nil {
		t.Fatal(err)
	}
	if want := []int{3, 3, 3}; !slices.Equal(perChunk, want) || r.events() != 0 {
		t.Fatalf("statements for each chunk %v, want %v", perChunk, want)
	}
}

// T-U-26: an event batch that waits in the lanes commits before the next
// chunk. The writer takes at most one batch between two chunks. Thus a flood
// cannot hold the run. 1 200 events wait. Two chunks write 500 each.
func TestTU26WaitingBatchCommitsBeforeNextChunk(t *testing.T) {
	var r *rig
	var addErr error
	var order []string // each chunk has one statement: it notes "chunk"
	r = retentionRig(t, 2500, onCall(deleteRange(seedTS, math.MaxInt64), func(i int, _ *sql.Tx) {
		order = append(order, "chunk")
		for j := 0; i == 0 && j < 1200 && addErr == nil; j++ {
			addErr = r.tryAdd(event.KindRequest, int64(j))
		}
	}))
	r.w.onCommit = func(n int) { order = append(order, fmt.Sprint("batch ", n)) }
	if err := r.retain(waitFor); err != nil || addErr != nil {
		t.Fatal(err, addErr)
	}
	if got, want := strings.Join(order, ", "), "chunk, batch 500, chunk, batch 500, chunk"; got != want {
		t.Fatalf("order %q, want %q", got, want)
	}
}

// T-U-26: during a run, the writer serves a row request and a tick that wait
// before the next chunk.
func TestTU26WaitingRowRequestAndTickAreServedBetweenChunks(t *testing.T) {
	tick := make(chan time.Time, 1)
	var r *rig
	var rowsLeft, ticksLeft, stored int
	r = retentionRig(t, 3000, onCall(deleteRange(seedTS, math.MaxInt64), func(i int, tx *sql.Tx) {
		switch i {
		case 0:
			r.w.rows <- rowRequest{size: 7, msg: []byte("note"), reply: make(chan error, 1)}
			tick <- time.Time{}
		case 1:
			rowsLeft, ticksLeft = len(r.w.rows), len(tick)
			if err := tx.QueryRow("SELECT count(*) FROM checkpoint").Scan(&stored); err != nil {
				t.Error(err)
			}
		}
	}))
	r.w.tick = tick
	if err := r.retain(waitFor); err != nil {
		t.Fatal(err)
	}
	if rowsLeft != 0 || ticksLeft != 0 || stored != 1 {
		t.Fatalf("at the second chunk: %d requests, %d ticks wait, %d rows stored", rowsLeft, ticksLeft, stored)
	}
}

// T-U-26: an error of a chunk statement, of BEGIN and of COMMIT stops the
// writer as a database error does. So does a step count above its limit or
// below 0. The chunk changes no row.
func TestTU26ChunkErrorStopsTheWriter(t *testing.T) {
	boom := errors.New("refused")
	bad := func(count func(limit int) int) []retentionStep {
		return []retentionStep{deleteRange(seedTS, seedTS+10), func(_ context.Context, _ *sql.Tx, limit int) (int, error) {
			return count(limit), nil
		}}
	}
	all := []retentionStep{deleteRange(seedTS, math.MaxInt64)}
	cases := []struct {
		name  string
		steps []retentionStep
		set   func(w *Writer)
	}{
		{"statement", []retentionStep{
			deleteRange(seedTS, seedTS+10),
			func(context.Context, *sql.Tx, int) (int, error) { return 0, boom },
		}, func(*Writer) {}},
		{"count above the limit", bad(func(limit int) int { return limit + 1 }), func(*Writer) {}},
		{"count below 0", bad(func(int) int { return -1 }), func(*Writer) {}},
		{"BEGIN", all, func(w *Writer) { w.beforeBegin = func() error { return boom } }},
		{"COMMIT", all, func(w *Writer) { w.beforeCommit = func(*sql.Tx) error { return boom } }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := retentionRig(t, 2500, c.steps...)
			c.set(r.w)
			err := r.retain(waitFor)
			wantRule(t, err, writerName, ruleDatabase)
			wantRule(t, r.w.Err(), writerName, ruleDatabase)
			if _, merr := r.marker(); merr != nil || r.w.Healthy() || r.events() != 2500 {
				t.Fatalf("marker %v, healthy %v, %d rows (want 2500)", merr, r.w.Healthy(), r.events())
			}
		})
	}
}

// T-U-26: a run ends early, with the retention rule, when ctx ends, when a row
// request stops the writer, or when the queue closes between two chunks. The
// chunk before it stays whole, and no second chunk commits.
func TestTU26RunEndsEarly(t *testing.T) {
	cases := []struct {
		name    string
		trigger func(r *rig, cancel context.CancelFunc) // runs in the first statement
		healthy bool
		waitRun bool  // wait for Run, which then returns wantRun
		wantRun error // the result of Run
	}{
		{"ctx ends", func(_ *rig, cancel context.CancelFunc) { cancel() }, true, true, context.Canceled},
		{"row request stops the writer", func(r *rig, _ context.CancelFunc) {
			r.w.rows <- rowRequest{size: 7, msg: []byte("note"), reply: make(chan error, 1)}
		}, false, false, nil},
		{"queue closes", func(r *rig, _ context.CancelFunc) { r.q.Close() }, true, true, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var r *rig
			var cancel context.CancelFunc
			r = retentionRig(t, 3000, onCall(deleteRange(seedTS, math.MaxInt64), func(i int, _ *sql.Tx) {
				if i == 0 {
					c.trigger(r, cancel)
				}
			}))
			r.w.beforeRowCommit = func(*sql.Tx) error { return errors.New("refused") }
			var done <-chan error
			done, cancel = r.launchCancelable(context.Background())
			ctx, stop := context.WithTimeout(context.Background(), waitFor)
			defer stop()
			wantRule(t, r.w.RunRetention(ctx), writerName, ruleRetention)
			if c.waitRun {
				if err := r.wait(done); !errors.Is(err, c.wantRun) {
					t.Fatalf("Run returned %v, want %v", err, c.wantRun)
				}
			}
			if r.w.Healthy() != c.healthy || r.events() != 2000 {
				t.Fatalf("healthy %v, %d rows (want %v, 2000)", r.w.Healthy(), r.events(), c.healthy)
			}
		})
	}
}

// countingRig makes a rig with 10 rows. Its step list holds one step that
// counts its calls, or no step. It also records the PRAGMA statements.
func countingRig(t *testing.T, withStep bool) (*rig, *int, *[]string) {
	t.Helper()
	calls := 0
	var steps []retentionStep
	if withStep {
		steps = append(steps, onCall(deleteRange(seedTS, math.MaxInt64), func(int, *sql.Tx) { calls++ }))
	}
	r := retentionRig(t, 10, steps...)
	return r, &calls, r.recordPragmas()
}

// T-U-26: a stopped writer starts no run from the take loop. A batch of 500
// events fails at its COMMIT, and a retention request waits at that time. The
// request stays in its channel. No step, BEGIN or checkpoint statement runs.
func TestTU26StoppedWriterStartsNoRunFromTheTakeLoop(t *testing.T) {
	for _, withStep := range []bool{true, false} {
		t.Run(fmt.Sprint("with step ", withStep), func(t *testing.T) {
			r, calls, stmts := countingRig(t, withStep)
			rq := retentionRequest{reply: make(chan error, 1)}
			hooked, first := make(chan struct{}), true
			r.w.beforeCommit = func(*sql.Tx) error {
				if first {
					first = false
					r.w.retention <- rq
					close(hooked)
				}
				return errors.New("refused")
			}
			for i := range maxBatch {
				r.add(event.KindRequest, int64(i))
			}
			done, _ := r.launchCancelable(context.Background())
			select {
			case <-hooked:
			case <-time.After(waitFor):
				t.Fatal("the batch did not reach its COMMIT")
			}
			// A Close lets Run end after the take loop. A cancel is too soon.
			r.q.Close()
			if err := r.wait(done); err != nil {
				t.Fatal(err)
			}
			if r.w.Healthy() || *calls != 0 || len(*stmts) != 0 || len(r.w.retention) != 1 || len(rq.reply) != 0 || r.events() != 10 {
				t.Fatalf("healthy %v, %d steps, statements %v, %d waiting, %d replies, %d rows",
					r.w.Healthy(), *calls, *stmts, len(r.w.retention), len(rq.reply), r.events())
			}
		})
	}
}

// T-U-26: serveRetention on a stopped writer replies with the retention rule.
// It runs no step, no BEGIN and no checkpoint statement.
func TestTU26RunOnStoppedWriterIsRefused(t *testing.T) {
	for _, withStep := range []bool{true, false} {
		t.Run(fmt.Sprint("with step ", withStep), func(t *testing.T) {
			r, calls, stmts := countingRig(t, withStep)
			begins := 0
			r.w.beforeBegin = func() error { begins++; return nil }
			r.w.stop(fail(writerName, ruleDatabase))
			rq := retentionRequest{reply: make(chan error, 1)}
			r.w.serveRetention(context.Background(), nil, nil, rq)
			wantRule(t, r.reply(rq), writerName, ruleRetention)
			if *calls != 0 || begins != 0 || len(*stmts) != 0 || r.events() != 10 {
				t.Fatalf("%d steps, %d BEGIN, statements %v, %d rows", *calls, begins, *stmts, r.events())
			}
		})
	}
}

// T-U-26: a run that starts in the take loop completes. The lanes still hold
// events when its first statement runs: the main select did not start it.
func TestTU26RunStartsFromTheTakeLoop(t *testing.T) {
	var r *rig
	var lanesBusy bool
	r = retentionRig(t, 2000, onCall(deleteRange(seedTS, math.MaxInt64), func(i int, _ *sql.Tx) {
		if i == 0 {
			lanesBusy = r.q.Bytes() != (event.Bytes{})
		}
	}))
	rq, queued := retentionRequest{reply: make(chan error, 1)}, false
	r.w.beforeCommit = func(*sql.Tx) error {
		if !queued {
			queued = true
			r.w.retention <- rq
		}
		return nil
	}
	for i := range 1200 {
		r.add(event.KindRequest, int64(i))
	}
	r.launchCancelable(context.Background())
	if err := r.reply(rq); err != nil || !lanesBusy {
		t.Fatalf("reply %v, lanes busy at the first statement: %v", err, lanesBusy)
	}
}

// T-U-26: a ctx that has ended gives ctx.Err(), and a stopped writer gives its
// error. Both return at once and send no request.
func TestTU26RunRetentionSendsNoRequestAtOnce(t *testing.T) {
	r := retentionRig(t, 0)
	ended, cancel := context.WithCancel(context.Background())
	cancel()
	if err := r.w.RunRetention(ended); !errors.Is(err, context.Canceled) {
		t.Fatalf("ended ctx: got %v", err)
	}
	r.w.stop(fail(writerName, ruleDatabase))
	ctx, stop := context.WithTimeout(context.Background(), waitFor)
	defer stop()
	wantRule(t, r.w.RunRetention(ctx), writerName, ruleDatabase)
	if len(r.w.retention) != 0 {
		t.Fatalf("%d requests wait", len(r.w.retention))
	}
}

// T-U-26: a caller that has left gets no run. If it leaves before the first
// chunk, no step runs. If it leaves during the first chunk, no second chunk
// runs.
func TestTU26CallerThatLeftGetsNoRun(t *testing.T) {
	for _, between := range []bool{false, true} {
		t.Run(fmt.Sprint("between chunks ", between), func(t *testing.T) {
			gone, calls := make(chan struct{}), 0
			r := retentionRig(t, 3000, onCall(deleteRange(seedTS, math.MaxInt64), func(int, *sql.Tx) {
				if calls++; between && calls == 1 {
					close(gone)
				}
			}))
			if !between {
				close(gone)
			}
			rq := retentionRequest{reply: make(chan error, 1), gone: gone}
			r.w.retention <- rq
			r.launchCancelable(context.Background())
			wantRule(t, r.reply(rq), writerName, ruleRetention)
			want := map[bool][2]int{false: {0, 3000}, true: {1, 2000}}[between]
			if got := [2]int{calls, r.events()}; got != want {
				t.Fatalf("steps and rows %v, want %v", got, want)
			}
		})
	}
}

// T-S-33: after a run with no reader the WAL file has 0 bytes. The checkpoint
// runs with busy_timeout 0. The pool value comes back after it.
func TestTS33RunEndsWithTruncatedWAL(t *testing.T) {
	r := retentionRig(t, 3000, deleteRange(seedTS, math.MaxInt64))
	wal := filepath.Join(r.state, "events.db-wal")
	if fi, err := os.Stat(wal); err != nil || fi.Size() == 0 {
		t.Fatalf("WAL before the run: %v, %v", fi, err)
	}
	stmts := r.recordPragmas()
	if err := r.retain(waitFor); err != nil {
		t.Fatal(err)
	}
	var timeout int
	if err := r.db.QueryRow("PRAGMA busy_timeout").Scan(&timeout); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(wal)
	if err != nil || fi.Size() != 0 || r.w.RetentionCheckpointBusy() != 0 || timeout != 5000 {
		t.Fatalf("WAL %v (%v), busy %d, busy_timeout %d", fi, err, r.w.RetentionCheckpointBusy(), timeout)
	}
	if !slices.Equal(*stmts, wantCheckpoint) {
		t.Fatalf("statements %v, want %v", *stmts, wantCheckpoint)
	}
}

// T-S-33: a failed busy_timeout restore after the checkpoint is a database
// error. The writer stops and the stop marker exists.
func TestTS33RestoreFailureStopsTheWriter(t *testing.T) {
	r := retentionRig(t, 0)
	r.w.beforePragma = func(s string) error {
		if s == "PRAGMA busy_timeout=5000" {
			return errors.New("pragma refused")
		}
		return nil
	}
	wantRule(t, r.retain(waitFor), writerName, ruleDatabase)
	wantRule(t, r.w.Err(), writerName, ruleDatabase)
	if _, err := r.marker(); err != nil || r.w.Healthy() {
		t.Fatalf("marker %v, healthy %v", err, r.w.Healthy())
	}
}

// T-S-33: a reader holds a snapshot. The checkpoint runs with busy_timeout 0,
// so it does not wait for the reader. The busy count adds 1 and the writer
// stays healthy. After the reader ends, the next run truncates the WAL.
func TestTS33ReaderMakesCheckpointBusyNotAnError(t *testing.T) {
	r := retentionRig(t, 3000, deleteRange(seedTS, math.MaxInt64))
	rdb := mustOpen(t, r.root, "events.db")
	defer rdb.Close()
	conn, err := rdb.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var n int
	if _, err := conn.ExecContext(context.Background(), "BEGIN"); err != nil {
		t.Fatal(err)
	}
	if err := conn.QueryRowContext(context.Background(), "SELECT count(*) FROM event").Scan(&n); err != nil || n != 3000 {
		t.Fatalf("reader sees %d rows: %v", n, err)
	}
	stmts := r.recordPragmas()
	err = r.retain(10 * time.Second) // a bound for a failure, not a check
	if err != nil || r.w.RetentionCheckpointBusy() != 1 || !r.w.Healthy() {
		t.Fatalf("run: %v, busy %d, healthy %v", err, r.w.RetentionCheckpointBusy(), r.w.Healthy())
	}
	if !slices.Equal(*stmts, wantCheckpoint) {
		t.Fatalf("statements %v, want %v", *stmts, wantCheckpoint)
	}
	if _, err := conn.ExecContext(context.Background(), "COMMIT"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), waitFor)
	defer cancel()
	fi, statErr := os.Stat(filepath.Join(r.state, "events.db-wal"))
	if err := r.w.RunRetention(ctx); err != nil || statErr != nil {
		t.Fatal(err, statErr)
	}
	if fi, err = os.Stat(filepath.Join(r.state, "events.db-wal")); err != nil || fi.Size() != 0 || r.w.RetentionCheckpointBusy() != 1 {
		t.Fatalf("second run: WAL %v (%v), busy %d", fi, err, r.w.RetentionCheckpointBusy())
	}
}

const (
	// retChildDir is the state directory of the child. With "1" in retChildOff,
	// the child sets secure_delete OFF.
	retChildDir = "STORE_RETENTION_CHILD_DIR"
	retChildOff = "STORE_RETENTION_CHILD_OFF"
)

// BenchmarkRetentionDeleteChunk measures the peak RSS and the time of one
// 1 000-row delete chunk of the real runner. It does this with secure_delete
// ON and with OFF. PHANTOM_RETENTION_ROWS gives the rows (default 20 000).
// They have 300 bytes and cover 40 days. Each chunk runs in a child process of
// the test binary. Thus the setup is not in the peak. The OFF child sets
// secure_delete after the open, because the open refuses a string with OFF.
// Run it with -benchtime=1x. A MB is 2^20 bytes.
func BenchmarkRetentionDeleteChunk(b *testing.B) {
	n := 20_000
	if s := os.Getenv("PHANTOM_RETENTION_ROWS"); s != "" {
		v, err := strconv.Atoi(s)
		if err != nil || v < chunkRows {
			b.Fatalf("PHANTOM_RETENTION_ROWS %q: want a number of at least %d", s, chunkRows)
		}
		n = v
	}
	span := int64(40 * 24 * time.Hour / time.Millisecond)
	for _, off := range []string{"", "1"} {
		top, err := filepath.EvalSymlinks(b.TempDir())
		if err != nil {
			b.Fatal(err)
		}
		state := filepath.Join(top, "state")
		if err := os.Mkdir(state, 0o700); err != nil {
			b.Fatal(err)
		}
		root, err := os.OpenRoot(state)
		if err != nil {
			b.Fatal(err)
		}
		db, err := Open(root, "events.db", Options{})
		if err != nil || Migrate(db, "origin") != nil {
			b.Fatal("setup:", err)
		}
		seedEvents(b, db, n, time.Now().UnixMilli()-span, max(1, span/int64(n)), true)
		db.Close()
		root.Close()
		cmd := exec.Command(os.Args[0], "-test.run=^$", "-test.bench=^BenchmarkRetentionChunkChild$", "-test.benchtime=1x")
		cmd.Env = append(os.Environ(), retChildDir+"="+state, retChildOff+"="+off)
		out, err := cmd.CombinedOutput()
		var rss int64
		var ms float64
		for _, line := range strings.Split(string(out), "\n") {
			if _, e := fmt.Sscanf(line, "retention-child rss=%d ms=%f", &rss, &ms); e == nil {
				break
			}
		}
		if err != nil || rss == 0 {
			b.Fatalf("child: %v\n%s", err, out)
		}
		unit := map[string]string{"": "", "1": "-off"}[off]
		b.ReportMetric(float64(rss)/(1<<20), "peak-rss"+unit+"-MB")
		b.ReportMetric(ms, "chunk"+unit+"-ms")
	}
}

// BenchmarkRetentionChunkChild is the child process of the benchmark above. It
// opens the built file, runs one chunk, and prints VmHWM and the chunk time.
// Without the environment variable, it skips.
func BenchmarkRetentionChunkChild(b *testing.B) {
	dir := os.Getenv(retChildDir)
	if dir == "" {
		b.Skip("child process of BenchmarkRetentionDeleteChunk")
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		b.Fatal(err)
	}
	db, err := Open(root, "events.db", Options{})
	if err != nil {
		b.Fatal(err)
	}
	if os.Getenv(retChildOff) == "1" {
		// The open refuses a string with secure_delete OFF. So the child sets
		// it on the one pool connection after the open. Then it reads it back.
		var v int
		if _, err := db.Exec("PRAGMA secure_delete=OFF"); err != nil {
			b.Fatal(err)
		}
		if err := db.QueryRow("PRAGMA secure_delete").Scan(&v); err != nil || v != 0 {
			b.Fatalf("secure_delete %d: %v", v, err)
		}
	}
	q, err := event.NewQueue(1, event.NewCounters())
	if err != nil {
		b.Fatal(err)
	}
	w, cur := NewWriter(db, q, false, nil, Recovery{}), 0
	begin := time.Now()
	rows, err := w.chunk([]retentionStep{deleteRange(0, math.MaxInt64)}, &cur)
	took := time.Since(begin)
	if err != nil || rows != chunkRows {
		b.Fatalf("chunk: %d rows, %v", rows, err)
	}
	fmt.Printf("retention-child rss=%d ms=%.3f\n", procStatus(b, "VmHWM"), float64(took)/float64(time.Millisecond))
}
