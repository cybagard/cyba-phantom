package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cybagard/cyba-phantom/internal/event"
	"github.com/cybagard/cyba-phantom/internal/tlog"
)

const waitFor = 5 * time.Second

// testAppender gives sequential leaf indices from next and keeps what it got.
type testAppender struct {
	mu     sync.Mutex
	next   int64
	err    error
	tries  int // calls, also the failed ones
	firsts []int64
	calls  [][]tlog.EventHash

	// While gated is true, AppendBatch sends on entered and waits for release.
	gated   atomic.Bool
	entered chan struct{}
	release chan struct{}
}

func (a *testAppender) AppendBatch(hs []tlog.EventHash) (int64, error) {
	if a.gated.Load() {
		a.entered <- struct{}{}
		<-a.release
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.tries++
	if a.err != nil {
		return 0, a.err
	}
	first := a.next
	a.next += int64(len(hs))
	a.firsts = append(a.firsts, first)
	a.calls = append(a.calls, append([]tlog.EventHash(nil), hs...))
	return first, nil
}

type rig struct {
	t       *testing.T
	w       *Writer
	q       *event.Queue
	c       *event.Counters
	db      *sql.DB
	app     *testAppender
	root    *os.Root // the state directory
	state   string   // its path
	lg      *fakeLog // what the start check reads
	tick    chan time.Time
	commits chan int
	exited  chan struct{} // closed when the last launched Run returns
}

func newRig(t *testing.T, depth int) *rig {
	t.Helper()
	c := event.NewCounters()
	q, err := event.NewQueue(depth, c)
	if err != nil {
		t.Fatal(err)
	}
	root, state, _ := newState(t)
	db := mustOpen(t, root, "events.db")
	t.Cleanup(func() { db.Close() })
	if err := Migrate(db, "origin"); err != nil {
		t.Fatal(err)
	}
	r := &rig{t: t, q: q, c: c, db: db, app: &testAppender{next: 100}, root: root, state: state,
		lg: &fakeLog{}, tick: make(chan time.Time), commits: make(chan int, 64)}
	r.w = NewWriter(r.db, q, r.app, c, false, nil, Recovery{State: root, Origin: "origin", Log: r.lg})
	r.w.tick = r.tick
	r.w.onCommit = func(n int) { r.commits <- n }
	return r
}

// add enqueues one event. ts is its time, so a test can tell the events apart.
func (r *rig) add(kind event.Kind, ts int64) {
	r.t.Helper()
	e, err := event.NewEvent(func() time.Time { return time.UnixMilli(ts) }, event.Input{Kind: kind})
	if err != nil || !r.q.Enqueue(e) {
		r.t.Fatalf("enqueue kind %v: %v", kind, err)
	}
}

// launch starts the writer goroutine. The channel gets the result of Run.
func (r *rig) launch(ctx context.Context) <-chan error {
	done, exited := make(chan error, 1), make(chan struct{})
	r.exited = exited
	go func() {
		done <- r.w.Run(ctx)
		close(exited)
	}()
	return done
}

// wait gets the result of Run. It fails if Run does not return in waitFor.
func (r *rig) wait(done <-chan error) error {
	r.t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(waitFor):
		r.t.Fatal("Run did not return")
		return nil
	}
}

// run calls Run and waits for it with a bound.
func (r *rig) run(ctx context.Context) error {
	r.t.Helper()
	return r.wait(r.launch(ctx))
}

// gate makes the next AppendBatch call wait. ungate releases it. Call gate only
// when Run is not inside AppendBatch.
func (r *rig) gate() {
	r.app.entered, r.app.release = make(chan struct{}, 1), make(chan struct{})
	r.app.gated.Store(true)
}

func (r *rig) ungate() {
	if r.app.gated.Swap(false) {
		close(r.app.release)
	}
}

// stopRun is for a cleanup. It releases the gate, cancels ctx, and waits for Run
// to return. It reports a Run that does not return, and does not call Fatal.
func (r *rig) stopRun(cancel context.CancelFunc) {
	r.ungate()
	cancel()
	select {
	case <-r.exited:
	case <-time.After(waitFor):
		r.t.Error("Run did not return at the end of the test")
	}
}

// start runs the writer goroutine. The returned function stops it. If the test
// fails first, the cleanup releases the gate and cancels ctx, so Run ends.
func (r *rig) start() (stop func() error) {
	ctx, cancel := context.WithCancel(context.Background())
	done := r.launch(ctx)
	r.t.Cleanup(func() { r.stopRun(cancel) })
	return func() error {
		cancel()
		return r.wait(done)
	}
}

// drained waits until the writer has taken every event from the lanes. The
// writer reads the tick only after it takes all events, so a tick sent after
// drained is not early.
func (r *rig) drained() {
	r.t.Helper()
	for end := time.Now().Add(waitFor); r.q.Bytes() != (event.Bytes{}); runtime.Gosched() {
		if time.Now().After(end) {
			r.t.Fatal("the writer did not take the events")
		}
	}
}

func (r *rig) fire() {
	r.t.Helper()
	select {
	case r.tick <- time.Now():
	case <-time.After(waitFor):
		r.t.Fatal("the writer did not read the tick")
	}
}

func (r *rig) commit() int {
	r.t.Helper()
	select {
	case n := <-r.commits:
		return n
	case <-time.After(waitFor):
		r.t.Fatal("no commit")
		return 0
	}
}

func (r *rig) rows() (n int) {
	r.t.Helper()
	if err := r.db.QueryRow("SELECT count(*) FROM event").Scan(&n); err != nil {
		r.t.Fatal(err)
	}
	return n
}

func wantCommits(t *testing.T, r *rig, want ...int) {
	t.Helper()
	for i, w := range want {
		if n := r.commit(); n != w {
			t.Fatalf("commit %d has %d rows, want %d", i, n, w)
		}
	}
}

// T-U-18: with both lanes full, the first batch holds the evidence events first.
func TestTU18EvidenceLaneIsFirst(t *testing.T) {
	r := newRig(t, 40) // bulk lane 40, evidence lane 10
	for i := int64(0); i < 40; i++ {
		r.add(event.KindRequest, 1000+i)
		if i%4 == 3 {
			r.add(event.KindBundleLoad, i/4)
		}
	}
	r.q.Close()
	if err := r.run(context.Background()); err != nil {
		t.Fatal(err)
	}
	wantCommits(t, r, 50)
	rows, err := r.db.Query("SELECT ts, leaf_index FROM event ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for i := int64(0); i < 50; i++ {
		var ts int64
		var leaf sql.NullInt64
		if !rows.Next() || rows.Scan(&ts, &leaf) != nil {
			t.Fatalf("row %d is missing", i)
		}
		wantTS, wantLeaf := 1000+i-10, sql.NullInt64{}
		if i < 10 {
			wantTS, wantLeaf = i, sql.NullInt64{Int64: 100 + i, Valid: true}
		}
		if ts != wantTS || leaf != wantLeaf {
			t.Fatalf("row %d: ts %d leaf %v", i, ts, leaf)
		}
	}
}

// T-U-18: 1 250 events give three transactions (500, 500, 250). The last one
// waits for the tick. The gated appender makes the check exact: Run is one
// goroutine, so the tick send succeeds only while Run waits in select. An early
// write of the last 250 events (one has evidence) would block in AppendBatch.
func TestTU18BatchesHaveAtMost500Events(t *testing.T) {
	r := newRig(t, 2000)
	for i := int64(0); i < 1000; i++ {
		r.add(event.KindRequest, i)
	}
	stop := r.start()
	wantCommits(t, r, 500, 500)
	r.drained()
	r.gate()
	for i := int64(0); i < 250; i++ {
		kind := event.KindRequest
		if i == 0 {
			kind = event.KindAlertSent
		}
		r.add(kind, 1000+i)
	}
	r.drained()
	select {
	case <-r.app.entered:
		t.Fatal("the last 250 events were written before the tick")
	case r.tick <- time.Now():
	case <-time.After(waitFor):
		t.Fatal("Run did not wait for the tick")
	}
	r.ungate()
	wantCommits(t, r, 250)
	if err := stop(); !errors.Is(err, context.Canceled) || r.rows() != 1250 {
		t.Fatalf("err %v, rows %d", err, r.rows())
	}
}

// T-U-18: 10 events commit at the tick and not before.
func TestTU18EventsCommitAtTheTick(t *testing.T) {
	r := newRig(t, 100)
	stop := r.start()
	for i := int64(0); i < 10; i++ {
		r.add(event.KindRequest, i)
	}
	r.drained()
	if len(r.commits) != 0 || r.rows() != 0 {
		t.Fatal("the batch was written before the tick")
	}
	r.fire()
	wantCommits(t, r, 10)
	if err := stop(); !errors.Is(err, context.Canceled) || r.rows() != 10 {
		t.Fatalf("err %v, rows %d", err, r.rows())
	}
}

// T-U-18: the goroutine count does not grow with the number of events. The base
// is the count before Run starts. A batch in flight adds the goroutine of its
// transaction (database/sql ends it after the commit) and the goroutine of Run.
// Limit of this test: a goroutine that ends before the count is not seen.
func TestTU18GoroutineCountDoesNotGrow(t *testing.T) {
	r := newRig(t, 4000)
	r.gate()
	base := runtime.NumGoroutine()
	stop := r.start()
	for i := int64(0); i < 2000; i++ {
		kind := event.KindRequest
		if i%5 == 0 {
			kind = event.KindAlertSent
		}
		r.add(kind, i)
	}
	select { // the first batch waits in AppendBatch with its transaction open
	case <-r.app.entered:
	case <-time.After(waitFor):
		t.Fatal("no batch reached the appender")
	}
	if n := runtime.NumGoroutine(); n > base+2 {
		t.Fatalf("%d goroutines with a batch in flight, %d before Run", n, base)
	}
	r.ungate()
	wantCommits(t, r, 500, 500, 500, 500)
	// The goroutine of the last transaction can end a short time after Commit.
	for end := time.Now().Add(waitFor); runtime.NumGoroutine() > base+1; runtime.Gosched() {
		if time.Now().After(end) {
			t.Fatalf("%d goroutines after 2 000 events, %d before Run", runtime.NumGoroutine(), base)
		}
	}
	if err := stop(); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

// T-U-18: each evidence row has the hash, the leaf index first+i and the record
// bytes; the appender gets one call for a batch with evidence and none for a
// batch with bulk events only.
func TestTU18EvidenceRowsHaveHashLeafAndRecord(t *testing.T) {
	r := newRig(t, 100)
	stop := r.start()
	for _, batch := range [][]event.Kind{
		{event.KindRequest, event.KindBeacon, event.KindRequest},
		{event.KindRequest, event.KindCallback, event.KindBeacon, event.KindScoreChange},
		{event.KindRetention, event.KindAlertSent, event.KindBundleRejected},
	} {
		for _, k := range batch {
			r.add(k, int64(r.rows()))
		}
		r.drained()
		r.fire()
		r.commit()
	}
	if err := stop(); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if len(r.app.calls) != 2 || len(r.app.calls[0]) != 2 || len(r.app.calls[1]) != 3 ||
		r.app.firsts[0] != 100 || r.app.firsts[1] != 102 {
		t.Fatalf("appender calls %v at %v", r.app.calls, r.app.firsts)
	}
	rows, err := r.db.Query("SELECT hash, leaf_index, record FROM event WHERE leaf_index IS NOT NULL ORDER BY leaf_index")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	leaf := int64(100)
	for _, call := range r.app.calls {
		for _, h := range call {
			var hash, record []byte
			var got int64
			if !rows.Next() || rows.Scan(&hash, &got, &record) != nil {
				t.Fatalf("row %d is missing", leaf)
			}
			sum := sha256.Sum256(record)
			if got != leaf || !bytes.Equal(hash, h[:]) || !bytes.Equal(hash, sum[:]) {
				t.Fatalf("leaf %d: row has leaf %d, hash %x, sha256 %x", leaf, got, hash, sum)
			}
			leaf++
		}
	}
	rows.Close() // the pool has one connection
	var n int
	q := "SELECT count(*) FROM event WHERE kind IN ('request', 'beacon', 'refused') AND (hash IS NOT NULL OR leaf_index IS NOT NULL OR record IS NOT NULL)"
	if err := r.db.QueryRow(q).Scan(&n); err != nil || n != 0 || r.rows() != 10 {
		t.Fatalf("bulk rows with evidence columns: %d, %v", n, err)
	}
}

// T-U-18: the writer stores a refused event as one bulk row of the kind
// refused. The row has no hash, no leaf index and no record. The writer gives
// the log no hash.
func TestTU18RefusedEventIsStoredAsBulkRow(t *testing.T) {
	r := newRig(t, 100)
	if err := r.w.write([]*event.Event{refusedEvent(t, "198.51.100.23", "")}); err != nil {
		t.Fatal(err)
	}
	var n int
	q := "SELECT count(*) FROM event WHERE kind = 'refused' AND hash IS NULL AND leaf_index IS NULL AND record IS NULL"
	if err := r.db.QueryRow(q).Scan(&n); err != nil || n != 1 || r.rows() != 1 || len(r.app.calls) != 0 {
		t.Fatalf("%d bulk rows of the kind refused, %d rows, %d log calls: %v", n, r.rows(), len(r.app.calls), err)
	}
}

// T-U-18: after Close, Run writes its batch and the rest, returns nil, and
// loses no event.
func TestTU18CloseWritesAllEvents(t *testing.T) {
	r := newRig(t, 2000)
	for i := int64(0); i < 1100; i++ {
		kind := event.KindRequest
		if i%11 == 0 {
			kind = event.KindCallback
		}
		r.add(kind, i)
	}
	r.q.Close()
	if err := r.run(context.Background()); err != nil {
		t.Fatal(err)
	}
	wantCommits(t, r, 500, 500, 100)
	if r.rows() != 1100 {
		t.Fatalf("%d rows for 1 100 events", r.rows())
	}
}

// T-U-18: the shutdown step writes the batch, then the events that Drain
// returns, in batches of at most 500, in order, and loses no event.
func TestTU18ShutdownWritesTheDrainedEvents(t *testing.T) {
	r := newRig(t, 2000)
	for i := int64(0); i < 605; i++ {
		kind := event.KindRequest
		if i%6 == 0 {
			kind = event.KindScoreChange
		}
		r.add(kind, i)
	}
	var batch []*event.Event
	for len(batch) < 5 {
		e, ok := r.q.TryTake()
		if !ok {
			t.Fatal("the lanes are empty")
		}
		batch = append(batch, e)
	}
	r.q.Close()
	r.w.shutdown(batch)
	wantCommits(t, r, 5, 500, 100)
	if e, ok := r.q.TryTake(); ok || e != nil {
		t.Fatal("an event is left in the lanes")
	}
	if r.rows() != 605 {
		t.Fatalf("%d rows for 605 events", r.rows())
	}
	rows, err := r.db.Query("SELECT leaf_index FROM event WHERE leaf_index IS NOT NULL ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	n := int64(0)
	for ; rows.Next(); n++ {
		var leaf int64
		if rows.Scan(&leaf) != nil || leaf != 100+n {
			t.Fatalf("evidence row %d has leaf %d", n, leaf)
		}
	}
	if n != 101 { // i = 0, 6, ..., 600
		t.Fatalf("%d evidence rows, want 101", n)
	}
}

// T-U-18: when ctx ends, Run writes the events that it took and returns ctx.Err().
func TestTU18CancelWritesTheTakenEvents(t *testing.T) {
	r := newRig(t, 100)
	stop := r.start()
	for i := int64(0); i < 10; i++ {
		r.add(event.KindRequest, i)
	}
	r.drained()
	if err := stop(); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	wantCommits(t, r, 10)
	if r.rows() != 10 {
		t.Fatalf("%d rows", r.rows())
	}
}

// T-U-18: Close while Run waits ends Run with nil and writes the events. Case
// one closes right after the adds: Run may or may not have taken the events.
// Case two closes when Run holds the batch. No tick is sent.
func TestTU18CloseWhileRunning(t *testing.T) {
	for _, waitForBatch := range []bool{false, true} {
		name := "Close right after the adds"
		if waitForBatch {
			name = "batch in hand"
		}
		t.Run(name, func(t *testing.T) {
			r := newRig(t, 100)
			done := r.launch(context.Background())
			for i := int64(0); i < 10; i++ {
				r.add(event.KindRequest, i)
			}
			if waitForBatch {
				r.drained()
			}
			r.q.Close()
			if err := r.wait(done); err != nil {
				t.Fatal(err)
			}
			if r.rows() != 10 {
				t.Fatalf("%d rows for 10 events", r.rows())
			}
		})
	}
}

// T-U-18: when Close and the end of ctx both come before Run sees them, Run does
// the normal shutdown: it writes all events and returns nil. In the case "only
// ctx is ready", the test takes the one pending wake, so Run takes the ctx.Done
// branch with all 700 events in the lanes and Drain returns them. In the other
// case, Run can take either branch.
func TestTU18CloseWinsOverCancel(t *testing.T) {
	for _, onlyCtx := range []bool{true, false} {
		name := "both ready"
		if onlyCtx {
			name = "only ctx is ready"
		}
		t.Run(name, func(t *testing.T) {
			r := newRig(t, 2000)
			for i := int64(0); i < 700; i++ {
				kind := event.KindRequest
				if i%7 == 0 {
					kind = event.KindCallback
				}
				r.add(kind, i)
			}
			ctx, cancel := context.WithCancel(context.Background())
			r.q.Close()
			cancel()
			if onlyCtx {
				<-r.q.Ready() // the wake channel holds one value
			}
			if err := r.run(ctx); err != nil {
				t.Fatal(err)
			}
			if r.rows() != 700 {
				t.Fatalf("%d rows for 700 events", r.rows())
			}
		})
	}
}

// T-U-18: after a full flush, Run leaves the take loop when ctx has ended. The
// test enqueues 1 200 events. When the first batch waits in AppendBatch, 500
// events are in the batch and the rest stay in the lanes. Then the test cancels
// ctx (no Close) and releases the batch. Run writes at most one more batch,
// returns context.Canceled, and leaves events in the lanes.
func TestTU18CancelAfterFullFlushLeavesEventsInTheLanes(t *testing.T) {
	r := newRig(t, 4000)
	r.gate()
	ctx, cancel := context.WithCancel(context.Background())
	done := r.launch(ctx)
	t.Cleanup(func() { r.stopRun(cancel) })
	for i := int64(0); i < 1200; i++ {
		kind := event.KindRequest
		if i%5 == 0 {
			kind = event.KindAlertSent
		}
		r.add(kind, i)
	}
	select {
	case <-r.app.entered:
	case <-time.After(waitFor):
		t.Fatal("no batch reached the appender")
	}
	cancel()
	r.ungate()
	if err := r.wait(done); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run returned %v", err)
	}
	if n := len(r.commits); n < 1 || n > 2 {
		t.Fatalf("%d batches written, want 1 or 2", n)
	}
	if r.q.Bytes() == (event.Bytes{}) {
		t.Fatal("no event is left in the lanes")
	}
}

// runAfterStart starts the writer and waits until it has passed the start check
// and committed one event. Then it calls late, calls batch to queue the events,
// closes the queue, and returns the result of Run. Thus late changes the world
// after the start check and before the batch is written.
func (r *rig) runAfterStart(late, batch func()) error {
	r.t.Helper()
	stop := r.start()
	r.add(event.KindRequest, 0)
	r.drained()
	r.fire()
	r.commit()
	if !r.w.Healthy() {
		r.t.Fatalf("the writer stopped at the start: %v", r.w.Err())
	}
	late()
	batch()
	r.q.Close()
	return stop()
}

// T-U-18: a closed database and a refused row stop the writer and commit nothing
// of the batch; Run returns nil after Close and Err holds the database rule. The
// database closes after the start check, so the write path fails. For the
// refused row, the appender got its one call, so the leaves of that batch stay
// in the log with no row. They count as orphan leaves: one evidence event, one
// orphan leaf. The closed database fails before the append and counts none.
func TestTU18DatabaseErrorsRollBackTheBatch(t *testing.T) {
	cases := []struct {
		name    string
		rule    string
		late    bool // close the database after the start check
		orphans uint64
		setup   func(r *rig)
	}{
		{"closed database", ruleDatabase, true, 0, func(r *rig) { r.db.Close() }},
		{"refused row", ruleDatabase, false, 1, func(r *rig) { r.app.next = -1 }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t, 100)
			batch := func() {
				r.add(event.KindRequest, 1)
				r.add(event.KindCallback, 2)
			}
			var err error
			if c.late {
				err = r.runAfterStart(func() { c.setup(r) }, batch)
			} else {
				batch()
				r.q.Close()
				c.setup(r)
				err = r.run(context.Background())
			}
			if err != nil {
				t.Fatal(err)
			}
			wantRule(t, r.w.Err(), writerName, c.rule)
			if r.w.Healthy() || len(r.commits) != 0 || r.w.Stats().OrphanLeaves != c.orphans {
				t.Fatalf("healthy %v, %d commits, stats %+v", r.w.Healthy(), len(r.commits), r.w.Stats())
			}
			if c.name == "refused row" && (r.rows() != 0 || len(r.app.calls) != 1) {
				t.Fatalf("%d rows, %d appender calls", r.rows(), len(r.app.calls))
			}
		})
	}
}

// batchOfFour queues one bulk event and three evidence events, and closes the
// queue.
func (r *rig) batchOfFour() {
	r.add(event.KindRequest, 1)
	for i := int64(2); i < 5; i++ {
		r.add(event.KindCallback, i)
	}
	r.q.Close()
}

// ipCounters returns the ip_counter rows as "day ip_hmac dropped" texts.
func (r *rig) ipCounters() (out []string) {
	r.t.Helper()
	rows, err := r.db.Query("SELECT day, ip_hmac, dropped FROM ip_counter ORDER BY day, ip_hmac")
	if err != nil {
		r.t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var day, hmac string
		var dropped int64
		if err := rows.Scan(&day, &hmac, &dropped); err != nil {
			r.t.Fatal(err)
		}
		out = append(out, fmt.Sprintf("%s %s %d", day, hmac, dropped))
	}
	if err := rows.Err(); err != nil {
		r.t.Fatal(err)
	}
	return out
}

// T-U-18: take a good AppendBatch call. After it, an error of the record bytes,
// of an insert, of the drop counts or of the COMMIT counts each leaf of the
// batch as an orphan leaf. The writer stops and no row of the batch exists. The
// batch has three evidence events.
func TestTU18ErrorAfterGoodAppendCountsOrphanLeaves(t *testing.T) {
	cases := []struct {
		name  string
		rule  string
		setup func(r *rig)
	}{
		{"record bytes", ruleRecord, func(r *rig) {
			r.w.evidenceBytes = func(event.Record) ([]byte, error) { return nil, errors.New("no bytes") }
		}},
		{"insert", ruleDatabase, func(r *rig) { r.app.next = -1 }},
		{"drop counts", ruleDatabase, func(r *rig) {
			if _, err := r.db.Exec("DROP TABLE ip_counter"); err != nil {
				r.t.Fatal(err)
			}
			r.c.DropNoAddr()
		}},
		{"COMMIT", ruleDatabase, func(r *rig) {
			r.w.beforeCommit = func(*sql.Tx) error { return errors.New("commit refused") }
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t, 100)
			c.setup(r)
			r.batchOfFour()
			if err := r.run(context.Background()); err != nil {
				t.Fatal(err)
			}
			wantRule(t, r.w.Err(), writerName, c.rule)
			s := r.w.Stats()
			if r.w.Healthy() || s.OrphanLeaves != 3 || s.WriteFailed != 0 || r.app.tries != 1 {
				t.Fatalf("healthy %v, stats %+v, %d appender calls", r.w.Healthy(), s, r.app.tries)
			}
			if r.rows() != 0 || len(r.commits) != 0 {
				t.Fatalf("%d rows, %d commits", r.rows(), len(r.commits))
			}
		})
	}
}

// T-U-18: the prepare runs before the batch append. An error of the prepare
// proves that no leaf reached the log. The appender gets no call, the orphan
// count is 0, and the writer stops.
func TestTU18PrepareErrorCountsNoOrphanLeaf(t *testing.T) {
	r := newRig(t, 100)
	late := func() {
		if _, err := r.db.Exec("ALTER TABLE event RENAME TO event_gone"); err != nil {
			t.Fatal(err)
		}
	}
	batch := func() {
		r.add(event.KindRequest, 1)
		r.add(event.KindCallback, 2)
		r.add(event.KindCallback, 3)
	}
	if err := r.runAfterStart(late, batch); err != nil {
		t.Fatal(err)
	}
	wantRule(t, r.w.Err(), writerName, ruleDatabase)
	if s := r.w.Stats(); r.w.Healthy() || s.OrphanLeaves != 0 || s.WriteFailed != 0 || r.app.tries != 0 {
		t.Fatalf("healthy %v, stats %+v, %d appender calls", r.w.Healthy(), s, r.app.tries)
	}
}

// T-U-18: an AppendBatch error can match tlog.ErrHeadOnDisk, also when it is
// wrapped. Then each leaf of the batch counts as an orphan leaf. Each evidence
// event counts as a failed log write. The COMMIT of the bulk rows still works,
// and no evidence row exists. A failed COMMIT after the error counts the leaves
// one time. An error without the mark counts no orphan leaf.
func TestTU18AppendErrorWithTheMarkCountsOrphanLeaves(t *testing.T) {
	marked := fmt.Errorf("append: %w", tlog.ErrHeadOnDisk)
	cases := []struct {
		name         string
		err          error
		failedCommit bool
		orphans      uint64
	}{
		{"marked error, COMMIT works", marked, false, 3},
		{"marked error, COMMIT fails", marked, true, 3},
		{"error without the mark", errors.New("log is stopped"), false, 0},
		{"error without the mark, COMMIT fails", errors.New("log is stopped"), true, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t, 100)
			r.app.err = c.err
			if c.failedCommit {
				r.w.beforeCommit = func(*sql.Tx) error { return errors.New("commit refused") }
			}
			r.batchOfFour()
			if err := r.run(context.Background()); err != nil {
				t.Fatal(err)
			}
			wantRule(t, r.w.Err(), writerName, ruleAppend)
			s := r.w.Stats()
			if r.w.Healthy() || s.OrphanLeaves != c.orphans || s.WriteFailed != 3 || r.app.tries != 1 {
				t.Fatalf("healthy %v, stats %+v, %d appender calls", r.w.Healthy(), s, r.app.tries)
			}
			wantRows := 1
			if c.failedCommit {
				wantRows = 0
			}
			if r.rows() != wantRows || r.evidenceRows() != 0 || len(r.commits) != wantRows {
				t.Fatalf("%d rows, %d evidence rows, %d commits", r.rows(), r.evidenceRows(), len(r.commits))
			}
		})
	}
}

// T-U-18: at a tick with an empty queue and a pending drop count, the writer runs
// a transaction with no row. It adds the count to ip_counter with the day of the
// clock at the start of the transaction and the ip_hmac of the day key. It calls
// no appender. The transaction is in NORMAL synchronous mode, and it does not
// call the timing hook.
func TestTU18TickWithPendingCountWritesCounterRow(t *testing.T) {
	r := newRig(t, 100)
	var syncMode, timings int
	r.w.timing = func(time.Duration, time.Duration) { timings++ }
	r.w.beforeCommit = func(tx *sql.Tx) error {
		return tx.QueryRow("PRAGMA synchronous").Scan(&syncMode)
	}
	var calls int
	r.w.clock = func() time.Time {
		calls++
		if calls == 1 {
			return time.Date(2026, 3, 1, 23, 59, 59, 0, time.UTC)
		}
		return time.Date(2026, 3, 2, 0, 0, 1, 0, time.UTC)
	}
	addr := netip.MustParseAddr("192.0.2.7")
	r.c.Drop(addr)
	r.c.Drop(addr)
	r.start()
	r.fire()
	wantCommits(t, r, 0)
	want := "2026-03-01 " + r.w.dk.hmac(addr) + " 2"
	if got := r.ipCounters(); len(got) != 1 || got[0] != want || calls != 1 || r.app.tries != 0 || r.rows() != 0 {
		t.Fatalf("ip_counter %q, want %q; %d clock reads, %d appender calls", got, want, calls, r.app.tries)
	}
	if r.w.dk.date != "2026-03-01" {
		t.Fatalf("day key for %q", r.w.dk.date)
	}
	if syncMode != 1 || timings != 0 {
		t.Fatalf("synchronous %d (want 1, NORMAL), %d timing calls (want 0)", syncMode, timings)
	}
}

// T-U-18: at a tick with an empty queue and no pending count, the writer runs no
// transaction.
func TestTU18TickWithNoPendingCountRunsNoTransaction(t *testing.T) {
	r := newRig(t, 100)
	r.start()
	r.fire()
	r.fire() // the writer has finished the first tick when it reads the second
	if len(r.commits) != 0 || len(r.ipCounters()) != 0 {
		t.Fatalf("%d commits, ip_counter %q", len(r.commits), r.ipCounters())
	}
}

// T-U-18: the shutdown of a healthy writer ends with a write of the drop counts.
// Probe: DropNoAddr, Close, Run until it returns: one ip_counter row, the
// overflow row, with dropped 1.
func TestTU18ShutdownWritesTheCountsInMemory(t *testing.T) {
	r := newRig(t, 100)
	r.c.DropNoAddr()
	r.q.Close()
	if err := r.run(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := r.ipCounters()
	if len(got) != 1 || !strings.HasSuffix(got[0], " "+overflowHMAC+" 1") || r.c.Pending() {
		t.Fatalf("ip_counter %q, pending %v", got, r.c.Pending())
	}
}

// T-U-18: the last batch at Close has an event, and a drop is counted after the
// snapshot of that batch. The last step of the shutdown, a flush of an empty
// batch, writes this late count: one ip_counter row, the overflow row, with
// dropped 1, and nothing pending.
func TestTU18ShutdownLastStepWritesLateCounts(t *testing.T) {
	r := newRig(t, 100)
	dropped := false
	r.w.beforeCommit = func(*sql.Tx) error {
		if !dropped {
			dropped = true
			r.c.DropNoAddr()
		}
		return nil
	}
	r.add(event.KindRequest, 1)
	r.q.Close()
	if err := r.run(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := r.ipCounters()
	if len(got) != 1 || !strings.HasSuffix(got[0], " "+overflowHMAC+" 1") || r.c.Pending() {
		t.Fatalf("ip_counter %q, pending %v", got, r.c.Pending())
	}
}

// T-U-18: a request for a checkpoint row stops the writer, while a drop count is
// pending. Then two ticks write no ip_counter row, and the count stays pending.
func TestTU18RowStopKeepsThePendingCount(t *testing.T) {
	r := newSinkRig(t)
	r.w.beforeRowCommit = func(*sql.Tx) error { return errors.New("commit failed") }
	stop := r.start()
	r.c.DropNoAddr()
	wantRule(t, r.sink.Add(4, r.note(4, 1)), writerName, ruleDatabase)
	eventually(t, func() bool { return !r.w.Healthy() })
	r.fire()
	r.fire() // the writer has finished the first tick when it reads the second
	if got := r.ipCounters(); len(got) != 0 || !r.c.Pending() {
		t.Fatalf("ip_counter %q, pending %v", got, r.c.Pending())
	}
	if err := stop(); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

// T-U-18: a stopped writer writes no ip_counter row, also with a pending count,
// at a tick and at Close.
func TestTU18StoppedWriterWritesNoCounterRow(t *testing.T) {
	r := newRig(t, 100)
	r.app.err = errors.New("log is stopped")
	stop := r.start()
	r.add(event.KindCallback, 1)
	r.drained()
	r.fire()
	waitUntil(t, "the stop", func() bool { return !r.w.Healthy() })
	r.c.DropNoAddr()
	r.fire()
	r.fire()
	r.q.Close()
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	if got := r.ipCounters(); len(got) != 0 || !r.c.Pending() {
		t.Fatalf("ip_counter %q, pending %v", got, r.c.Pending())
	}
}
