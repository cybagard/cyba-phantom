package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"runtime"
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
	db      *sql.DB
	app     *testAppender
	tick    chan time.Time
	commits chan int
}

func newRig(t *testing.T, depth int) *rig {
	t.Helper()
	q, err := event.NewQueue(depth, event.NewCounters())
	if err != nil {
		t.Fatal(err)
	}
	r := &rig{t: t, q: q, db: migrated(t), app: &testAppender{next: 100},
		tick: make(chan time.Time), commits: make(chan int, 64)}
	r.w = NewWriter(r.db, q, r.app)
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
	done := make(chan error, 1)
	go func() { done <- r.w.Run(ctx) }()
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

// start runs the writer goroutine. The returned function stops it. If the test
// fails first, the cleanup releases the gate and cancels ctx, so Run ends.
func (r *rig) start() (stop func() error) {
	ctx, cancel := context.WithCancel(context.Background())
	done := r.launch(ctx)
	r.t.Cleanup(func() { r.ungate(); cancel() })
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
	q := "SELECT count(*) FROM event WHERE kind IN ('request', 'beacon') AND (hash IS NOT NULL OR leaf_index IS NOT NULL OR record IS NOT NULL)"
	if err := r.db.QueryRow(q).Scan(&n); err != nil || n != 0 || r.rows() != 10 {
		t.Fatalf("bulk rows with evidence columns: %d, %v", n, err)
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
	if err := r.w.shutdown(batch); err != nil {
		t.Fatal(err)
	}
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
// first batch waits in AppendBatch while more than 1 000 events are queued. Then
// the test cancels ctx (no Close) and releases the batch. Run writes at most one
// more batch, returns context.Canceled, and leaves events in the lanes.
func TestTU18CancelAfterFullFlushLeavesEventsInTheLanes(t *testing.T) {
	r := newRig(t, 4000)
	r.gate()
	ctx, cancel := context.WithCancel(context.Background())
	done := r.launch(ctx)
	t.Cleanup(func() { r.ungate(); cancel() })
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

// T-U-18: closed database: BEGIN fails, nothing is committed, and Run returns
// the database rule. A refused row and an append error roll back the batch (no
// row). For the refused row, the appender got its one call, so the leaves of
// that batch stay in the appender with no row; the later stop rules count them.
func TestTU18ErrorsRollBackTheBatch(t *testing.T) {
	cases := []struct {
		name, rule string
		setup      func(r *rig)
	}{
		{"closed database", ruleDatabase, func(r *rig) { r.db.Close() }},
		{"refused row", ruleDatabase, func(r *rig) { r.app.next = -1 }},
		{"append error", ruleAppend, func(r *rig) { r.app.err = errors.New("log is stopped") }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t, 100)
			r.add(event.KindRequest, 1)
			r.add(event.KindCallback, 2)
			r.q.Close()
			c.setup(r)
			wantRule(t, r.run(context.Background()), writerName, c.rule)
			if len(r.commits) != 0 {
				t.Fatal("the batch was committed")
			}
			if c.name != "closed database" && r.rows() != 0 {
				t.Fatalf("%d rows after the rollback", r.rows())
			}
			if c.name == "refused row" && len(r.app.calls) != 1 {
				t.Fatalf("%d appender calls, want 1", len(r.app.calls))
			}
		})
	}
}
