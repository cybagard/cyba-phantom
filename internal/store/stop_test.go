package store

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cybagard/cyba-phantom/internal/event"
)

// logBuf is a log sink that the writer goroutine and the test can use together.
type logBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// waitUntil polls cond for waitFor.
func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for end := time.Now().Add(waitFor); !cond(); time.Sleep(time.Millisecond) {
		if time.Now().After(end) {
			t.Fatalf("timeout: %s", what)
		}
	}
}

func (r *rig) evidenceRows() (n int) {
	r.t.Helper()
	if err := r.db.QueryRow("SELECT count(*) FROM event WHERE leaf_index IS NOT NULL OR hash IS NOT NULL OR record IS NOT NULL").Scan(&n); err != nil {
		r.t.Fatal(err)
	}
	return n
}

// T-U-18: a failed AppendBatch commits the bulk rows of the batch and no
// evidence row, counts each evidence event of the batch, and stops the writer.
// Run returns nil after Close. Later batches call the appender no more.
func TestTU18FailedAppendCommitsBulkRowsAndStops(t *testing.T) {
	r := newRig(t, 100)
	r.app.err = errors.New("log is stopped")
	r.add(event.KindRequest, 1)
	r.add(event.KindCallback, 2)
	r.add(event.KindBeacon, 3)
	r.add(event.KindAlertSent, 4)
	r.add(event.KindScoreChange, 5)
	r.q.Close()
	if err := r.run(context.Background()); err != nil {
		t.Fatal(err)
	}
	wantRule(t, r.w.Err(), writerName, ruleAppend)
	wantCommits(t, r, 2)
	if r.w.Healthy() || r.rows() != 2 || r.evidenceRows() != 0 {
		t.Fatalf("healthy %v, %d rows, %d evidence rows", r.w.Healthy(), r.rows(), r.evidenceRows())
	}
	if s := r.w.Stats(); s.WriteFailed != 3 || s.OrphanLeaves != 0 || r.app.tries != 1 {
		t.Fatalf("stats %+v, %d appender calls", s, r.app.tries)
	}
}

// T-U-18: both lanes are full when the writer stops. At one tick after the stop,
// the writer takes each event out of both lanes and drops it, and counts each
// drop for its lane. It writes no row and makes no AppendBatch call. After Close,
// it drops the events that are left.
func TestTU18StoppedWriterDropsBothLanes(t *testing.T) {
	r := newRig(t, 40) // bulk lane 40, evidence lane 10
	r.app.err = errors.New("log is stopped")
	ctx, cancel := context.WithCancel(context.Background())
	done := r.launch(ctx)
	t.Cleanup(func() { r.stopRun(cancel) })

	// Hold the first AppendBatch call, so that the lanes fill before the stop.
	r.gate()
	r.add(event.KindCallback, 0)
	r.drained()
	r.fire()
	select {
	case <-r.app.entered:
	case <-time.After(waitFor):
		t.Fatal("no batch reached the appender")
	}
	for i := int64(0); i < 40; i++ {
		r.add(event.KindRequest, i)
	}
	for i := int64(0); i < 10; i++ {
		r.add(event.KindBundleLoad, i)
	}
	for _, k := range []event.Kind{event.KindRequest, event.KindBundleLoad} {
		e, err := event.NewEvent(nil, event.Input{Kind: k})
		if err != nil || r.q.Enqueue(e) {
			t.Fatalf("the lane of kind %v is not full (err %v)", k, err)
		}
	}
	full := r.q.Bytes()

	r.ungate() // the held call fails and stops the writer
	waitUntil(t, "the stop", func() bool { return !r.w.Healthy() })
	if r.q.Bytes() != full || r.w.Stats().Dropped != (Drops{}) {
		t.Fatalf("bytes %+v, drops %+v before the tick", r.q.Bytes(), r.w.Stats().Dropped)
	}
	r.fire() // one tick
	waitUntil(t, "the drops", func() bool { return r.w.Stats().Dropped == (Drops{Bulk: 40, Evidence: 10}) })
	if r.q.Bytes() != (event.Bytes{}) || r.rows() != 0 || r.app.tries != 1 {
		t.Fatalf("bytes %+v, %d rows, %d appender calls", r.q.Bytes(), r.rows(), r.app.tries)
	}

	r.add(event.KindRequest, 1)
	r.add(event.KindAlertSent, 2)
	r.q.Close()
	if err := r.wait(done); err != nil {
		t.Fatal(err)
	}
	if d := r.w.Stats().Dropped; d != (Drops{Bulk: 41, Evidence: 11}) || r.rows() != 0 || r.app.tries != 1 {
		t.Fatalf("drops %+v, %d rows, %d appender calls", d, r.rows(), r.app.tries)
	}
}

// T-U-18: Discard needs no store and no writer. It drops at the tick, counts for
// each lane, returns ctx.Err() on a cancel, and returns nil after Close.
func TestTU18DiscardNeedsNoWriter(t *testing.T) {
	c := event.NewCounters()
	q, err := event.NewQueue(8, c)
	if err != nil {
		t.Fatal(err)
	}
	var d DropCount
	tick := make(chan time.Time)
	done := make(chan error, 1)
	go func() { done <- discard(context.Background(), q, &d, tick) }()
	for _, k := range []event.Kind{event.KindRequest, event.KindBeacon, event.KindCallback} {
		e, err := event.NewEvent(nil, event.Input{Kind: k})
		if err != nil || !q.Enqueue(e) {
			t.Fatal(err)
		}
	}
	tick <- time.Now()
	waitUntil(t, "the drops", func() bool { return d.Load() == (Drops{Bulk: 2, Evidence: 1}) })
	q.Close()
	if err := <-done; err != nil || d.Load() != (Drops{Bulk: 2, Evidence: 1}) {
		t.Fatalf("err %v, drops %+v", err, d.Load())
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	q2, err := event.NewQueue(8, c)
	if err != nil {
		t.Fatal(err)
	}
	if err := Discard(ctx, q2, &d); !errors.Is(err, context.Canceled) {
		t.Fatalf("Discard returned %v", err)
	}
}

// T-U-18: a database error stops the writer with one log line that holds a fixed
// class. A marker in each request-derived column of the batch is not in the log
// and not in Err().
func TestTU18StopLogsOneLineWithNoRowValue(t *testing.T) {
	const m = "zq9marker"
	cases := []struct {
		name  string
		setup func(r *rig)
	}{
		{"closed database", func(r *rig) { r.db.Close() }},
		{"refused row", func(r *rig) { r.app.next = -1 }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t, 100)
			var out logBuf
			r.w.log = slog.New(slog.NewTextHandler(&out, nil))
			st := int64(404)
			e, err := event.NewEvent(nil, event.Input{
				Kind: event.KindCallback, Session: "sess-" + m, Vhost: m + ".example.test", Method: "POST",
				Path: "/" + m, Status: &st, TrapID: "trap-" + m, TokenID: "tok-" + m, Surface: event.SurfaceQuery,
				ClientIP: "203.0.113.9", BodyPrefix: []byte(m),
				Detail: event.Detail{"k": event.Str(m)},
			})
			if err != nil || !r.q.Enqueue(e) {
				t.Fatal(err)
			}
			r.add(event.KindRequest, 1)
			r.q.Close()
			c.setup(r)
			if err := r.run(context.Background()); err != nil {
				t.Fatal(err)
			}
			wantRule(t, r.w.Err(), writerName, ruleDatabase)
			text := out.String()
			if n := strings.Count(text, "\n"); n != 1 || !strings.Contains(text, r.w.Err().Error()) {
				t.Fatalf("%d log lines, want 1: %q", n, text)
			}
			for _, s := range []string{text, r.w.Err().Error()} {
				if strings.Contains(strings.ToLower(s), m) || strings.Contains(s, "203.0.113.9") {
					t.Fatalf("a request value is in %q", s)
				}
			}
		})
	}
}
