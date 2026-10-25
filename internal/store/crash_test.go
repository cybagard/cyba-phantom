package store

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cybagard/cyba-phantom/internal/event"
	"github.com/cybagard/cyba-phantom/internal/tlog"
)

const (
	crashPointEnv = "STORE_CRASH_TEST_POINT" // names the crash point; empty in a normal run
	crashStateEnv = "STORE_CRASH_TEST_STATE" // the state directory that the parent made
	crashMessage  = "intended crash of the writer"

	goodBatch = 1000 // ts of the events of the batch that commits
	badBatch  = 2000 // ts of the events of the batch that the helper stops
	newBatch  = 3000 // ts of the events that the new writer stores
)

// openCrashState opens the root, the database and the log below the state
// directory. It migrates the database, which keeps an existing one.
func openCrashState(t *testing.T, state string) (*os.Root, *sql.DB, *tlog.Log) {
	t.Helper()
	root, err := os.OpenRoot(state)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	db := mustOpen(t, root, "events.db")
	t.Cleanup(func() { db.Close() })
	if err := Migrate(db, "origin"); err != nil {
		t.Fatal(err)
	}
	l, err := tlog.OpenLog(root, "tlog")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return root, db, l
}

// crashEvents queues one request and three callbacks with the times base to base+3.
func crashEvents(t *testing.T, q *event.Queue, base int64) {
	t.Helper()
	for i := range int64(4) {
		kind := event.KindCallback
		if i == 0 {
			kind = event.KindRequest
		}
		e, err := event.NewEvent(func() time.Time { return time.UnixMilli(base + i) }, event.Input{Kind: kind})
		if err != nil || !q.Enqueue(e) {
			t.Fatalf("enqueue: %v", err)
		}
	}
}

// flushWhenTaken waits until the writer has taken all events from the lanes, then
// sends one tick. A tick while events are still in the lanes can write a part of
// the batch, because Run picks at random between a waiting tick and new events.
// Run reads the tick only after it has put each event it took in its batch.
func flushWhenTaken(t *testing.T, q *event.Queue, tick chan<- time.Time) {
	t.Helper()
	for end := time.Now().Add(waitFor); q.Bytes() != (event.Bytes{}); time.Sleep(time.Millisecond) {
		if time.Now().After(end) {
			t.Fatal("the writer did not take the events")
		}
	}
	select {
	case tick <- time.Now():
	case <-time.After(waitFor):
		t.Fatal("the writer did not read the tick")
	}
}

// T-I-07: this is the helper process of the crash test. It runs the real writer
// with the real log, commits one batch, and panics in the second batch at the
// crash point from the environment. Without the environment it does nothing.
func TestTI07CrashHelper(t *testing.T) {
	point, state := os.Getenv(crashPointEnv), os.Getenv(crashStateEnv)
	if point == "" {
		t.Skip("helper process of TestTI07WriterCrashKeepsEvidenceVerifiable")
	}
	root, db, l := openCrashState(t, state)
	c := event.NewCounters()
	q, err := event.NewQueue(100, c)
	if err != nil {
		t.Fatal(err)
	}
	w := NewWriter(db, q, l, c, false, nil, Recovery{State: root, Origin: "origin", Log: l})
	var calls atomic.Int32
	crash := func() {
		if calls.Add(1) == 2 {
			panic(crashMessage)
		}
	}
	switch point {
	case "append":
		w.beforeAppend = crash
	case "commit":
		w.beforeCommit = func(*sql.Tx) error { crash(); return nil }
	default:
		t.Fatalf("unknown crash point %q", point)
	}
	committed := make(chan int, 4)
	w.onCommit = func(n int) { committed <- n }
	// The tick channel has no buffer, so a completed send proves that Run read
	// the tick. The real ticker could fire between two enqueues and split a batch.
	tick := make(chan time.Time)
	w.tick = tick
	crashEvents(t, q, goodBatch)
	go w.Run(context.Background())
	flushWhenTaken(t, q, tick)
	select {
	case <-committed:
	case <-time.After(waitFor):
		t.Fatal("the first batch was not committed")
	}
	crashEvents(t, q, badBatch)
	flushWhenTaken(t, q, tick)
	time.Sleep(waitFor) // the panic in the writer goroutine ends the process
	t.Fatal("the writer did not crash")
}

// checkEvidence checks each evidence row against the log. It returns the log size
// and the number of rows, and fails if a row lacks a leaf or does not verify.
func checkEvidence(t *testing.T, db *sql.DB, l *tlog.Log) (size, rows int64) {
	t.Helper()
	var bad int
	if err := db.QueryRow("SELECT count(*) FROM event WHERE kind NOT IN ('request','beacon','refused') AND (hash IS NULL OR leaf_index IS NULL)").Scan(&bad); err != nil || bad != 0 {
		t.Fatalf("%d evidence rows without a hash or a leaf: %v", bad, err)
	}
	size, _ = l.Head()
	root, err := l.RootAt(size)
	if err != nil {
		t.Fatal(err)
	}
	rs, err := db.Query("SELECT hash, leaf_index FROM event WHERE leaf_index IS NOT NULL ORDER BY leaf_index")
	if err != nil {
		t.Fatal(err)
	}
	defer rs.Close()
	for ; rs.Next(); rows++ {
		var hash []byte
		var leaf int64
		var h tlog.EventHash
		if err := rs.Scan(&hash, &leaf); err != nil || copy(h[:], hash) != len(h) {
			t.Fatalf("row %d: %d hash bytes, %v", rows, len(hash), err)
		}
		proof, err := l.ProveInclusion(leaf, size)
		if err != nil {
			t.Fatal(err)
		}
		if err := tlog.VerifyInclusion(h, leaf, size, root, proof); err != nil {
			t.Fatalf("leaf %d does not verify: %v", leaf, err)
		}
	}
	return size, rows
}

// countRows returns the number of event rows with a ts from lo to hi.
func countRows(t *testing.T, db *sql.DB, lo, hi int64) (n int) {
	t.Helper()
	if err := db.QueryRow("SELECT count(*) FROM event WHERE ts BETWEEN ? AND ?", lo, hi).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// T-I-07: the writer process stops with a panic before AppendBatch, or between
// AppendBatch and COMMIT. The database has no evidence row without a leaf, and
// each row verifies. A new writer starts at the log size and makes no duplicate
// leaf index.
func TestTI07WriterCrashKeepsEvidenceVerifiable(t *testing.T) {
	for _, c := range []struct {
		name, point string
		orphans     bool // the failed batch left leaves in the log
	}{
		{"panic before AppendBatch", "append", false},
		{"panic before COMMIT", "commit", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			state := filepath.Join(t.TempDir(), "state")
			if err := os.Mkdir(state, 0o700); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestTI07CrashHelper$")
			cmd.Env = append(os.Environ(), crashPointEnv+"="+c.point, crashStateEnv+"="+state)
			out, err := cmd.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || !bytes.Contains(out, []byte("panic: "+crashMessage)) {
				t.Fatalf("helper error %v, output:\n%s", err, out)
			}

			root, db, l := openCrashState(t, state)
			if n := countRows(t, db, goodBatch, goodBatch+3); n != 4 {
				t.Fatalf("%d rows of the committed batch, want 4", n)
			}
			if n := countRows(t, db, badBatch, badBatch+3); n != 0 {
				t.Fatalf("%d rows of the failed batch, want 0", n)
			}
			size, rows := checkEvidence(t, db, l)
			wantSize := int64(3)
			if c.orphans {
				wantSize = 6 // the three leaves of the failed batch have no row
			}
			if rows != 3 || size != wantSize {
				t.Fatalf("%d evidence rows, log size %d, want 3 and %d", rows, size, wantSize)
			}

			cnt := event.NewCounters()
			q, err := event.NewQueue(100, cnt)
			if err != nil {
				t.Fatal(err)
			}
			w := NewWriter(db, q, l, cnt, false, nil, Recovery{State: root, Origin: "origin", Log: l})
			crashEvents(t, q, newBatch)
			q.Close()
			done := make(chan error, 1)
			go func() { done <- w.Run(context.Background()) }()
			select {
			case err := <-done:
				if err != nil || !w.Healthy() {
					t.Fatalf("Run returned %v, writer error %v", err, w.Err())
				}
			case <-time.After(waitFor):
				t.Fatal("Run did not return")
			}
			var first sql.NullInt64
			var leaves, distinct int
			if err := db.QueryRow("SELECT min(leaf_index) FROM event WHERE ts >= ?", newBatch).Scan(&first); err != nil {
				t.Fatal(err)
			}
			if err := db.QueryRow("SELECT count(leaf_index), count(DISTINCT leaf_index) FROM event").Scan(&leaves, &distinct); err != nil {
				t.Fatal(err)
			}
			if first.Int64 != size || leaves != distinct {
				t.Fatalf("first new leaf %d, want %d; %d leaf indices, %d distinct", first.Int64, size, leaves, distinct)
			}
			if size2, rows2 := checkEvidence(t, db, l); size2 != size+3 || rows2 != 6 {
				t.Fatalf("log size %d and %d rows after the restart, want %d and 6", size2, rows2, size+3)
			}
		})
	}
}
