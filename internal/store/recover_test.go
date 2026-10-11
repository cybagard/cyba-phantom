package store

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	xtlog "golang.org/x/mod/sumdb/tlog"

	"github.com/cybagard/cyba-phantom/internal/event"
	"github.com/cybagard/cyba-phantom/internal/tlog"
)

var errBadTile = errors.New("bad tile")

// fakeLog is a log for the start check. It counts the proof calls.
type fakeLog struct {
	size              int64
	rootErr, proofErr error
	proves            int
}

func (f *fakeLog) Head() (int64, xtlog.Hash)        { return f.size, xtlog.Hash{} }
func (f *fakeLog) RootAt(int64) (xtlog.Hash, error) { return xtlog.Hash{}, f.rootErr }
func (f *fakeLog) ProveInclusion(int64, int64) (xtlog.RecordProof, error) {
	f.proves++
	return nil, f.proofErr
}

// headLiar gives a wrong root from Head, as a stopped log can.
type headLiar struct{ *tlog.Log }

func (h headLiar) Head() (int64, xtlog.Hash) {
	n, _ := h.Log.Head()
	return n, xtlog.Hash{9}
}

// lines is a log buffer that the writer goroutine and a test can use.
type lines struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lines) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lines) count(s string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Count(l.b.String(), s)
}

func (r *rig) logTo() *lines {
	l := &lines{}
	r.w.log = slog.New(slog.NewTextHandler(l, nil))
	return l
}

// seed writes n evidence events through the writer of r and the log l.
func (r *rig) seed(l *tlog.Log, n int) {
	r.t.Helper()
	r.w.app, r.w.rec.Log = l, l
	for i := range n {
		r.add(event.KindCallback, int64(i))
	}
	r.q.Close()
	if err := r.run(context.Background()); err != nil || !r.w.Healthy() {
		r.t.Fatalf("seed: Run returned %v, writer error %v", err, r.w.Err())
	}
}

// restart returns a rig with a new queue and a new writer on the same database
// and state directory, as a restart does.
func (r *rig) restart(app appender, lg logReader, origin string) *rig {
	c := event.NewCounters()
	q, err := event.NewQueue(100, c)
	if err != nil {
		r.t.Fatal(err)
	}
	n := &rig{t: r.t, q: q, c: c, db: r.db, app: &testAppender{next: 100}, root: r.root, state: r.state,
		tick: make(chan time.Time), commits: make(chan int, 64)}
	if app == nil {
		app = n.app
	}
	n.w = NewWriter(r.db, q, app, c, false, nil, Recovery{State: r.root, Origin: origin, Log: lg})
	n.w.tick = n.tick
	return n
}

// finish queues one evidence event, closes the queue, and runs the writer.
func (r *rig) finish() {
	r.t.Helper()
	r.add(event.KindCallback, 9)
	r.q.Close()
	if err := r.run(context.Background()); err != nil {
		r.t.Fatal(err)
	}
}

func (r *rig) marker() (os.FileInfo, error) { return os.Lstat(filepath.Join(r.state, markerName)) }

func eventually(t *testing.T, ok func() bool) {
	t.Helper()
	for end := time.Now().Add(waitFor); !ok(); runtime.Gosched() {
		if time.Now().After(end) {
			t.Fatal("the condition did not hold")
		}
	}
}

// T-I-07: each failed check of the start stops the writer before the first write.
func TestTI07StartCheckStopsTheWriter(t *testing.T) {
	for _, c := range []struct {
		name, rule, origin, sql string
		lg                      func() logReader
		proves                  int
	}{
		{"another origin", ruleOrigin, "other", "", nil, 0},
		{"no origin", ruleNoOrigin, "origin", "DELETE FROM meta WHERE key = 'tlog_origin'", nil, 0},
		{"database past the log", rulePastLog, "origin", "", func() logReader { return &fakeLog{size: 2} }, 0},
		{"last row does not verify", ruleLeafProof, "origin", "UPDATE event SET hash = zeroblob(32) WHERE leaf_index = 2", nil, 0},
		{"root error", ruleLogRead, "origin", "", func() logReader { return &fakeLog{size: 3, rootErr: errBadTile} }, 0},
		{"proof error", ruleLogRead, "origin", "", func() logReader { return &fakeLog{size: 3, proofErr: errBadTile} }, 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			l, r := realLog(t), newRig(t, 100)
			r.seed(l, 3)
			if _, err := r.db.Exec(c.sql); c.sql != "" && err != nil {
				t.Fatal(err)
			}
			var lg logReader = l
			if c.lg != nil {
				lg = c.lg()
			}
			n := r.restart(l, lg, c.origin)
			n.finish()
			wantRule(t, n.w.Err(), writerName, c.rule)
			if f, ok := lg.(*fakeLog); ok && f.proves != c.proves {
				t.Fatalf("%d proof calls, want %d", f.proves, c.proves)
			}
			if size, _ := l.Head(); size != 3 || n.rows() != 3 || n.w.Stats().Dropped.Evidence != 1 {
				t.Fatalf("log size %d, %d rows, drops %+v", size, n.rows(), n.w.Stats().Dropped)
			}
			if fi, err := n.marker(); err != nil || fi.Size() != 0 {
				t.Fatalf("marker %v, %v", fi, err)
			}
		})
	}
}

// T-I-07: the root for the check comes from RootAt and not from Head.
func TestTI07StartCheckTakesTheRootFromRootAt(t *testing.T) {
	l, r := realLog(t), newRig(t, 100)
	r.seed(l, 3)
	n := r.restart(l, headLiar{l}, "origin")
	n.finish()
	if !n.w.Healthy() {
		t.Fatalf("the writer stopped: %v", n.w.Err())
	}
}

// T-I-07: orphan leaves are permitted. The writer logs their number one time, and
// new leaves start at the log size.
func TestTI07OrphanLeavesAreLoggedOnce(t *testing.T) {
	l, r := realLog(t), newRig(t, 100)
	r.seed(l, 3)
	if _, err := l.AppendBatch([]tlog.EventHash{{1}, {2}}); err != nil {
		t.Fatal(err)
	}
	n := r.restart(l, l, "origin")
	out := n.logTo()
	n.finish()
	var leaf int64
	if err := r.db.QueryRow("SELECT max(leaf_index) FROM event").Scan(&leaf); err != nil {
		t.Fatal(err)
	}
	if !n.w.Healthy() || out.count("orphan leaves") != 1 || out.count("count=2") != 1 || leaf != 5 {
		t.Fatalf("healthy %v, newest leaf %d, log:\n%s", n.w.Healthy(), leaf, out.b.String())
	}
}

// T-I-07: a database with no evidence row has the origin check only. All leaves
// of the log are orphan leaves.
func TestTI07EmptyDatabaseMakesNoProofCall(t *testing.T) {
	r := newRig(t, 100)
	r.lg.size = 3
	out := r.logTo()
	r.finish()
	if !r.w.Healthy() || r.lg.proves != 0 || out.count("count=3") != 1 {
		t.Fatalf("healthy %v, %d proof calls, log:\n%s", r.w.Healthy(), r.lg.proves, out.b.String())
	}
}

// T-I-07: a stop makes the empty marker with mode 0600. A marker that exists is a
// success, and the writer does not change it.
func TestTI07StopMakesTheMarkerAndKeepsAnOldOne(t *testing.T) {
	r := newRig(t, 100)
	r.app.err = errBadTile
	r.finish()
	fi, err := r.marker()
	if err != nil || fi.Mode() != 0o600 || fi.Size() != 0 || r.w.Healthy() {
		t.Fatalf("marker %v, %v, healthy %v", fi, err, r.w.Healthy())
	}
	old := newRig(t, 100)
	out := old.logTo()
	if err := os.WriteFile(filepath.Join(old.state, markerName), []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	old.w.stop(fail(writerName, ruleDatabase))
	if b, _ := os.ReadFile(filepath.Join(old.state, markerName)); string(b) != "old" || out.count("marker") != 0 {
		t.Fatalf("marker content %q, log:\n%s", b, out.b.String())
	}
}

// T-I-07: a marker of any type stops the writer before the first write. A restart
// after a stop finds the marker and writes nothing.
func TestTI07MarkerStopsTheWriterAtStart(t *testing.T) {
	for _, kind := range []string{"file", "symlink", "directory", "after a stop"} {
		t.Run(kind, func(t *testing.T) {
			r := newRig(t, 100)
			path := filepath.Join(r.state, markerName)
			var err error
			switch kind {
			case "file":
				err = os.WriteFile(path, nil, 0o600)
			case "symlink":
				err = os.Symlink("gone", path)
			case "directory":
				err = os.Mkdir(path, 0o700)
			default:
				r.app.err = errBadTile
				r.finish()
				r = r.restart(nil, r.lg, "origin")
			}
			if err != nil {
				t.Fatal(err)
			}
			r.finish()
			wantRule(t, r.w.Err(), writerName, ruleMarkerExists)
			if _, err := os.Lstat(filepath.Join(r.state, "gone")); !errors.Is(err, os.ErrNotExist) || r.app.tries != 0 || r.rows() != 0 {
				t.Fatalf("link target %v, %d appends, %d rows", err, r.app.tries, r.rows())
			}
		})
	}
}

// T-I-07: if the writer cannot make the marker, it logs this one time and tries
// again at each tick of the stopped state.
func TestTI07MarkerIsTriedAgainAtEachTick(t *testing.T) {
	r := newRig(t, 100)
	out := r.logTo()
	closed, err := os.OpenRoot(r.state)
	if err != nil {
		t.Fatal(err)
	}
	closed.Close()
	r.w.rec.State = closed // every use of this root fails
	r.start()
	eventually(t, func() bool { return out.count("cannot make the stop marker") == 1 })
	// A tick drops the event after the marker step. The drop shows that the step
	// has ended, so the next change of the root is not a race.
	tick := func(drops uint64) {
		r.add(event.KindRequest, int64(drops))
		r.fire()
		eventually(t, func() bool { return r.w.Stats().Dropped.Bulk == drops })
	}
	tick(1)
	if _, err := r.marker(); !errors.Is(err, os.ErrNotExist) || out.count("cannot make the stop marker") != 1 {
		t.Fatalf("marker %v, log:\n%s", err, out.b.String())
	}
	r.w.rec.State = r.root
	tick(2)
	if fi, err := r.marker(); err != nil || fi.Mode() != 0o600 || fi.Size() != 0 {
		t.Fatalf("marker %v, %v", fi, err)
	}
}
