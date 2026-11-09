package store

import (
	"context"
	"errors"
	"log/slog"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/cybagard/cyba-phantom/internal/event"
)

// atomicFloat is a use value that the test and the writer goroutine share.
type atomicFloat struct{ bits atomic.Uint64 }

func (a *atomicFloat) set(v float64) { a.bits.Store(math.Float64bits(v)) }
func (a *atomicFloat) get() float64  { return math.Float64frombits(a.bits.Load()) }

// T-I-16: the use is the higher of the block use and the inode use. A file
// system with no inode count adds no inode use.
func TestTI16_FsUse(t *testing.T) {
	for _, c := range []struct {
		name                                string
		blocks, bfree, bavail, files, ffree uint64
		want                                float64
	}{
		{"blocks only, root reserve ignored", 1000, 300, 200, 0, 0, 0.7 / 0.9},
		{"90 percent", 1000, 100, 100, 1000, 1000, 0.9},
		{"inodes are higher", 1000, 900, 900, 1000, 50, 0.95},
		{"blocks are higher", 1000, 50, 50, 1000, 500, 0.95},
		{"no inode count", 1000, 900, 900, 0, 0, 0.1},
		{"empty", 0, 0, 0, 0, 0, 0},
		{"used blocks equal the available blocks", 1000, 500, 500, 0, 0, 0.5},
	} {
		if got := fsUse(c.blocks, c.bfree, c.bavail, c.files, c.ffree); !(math.Abs(got-c.want) <= 1e-9) {
			t.Errorf("%s: use %v, want %v", c.name, got, c.want)
		}
	}
}

// T-I-16: the guard uses the higher value of its two directories, and a failed
// measure of one is an error. The real measure of a directory is a share.
func TestTI16_GuardTakesTheHigherDirectory(t *testing.T) {
	root, _, _ := newState(t)
	if err := root.Mkdir("tlog", 0o700); err != nil {
		t.Fatal(err)
	}
	g, err := OpenDiskGuard(root, "tlog")
	if err != nil {
		t.Fatal(err)
	}
	if u, err := g.Use(); err != nil || u < 0 || u > 1 {
		t.Fatalf("real use %v, error %v", u, err)
	}
	var bad error
	g.measure = func(f *os.File) (float64, error) {
		if filepath.Base(f.Name()) == "tlog" {
			return 0.91, bad
		}
		return 0.4, nil
	}
	if u, err := g.Use(); u != 0.91 || err != nil {
		t.Fatalf("use %v, error %v; want 0.91", u, err)
	}
	bad = errors.New("measure failed")
	if _, err := g.Use(); err == nil {
		t.Fatal("no error from a failed measure")
	}
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	g.measure = fdUse
	if _, err := g.Use(); err == nil {
		t.Fatal("no error after Close")
	}
	if _, err := OpenDiskGuard(root, "missing"); err == nil {
		t.Fatal("a guard opened with no directory")
	}
}

// T-I-16: the real measure of a directory is the use that Statfs gives for it,
// and it is not zero. A measure that ignores the Fstatfs result would give 0.
func TestTI16_RealUseMatchesStatfs(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := root.Mkdir("tlog", 0o700); err != nil {
		t.Fatal(err)
	}
	g, err := OpenDiskGuard(root, "tlog")
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		t.Fatal(err)
	}
	want := fsUse(uint64(st.Blocks), uint64(st.Bfree), uint64(st.Bavail), uint64(st.Files), uint64(st.Ffree))
	got, err := g.Use()
	if err != nil {
		t.Fatal(err)
	}
	if !(got > 0) || !(math.Abs(got-want) <= 0.01) {
		t.Fatalf("use %v, Statfs gives %v", got, want)
	}
}

// T-I-16: a paused writer writes the drop counts of the queue to ip_counter at
// shutdown. It writes no event row and makes no append, and it stays paused.
func TestTI16_PausedShutdownWritesTheDropCounts(t *testing.T) {
	r := newRig(t, 10)
	r.w.disk = func() (float64, error) { return 0.95, nil }
	addr := netip.MustParseAddr("192.0.2.7")
	r.c.Drop(addr)
	r.c.Drop(addr)
	r.q.Close()
	if err := r.run(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := r.ipCounters()
	if len(got) != 1 || !strings.HasSuffix(got[0], " 2") || r.c.Pending() {
		t.Fatalf("ip_counter %q, pending %v", got, r.c.Pending())
	}
	if r.rows() != 0 || r.app.tries != 0 || !r.w.Paused() || !r.w.Healthy() {
		t.Fatalf("%d rows, %d appends, paused %v, healthy %v", r.rows(), r.app.tries, r.w.Paused(), r.w.Healthy())
	}
}

// T-I-16: pause at 90 %. Keep the state from 85 % up to 90 %. Resume below
// 85 %.
func TestTI16_PauseResumeHysteresis(t *testing.T) {
	r := newRig(t, 10)
	var use float64
	r.w.disk = func() (float64, error) { return use, nil }
	for _, c := range []struct {
		use  float64
		want bool
	}{{0.89, false}, {0.90, true}, {0.87, true}, {0.851, true}, {0.849, false}, {0.87, false}, {0.95, true}, {0.85, true}, {0, false}} {
		use = c.use
		if got := r.w.diskPaused(); got != c.want || r.w.Paused() != c.want {
			t.Fatalf("use %v: paused %v, want %v", c.use, got, c.want)
		}
	}
}

// T-I-16: a failed measure keeps the last state and counts the error. It logs
// one line with a fixed text. The line has no path and no error text.
func TestTI16_FailedMeasureKeepsTheState(t *testing.T) {
	r := newRig(t, 10)
	var buf logBuf
	r.w.log = slog.New(slog.NewTextHandler(&buf, nil))
	use, err := 0.2, error(nil)
	r.w.disk = func() (float64, error) { return use, err }
	err = &os.PathError{Op: "fstatfs", Path: "/secret/path", Err: syscall.EIO}
	if r.w.diskPaused() {
		t.Fatal("paused after a failed measure")
	}
	use, err = 0.95, nil
	if !r.w.diskPaused() {
		t.Fatal("not paused at 95 %")
	}
	use, err = 0.1, syscall.EIO
	r.w.diskPaused()
	r.w.diskPaused()
	if !r.w.Paused() || r.w.DiskCheckErrors() != 3 {
		t.Fatalf("paused %v, %d errors; want paused and 3", r.w.Paused(), r.w.DiskCheckErrors())
	}
	if n := strings.Count(buf.String(), "disk check failed"); n != 1 || strings.Contains(buf.String(), "secret") || strings.Contains(buf.String(), "input/output") {
		t.Fatalf("%d log lines about the failed check; text %q", n, buf.String())
	}
}

// T-I-16: while paused the writer writes no row and makes no append. It drops
// the events of both lanes with a count for each lane, makes no stop marker,
// and stays healthy. The enqueue does not wait. Below 85 % it writes again.
func TestTI16_PausedWriterDropsBothLanes(t *testing.T) {
	r := newRig(t, 40)
	var use atomicFloat
	use.set(0.95)
	r.w.disk = func() (float64, error) { return use.get(), nil }
	r.start()
	for i := int64(0); i < 3; i++ {
		r.add(event.KindRequest, i)
	}
	for i := int64(0); i < 2; i++ {
		r.add(event.KindCallback, i)
	}
	r.drained()
	r.fire()
	waitUntil(t, "the drops", func() bool { return r.w.Stats().Dropped == (Drops{Bulk: 3, Evidence: 2}) })
	if _, err := r.root.Lstat(markerName); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stop marker: %v", err)
	}
	if r.rows() != 0 || r.app.tries != 0 || !r.w.Healthy() || r.w.Err() != nil || !r.w.Paused() || r.w.Stats().WriteFailed != 0 {
		t.Fatalf("%d rows, %d appends, healthy %v, err %v, paused %v", r.rows(), r.app.tries, r.w.Healthy(), r.w.Err(), r.w.Paused())
	}

	use.set(0.849)
	r.add(event.KindCallback, 10)
	r.commit()
	if r.rows() != 1 || r.app.tries != 1 || r.w.Paused() {
		t.Fatalf("%d rows, %d appends, paused %v after the resume", r.rows(), r.app.tries, r.w.Paused())
	}
	if d := r.w.Stats().Dropped; d != (Drops{Bulk: 3, Evidence: 2}) {
		t.Fatalf("drops %+v after the resume", d)
	}
}

// T-I-16: a retention run, and its checkpoint, run as before while the writer
// pauses.
func TestTI16_RetentionRunsInAPause(t *testing.T) {
	r := retentionRig(t, 2500, deleteRange(seedTS, math.MaxInt64))
	r.w.disk = func() (float64, error) { return 0.99, nil }
	r.w.paused.Store(true)
	pragmas := r.recordPragmas()
	if err := r.retain(waitFor); err != nil {
		t.Fatal(err)
	}
	if r.events() != 0 || len(*pragmas) != len(wantCheckpoint) || !r.w.Paused() || !r.w.Healthy() {
		t.Fatalf("%d rows left, pragmas %v, paused %v, healthy %v", r.events(), *pragmas, r.w.Paused(), r.w.Healthy())
	}
}

// BenchmarkDiskGuardUse is the cost of one check: two Fstatfs calls on open
// descriptors. The writer runs it at each batch and at each tick.
func BenchmarkDiskGuardUse(b *testing.B) {
	root, err := os.OpenRoot(b.TempDir())
	if err != nil {
		b.Fatal(err)
	}
	defer root.Close()
	if err := root.Mkdir("tlog", 0o700); err != nil {
		b.Fatal(err)
	}
	g, err := OpenDiskGuard(root, "tlog")
	if err != nil {
		b.Fatal(err)
	}
	defer g.Close()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := g.Use(); err != nil {
			b.Fatal(err)
		}
	}
}

// smallFS returns a new directory on the small file system that the variable
// PHANTOM_DISKFULL names. The test is for a tmpfs of at most 256 MiB. It never
// fills a large file system. Another test on the same file system could pause.
// So the test runs only when asked for.
func smallFS(t *testing.T) string {
	t.Helper()
	dir := os.Getenv("PHANTOM_DISKFULL")
	if dir == "" {
		t.Skip("PHANTOM_DISKFULL is not set: it names a directory on a small tmpfs")
	}
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		t.Fatal(err)
	}
	if size := uint64(st.Bsize) * uint64(st.Blocks); size > 256<<20 {
		t.Skipf("PHANTOM_DISKFULL is on a file system of %d MiB: the limit is 256 MiB", size>>20)
	}
	state, err := os.MkdirTemp(dir, "phantom-diskfull-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(state) })
	return state
}

// fillTo writes the file name until the use of g is at least target.
func fillTo(t *testing.T, g *DiskGuard, name string, target float64) {
	t.Helper()
	f, err := os.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	chunk := make([]byte, 256<<10)
	for i := 0; i < 1100; i++ {
		if u, err := g.Use(); err != nil || u >= target {
			if err != nil {
				t.Fatal(err)
			}
			return
		}
		if _, err := f.Write(chunk); err != nil {
			t.Fatal(err)
		}
	}
	t.Fatal("the fill did not reach the target")
}

// T-I-16 on a real small file system. At 92 % use the writer writes no row and
// makes no append. It counts the drops for each lane and makes no stop marker.
// It is paused and healthy. Offers to the queue do not wait. After the fill
// file is gone, the use is below 85 % and the writer writes rows again. Set
// PHANTOM_DISKFULL to a directory on a tmpfs of at most 256 MiB.
func TestTI16_FullSmallFileSystemPausesTheWriter(t *testing.T) {
	state := smallFS(t)
	root, err := os.OpenRoot(state)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	if err := root.Mkdir("tlog", 0o700); err != nil {
		t.Fatal(err)
	}
	db := mustOpen(t, root, "events.db")
	t.Cleanup(func() { db.Close() })
	if err := Migrate(db, "origin"); err != nil {
		t.Fatal(err)
	}
	q, err := event.NewQueue(40, event.NewCounters())
	if err != nil {
		t.Fatal(err)
	}
	app := &testAppender{}
	w := NewWriter(db, q, false, nil, Recovery{State: root, Origin: "origin", Log: &fakeLog{testAppender: app}})
	g, err := OpenDiskGuard(root, "tlog")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { g.Close() })
	w.SetDiskGuard(g)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })

	rows := func() (n int) {
		if err := db.QueryRow("SELECT count(*) FROM event").Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	put := func(k event.Kind, n int) {
		start := time.Now()
		for range n {
			e, err := event.NewEvent(nil, event.Input{Kind: k})
			if err != nil || !q.Enqueue(e) {
				t.Fatalf("enqueue kind %v: %v", k, err)
			}
		}
		if d := time.Since(start); d > time.Second {
			t.Fatalf("%d offers took %v while the writer paused", n, d)
		}
	}
	put(event.KindRequest, 2)
	put(event.KindCallback, 1)
	waitUntil(t, "the first rows", func() bool { return rows() == 3 })

	fill := filepath.Join(state, "fill")
	fillTo(t, g, fill, 0.92)
	waitUntil(t, "the pause", w.Paused)
	put(event.KindRequest, 3)
	put(event.KindCallback, 2)
	waitUntil(t, "the drops", func() bool { return w.Stats().Dropped == (Drops{Bulk: 3, Evidence: 2}) })
	if _, err := root.Lstat(markerName); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stop marker: %v", err)
	}
	if n := rows(); n != 3 || app.tries != 1 || !w.Healthy() {
		t.Fatalf("%d rows, %d appends, healthy %v during the pause", n, app.tries, w.Healthy())
	}

	if err := os.Remove(fill); err != nil {
		t.Fatal(err)
	}
	if u, err := g.Use(); err != nil || u >= resumeAt {
		t.Fatalf("use %v after the fill file went, error %v", u, err)
	}
	waitUntil(t, "the resume", func() bool { return !w.Paused() })
	put(event.KindRequest, 1)
	put(event.KindCallback, 1)
	waitUntil(t, "new rows", func() bool { return rows() == 5 })
}
