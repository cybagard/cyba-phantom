package main

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/note"

	"github.com/cybagard/cyba-phantom/internal/config"
	"github.com/cybagard/cyba-phantom/internal/event"
	"github.com/cybagard/cyba-phantom/internal/store"
	"github.com/cybagard/cyba-phantom/internal/testutil"
	"github.com/cybagard/cyba-phantom/internal/tlog"
)

// opens counts the opens of the log and of the store, and the runs of the migration. It gives the real parts to start.
type opens struct{ log, store, migrate int }

func (o *opens) deps() startDeps {
	d := realDeps
	d.openLog = func(r *os.Root, dir string) (*tlog.Log, error) { o.log++; return tlog.OpenLog(r, dir) }
	d.openStore = func(r *os.Root, p string, opt store.Options) (*sql.DB, error) {
		o.store++
		return store.Open(r, p, opt)
	}
	d.migrate = func(db *sql.DB, origin string) error { o.migrate++; return store.Migrate(db, origin) }
	return d
}

func testParams(t *testing.T, storePath string) startParams {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil { // The log refuses a state directory with group or other bits.
		t.Fatal(err)
	}
	return startParams{Root: root, StorePath: storePath, TlogDir: "tlog", Origin: "test/origin", Interval: time.Hour, BodyPrefix: true}
}

func launch(t *testing.T, p startParams, d startDeps) (*started, *event.Queue) {
	t.Helper()
	return launchLog(t, p, d, slog.New(slog.DiscardHandler))
}

func launchLog(t *testing.T, p startParams, d startDeps, lg *slog.Logger) (*started, *event.Queue) {
	t.Helper()
	c := event.NewCounters()
	q, err := event.NewQueue(8, c)
	if err != nil {
		t.Fatal(err)
	}
	s := start(p, q, c, d, lg)
	t.Cleanup(s.Stop)
	return s, q
}

func put(t *testing.T, q *event.Queue, k event.Kind, n int) {
	t.Helper()
	for range n {
		e, err := event.NewEvent(nil, event.Input{Kind: k})
		if err != nil || !q.Enqueue(e) {
			t.Fatalf("enqueue kind %d: %v", k, err)
		}
	}
}

// refusals are the stores that do not open: a refused path, a file that is not a database, and a refused schema.
var refusals = []struct {
	name, path string
	want       string // the text of the *store.Error in the log
	migrates   int    // the runs of the migration: only a database that opens reaches it
	prep       func(t *testing.T, file string)
}{
	{"refused path", "keys/events.db", "store: store.path must not be a reserved state path", 0, nil},
	{"not a database", "events.db", "store: events.db cannot be opened as a database", 0, func(t *testing.T, file string) {
		if err := os.WriteFile(file, []byte(strings.Repeat("not a database ", 100)), 0o600); err != nil {
			t.Fatal(err)
		}
	}},
	{"refused schema", "events.db", "store: database schema has tables and no schema version", 1, func(t *testing.T, file string) {
		db, err := sql.Open("sqlite", file)
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		if _, err := db.Exec("PRAGMA auto_vacuum = 2; CREATE TABLE other (a)"); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(file, 0o600); err != nil { // The store refuses a file with group or other bits.
			t.Fatal(err)
		}
	}},
}

// T-U-18: a store that does not open leaves the process running with no writer, not healthy, and with one open
// of the log and of the store. The log has the reason, and a refused schema leaves the database closed.
func TestTU18_StoreRefused(t *testing.T) {
	for _, c := range refusals {
		t.Run(c.name, func(t *testing.T) {
			p := testParams(t, c.path)
			if c.prep != nil {
				c.prep(t, filepath.Join(p.Root, c.path))
			}
			var o opens
			var db *sql.DB
			d := o.deps()
			migrate := d.migrate
			d.migrate = func(x *sql.DB, origin string) error { db = x; return migrate(x, origin) }
			var buf bytes.Buffer
			s, _ := launchLog(t, p, d, slog.New(slog.NewTextHandler(&buf, nil)))
			if s.Healthy() || s.writer != nil || s.db != nil {
				t.Errorf("healthy %v, writer %v, db %v; want not healthy, no writer, no database", s.Healthy(), s.writer, s.db)
			}
			s.Stop()
			if want := (opens{log: 1, store: 1, migrate: c.migrates}); o != want {
				t.Errorf("opens %+v, want %+v", o, want)
			}
			if out := buf.String(); !strings.Contains(out, "store does not open") || !strings.Contains(out, c.want) {
				t.Errorf("log %q; want \"store does not open\" and %q", out, c.want)
			}
			if db != nil && db.Ping() == nil {
				t.Error("the database is still open after the refusal")
			}
		})
	}
}

// T-U-18: a log that does not open gives no store and no writer, not healthy, and no key directory.
func TestTU18_LogRefused(t *testing.T) {
	var o opens
	d := o.deps()
	d.openLog = func(*os.Root, string) (*tlog.Log, error) { o.log++; return nil, errors.New("refused") }
	p := testParams(t, "events.db")
	s, _ := launch(t, p, d)
	if s.Healthy() || s.TlogHealthy() || s.writer != nil {
		t.Errorf("healthy %v, tlog healthy %v, writer %v; want none", s.Healthy(), s.TlogHealthy(), s.writer)
	}
	if want := (opens{log: 1}); o != want {
		t.Errorf("opens %+v, want %+v", o, want)
	}
	if _, err := os.Stat(filepath.Join(p.Root, "keys")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("keys directory: %v; want it not made", err)
	}
}

// T-U-18: a checkpointer that starts gives TlogHealthy. A signer that refuses (a log with a leaf, no key, no
// signer state) leaves no checkpointer and no key file, and the writer runs.
func TestTU18_Checkpointer(t *testing.T) {
	t.Run("starts", func(t *testing.T) {
		s, _ := launch(t, testParams(t, "events.db"), realDeps)
		if !s.TlogHealthy() || !s.Healthy() {
			t.Errorf("tlog healthy %v, healthy %v; want both", s.TlogHealthy(), s.Healthy())
		}
	})
	t.Run("signer refuses", func(t *testing.T) {
		p := testParams(t, "events.db")
		r, err := os.OpenRoot(p.Root)
		if err != nil {
			t.Fatal(err)
		}
		l, err := tlog.OpenLog(r, p.TlogDir)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := l.Append(tlog.EventHash{1}); err != nil {
			t.Fatal(err)
		}
		l.Close()
		r.Close()
		s, _ := launch(t, p, realDeps)
		if s == nil || s.cp != nil || s.TlogHealthy() {
			t.Errorf("checkpointer %v, tlog healthy %v; want none", s.cp, s.TlogHealthy())
		}
		if !s.Healthy() {
			t.Error("the writer does not run")
		}
		if _, err := os.Stat(filepath.Join(p.Root, "keys/checkpoint.key")); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("key file: %v; want it not made", err)
		}
	})
}

// T-U-18: with no store, the drain takes the events out of both lanes at its tick, and counts each drop for its
// lane. The tick of Discard is fixed (250 ms) and cannot be replaced from here, so the test waits for the
// drops with a limit of 10 s.
func TestTU18_DrainWithoutStore(t *testing.T) {
	s, q := launch(t, testParams(t, "keys/events.db"), realDeps)
	put(t, q, event.KindRequest, 2)
	put(t, q, event.KindCallback, 1)
	want := store.Drops{Bulk: 2, Evidence: 1}
	testutil.WaitFor(t, func() bool { return s.Drops() == want }, 10*time.Second)
	if got := s.Drops(); got != want {
		t.Errorf("drops %+v, want %+v", got, want)
	}
	if b := q.Bytes(); b != (event.Bytes{}) {
		t.Errorf("the lanes hold %+v bytes after the drain", b)
	}
}

// T-U-18: the checkpointer gets the checkpoint row sink, with the writer and with no writer, and never the bare
// spool. With the writer, the sink call stores the row.
func TestTU18_Sink(t *testing.T) {
	for _, c := range []struct {
		name, path string
		healthy    bool
		missing    uint64
	}{{"writer", "events.db", true, 0}, {"no writer", "keys/events.db", false, 1}} {
		t.Run(c.name, func(t *testing.T) {
			var sink tlog.NoteSink
			var signer note.Signer
			d := realDeps
			d.newCheckpointer = func(l *tlog.Log, sg note.Signer, v note.Verifier, sk tlog.NoteSink, r *os.Root, o string, i time.Duration, lg *slog.Logger) (*tlog.Checkpointer, error) {
				sink, signer = sk, sg
				return tlog.NewCheckpointer(l, sg, v, sk, r, o, i, lg)
			}
			s, _ := launch(t, testParams(t, c.path), d)
			ss, ok := sink.(*store.Sink)
			if !ok {
				t.Fatalf("the checkpointer sink is %T, want *store.Sink", sink)
			}
			if s.Healthy() != c.healthy {
				t.Errorf("healthy = %v, want %v", s.Healthy(), c.healthy)
			}
			msg, err := tlog.SignCheckpoint(signer, 1, [32]byte{1})
			if err != nil {
				t.Fatal(err)
			}
			if err := ss.Add(1, msg); err != nil {
				t.Fatal(err)
			}
			if got := ss.RowMissing(); got != c.missing {
				t.Errorf("RowMissing = %d, want %d", got, c.missing)
			}
			if c.healthy {
				var n int
				if err := s.db.QueryRow("SELECT count(*) FROM checkpoint WHERE tree_size = ?", 1).Scan(&n); err != nil || n != 1 {
					t.Errorf("checkpoint rows of size 1 = %d (%v), want 1", n, err)
				}
			}
		})
	}
}

// T-U-18: a writer that stopped at its start check leaves the part not healthy. After that, the checkpointer
// and the drain tick several times, and start opens the log and the store one time each and makes one writer.
func TestTU18_OneStart(t *testing.T) {
	p := testParams(t, "events.db")
	p.Interval = 10 * time.Millisecond
	if err := os.WriteFile(filepath.Join(p.Root, "writer.stop"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	var o opens
	writers := 0
	d := o.deps()
	d.newWriter = func(db *sql.DB, q *event.Queue, l *tlog.Log, c *event.Counters, bp bool, lg *slog.Logger, r store.Recovery) *store.Writer {
		writers++
		return store.NewWriter(db, q, l, c, bp, lg, r)
	}
	s, q := launch(t, p, d)
	testutil.WaitFor(t, func() bool { return !s.Healthy() }, 10*time.Second)
	// The stopped writer drops the events of the lanes only at its tick, and a new event does not wake it. So
	// each drop that the count shows is one tick of the drain. Wait for three, then check the counts. The
	// checkpointer ticks every 10 ms, so it ticked many times in these three.
	for want := uint64(1); want <= 3; want++ {
		put(t, q, event.KindRequest, 1)
		testutil.WaitFor(t, func() bool { return s.writer.Stats().Dropped.Bulk >= want }, 10*time.Second)
	}
	s.Stop()
	if want := (opens{log: 1, store: 1, migrate: 1}); o != want || writers != 1 {
		t.Errorf("opens %+v, writers %d; want %+v, 1", o, writers, want)
	}
}

// T-U-18: Stop ends the checkpointer before it closes the queue.
func TestTU18_StopOrder(t *testing.T) {
	exited := make(chan bool, 1)
	c := event.NewCounters()
	q, err := event.NewQueue(8, c)
	if err != nil {
		t.Fatal(err)
	}
	d := realDeps
	d.runCheckpointer = func(ctx context.Context, cp *tlog.Checkpointer) { cp.Run(ctx); exited <- q.Closed() }
	s := start(testParams(t, "events.db"), q, c, d, slog.New(slog.DiscardHandler))
	if !s.Healthy() {
		t.Fatal("the part is not healthy")
	}
	s.Stop()
	select {
	case closed := <-exited:
		if closed {
			t.Error("the queue was closed before the checkpointer ended")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the checkpointer did not end")
	}
}

// T-U-18: the values that start takes from the loaded config.
func TestTU18_Params(t *testing.T) {
	cfg, err := config.Load(writeFile(t, validBody(t)), []string{"CKPT_TOKEN=" + strings.Repeat("t", 32)})
	if err != nil {
		t.Fatal(err)
	}
	want := startParams{Root: "/var/lib/phantom", StorePath: "events.db", TlogDir: "tlog", Origin: "test/origin", CacheDir: "certs",
		Reserved: []string{"tlog", "certs", "bundle"}, Interval: time.Hour, BodyPrefix: true}
	if got := paramsOf(cfg); !reflect.DeepEqual(got, want) {
		t.Errorf("params %+v, want %+v", got, want)
	}
}
