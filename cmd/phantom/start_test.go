package main

import (
	"context"
	"database/sql"
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
	c := event.NewCounters()
	q, err := event.NewQueue(8, c)
	if err != nil {
		t.Fatal(err)
	}
	s := start(p, q, c, d, slog.New(slog.DiscardHandler))
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
	migrates   int // the runs of the migration: only a database that opens reaches it
	prep       func(t *testing.T, file string)
}{
	{"refused path", "keys/events.db", 0, nil},
	{"not a database", "events.db", 0, func(t *testing.T, file string) {
		if err := os.WriteFile(file, []byte(strings.Repeat("not a database ", 100)), 0o600); err != nil {
			t.Fatal(err)
		}
	}},
	{"refused schema", "events.db", 1, func(t *testing.T, file string) {
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

// TestTU18_StoreRefused checks that a store that does not open leaves the process running with no writer,
// not healthy, and with one open of the log and of the store.
func TestTU18_StoreRefused(t *testing.T) {
	for _, c := range refusals {
		t.Run(c.name, func(t *testing.T) {
			p := testParams(t, c.path)
			if c.prep != nil {
				c.prep(t, filepath.Join(p.Root, c.path))
			}
			var o opens
			s, _ := launch(t, p, o.deps())
			if s.Healthy() || s.writer != nil || s.db != nil {
				t.Errorf("healthy %v, writer %v, db %v; want not healthy, no writer, no database", s.Healthy(), s.writer, s.db)
			}
			s.Stop()
			if want := (opens{log: 1, store: 1, migrate: c.migrates}); o != want {
				t.Errorf("opens %+v, want %+v", o, want)
			}
		})
	}
}

// TestTU18_DrainWithoutStore checks that with no store, the drain takes the events out of both lanes at its
// tick, and counts each drop for its lane. The tick of Discard is fixed (250 ms) and cannot be replaced from
// here, so the test waits for the drops with a limit of 10 s.
func TestTU18_DrainWithoutStore(t *testing.T) {
	s, q := launch(t, testParams(t, "keys/events.db"), realDeps)
	put(t, q, event.KindRequest, 2)
	put(t, q, event.KindCallback, 1)
	want := store.Drops{Bulk: 2, Evidence: 1}
	for end := time.Now().Add(10 * time.Second); s.drops.Load() != want && time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
	}
	if got := s.drops.Load(); got != want {
		t.Errorf("drops %+v, want %+v", got, want)
	}
	if b := q.Bytes(); b != (event.Bytes{}) {
		t.Errorf("the lanes hold %+v bytes after the drain", b)
	}
}

// TestTU18_Sink checks that the checkpointer gets the checkpoint row sink, with the writer and with no writer,
// and never the bare spool.
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
		})
	}
}

// TestTU18_OneStart checks that a writer that stopped at its start check leaves the part not healthy, and that
// the log and the store are opened one time: no reopen, no second writer.
func TestTU18_OneStart(t *testing.T) {
	p := testParams(t, "events.db")
	if err := os.WriteFile(filepath.Join(p.Root, "writer.stop"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	var o opens
	s, _ := launch(t, p, o.deps())
	s.Stop() // The writer returns after the close of the queue, so its stop is final here.
	if s.writer == nil || s.Healthy() {
		t.Errorf("writer %v, healthy %v; want a writer that is not healthy", s.writer, s.Healthy())
	}
	if want := (opens{log: 1, store: 1, migrate: 1}); o != want {
		t.Errorf("opens %+v, want %+v", o, want)
	}
}

// TestTU18_StopOrder checks that Stop ends the checkpointer before it closes the queue.
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
	if closed := <-exited; closed {
		t.Error("the queue was closed before the checkpointer ended")
	}
}

// TestTU18_Params checks the values that the start takes from the loaded config.
func TestTU18_Params(t *testing.T) {
	cfg, err := config.Load(writeFile(t, validBody(t)), []string{"CKPT_TOKEN=" + strings.Repeat("t", 32)})
	if err != nil {
		t.Fatal(err)
	}
	want := startParams{Root: "/var/lib/phantom", StorePath: "events.db", TlogDir: "tlog", Origin: "test/origin",
		Reserved: []string{"tlog", "certs", "bundle"}, Interval: time.Hour, BodyPrefix: true}
	if got := paramsOf(cfg); !reflect.DeepEqual(got, want) {
		t.Errorf("params %+v, want %+v", got, want)
	}
}
