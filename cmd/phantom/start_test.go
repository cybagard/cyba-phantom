package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/note"

	"github.com/cybagard/cyba-phantom/internal/config"
	"github.com/cybagard/cyba-phantom/internal/event"
	"github.com/cybagard/cyba-phantom/internal/safefile"
	"github.com/cybagard/cyba-phantom/internal/store"
	"github.com/cybagard/cyba-phantom/internal/testutil"
	"github.com/cybagard/cyba-phantom/internal/tlog"
	"github.com/cybagard/cyba-phantom/internal/verify"
)

// opens counts the calls that open the log and the store, and the runs of the
// migration. Its deps method gives the real parts to start.
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

func launch(t *testing.T, p startParams, d startDeps) (*storePart, *event.Queue) {
	t.Helper()
	return launchLog(t, p, d, slog.New(slog.DiscardHandler))
}

func launchLog(t *testing.T, p startParams, d startDeps, lg *slog.Logger) (*storePart, *event.Queue) {
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

// refusals are the stores that do not open. One row refuses the path, and one
// has a file that is not a database. One row refuses the schema, and one has
// a wrong auto_vacuum. The last row fails the migration.
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
		prepDB(t, file, "PRAGMA auto_vacuum = 2; CREATE TABLE other (a)")
	}},
	{"auto_vacuum not 2", "events.db", "store: database schema must use auto_vacuum incremental", 1, func(t *testing.T, file string) {
		prepDB(t, file, "PRAGMA auto_vacuum = 0; CREATE TABLE other (a)")
	}},
	{"failed migration", "events.db", "store: database schema migration failed", 1, func(t *testing.T, file string) {
		// The meta table has no value column, so the read of the schema version
		// fails.
		prepDB(t, file, "PRAGMA auto_vacuum = 2; CREATE TABLE meta (key)")
	}},
}

// prepDB makes the database file and runs stmts in it.
func prepDB(t *testing.T, file, stmts string) {
	t.Helper()
	db, err := sql.Open("sqlite", file)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(stmts); err != nil {
		t.Fatal(err)
	}
	// The store refuses a file with group or other bits.
	if err := os.Chmod(file, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestTU18_StoreRefused checks that a store that does not open leaves the
// process running. There is no writer, and the part is not healthy. One call
// opens the log and one call opens the store. The log has the reason. A
// refused schema leaves the database closed (T-U-18).
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

// TestTU18_LogRefused checks that a log that does not open gives no store, no
// writer and no key directory. The part is not healthy (T-U-18).
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

// TestTU18_Checkpointer checks that a checkpointer that starts gives
// TlogHealthy. A signer that refuses leaves no checkpointer and no key file,
// and the writer runs. The signer refuses a log with a leaf, no key and no
// signer state (T-U-18).
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
		if s.cp != nil || s.TlogHealthy() {
			t.Errorf("checkpointer %v, tlog healthy %v; want none", s.cp, s.TlogHealthy())
		}
		// The writer sets Healthy in its own goroutine, so wait for it.
		testutil.WaitFor(t, s.Healthy, 10*time.Second)
		if _, err := os.Stat(filepath.Join(p.Root, "keys/checkpoint.key")); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("key file: %v; want it not made", err)
		}
	})
}

// TestTU18_DrainWithoutStore checks that with no store, the drain takes the
// events out of both lanes at its tick. It counts each drop for its lane. The
// tick of the drain is fixed (250 ms), and a test cannot replace it. So the
// test waits for the drops with a limit of 10 s (T-U-18).
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

// TestTU18_Sink checks that the checkpointer gets the checkpoint row sink and
// never the bare spool. This holds with the writer and with no writer. With the
// writer, the sink call stores the row (T-U-18).
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

// TestTU18_OneStart checks that a writer that stopped at its start check leaves
// the part not healthy. After that, the checkpointer runs and the drain ticks
// several times. start opens the log and the store one time each and makes one
// writer (T-U-18).
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
	var runs atomic.Int32
	d.runCheckpointer = func(ctx context.Context, cp *tlog.Checkpointer) { runs.Add(1); cp.Run(ctx) }
	s, q := launch(t, p, d)
	if s.cp == nil || !s.TlogHealthy() {
		t.Errorf("checkpointer started %v, tlog healthy %v; want it to run", s.cp != nil, s.TlogHealthy())
	}
	testutil.WaitFor(t, func() bool { return !s.Healthy() }, 10*time.Second)
	// The stopped writer drops the events of the lanes only at its tick. A new
	// event does not wake it. So each drop that the count shows is one tick of
	// the drain. Wait for three, then check the counts. The checkpointer ticks
	// every 10 ms, so it ticked many times in these three.
	for want := uint64(1); want <= 3; want++ {
		put(t, q, event.KindRequest, 1)
		testutil.WaitFor(t, func() bool { return s.writer.Stats().Dropped.Bulk >= want }, 10*time.Second)
	}
	// Stop waits for the checkpointer goroutine, so runs is final after it.
	s.Stop()
	if want := (opens{log: 1, store: 1, migrate: 1}); o != want || writers != 1 {
		t.Errorf("opens %+v, writers %d; want %+v, 1", o, writers, want)
	}
	if n := runs.Load(); n != 1 {
		t.Errorf("checkpointer runs = %d, want 1", n)
	}
}

// TestTU18_StopOrder checks that Stop ends the checkpointer before it closes
// the queue (T-U-18).
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
			t.Error("the queue closed before the checkpointer ended")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the checkpointer did not end")
	}
}

// savedKey makes the signer key and the public key file in the state
// directory of p. An earlier start did the same.
func savedKey(t *testing.T, p startParams) {
	t.Helper()
	r, err := os.OpenRoot(p.Root)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err := tlog.LoadOrCreateSigner(r, nil, p.Origin, false, 0); err != nil {
		t.Fatal(err)
	}
}

// otherKey returns the public key text of a new key with the given name.
func otherKey(t *testing.T, name string) string {
	t.Helper()
	_, vkey, err := note.GenerateKey(rand.Reader, name)
	if err != nil {
		t.Fatal(err)
	}
	return vkey
}

// TestTU18_VkeyMismatch checks a public key file that is not the key of the
// signer. Start gives an error, and the spool does not open (T-U-18). The
// table has no key with the same name and the same 32-bit key hash as the
// signer. Such a key needs about 2^32 keys, and NewVerifier checks the hash.
// TestTU18_SameKey covers it.
func TestTU18_VkeyMismatch(t *testing.T) {
	for _, c := range []struct {
		name string
		// the new public key text
		vkey func(t *testing.T, p startParams, saved string) string
	}{
		{"other name", func(t *testing.T, p startParams, _ string) string { return otherKey(t, "other/origin") }},
		{"same name, other key", func(t *testing.T, p startParams, _ string) string { return otherKey(t, p.Origin) }},
		{"same key, other name", func(t *testing.T, _ startParams, saved string) string {
			// The text is name+hash+base64(algorithm byte, public key).
			parts := strings.SplitN(strings.TrimSpace(saved), "+", 3)
			if len(parts) != 3 {
				t.Fatalf("public key text has %d parts, want 3", len(parts))
			}
			raw, err := base64.StdEncoding.DecodeString(parts[2])
			if err != nil || len(raw) != 1+ed25519.PublicKeySize {
				t.Fatalf("public key bytes: %d, %v", len(raw), err)
			}
			v, err := note.NewEd25519VerifierKey("other/origin", ed25519.PublicKey(raw[1:]))
			if err != nil {
				t.Fatal(err)
			}
			return v
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := testParams(t, "events.db")
			savedKey(t, p)
			vpath := filepath.Join(p.Root, tlog.VKeyName)
			saved, err := os.ReadFile(vpath)
			if err != nil {
				t.Fatal(err)
			}
			vkey := c.vkey(t, p, string(saved))
			if err := os.Remove(vpath); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(vpath, []byte(vkey+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			var buf bytes.Buffer
			checkpointerCalls := 0
			d := realDeps
			d.newCheckpointer = func(*tlog.Log, note.Signer, note.Verifier, tlog.NoteSink, *os.Root, string, time.Duration, *slog.Logger) (*tlog.Checkpointer, error) {
				checkpointerCalls++
				return nil, errors.New("the checkpointer must not start")
			}
			s, _ := launchLog(t, p, d, slog.New(slog.NewTextHandler(&buf, nil)))
			if s.cp != nil || s.TlogHealthy() || checkpointerCalls != 0 {
				t.Errorf("checkpointer started %v, tlog healthy %v, checkpointer calls %d; want none", s.cp != nil, s.TlogHealthy(), checkpointerCalls)
			}
			if !strings.Contains(buf.String(), "checkpointer does not start") {
				t.Errorf("log %q; want \"checkpointer does not start\"", buf.String())
			}
			if _, err := os.Stat(filepath.Join(p.Root, tlog.SpoolDirName)); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("spool directory: %v; want it not made", err)
			}
		})
	}
}

// startBadVkey saves a key and moves its public key file to copy.vkey in the
// state directory. prep makes the file at vpath. Then start must return in
// 10 s, start no checkpointer, and log the error text want.
func startBadVkey(t *testing.T, want error, prep func(vpath string) error) {
	t.Helper()
	p := testParams(t, "events.db")
	savedKey(t, p)
	vpath := filepath.Join(p.Root, tlog.VKeyName)
	if err := os.Rename(vpath, filepath.Join(p.Root, "copy.vkey")); err != nil {
		t.Fatal(err)
	}
	if err := prep(vpath); err != nil {
		t.Fatal(err)
	}
	cnt := event.NewCounters()
	q, err := event.NewQueue(8, cnt)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan *storePart, 1)
	var buf bytes.Buffer
	go func() { done <- start(p, q, cnt, realDeps, slog.New(slog.NewTextHandler(&buf, nil))) }()
	select {
	case s := <-done:
		t.Cleanup(s.Stop)
		if s.cp != nil {
			t.Error("checkpointer started; want none")
		}
		for _, w := range []string{"checkpointer does not start", want.Error()} {
			if !strings.Contains(buf.String(), w) {
				t.Errorf("log %q; want %q", buf.String(), w)
			}
		}
	case <-time.After(10 * time.Second):
		t.Fatal("start did not return")
	}
}

// TestTU18_VkeyFifo checks a FIFO at the public key file (T-U-18).
func TestTU18_VkeyFifo(t *testing.T) {
	startBadVkey(t, safefile.ErrType, func(v string) error { return syscall.Mkfifo(v, 0o600) })
}

// TestTU18_VkeyRefused checks a public key file that is a directory, a
// symlink to a correct file, or over 1 KiB. Each gives its own error (T-U-18).
func TestTU18_VkeyRefused(t *testing.T) {
	for _, c := range []struct {
		name string
		want error
		prep func(vpath string) error
	}{
		{"directory", safefile.ErrType, func(v string) error { return os.Mkdir(v, 0o700) }},
		{"symlink", safefile.ErrSymlink, func(v string) error { return os.Symlink("../copy.vkey", v) }},
		{"over 1 KiB", safefile.ErrSize, func(v string) error {
			return os.WriteFile(v, bytes.Repeat([]byte("k"), verify.MaxKeyBytes+1), 0o600)
		}},
	} {
		t.Run(c.name, func(t *testing.T) { startBadVkey(t, c.want, c.prep) })
	}
}

// sigtermHelperEnv makes TestTU18_SigtermHelper run. Else the helper skips.
const sigtermHelperEnv = "PHANTOM_TEST_SIGTERM_HELPER"

// TestTU18_SigtermDuringStart runs the real serve function in a child process
// with a FIFO at the public key file. A SIGTERM during the start must end the
// child with exit code 0 before the deadline (T-U-18).
func TestTU18_SigtermDuringStart(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestTU18_SigtermHelper$")
	cmd.Env = append(os.Environ(), sigtermHelperEnv+"=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("child: %v (context %v), output:\n%s", err, ctx.Err(), out)
	}
}

// TestTU18_SigtermHelper is the child of TestTU18_SigtermDuringStart. The
// migrate step sends SIGTERM to the process, so the signal comes during start.
func TestTU18_SigtermHelper(t *testing.T) {
	if os.Getenv(sigtermHelperEnv) == "" {
		t.Skip("child of TestTU18_SigtermDuringStart")
	}
	https, plain, ca := openListeners(t)
	cfg := serveCfg(t, https.Addr().String(), plain.Addr().String(), ca)
	p := tempState(t, cfg)
	savedKey(t, p)
	vpath := filepath.Join(p.Root, tlog.VKeyName)
	if err := os.Remove(vpath); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(vpath, 0o600); err != nil {
		t.Fatal(err)
	}
	d := realDeps
	d.migrate = func(db *sql.DB, origin string) error {
		if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
			t.Error(err)
		}
		return store.Migrate(db, origin)
	}
	serveSetup = func(startParams) (startParams, startDeps) { return p, d }
	os.Exit(serve(cfg, io.Discard, os.Stderr))
}

// rejectingKey has the name and the key hash of a key, and verifies no
// signature.
type rejectingKey struct{ note.Verifier }

func (rejectingKey) Verify(msg, sig []byte) bool { return false }

// TestTU18_SameKey checks that sameKey accepts the public key of the signer.
// It also checks that sameKey refuses a verifier with the name and the key
// hash of the signer. That verifier does not verify the signature of the
// signer (T-U-18).
func TestTU18_SameKey(t *testing.T) {
	skey, vkey, err := note.GenerateKey(rand.Reader, "test/origin")
	if err != nil {
		t.Fatal(err)
	}
	signer, err := note.NewSigner(skey)
	if err != nil {
		t.Fatal(err)
	}
	v, err := note.NewVerifier(vkey)
	if err != nil {
		t.Fatal(err)
	}
	if err := sameKey(signer, v); err != nil {
		t.Errorf("the key of the signer: %v", err)
	}
	if err := sameKey(signer, rejectingKey{v}); err == nil {
		t.Error("a verifier with the same name and hash that rejects the signature: no error")
	}
}

// storeWithCheckpointRow makes the store of p with one checkpoint row, and
// closes it.
func storeWithCheckpointRow(t *testing.T, p startParams) {
	t.Helper()
	r, err := os.OpenRoot(p.Root)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	db, err := store.Open(r, p.StorePath, store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := store.Migrate(db, p.Origin); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO checkpoint (tree_size, root_hash, signed_note, created_at) VALUES (1, zeroblob(32), 'n', 1)"); err != nil {
		t.Fatal(err)
	}
}

// TestTS13_NoKeyOverRows checks a start with keys/, checkpoint.state and tlog/
// removed. A store with a checkpoint row gives no new key, no signer state and
// no checkpointer. A spool with an entry does the same (T-S-13, SEC-16). A
// store that exists and does not open also gives no key. A store path that
// cannot be examined gives no key and names that cause. A spool that start
// cannot read does the same. A spool that is a FIFO or a symlink gives no key,
// and start returns. The empty store with no spool entry still makes a key
// (first start).
func TestTS13_NoKeyOverRows(t *testing.T) {
	for _, c := range []struct {
		name       string
		prep       func(t *testing.T, p startParams)
		deps       func(d *startDeps, hookErr *error)
		wantKey    bool   // a first start: the key and the checkpointer
		storePath  string // the store path; empty means events.db
		writerRuns bool   // the writer runs
		opens      bool   // the store opens
		skipAsRoot bool   // the row cannot run as root, so root skips it
		wantLog    string // text that the log must have
		notLog     string // text that the log must not have
	}{
		{name: "checkpoint row", writerRuns: true, prep: storeWithCheckpointRow},
		{name: "store path cannot be examined", storePath: "x/events.db",
			wantLog: "store path cannot be examined", notLog: "signed checkpoint",
			prep: func(t *testing.T, p startParams) {
				// x is a file, so the Lstat of x/events.db gives ENOTDIR.
				if err := os.WriteFile(filepath.Join(p.Root, "x"), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}},
		{name: "store with a checkpoint row that does not open", prep: func(t *testing.T, p startParams) {
			storeWithCheckpointRow(t, p)
			// The store refuses a file with group or other bits.
			if err := os.Chmod(filepath.Join(p.Root, p.StorePath), 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "checkpoint query fails", opens: true,
			deps: func(d *startDeps, hookErr *error) {
				d.migrate = func(db *sql.DB, origin string) error {
					if err := store.Migrate(db, origin); err != nil {
						return err
					}
					_, *hookErr = db.Exec("DROP TABLE checkpoint")
					return *hookErr
				}
			}},
		{name: "spool entry", prep: func(t *testing.T, p startParams) {
			if err := os.Mkdir(filepath.Join(p.Root, tlog.SpoolDirName), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(p.Root, tlog.SpoolDirName, "1.note"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "spool is a file", prep: func(t *testing.T, p startParams) {
			if err := os.WriteFile(filepath.Join(p.Root, tlog.SpoolDirName), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "spool is a FIFO", prep: func(t *testing.T, p startParams) {
			if err := syscall.Mkfifo(filepath.Join(p.Root, tlog.SpoolDirName), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "spool is a symlink", prep: func(t *testing.T, p startParams) {
			if err := os.Mkdir(filepath.Join(p.Root, "empty"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("empty", filepath.Join(p.Root, tlog.SpoolDirName)); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "spool is a dangling symlink", prep: func(t *testing.T, p startParams) {
			if err := os.Symlink("missing", filepath.Join(p.Root, tlog.SpoolDirName)); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "spool directory does not open", skipAsRoot: true, prep: func(t *testing.T, p startParams) {
			dir := filepath.Join(p.Root, tlog.SpoolDirName)
			if err := os.Mkdir(dir, 0o000); err != nil {
				t.Fatal(err)
			}
			// The cleanup of the temporary directory needs the mode back.
			t.Cleanup(func() { os.Chmod(dir, 0o700) })
		}},
		{name: "empty store, no spool", wantKey: true},
		{name: "empty store, empty spool directory", wantKey: true, prep: func(t *testing.T, p startParams) {
			if err := os.Mkdir(filepath.Join(p.Root, tlog.SpoolDirName), 0o700); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			if c.skipAsRoot && os.Geteuid() == 0 {
				t.Skip("root reads a directory with mode 0")
			}
			storePath := c.storePath
			if storePath == "" {
				storePath = "events.db"
			}
			p := testParams(t, storePath)
			if c.prep != nil {
				c.prep(t, p)
			}
			d := realDeps
			var hookErr error
			if c.deps != nil {
				c.deps(&d, &hookErr)
			}
			cnt := event.NewCounters()
			q, err := event.NewQueue(8, cnt)
			if err != nil {
				t.Fatal(err)
			}
			// A FIFO in the spool path must not block start.
			done := make(chan *storePart, 1)
			var buf bytes.Buffer
			go func() { done <- start(p, q, cnt, d, slog.New(slog.NewTextHandler(&buf, nil))) }()
			var s *storePart
			select {
			case s = <-done:
				t.Cleanup(s.Stop)
			case <-time.After(10 * time.Second):
				t.Fatal("start did not return")
			}
			if hookErr != nil {
				t.Fatalf("migrate hook: %v", hookErr)
			}
			if c.opens && s.db == nil {
				t.Error("the store did not open; want it open")
			}
			if c.writerRuns {
				// The writer sets Healthy in its own goroutine, so wait for it.
				testutil.WaitFor(t, s.Healthy, 10*time.Second)
			}
			if c.wantKey {
				if s.cp == nil {
					t.Error("no checkpointer; want a first start to make one")
				}
				if _, err := os.Stat(filepath.Join(p.Root, tlog.VKeyName)); err != nil {
					t.Errorf("public key file: %v; want it made", err)
				}
				return
			}
			if s.cp != nil || s.TlogHealthy() {
				t.Errorf("checkpointer started %v, tlog healthy %v; want none", s.cp != nil, s.TlogHealthy())
			}
			if c.wantLog != "" && !strings.Contains(buf.String(), c.wantLog) {
				t.Errorf("log %q; want %q", buf.String(), c.wantLog)
			}
			if c.notLog != "" && strings.Contains(buf.String(), c.notLog) {
				t.Errorf("log %q; want no %q", buf.String(), c.notLog)
			}
			for _, name := range []string{"keys", "checkpoint.state"} {
				if _, err := os.Stat(filepath.Join(p.Root, name)); !errors.Is(err, fs.ErrNotExist) {
					t.Errorf("%s: %v; want it not made", name, err)
				}
			}
		})
	}
}

// TestParamsOf checks the values that start takes from the loaded config
// (FR-07, FR-12). It has no spec test ID: it tests the mapping of the config
// values, not the start.
func TestParamsOf(t *testing.T) {
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
