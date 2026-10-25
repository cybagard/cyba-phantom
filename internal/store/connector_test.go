//go:build unix

package store

import (
	"context"
	"database/sql"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/cybagard/cyba-phantom/internal/event"
	"github.com/cybagard/cyba-phantom/internal/safefile"
	"github.com/cybagard/cyba-phantom/internal/safefile/safefiletest"
)

// countConnects counts the calls of Connect until the end of the test.
func countConnects(t *testing.T) *atomic.Int64 {
	t.Helper()
	var n atomic.Int64
	onConnect = func() { n.Add(1) }
	t.Cleanup(func() { onConnect = nil })
	return &n
}

// cancelQuery cancels the context during a long query, so that the pool drops
// the connection. It checks that the query failed.
func cancelQuery(t *testing.T, db *sql.DB) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	var n int
	err := db.QueryRowContext(ctx,
		"WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c) SELECT count(*) FROM c").Scan(&n)
	if err == nil {
		t.Fatal("the cancelled query did not fail")
	}
}

// T-S-15: after the pool drops a connection, it makes the next one through the
// connector. With no change on disk, the next query works.
func TestTS15CancelledQueryReconnects(t *testing.T) {
	root, _, _ := newState(t)
	db := mustOpen(t, root, "events.db")
	defer db.Close()
	n := countConnects(t)
	cancelQuery(t, db)
	var one int
	if err := db.QueryRow("SELECT 1").Scan(&one); err != nil || one != 1 {
		t.Fatalf("query after the cancel: %v", err)
	}
	if n.Load() != 1 {
		t.Fatalf("%d Connect calls after the cancel, want 1", n.Load())
	}
}

// noHooks turns the test hooks off, so that a helper can call Open inside a
// hook. The returned function sets them again.
func noHooks() func() {
	a, b, c, d, e := onConnect, afterChecks, afterVerify, beforeDriverOpen, onHeld
	onConnect, afterChecks, afterVerify, beforeDriverOpen, onHeld = nil, nil, nil, nil, nil
	return func() { onConnect, afterChecks, afterVerify, beforeDriverOpen, onHeld = a, b, c, d, e }
}

// cleanDatabase makes a valid database file in another state directory, with
// mode 0600 and one link, and returns its path.
func cleanDatabase(t *testing.T) string {
	t.Helper()
	defer noHooks()()
	root, state, _ := newState(t)
	mustOpen(t, root, "events.db").Close()
	return filepath.Join(state, "events.db")
}

// replaceFile renames a clean database file over file.
func replaceFile(t *testing.T, file string) {
	t.Helper()
	if err := os.Rename(cleanDatabase(t), file); err != nil {
		t.Fatal(err)
	}
}

// swapStateDir renames the state directory away and makes a new 0700 directory
// with a new database file at its path. The root still leads to the old one.
func swapStateDir(t *testing.T, state string) {
	t.Helper()
	defer noHooks()()
	if err := os.Rename(state, state+".away"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(state)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	mustOpen(t, root, "events.db").Close()
}

// T-S-15: the pool makes a new connection after a change at the database file.
// The change is a symlink, a rename away, a different clean file, or a
// different state directory. The connector refuses the connection with a
// fixed error. The file that the link points to does not change.
func TestTS15ReconnectChecksTheFiles(t *testing.T) {
	for _, mode := range []string{"symlink", "renamed", "other file", "state directory"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			db := mustOpen(t, f.root, "events.db")
			defer db.Close()
			n := countConnects(t)
			cancelQuery(t, db)
			file := filepath.Join(f.state, "events.db")
			rule := ruleChanged
			switch mode {
			case "other file":
				replaceFile(t, file)
			case "state directory":
				swapStateDir(t, f.state)
				rule = ruleLocation
			default:
				if err := os.Rename(file, file+".moved"); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "symlink" {
				if err := os.Symlink(f.target, file); err != nil {
					t.Fatal(err)
				}
				rule = ruleType
			}
			before := snapshot(t, f.outside)
			wantRule(t, db.QueryRow("SELECT 1").Scan(new(int)), "events.db", rule)
			if n.Load() != 1 || snapshot(t, f.outside) != before {
				t.Fatalf("%d Connect calls; outside changed: %v", n.Load(), snapshot(t, f.outside) != before)
			}
			if _, err := os.Lstat(file); mode == "renamed" && err == nil {
				t.Fatal("the refused connection made a new database file")
			}
		})
	}
}

// T-S-15: the writer stops with a database error when the pool cannot make a
// connection, and it does not stop when the pool makes a good new one.
func TestTS15WriterAfterReconnect(t *testing.T) {
	for _, name := range []string{"no change", "file renamed", "symlink", "other file renamed over", "state directory swapped"} {
		bad := name != "no change"
		t.Run(name, func(t *testing.T) {
			r := newRig(t, 100)
			stop := r.start()
			r.add(event.KindRequest, 1)
			r.drained()
			r.fire()
			r.commit()

			n, want := countConnects(t), int64(1)
			cancelQuery(t, r.db)
			file := filepath.Join(r.state, "events.db")
			switch name {
			case "file renamed":
				if err := os.Rename(file, file+".moved"); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Rename(file, file+".moved"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(file+".moved", file); err != nil {
					t.Fatal(err)
				}
				// The file check refuses this direct query.
				wantRule(t, r.db.QueryRow("SELECT 1").Scan(new(int)), "events.db", ruleType)
				want++ // the writer makes one more try
			case "other file renamed over":
				replaceFile(t, file)
			case "state directory swapped":
				swapStateDir(t, r.state)
				// This direct query is refused by the check of the path.
				wantRule(t, r.db.QueryRow("SELECT 1").Scan(new(int)), "events.db", ruleLocation)
				want++ // the writer makes one more try
			}
			r.add(event.KindRequest, 2)
			r.drained()
			r.fire()
			if bad {
				waitUntil(t, "the stop", func() bool { return !r.w.Healthy() })
				wantRule(t, r.w.Err(), writerName, ruleDatabase)
			} else {
				r.commit()
			}
			stop()
			if r.w.Healthy() == bad || n.Load() != want {
				t.Fatalf("healthy %v, %d Connect calls, want %d", r.w.Healthy(), n.Load(), want)
			}
		})
	}
}

// swapAfterVerify makes Open run swap between the open of SQLite and the second
// checks. It checks that Open refuses with the rule for events.db, that the file
// outside does not change, and that the database file is not removed.
// Open keeps the file, because the fixture made it before the call.
func swapAfterVerify(t *testing.T, rule string, swap func(f *fixture)) {
	swapAfterVerifyOf(t, "events.db", rule, swap)
}

// swapAfterVerifyOf is swapAfterVerify with one more argument: name is the
// file that the refusal names, for example events.db-wal.
func swapAfterVerifyOf(t *testing.T, name, rule string, swap func(f *fixture)) {
	f := newFixture(t)
	data, err := os.ReadFile(filepath.Join(f.state, "events.db"))
	if err != nil {
		t.Fatal(err)
	}
	setHook(t, &afterVerify, func() { swap(f) })
	db, err := Open(f.root, "events.db", Options{})
	if db != nil {
		db.Close()
	}
	wantRule(t, err, name, rule)
	if _, err := os.Lstat(filepath.Join(f.state, "events.db")); err != nil {
		t.Fatalf("the database file is gone: %v", err)
	}
	if b, err := os.ReadFile(f.target); err != nil || string(b) != "outside" {
		t.Fatalf("the file outside changed: %q, %v", b, err)
	}
	if b, err := os.ReadFile(filepath.Join(f.outside, "copy")); err == nil && string(b) != string(data) {
		t.Fatal("the hard link target changed")
	}
}

// T-S-15: the second checks find a swap that someone puts in place after the
// open of SQLite. The swap can be a rename that puts a symlink in place of
// the file. It can be a rename that puts a different clean file in place. It
// can be a new hard link to the file. The second checks also find a symlink in
// place of the WAL, SHM or journal file.
func TestTS15SwapAfterOpenIsRefused(t *testing.T) {
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		t.Run("symlink in place of "+suffix, func(t *testing.T) {
			swapAfterVerifyOf(t, "events.db"+suffix, ruleType, func(f *fixture) {
				file := filepath.Join(f.state, "events.db"+suffix)
				// The -journal file is absent in WAL mode.
				if err := os.Remove(file); err != nil && !errors.Is(err, fs.ErrNotExist) {
					t.Fatal(err)
				}
				if err := os.Symlink(f.target, file); err != nil {
					t.Fatal(err)
				}
			})
		})
	}
	t.Run("rename puts a symlink in place", func(t *testing.T) {
		swapAfterVerify(t, ruleType, func(f *fixture) {
			file := filepath.Join(f.state, "events.db")
			os.Rename(file, file+".moved")
			os.Symlink(f.target, file)
		})
	})
	t.Run("clean file renamed over", func(t *testing.T) {
		swapAfterVerify(t, ruleChanged, func(f *fixture) {
			replaceFile(t, filepath.Join(f.state, "events.db"))
		})
	})
	t.Run("hard link", func(t *testing.T) {
		swapAfterVerify(t, ruleLinks, func(f *fixture) {
			os.Link(filepath.Join(f.state, "events.db"), filepath.Join(f.outside, "copy"))
		})
	})
}

// changeBeforeDriverOpen opens the fixture database, cancels a query, and sets
// change to run between the checks of the next connection and the open of the
// driver. It returns the error of the next query.
func changeBeforeDriverOpen(t *testing.T, f *fixture, rel string, change func()) error {
	t.Helper()
	db := mustOpen(t, f.root, rel)
	defer db.Close()
	cancelQuery(t, db)
	setHook(t, &beforeDriverOpen, change)
	return db.QueryRow("SELECT 1").Scan(new(int))
}

// T-S-15: a change after the checks and before the open of the driver is found
// by the checks on the new connection.
func TestTS15ChangeBeforeDriverOpenIsRefused(t *testing.T) {
	t.Run("clean file renamed over", func(t *testing.T) {
		f := newFixture(t)
		err := changeBeforeDriverOpen(t, f, "events.db", func() {
			replaceFile(t, filepath.Join(f.state, "events.db"))
		})
		wantRule(t, err, "events.db", ruleChanged)
	})
	t.Run("symlink in place of the parent directory", func(t *testing.T) {
		f := newFixture(t)
		if err := os.Mkdir(filepath.Join(f.state, "data"), 0o700); err != nil {
			t.Fatal(err)
		}
		err := changeBeforeDriverOpen(t, f, "data/events.db", func() {
			dir := filepath.Join(f.state, "data")
			os.Rename(dir, dir+".real")
			os.Symlink("data.real", dir)
		})
		wantRule(t, err, "data/events.db", ruleLocation)
	})
	t.Run("file removed and made again by the driver", func(t *testing.T) {
		old := syscall.Umask(0o077) // so that the driver makes a mode 0600 file
		defer syscall.Umask(old)
		f := newFixture(t)
		file := filepath.Join(f.state, "events.db")
		err := changeBeforeDriverOpen(t, f, "events.db", func() {
			os.Remove(file)
		})
		wantRule(t, err, "events.db", ruleChanged)
	})
}

// removeDatabase removes the database file and its WAL and SHM files, if any.
func removeDatabase(t *testing.T, file string) {
	t.Helper()
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if err := os.Remove(file + suffix); err != nil && !errors.Is(err, fs.ErrNotExist) {
			t.Fatal(err)
		}
	}
}

// T-S-15: a database file that is removed and made again while the pool has no
// connection is refused, also when the new file gets the number of the old
// inode. Each row runs 10 times, because the number is not the same each time.
// A row makes its new file in the same directory, after the removal, so that
// the file system can give it the number of the removed inode.
func TestTS15RemovedFileMadeAgainIsRefused(t *testing.T) {
	remake := map[string]func(t *testing.T, f *fixture) func(){
		"clean file renamed in": func(t *testing.T, f *fixture) func() {
			return func() {
				mustOpen(t, f.root, "other.db").Close()
				err := os.Rename(filepath.Join(f.state, "other.db"), filepath.Join(f.state, "events.db"))
				if err != nil {
					t.Fatal(err)
				}
			}
		},
		"new database written": func(t *testing.T, f *fixture) func() {
			b, err := os.ReadFile(cleanDatabase(t))
			if err != nil {
				t.Fatal(err)
			}
			return func() {
				if err := os.WriteFile(filepath.Join(f.state, "events.db"), b, 0o600); err != nil {
					t.Fatal(err)
				}
			}
		},
	}
	for name, prepare := range remake {
		t.Run(name, func(t *testing.T) {
			for i := 0; i < 10; i++ {
				f := newFixture(t)
				db := mustOpen(t, f.root, "events.db")
				cancelQuery(t, db)
				remade := prepare(t, f)
				removeDatabase(t, filepath.Join(f.state, "events.db"))
				remade()
				err := db.QueryRow("SELECT 1").Scan(new(int))
				db.Close()
				wantRule(t, err, "events.db", ruleChanged)
			}
		})
	}
}

// holdHook makes onHeld save the descriptor that Open holds, until the end of
// the test. At the end, it closes the descriptor, so that a t.Fatal in a hook
// does not keep it open.
func holdHook(t *testing.T) **os.File {
	t.Helper()
	var held *os.File
	setHook(t, &onHeld, func(f *os.File) { held = f })
	t.Cleanup(func() {
		if held != nil {
			held.Close()
		}
	})
	return &held
}

// isClosed reports whether the descriptor is closed.
func isClosed(f *os.File) bool {
	_, err := f.Stat()
	return errors.Is(err, os.ErrClosed)
}

// T-S-15: the pool holds the database file open, for an existing file and for a
// new one, and the close of the pool closes the descriptor.
func TestTS15PoolCloseClosesHeldDescriptor(t *testing.T) {
	for _, name := range []string{"existing file", "new file"} {
		t.Run(name, func(t *testing.T) {
			held := holdHook(t)
			var root *os.Root
			if name == "new file" {
				root, _, _ = newState(t)
			} else {
				root = newFixture(t).root
			}
			db := mustOpen(t, root, "events.db")
			if *held == nil || isClosed(*held) {
				t.Fatal("Open does not hold the database file open")
			}
			cancelQuery(t, db) // the pool drops its connection, not the descriptor
			if isClosed(*held) {
				t.Fatal("the descriptor was closed with the connection")
			}
			db.Close()
			if !isClosed(*held) {
				t.Fatal("the close of the pool left the descriptor open")
			}
		})
	}
}

// T-S-15: a refused Open leaves no descriptor open, in the second checks and in
// the failure of the identity check.
func TestTS15RefusedOpenClosesDescriptor(t *testing.T) {
	t.Run("second checks", func(t *testing.T) {
		held := holdHook(t)
		swapAfterVerify(t, ruleChanged, func(f *fixture) {
			replaceFile(t, filepath.Join(f.state, "events.db"))
		})
		if *held == nil || !isClosed(*held) {
			t.Fatal("the refused Open left the descriptor open")
		}
	})
	t.Run("connection refused", func(t *testing.T) {
		held := holdHook(t)
		f := newFixture(t)
		setHook(t, &afterChecks, func() { replaceFile(t, filepath.Join(f.state, "events.db")) })
		_, err := Open(f.root, "events.db", Options{})
		wantRule(t, err, "events.db", ruleChanged)
		if *held == nil || !isClosed(*held) {
			t.Fatal("the refused Open left the descriptor open")
		}
	})
}

// T-S-15: a clean file that is renamed over the database after the file checks
// and before Open opens it is refused, and the file outside does not change.
func TestTS15RenameInsideOpenIsRefused(t *testing.T) {
	f := newFixture(t)
	held := holdHook(t)
	clean := cleanDatabase(t)
	before := snapshot(t, f.outside)
	renamed := false
	// The hook runs at the start of the checked open, after the file checks.
	// The checked open sees the new file only, so the compare of the identity
	// with the checked file finds the change.
	safefiletest.Set(t, safefiletest.Hooks{BeforeCheck: func(name string) {
		if name == "events.db" && !renamed {
			renamed = true
			if err := os.Rename(clean, filepath.Join(f.state, "events.db")); err != nil {
				t.Error(err)
			}
		}
	}})
	db, err := Open(f.root, "events.db", Options{})
	if db != nil {
		db.Close()
	}
	wantRule(t, err, "events.db", ruleChanged)
	if !renamed || snapshot(t, f.outside) != before {
		t.Fatalf("renamed %v; outside changed: %v", renamed, snapshot(t, f.outside) != before)
	}
	if *held != nil && !isClosed(*held) {
		t.Fatal("the refused Open left the descriptor open")
	}
}

// fdsOf counts the descriptors of the process that point to path. It needs Linux.
func fdsOf(t *testing.T, path string) int {
	t.Helper()
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range ents {
		if to, err := os.Readlink("/proc/self/fd/" + e.Name()); err == nil && to == path {
			n++
		}
	}
	return n
}

// T-S-15: the checks of a connection open no descriptor of the database file.
// The close of any such descriptor would drop the locks of SQLite. The count of
// descriptors that point to the file is the same before and after the checks,
// and no check opens the file, also for a file below a parent directory.
func TestTS15ChecksOpenNoDescriptorOfDatabase(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the test reads /proc/self/fd")
	}
	for _, rel := range []string{"events.db", "data/events.db"} {
		t.Run(rel, func(t *testing.T) {
			f := newFixture(t)
			if err := os.Mkdir(filepath.Join(f.state, "data"), 0o700); err != nil {
				t.Fatal(err)
			}
			held := holdHook(t)
			db := mustOpen(t, f.root, rel)
			defer db.Close()
			fi, err := (*held).Stat()
			if err != nil {
				t.Fatal(err)
			}
			id, _ := safefile.Identity(fi)
			path := filepath.Join(f.state, filepath.FromSlash(rel))
			c := &connector{root: f.root, rel: rel, want: path, id: id, held: *held}
			safefiletest.Set(t, safefiletest.Hooks{AfterCheck: func(name string) {
				if name == "events.db" {
					t.Error("a check opened the database file")
				}
			}})
			before := fdsOf(t, path)
			if err := c.check(); err != nil {
				t.Fatal(err)
			}
			if after := fdsOf(t, path); before == 0 || after != before {
				t.Fatalf("%d descriptors of the database file before the checks, %d after", before, after)
			}
		})
	}
}

// T-S-15: a parent directory that gets group bits after the file checks is
// refused on the first connection, and the error names the directory.
func TestTS15ParentChangeNamesTheDirectory(t *testing.T) {
	root, state, _ := newState(t)
	data := filepath.Join(state, "data")
	if err := os.Mkdir(data, 0o700); err != nil {
		t.Fatal(err)
	}
	setHook(t, &afterChecks, func() {
		if err := os.Chmod(data, 0o755); err != nil {
			t.Fatal(err)
		}
	})
	db, err := Open(root, "data/events.db", Options{})
	if db != nil {
		db.Close()
	}
	wantRule(t, err, "data", ruleMode)
}
