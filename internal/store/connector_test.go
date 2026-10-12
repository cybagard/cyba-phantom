//go:build unix

package store

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/cybagard/cyba-phantom/internal/event"
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
	a, b, c, d := onConnect, afterChecks, afterVerify, beforeDriverOpen
	onConnect, afterChecks, afterVerify, beforeDriverOpen = nil, nil, nil, nil
	return func() { onConnect, afterChecks, afterVerify, beforeDriverOpen = a, b, c, d }
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

// T-S-15: a symlink, a file that was renamed away, a different clean file, or a
// different state directory in place of the database file when the pool makes a
// new connection: the connection is refused with a fixed error, and the file
// that the link points to is not changed.
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
	for _, name := range []string{"no change", "file renamed", "other file renamed over", "state directory swapped"} {
		bad := name != "no change"
		t.Run(name, func(t *testing.T) {
			r := newRig(t, 100)
			stop := r.start()
			r.add(event.KindRequest, 1)
			r.drained()
			r.fire()
			r.commit()

			n := countConnects(t)
			cancelQuery(t, r.db)
			file := filepath.Join(r.state, "events.db")
			switch name {
			case "file renamed":
				if err := os.Rename(file, file+".moved"); err != nil {
					t.Fatal(err)
				}
			case "other file renamed over":
				replaceFile(t, file)
			case "state directory swapped":
				swapStateDir(t, r.state)
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
			if r.w.Healthy() == bad || n.Load() != 1 {
				t.Fatalf("healthy %v, %d Connect calls", r.w.Healthy(), n.Load())
			}
		})
	}
}

// swapAfterVerify makes Open run swap between the open of SQLite and the second
// checks. It checks that Open refuses with the rule for events.db, that the file
// outside does not change, and that the database file is not removed.
// Open keeps the file, because the fixture made it before the call.
func swapAfterVerify(t *testing.T, rule string, swap func(f *fixture)) {
	f := newFixture(t)
	data, err := os.ReadFile(filepath.Join(f.state, "events.db"))
	if err != nil {
		t.Fatal(err)
	}
	afterVerify = func() { swap(f) }
	defer func() { afterVerify = nil }()
	db, err := Open(f.root, "events.db", Options{})
	if db != nil {
		db.Close()
	}
	wantRule(t, err, "events.db", rule)
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

// T-S-15: a swap that is put in place after the open of SQLite is found by the
// second checks: a rename that puts a symlink in place of the file, a rename
// that puts a different clean file in place, and a new hard link to the file.
func TestTS15SwapAfterOpenIsRefused(t *testing.T) {
	t.Run("symlink put in place by rename", func(t *testing.T) {
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
	beforeDriverOpen = change
	defer func() { beforeDriverOpen = nil }()
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
		// A kept link holds the old inode, so that the new file cannot reuse it.
		err := changeBeforeDriverOpen(t, f, "events.db", func() {
			os.Link(file, file+".kept")
			os.Remove(file)
		})
		wantRule(t, err, "events.db", ruleChanged)
	})
}
