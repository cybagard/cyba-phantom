//go:build unix

package store

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"sync/atomic"
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

// T-S-15: a symlink, or a file that was renamed away, in place of the database
// file when the pool makes a new connection: the connection is refused with a
// fixed error, and the file that the link points to is not changed.
func TestTS15ReconnectChecksTheFiles(t *testing.T) {
	for _, mode := range []string{"symlink", "renamed"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			db := mustOpen(t, f.root, "events.db")
			defer db.Close()
			n := countConnects(t)
			cancelQuery(t, db)
			file := filepath.Join(f.state, "events.db")
			if err := os.Rename(file, file+".moved"); err != nil {
				t.Fatal(err)
			}
			rule := ruleChanged
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
	for _, bad := range []bool{false, true} {
		name := map[bool]string{false: "no change", true: "file renamed"}[bad]
		t.Run(name, func(t *testing.T) {
			r := newRig(t, 100)
			stop := r.start()
			r.add(event.KindRequest, 1)
			r.drained()
			r.fire()
			r.commit()

			n := countConnects(t)
			cancelQuery(t, r.db)
			if bad {
				file := filepath.Join(r.state, "events.db")
				if err := os.Rename(file, file+".moved"); err != nil {
					t.Fatal(err)
				}
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
	if b, err := os.ReadFile(f.target); err != nil || string(b) != "outside" {
		t.Fatalf("the file outside changed: %q, %v", b, err)
	}
	if b, err := os.ReadFile(filepath.Join(f.outside, "copy")); err == nil && string(b) != string(data) {
		t.Fatal("the hard link target changed")
	}
}

// T-S-15: a swap that is put in place after the open of SQLite is found by the
// second checks: a rename that puts a symlink in place of the file, and a new hard
// link to the file.
func TestTS15SwapAfterOpenIsRefused(t *testing.T) {
	t.Run("rename", func(t *testing.T) {
		swapAfterVerify(t, ruleType, func(f *fixture) {
			file := filepath.Join(f.state, "events.db")
			os.Rename(file, file+".moved")
			os.Symlink(f.target, file)
		})
	})
	t.Run("hard link", func(t *testing.T) {
		swapAfterVerify(t, ruleLinks, func(f *fixture) {
			os.Link(filepath.Join(f.state, "events.db"), filepath.Join(f.outside, "copy"))
		})
	})
}
