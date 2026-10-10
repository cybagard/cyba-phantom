//go:build unix

package store

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// T-S-15: a new database file has mode 0600, and so have the WAL and SHM files
// that SQLite makes from it. After the open, SQLite reports the expected path.
func TestTS15NewFileHasMode0600(t *testing.T) {
	root, state, _ := newState(t)
	if err := os.Mkdir(filepath.Join(state, "data"), 0o700); err != nil {
		t.Fatal(err)
	}
	db := mustOpen(t, root, "data/events.db")
	defer db.Close()
	if _, err := db.Exec("CREATE TABLE t (x)"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO t VALUES (1)"); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		fi, err := os.Lstat(filepath.Join(state, "data", "events.db"+suffix))
		if err != nil || fi.Mode() != 0o600 {
			t.Errorf("events.db%s: %v, %v", suffix, fi, err)
		}
	}
	file, rule := mainFile(t.Context(), db)
	if want := filepath.Join(state, "data", "events.db"); rule != "" || file != want {
		t.Fatalf("database_list gives %q, want %q (%s)", file, want, rule)
	}
}

// T-S-15: a symlink in a parent directory that appears after the file checks
// changes the path that SQLite opens. Open finds it with database_list, closes
// the database, and returns an error.
func TestTS15ChangedPathAfterChecksIsRefused(t *testing.T) {
	root, state, _ := newState(t)
	if err := os.Mkdir(filepath.Join(state, "data"), 0o700); err != nil {
		t.Fatal(err)
	}
	afterChecks = func() {
		os.Rename(filepath.Join(state, "data"), filepath.Join(state, "data.real"))
		os.Symlink("data.real", filepath.Join(state, "data"))
	}
	defer func() { afterChecks = nil }()
	db, err := Open(root, "data/events.db", Options{})
	if db != nil {
		db.Close()
	}
	wantRule(t, err, "data/events.db", ruleLocation)
	// The refused open leaves no new database file.
	if _, err := os.Lstat(filepath.Join(state, "data.real", "events.db")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the file that Open made stays: %v", err)
	}
}

// fixture makes a state directory with a good database, closed again, and an
// outside file with a fixed old mtime.
type fixture struct {
	root           *os.Root
	state, outside string
	target         string // the outside file
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	root, state, outside := newState(t)
	db := mustOpen(t, root, "events.db")
	if _, err := db.Exec("CREATE TABLE t (x)"); err != nil {
		t.Fatal(err)
	}
	db.Close()
	target := filepath.Join(outside, "target")
	if err := os.WriteFile(target, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(target, old, old); err != nil {
		t.Fatal(err)
	}
	return &fixture{root, state, outside, target}
}

// refused runs Open for rel and checks that it fails with the rule for name, and
// that no file in the state directory or outside it changed (content, mode and
// mtime).
func (f *fixture) refused(t *testing.T, rel, name, rule string) {
	t.Helper()
	before := snapshot(t, f.state) + snapshot(t, f.outside)
	db, err := Open(f.root, rel, Options{})
	if db != nil {
		db.Close()
	}
	wantRule(t, err, name, rule)
	if snapshot(t, f.state)+snapshot(t, f.outside) != before {
		t.Fatal("a refused open changed a file")
	}
}

// T-S-15: a symlink in place of the database, WAL, SHM or journal file is
// refused, and the file that it points to is not changed.
func TestTS15SymlinkInPlaceOfFileIsRefused(t *testing.T) {
	for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		t.Run("events.db"+suffix, func(t *testing.T) {
			f := newFixture(t)
			link := filepath.Join(f.state, "events.db"+suffix)
			os.Remove(link)
			if err := os.Symlink(f.target, link); err != nil {
				t.Fatal(err)
			}
			f.refused(t, "events.db", "events.db"+suffix, ruleType)
		})
	}
}

// T-S-15: a symlink in place of a parent directory is refused, and the
// directory that it points to is not changed.
func TestTS15SymlinkInPlaceOfParentIsRefused(t *testing.T) {
	f := newFixture(t)
	if err := os.Symlink(f.outside, filepath.Join(f.state, "data")); err != nil {
		t.Fatal(err)
	}
	f.refused(t, "data/events.db", "data", ruleParent)
	if err := os.Mkdir(filepath.Join(f.state, "real"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real", filepath.Join(f.state, "sub")); err != nil {
		t.Fatal(err)
	}
	f.refused(t, "sub/events.db", "sub", ruleParent)
}

// T-S-15: a file with a second hard link, with group or other bits, or that is
// not a regular file, is refused, and nothing changes.
func TestTS15UnsafeFileIsRefused(t *testing.T) {
	for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		name := "events.db" + suffix
		t.Run("hard link "+name, func(t *testing.T) {
			f := newFixture(t)
			path := filepath.Join(f.state, name)
			if suffix != "" {
				if err := os.WriteFile(path, nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Link(path, filepath.Join(f.outside, "copy")); err != nil {
				t.Fatal(err)
			}
			f.refused(t, "events.db", name, ruleLinks)
		})
		for _, mode := range []os.FileMode{0o640, 0o604, 0o666} {
			t.Run(name+" mode "+mode.String(), func(t *testing.T) {
				f := newFixture(t)
				path := filepath.Join(f.state, name)
				if suffix != "" {
					if err := os.WriteFile(path, nil, 0o600); err != nil {
						t.Fatal(err)
					}
				}
				if err := os.Chmod(path, mode); err != nil {
					t.Fatal(err)
				}
				f.refused(t, "events.db", name, ruleMode)
			})
		}
		t.Run("fifo "+name, func(t *testing.T) {
			f := newFixture(t)
			path := filepath.Join(f.state, name)
			os.Remove(path)
			if err := syscall.Mkfifo(path, 0o600); err != nil {
				t.Fatal(err)
			}
			f.refused(t, "events.db", name, ruleType)
		})
	}
	t.Run("directory", func(t *testing.T) {
		f := newFixture(t)
		path := filepath.Join(f.state, "events.db")
		os.Remove(path)
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		f.refused(t, "events.db", "events.db", ruleType)
	})
}

// T-S-15: a file with another owner is refused. The hook makes the effective
// user differ from the owner, so the rule has a test that does not need root.
func TestTS15OtherOwnerIsRefusedByHook(t *testing.T) {
	f := newFixture(t)
	geteuid = func() int { return os.Geteuid() + 1 }
	defer func() { geteuid = os.Geteuid }()
	f.refused(t, "events.db", "events.db", ruleOwner)
}

// T-S-15: a file that another user owns is refused. The test needs root to
// change the owner, so it skips when the process does not run as root.
func TestTS15OtherOwnerIsRefused(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("changing the owner of a file needs root")
	}
	f := newFixture(t)
	if err := os.Chown(filepath.Join(f.state, "events.db"), 12345, -1); err != nil {
		t.Fatal(err)
	}
	f.refused(t, "events.db", "events.db", ruleOwner)
}
