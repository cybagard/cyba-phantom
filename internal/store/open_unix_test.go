//go:build unix

package store

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/cybagard/cyba-phantom/internal/safefile"
	"github.com/cybagard/cyba-phantom/internal/safefile/safefiletest"
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
	var seq int
	var name, file string
	if err := db.QueryRow("PRAGMA database_list").Scan(&seq, &name, &file); err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(state, "data", "events.db"); name != "main" || file != want {
		t.Fatalf("database_list gives %q %q, want main %q", name, file, want)
	}
}

// T-S-15: the descriptor that Open holds for a new file is read-only. A write
// through it fails.
func TestTS15HeldDescriptorOfNewFileIsReadOnly(t *testing.T) {
	root, _, _ := newState(t)
	held := holdHook(t)
	db := mustOpen(t, root, "events.db")
	defer db.Close()
	if *held == nil {
		t.Fatal("the hook got no descriptor")
	}
	if _, err := (*held).Write([]byte("x")); err == nil {
		t.Fatal("a write through the held descriptor of a new file worked")
	}
}

// swapMadeFile sets the hook of the second open of a new file. The hook moves
// the made file to file+".moved" and writes another file with mode 0600.
func swapMadeFile(t *testing.T, file string) {
	t.Helper()
	safefiletest.Set(t, safefiletest.Hooks{BeforeCheck: func(name string) {
		if name != "events.db" {
			return
		}
		if err := os.Rename(file, file+".moved"); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, []byte("other file"), 0o600); err != nil {
			t.Fatal(err)
		}
	}})
}

// T-S-15: Open refuses a new file if another file gets the name before the
// second open. The hook runs after Open makes the file. It moves the made file
// away and writes another file with mode 0600.
func TestTS15OtherFileBetweenCreateAndReopenIsRefused(t *testing.T) {
	root, state, _ := newState(t)
	swapMadeFile(t, filepath.Join(state, "events.db"))
	db, err := Open(root, "events.db", Options{})
	if db != nil {
		db.Close()
	}
	wantRule(t, err, "events.db", ruleChanged)
}

// T-S-15: Open refuses a new file if the second open refuses it. The hook
// changes the mode of the made file to 0644 before the second open. Open fails
// with the changed rule, and refuse removes the made file.
func TestTS15RefusedReopenRemovesMadeFile(t *testing.T) {
	root, state, _ := newState(t)
	file := filepath.Join(state, "events.db")
	safefiletest.Set(t, safefiletest.Hooks{BeforeCheck: func(name string) {
		if name != "events.db" {
			return
		}
		if err := os.Chmod(file, 0o644); err != nil {
			t.Fatal(err)
		}
	}})
	db, err := Open(root, "events.db", Options{})
	if db != nil {
		db.Close()
	}
	wantRule(t, err, "events.db", ruleChanged)
	if _, err := os.Lstat(file); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the made file stays at the name: %v", err)
	}
}

// T-S-15: Open makes a new file only if no entry has the name. The hook writes
// a file with mode 0600 after Open found no entry. Open fails with the changed
// rule, and the file stays with its content.
func TestTS15FileMadeBeforeCreateIsRefusedAndKept(t *testing.T) {
	root, state, _ := newState(t)
	file := filepath.Join(state, "events.db")
	const content = "other file"
	setHook(t, &beforeCreate, func() {
		if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	})
	db, err := Open(root, "events.db", Options{})
	if db != nil {
		db.Close()
	}
	wantRule(t, err, "events.db", ruleChanged)
	if b, err := os.ReadFile(file); err != nil || string(b) != content {
		t.Fatalf("the file is gone or changed: %q, %v", b, err)
	}
}

// T-S-15: the new database file is made in the directory that Open checked. The
// hook swaps the parent directory after Open opened it and before Open makes
// the file. So the path that SQLite opens leads to another file. Open fails.
func TestTS15NewFileIsMadeInCheckedParent(t *testing.T) {
	root, state, _ := newState(t)
	data := filepath.Join(state, "data")
	if err := os.Mkdir(data, 0o700); err != nil {
		t.Fatal(err)
	}
	setHook(t, &beforeCreate, func() {
		if err := os.Rename(data, data+".moved"); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(data, 0o700); err != nil {
			t.Fatal(err)
		}
	})
	// The hook runs in the second open, after Open makes the file and before
	// the Lstat of the second open. Then the file is in the moved directory,
	// and the path under data has no file.
	var ran, inMoved bool
	safefiletest.Set(t, safefiletest.Hooks{BeforeCheck: func(name string) {
		if name != "events.db" {
			return
		}
		_, moved := os.Lstat(filepath.Join(data+".moved", "events.db"))
		_, inData := os.Lstat(filepath.Join(data, "events.db"))
		ran = true
		inMoved = moved == nil && errors.Is(inData, fs.ErrNotExist)
	}})
	db, err := Open(root, "data/events.db", Options{})
	if db != nil {
		db.Close()
	}
	if err == nil {
		t.Fatal("Open worked with a swapped parent directory")
	}
	if !ran {
		t.Fatal("the hook of the reopen did not run")
	}
	if !inMoved {
		t.Fatal("the new file is not in the moved directory, or data/events.db exists")
	}
	// refuse removes the made file through the checked directory.
	if _, err := os.Lstat(filepath.Join(data+".moved", "events.db")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the made file is still in the moved directory: %v", err)
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
	setHook(t, &afterChecks, func() {
		if err := os.Rename(filepath.Join(state, "data"), filepath.Join(state, "data.real")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("data.real", filepath.Join(state, "data")); err != nil {
			t.Fatal(err)
		}
	})
	db, err := Open(root, "data/events.db", Options{})
	if db != nil {
		db.Close()
	}
	wantRule(t, err, "data/events.db", ruleLocation)
	// The refused open leaves no new database file, and no WAL or SHM file.
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if _, err := os.Lstat(filepath.Join(state, "data.real", "events.db"+suffix)); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("events.db%s of the refused open stays: %v", suffix, err)
		}
	}
}

// T-S-15: a refused open of a new file does not remove another file with the
// same name. The hook puts a different clean file in place of the new file.
// That file stays, and the refused open leaves no WAL or SHM file.
func TestTS15RefusedOpenKeepsOtherFileWithSameName(t *testing.T) {
	root, state, _ := newState(t)
	file := filepath.Join(state, "events.db")
	clean := cleanDatabase(t)
	other, err := os.Lstat(clean)
	if err != nil {
		t.Fatal(err)
	}
	setHook(t, &afterChecks, func() {
		if err := os.Rename(clean, file); err != nil {
			t.Fatal(err)
		}
	})
	db, err := Open(root, "events.db", Options{})
	if db != nil {
		db.Close()
	}
	wantRule(t, err, "events.db", ruleChanged)
	if fi, err := os.Lstat(file); err != nil || !os.SameFile(fi, other) {
		t.Fatalf("the other file with the same name is gone: %v", err)
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		if _, err := os.Lstat(file + suffix); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("events.db%s of the refused open stays: %v", suffix, err)
		}
	}
}

// T-S-15: a refused open of a new file calls refuse before it closes the
// held descriptor or the pool. The hook removes the file that Open made. Then
// it puts the hook's file at the path. While Open holds the descriptor, the
// hook's file cannot get the inode of the file that Open made. So refuse keeps
// the hook's file. The rows fail Open at the first connection and at the
// second checks. A row also fails Open when it makes the connector.
func TestTS15RefuseRunsBeforeCloseOfDescriptor(t *testing.T) {
	rows := []struct {
		name, rule string
		fail       func(t *testing.T, file string)
	}{
		{"connector", ruleOpen, func(t *testing.T, file string) {
			setHook(t, &editDSN, func(s string) string { return s + "&_pragma=%zz" })
		}},
		{"first connection", ruleMode, func(t *testing.T, file string) {
			setHook(t, &afterChecks, func() {
				if err := os.Chmod(file, 0o640); err != nil {
					t.Fatal(err)
				}
			})
		}},
		{"second checks", ruleChanged, func(t *testing.T, file string) {
			setHook(t, &afterVerify, func() { replaceFile(t, file) })
		}},
	}
	const content = "other file"
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			root, state, _ := newState(t)
			file := filepath.Join(state, "events.db")
			r.fail(t, file)
			ran := 0
			setHook(t, &beforeRefuse, func() {
				ran++
				if err := os.Remove(file); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
					t.Fatal(err)
				}
			})
			db, err := Open(root, "events.db", Options{})
			if db != nil {
				db.Close()
			}
			wantRule(t, err, "events.db", r.rule)
			if ran != 1 {
				t.Fatalf("refuse ran %d times, want 1", ran)
			}
			if b, err := os.ReadFile(file); err != nil || string(b) != content {
				t.Fatalf("the hook's file is gone or changed: %q, %v", b, err)
			}
		})
	}
}

// failStatOnce makes the first Stat of the create descriptor fail.
func failStatOnce(t *testing.T) {
	failed := false
	setHook(t, &afterStatCreated, func(fi fs.FileInfo, err error) (fs.FileInfo, error) {
		if !failed {
			failed, fi, err = true, nil, errors.New("stat failed")
		}
		return fi, err
	})
}

// openFails runs Open with the hooks that a test set. The test fails if the
// error does not have the rule.
func openFails(t *testing.T, root *os.Root, rule string) {
	t.Helper()
	db, err := Open(root, "events.db", Options{})
	if db != nil {
		db.Close()
	}
	wantRule(t, err, "events.db", rule)
}

// T-S-15: a failure after Open makes the file removes the file. No -wal or -shm
// file of the refused open stays.
func TestTS15FailureAfterCreateRemovesMadeFile(t *testing.T) {
	rows := []struct {
		name, rule string
		fail       func(t *testing.T, file string)
	}{
		{"held stat", ruleExamine, func(t *testing.T, file string) {
			setHook(t, &onHeld, func(f *os.File) { f.Close() })
		}},
		{"create stat once", ruleExamine, func(t *testing.T, file string) {
			failStatOnce(t)
		}},
		{"connector", ruleOpen, func(t *testing.T, file string) {
			setHook(t, &editDSN, func(s string) string { return s + "&_pragma=%zz" })
		}},
		{"first connection", ruleMode, func(t *testing.T, file string) {
			setHook(t, &afterChecks, func() {
				if err := os.Chmod(file, 0o640); err != nil {
					t.Fatal(err)
				}
			})
		}},
		{"second checks", ruleMode, func(t *testing.T, file string) {
			setHook(t, &afterVerify, func() {
				if err := os.Chmod(file, 0o640); err != nil {
					t.Fatal(err)
				}
			})
		}},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			root, state, _ := newState(t)
			file := filepath.Join(state, "events.db")
			r.fail(t, file)
			openFails(t, root, r.rule)
			for _, suffix := range []string{"", "-wal", "-shm"} {
				if _, err := os.Lstat(file + suffix); !errors.Is(err, fs.ErrNotExist) {
					t.Fatalf("events.db%s stays: %v", suffix, err)
				}
			}
		})
	}
}

// T-S-15: if no Stat of the made file works, Open cannot prove that the entry
// is its file. A refused open keeps the entry.
func TestTS15UnprovenMadeFileStays(t *testing.T) {
	root, state, _ := newState(t)
	file := filepath.Join(state, "events.db")
	setHook(t, &afterStatCreated, func(fs.FileInfo, error) (fs.FileInfo, error) {
		return nil, errors.New("stat failed")
	})
	openFails(t, root, ruleExamine)
	if fi, err := os.Lstat(file); err != nil || !fi.Mode().IsRegular() {
		t.Fatalf("the entry is gone: %v", err)
	}
}

// T-S-15: a refused open keeps a file that was there before Open: an old
// good database or an empty file. Each row fails the held Stat or the
// connector. Each file keeps its content and identity.
func TestTS15ExistingFileStaysOnFailure(t *testing.T) {
	setups := map[string]func(t *testing.T, root *os.Root, file string){
		"good database": func(t *testing.T, root *os.Root, file string) {
			db := mustOpen(t, root, "events.db")
			if _, err := db.Exec("CREATE TABLE t (x)"); err != nil {
				t.Fatal(err)
			}
			db.Close()
		},
		"empty file": func(t *testing.T, root *os.Root, file string) {
			if err := os.WriteFile(file, nil, 0o600); err != nil {
				t.Fatal(err)
			}
		},
	}
	fails := map[string]struct {
		rule string
		set  func(t *testing.T)
	}{
		"held stat": {ruleExamine, func(t *testing.T) {
			setHook(t, &onHeld, func(f *os.File) { f.Close() })
		}},
		"connector": {ruleOpen, func(t *testing.T) {
			setHook(t, &editDSN, func(s string) string { return s + "&_pragma=%zz" })
		}},
	}
	for sn, setup := range setups {
		for fn, f := range fails {
			t.Run(sn+"/"+fn, func(t *testing.T) {
				root, state, _ := newState(t)
				file := filepath.Join(state, "events.db")
				setup(t, root, file)
				before, err := os.Lstat(file)
				if err != nil {
					t.Fatal(err)
				}
				want, err := os.ReadFile(file)
				if err != nil {
					t.Fatal(err)
				}
				f.set(t)
				openFails(t, root, f.rule)
				after, err := os.Lstat(file)
				if err != nil || !os.SameFile(before, after) {
					t.Fatalf("the file is gone or replaced: %v", err)
				}
				if got, err := os.ReadFile(file); err != nil || string(got) != string(want) {
					t.Fatalf("the content changed: %v", err)
				}
			})
		}
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
		for _, mode := range []os.FileMode{0o640, 0o604, 0o666,
			0o600 | os.ModeSetuid, 0o600 | os.ModeSetgid, 0o600 | os.ModeSticky} {
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

// otherOwnerOf sets the test hook of the shared file checks. The file or
// directory at one path then has another owner. The hook is true for the inode
// of that path only. The returned function moves the hook to another path.
func otherOwnerOf(t *testing.T) func(path string) {
	t.Helper()
	var target atomic.Pointer[safefile.FileID]
	safefiletest.Set(t, safefiletest.Hooks{OtherOwner: func(id safefile.FileID) bool {
		want := target.Load()
		return want != nil && *want == id
	}})
	return func(path string) {
		t.Helper()
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		id, ok := safefile.Identity(fi)
		if !ok {
			t.Fatal("no identity")
		}
		target.Store(&id)
	}
}

// T-S-15: a file with another owner is refused. The hook makes the owner of one
// inode differ from the effective user. So the rule has a test that does not
// need root. The other inodes keep their owner.
func TestTS15OtherOwnerIsRefusedByHook(t *testing.T) {
	f := newFixture(t)
	other := otherOwnerOf(t)
	other(filepath.Join(f.state, "events.db"))
	f.refused(t, "events.db", "events.db", ruleOwner)
	// The same hook for a parent directory and for the state directory.
	if err := os.Mkdir(filepath.Join(f.state, "data"), 0o700); err != nil {
		t.Fatal(err)
	}
	other(filepath.Join(f.state, "data"))
	f.refused(t, "data/events.db", "data", ruleOwner)
	other(f.state)
	f.refused(t, "events.db", "state directory", ruleOwner)
}

// T-S-15: a FIFO is refused when someone puts it in place of the database file.
// This is after the file checks and before the open. Open returns. An open that
// can block would wait for a writer of the FIFO. The FIFO comes after the Lstat
// of the file check, or after the Lstat of the checked open.
func TestTS15FifoAfterChecksIsRefused(t *testing.T) {
	for _, when := range []string{"after the file check", "after the Lstat of the open"} {
		t.Run(when, func(t *testing.T) {
			f := newFixture(t)
			file := filepath.Join(f.state, "events.db")
			fi, err := os.Stat(file)
			if err != nil {
				t.Fatal(err)
			}
			dbID, _ := safefile.Identity(fi)
			var once sync.Once
			swap := func() {
				once.Do(func() {
					if err := os.Remove(file); err != nil {
						t.Error(err)
					}
					if err := syscall.Mkfifo(file, 0o600); err != nil {
						t.Error(err)
					}
				})
			}
			h := safefiletest.Hooks{OtherOwner: func(id safefile.FileID) bool {
				if id == dbID {
					swap() // the Lstat of the file check is done
				}
				return false
			}}
			if strings.HasSuffix(when, "open") {
				h = safefiletest.Hooks{AfterCheck: func(name string) {
					if name == "events.db" {
						swap()
					}
				}}
			}
			safefiletest.Set(t, h)
			done := make(chan error, 1)
			go func() {
				db, err := Open(f.root, "events.db", Options{})
				if db != nil {
					db.Close()
				}
				done <- err
			}()
			select {
			case err := <-done:
				wantRule(t, err, "events.db", ruleChanged)
			case <-time.After(5 * time.Second):
				// Open a writer, so that the blocked open ends.
				if w, err := os.OpenFile(file, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
					w.Close()
				}
				t.Fatal("Open does not return for a FIFO at the database path")
			}
		})
	}
}

// T-S-15: Open refuses a state directory or parent directory with group or
// other bits. It also refuses one with a setuid, setgid or sticky bit. Nothing
// changes.
func TestTS15UnsafeDirectoryIsRefused(t *testing.T) {
	for _, mode := range []os.FileMode{0o777, 0o750, 0o705, os.ModeSetgid | 0o700, os.ModeSticky | 0o700} {
		t.Run("parent "+strconv.FormatUint(uint64(mode), 8), func(t *testing.T) {
			f := newFixture(t)
			dir := filepath.Join(f.state, "data")
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(dir, mode); err != nil {
				t.Fatal(err)
			}
			f.refused(t, "data/events.db", "data", ruleMode)
		})
		t.Run("state "+strconv.FormatUint(uint64(mode), 8), func(t *testing.T) {
			f := newFixture(t)
			if err := os.Chmod(f.state, mode); err != nil {
				t.Fatal(err)
			}
			defer os.Chmod(f.state, 0o700)
			f.refused(t, "events.db", "state directory", ruleMode)
		})
	}
}

// T-S-15: a file that another user owns is refused. The test needs root to
// change the owner, so it skips when the process does not run as root.
func TestTS15OtherOwnerIsRefused(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("the test must run as root to change the owner of a file")
	}
	f := newFixture(t)
	if err := os.Chown(filepath.Join(f.state, "events.db"), 12345, -1); err != nil {
		t.Fatal(err)
	}
	f.refused(t, "events.db", "events.db", ruleOwner)
}
