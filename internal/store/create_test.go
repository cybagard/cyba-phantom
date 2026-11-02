//go:build unix

package store

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/cybagard/cyba-phantom/internal/safefile/safefiletest"
)

const (
	killCreate = "create" // after the create, before the first write
	killWrite  = "write"  // after the first write, before the rename
)

// T-S-15: this is the helper process of the kill tests. It opens a new
// database and stops itself with a panic at the kill point from the
// environment. Without the role variable, it skips.
func TestTS15CreateHelper(t *testing.T) {
	if os.Getenv(crashRoleEnv) != crashRoleHelp {
		t.Skip("helper process of TestTS15KilledStartLeavesNoFileAtRealName")
	}
	root, err := os.OpenRoot(os.Getenv(crashStateEnv))
	if err != nil {
		t.Fatal(err)
	}
	stop := func() { panic(crashMessage) }
	switch os.Getenv(crashPointEnv) {
	case killCreate:
		afterChecks = stop
	case killWrite:
		beforeRename = stop
	default:
		t.Fatal("unknown kill point")
	}
	Open(root, "events.db", Options{})
	t.Fatal("the helper process did not stop")
}

// T-S-15: a start that stops after the create, or after the first write, leaves
// no file at the real name. The next Open removes the leftover file and makes a
// new database that Migrate accepts.
func TestTS15KilledStartLeavesNoFileAtRealName(t *testing.T) {
	for _, c := range []struct {
		name, point string
		written     bool // the leftover file has the first write
	}{
		{"after the create", killCreate, false},
		{"after the first write", killWrite, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			state := filepath.Join(t.TempDir(), "state")
			if err := os.Mkdir(state, 0o700); err != nil {
				t.Fatal(err)
			}
			cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestTS15CreateHelper$")
			cmd.Env = append(os.Environ(), crashRoleEnv+"="+crashRoleHelp, crashPointEnv+"="+c.point, crashStateEnv+"="+state)
			out, err := cmd.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || !bytes.Contains(out, []byte("panic: "+crashMessage)) {
				t.Fatalf("helper error %v, output:\n%s", err, out)
			}
			file := filepath.Join(state, "events.db")
			if _, err := os.Lstat(file); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("a file is at the real name: %v", err)
			}
			if fi, err := os.Lstat(file + tempSuffix); err != nil || (fi.Size() > 0) != c.written {
				t.Fatalf("leftover file: %v, %v; want written %v", fi, err, c.written)
			}
			root, err := os.OpenRoot(state)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			db := mustOpen(t, root, "events.db")
			defer db.Close()
			if err := Migrate(db, "origin"); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Lstat(file + tempSuffix); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("the leftover file stays: %v", err)
			}
		})
	}
}

// T-S-15: a new database leaves no file with the temporary name, and no -wal or
// -shm file of it. It has auto_vacuum incremental and a first write.
func TestTS15NewDatabaseLeavesNoTemporaryFiles(t *testing.T) {
	root, state, _ := newState(t)
	db := mustOpen(t, root, "events.db")
	defer db.Close()
	for _, s := range suffixes {
		if _, err := os.Lstat(filepath.Join(state, "events.db"+tempSuffix+s)); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("events.db%s%s stays: %v", tempSuffix, s, err)
		}
	}
	var vacuum int
	if err := db.QueryRow("PRAGMA auto_vacuum").Scan(&vacuum); err != nil || vacuum != 2 {
		t.Fatalf("auto_vacuum %d, %v; want 2", vacuum, err)
	}
	if fi, err := os.Lstat(filepath.Join(state, "events.db")); err != nil || fi.Size() == 0 {
		t.Fatalf("the database file is empty or gone: %v, %v", fi, err)
	}
}

// T-S-15: Open syncs the file under the temporary name, then renames it, then
// syncs the directory. The hook sees which names exist at each sync.
func TestTS15NewDatabaseIsSyncedBeforeAndAfterRename(t *testing.T) {
	root, state, _ := newState(t)
	file := filepath.Join(state, "events.db")
	var steps []string
	setHook(t, &syncFile, func(f *os.File) error {
		kind := "file"
		if fi, err := f.Stat(); err == nil && fi.IsDir() {
			kind = "directory"
		}
		_, tmpErr := os.Lstat(file + tempSuffix)
		_, realErr := os.Lstat(file)
		steps = append(steps, fmt.Sprintf("%s: temporary %t, real %t", kind, tmpErr == nil, realErr == nil))
		return f.Sync()
	})
	mustOpen(t, root, "events.db").Close()
	want := []string{"file: temporary true, real false", "directory: temporary false, real true"}
	if !reflect.DeepEqual(steps, want) {
		t.Fatalf("sync steps %q, want %q", steps, want)
	}
}

// T-S-15: a leftover temporary file next to an existing database is removed,
// with its -wal, -shm and -journal files. The database stays the same file.
func TestTS15LeftoverNextToExistingDatabaseIsRemoved(t *testing.T) {
	root, state, _ := newState(t)
	file := filepath.Join(state, "events.db")
	db := mustOpen(t, root, "events.db")
	if _, err := db.Exec("CREATE TABLE t (x)"); err != nil {
		t.Fatal(err)
	}
	db.Close()
	before, err := os.Lstat(file)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range suffixes {
		if err := os.WriteFile(file+tempSuffix+s, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	db = mustOpen(t, root, "events.db")
	defer db.Close()
	for _, s := range suffixes {
		if _, err := os.Lstat(file + tempSuffix + s); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("events.db%s%s stays: %v", tempSuffix, s, err)
		}
	}
	if after, err := os.Lstat(file); err != nil || !os.SameFile(before, after) {
		t.Fatalf("the database is gone or replaced: %v", err)
	}
	if _, err := db.Exec("INSERT INTO t VALUES (1)"); err != nil {
		t.Fatalf("the table of the database is gone: %v", err)
	}
}

// T-S-15: a leftover that fails a file check makes Open refuse with the rule of
// the check. Open removes nothing. A clean -journal file next to it stays too.
func TestTS15UnsafeLeftoverIsRefusedAndKept(t *testing.T) {
	rows := []struct {
		name, rule string
		set        func(t *testing.T, tmp, outside string)
	}{
		{"events.db" + tempSuffix, ruleType, func(t *testing.T, tmp, outside string) {
			if err := os.Symlink(filepath.Join(outside, "target"), tmp); err != nil {
				t.Fatal(err)
			}
		}},
		{"events.db" + tempSuffix, ruleLinks, func(t *testing.T, tmp, outside string) {
			if err := os.WriteFile(tmp, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(tmp, filepath.Join(outside, "link")); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, r := range rows {
		t.Run(r.rule, func(t *testing.T) {
			root, state, outside := newState(t)
			if err := os.WriteFile(filepath.Join(outside, "target"), []byte("target"), 0o600); err != nil {
				t.Fatal(err)
			}
			tmp := filepath.Join(state, "events.db"+tempSuffix)
			r.set(t, tmp, outside)
			if err := os.WriteFile(tmp+"-journal", []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			before := snapshot(t, filepath.Dir(state))
			db, err := Open(root, "events.db", Options{})
			if db != nil {
				db.Close()
			}
			wantRule(t, err, r.name, r.rule)
			if after := snapshot(t, filepath.Dir(state)); after != before {
				t.Fatalf("Open changed the files:\n%s\nbefore:\n%s", after, before)
			}
		})
	}
}

// onDirSync sets the sync hook so that f runs at the sync of the directory.
func onDirSync(t *testing.T, f func()) {
	t.Helper()
	setHook(t, &syncFile, func(file *os.File) error {
		if fi, err := file.Stat(); err == nil && fi.IsDir() {
			f()
		}
		return file.Sync()
	})
}

// T-S-15: a -wal, -shm or -journal file at the real name, with no database
// file, makes Open refuse. Open makes nothing and removes nothing. Else SQLite
// could read the content of the file into the new database.
func TestTS15SideFileWithoutDatabaseIsRefused(t *testing.T) {
	// A valid -wal file of another database. It is copied while that database
	// is open.
	other, otherState, _ := newState(t)
	db := mustOpen(t, other, "events.db")
	defer db.Close()
	if _, err := db.Exec("CREATE TABLE planted (x)"); err != nil {
		t.Fatal(err)
	}
	wal, err := os.ReadFile(filepath.Join(otherState, "events.db-wal"))
	if err != nil || len(wal) == 0 {
		t.Fatalf("no -wal content: %d bytes, %v", len(wal), err)
	}
	for _, s := range suffixes[1:] {
		t.Run(s, func(t *testing.T) {
			root, state, _ := newState(t)
			content := []byte("side file")
			if s == "-wal" {
				content = wal
			}
			if err := os.WriteFile(filepath.Join(state, "events.db"+s), content, 0o600); err != nil {
				t.Fatal(err)
			}
			before := snapshot(t, state)
			db, err := Open(root, "events.db", Options{})
			if db != nil {
				db.Close()
			}
			wantRule(t, err, "events.db"+s, ruleOrphan)
			if after := snapshot(t, state); after != before {
				t.Fatalf("Open changed the files:\n%s\nbefore:\n%s", after, before)
			}
		})
	}
}

// T-S-15: a side file at the real name makes Open refuse before it removes a
// leftover temporary file. The state directory does not change.
func TestTS15SideFileRefusalKeepsLeftover(t *testing.T) {
	root, state, _ := newState(t)
	for _, n := range []string{"events.db-wal", "events.db" + tempSuffix} {
		if err := os.WriteFile(filepath.Join(state, n), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	before := snapshot(t, state)
	db, err := Open(root, "events.db", Options{})
	if db != nil {
		db.Close()
	}
	wantRule(t, err, "events.db-wal", ruleOrphan)
	if after := snapshot(t, state); after != before {
		t.Fatalf("Open changed the files:\n%s\nbefore:\n%s", after, before)
	}
}

// T-S-15: someone puts a regular -wal file and a symlink -journal in place. This
// is after the made file left the real name. Both stay. Open removes no file
// that SQLite did not make.
func TestTS15PlantedSideFilesStay(t *testing.T) {
	root, state, _ := newState(t)
	file := filepath.Join(state, "events.db")
	onDirSync(t, func() {
		for _, err := range []error{
			os.Rename(file, file+".moved"),
			os.WriteFile(file+"-wal", []byte("planted"), 0o600),
			os.Symlink("target", file+"-journal"),
		} {
			if err != nil {
				t.Error(err)
			}
		}
	})
	db, err := Open(root, "events.db", Options{})
	if db != nil {
		db.Close()
	}
	wantRule(t, err, "events.db-journal", ruleType)
	if b, err := os.ReadFile(file + "-wal"); err != nil || string(b) != "planted" {
		t.Fatalf("the -wal file is gone or changed: %q, %v", b, err)
	}
	if _, err := os.Lstat(file + "-journal"); err != nil {
		t.Fatalf("the -journal symlink is gone: %v", err)
	}
}

// T-S-15: a -wal file that appears at the real name after the create is not
// read into the new database. Open refuses, removes the made file, and keeps
// the -wal file. The hook runs before the rename or at the sync of the
// directory after it.
func TestTS15SideFilePutAfterCreateIsRefusedAndKept(t *testing.T) {
	for _, when := range []string{"before the rename", "after the rename"} {
		t.Run(when, func(t *testing.T) {
			root, state, _ := newState(t)
			file := filepath.Join(state, "events.db")
			plant := func() {
				if err := os.WriteFile(file+"-wal", []byte("planted"), 0o600); err != nil {
					t.Error(err)
				}
			}
			if when == "before the rename" {
				setHook(t, &beforeRename, plant)
			} else {
				onDirSync(t, plant)
			}
			db, err := Open(root, "events.db", Options{})
			if db != nil {
				db.Close()
			}
			wantRule(t, err, "events.db-wal", ruleOrphan)
			if b, err := os.ReadFile(file + "-wal"); err != nil || string(b) != "planted" {
				t.Fatalf("the -wal file is gone or changed: %q, %v", b, err)
			}
			for _, s := range []string{"", tempSuffix} {
				if _, err := os.Lstat(file + s); !errors.Is(err, fs.ErrNotExist) {
					t.Errorf("events.db%s stays: %v", s, err)
				}
			}
		})
	}
}

// T-S-15: a file at the temporary name after the leftover removal is not a file
// that open makes. open refuses and the file keeps its content.
func TestTS15FileAtTemporaryNameBeforeOpenIsKept(t *testing.T) {
	root, state, _ := newState(t)
	if err := os.Mkdir(filepath.Join(state, "data"), 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(state, "data", "events.db"+tempSuffix)
	const content = "other file"
	calls := 0
	// The hook runs before each check of the directory data. Call 1 is the
	// check in Open. Call 2 is the check in open for the temporary name. It is
	// after the leftover removal and before the check of the files.
	safefiletest.Set(t, safefiletest.Hooks{BeforeCheck: func(name string) {
		if name == "data" {
			if calls++; calls == 2 {
				if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
					t.Error(err)
				}
			}
		}
	}})
	db, err := Open(root, "data/events.db", Options{})
	if db != nil {
		db.Close()
	}
	wantRule(t, err, "data/events.db", ruleChanged)
	if b, err := os.ReadFile(file); err != nil || string(b) != content {
		t.Fatalf("the file is gone or changed: %q, %v", b, err)
	}
}

// T-S-15: the made file can leave the real name before Open opens that name.
// Open then makes no file at the real name, and it refuses. The made file is at
// neither name now, so it stays.
func TestTS15MadeFileMovedAfterRenameIsNotMadeAgain(t *testing.T) {
	root, state, _ := newState(t)
	file := filepath.Join(state, "events.db")
	onDirSync(t, func() {
		if err := os.Rename(file, file+".moved"); err != nil {
			t.Error(err)
		}
	})
	openFails(t, root, ruleChanged)
	if _, err := os.Lstat(file); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a file is at the real name: %v", err)
	}
	if _, err := os.Lstat(file + ".moved"); err != nil {
		t.Fatalf("the moved file is gone: %v", err)
	}
}

// T-S-15: if another file takes the real name after the rename, Open refuses.
// The other file is not the made file, so it stays.
func TestTS15OtherFileAtRealNameAfterRenameIsKept(t *testing.T) {
	root, state, _ := newState(t)
	file := filepath.Join(state, "events.db")
	const content = "other file"
	onDirSync(t, func() {
		if err := os.WriteFile(file+".other", []byte(content), 0o600); err != nil {
			t.Error(err)
		}
		if err := os.Rename(file+".other", file); err != nil {
			t.Error(err)
		}
	})
	openFails(t, root, ruleChanged)
	if b, err := os.ReadFile(file); err != nil || string(b) != content {
		t.Fatalf("the other file is gone or changed: %q, %v", b, err)
	}
}

// T-S-15: if another file takes the temporary name before the reopen of the
// made file, Open refuses. The other file stays at the temporary name.
func TestTS15OtherFileAtTemporaryNameAfterPoolCloseIsKept(t *testing.T) {
	root, state, _ := newState(t)
	file := filepath.Join(state, "events.db"+tempSuffix)
	const content = "other file"
	calls := 0
	safefiletest.Set(t, safefiletest.Hooks{BeforeCheck: func(name string) {
		// Call 1 is the second open in open. Call 2 is the reopen.
		if name != filepath.Base(file) {
			return
		}
		if calls++; calls == 2 {
			if err := os.WriteFile(file+".other", []byte(content), 0o600); err != nil {
				t.Error(err)
			}
			if err := os.Rename(file+".other", file); err != nil {
				t.Error(err)
			}
		}
	}})
	openFails(t, root, ruleChanged)
	if b, err := os.ReadFile(file); err != nil || string(b) != content {
		t.Fatalf("the other file is gone or changed: %q, %v", b, err)
	}
}

// T-S-15: an error about a side file of the temporary file keeps the temporary
// name. A symlink put at the -wal name after the first checks causes the error.
func TestTS15ErrorOfTemporarySideFileKeepsItsName(t *testing.T) {
	root, state, _ := newState(t)
	setHook(t, &afterChecks, nth(1, func() {
		if err := os.Symlink("target", filepath.Join(state, "events.db"+tempSuffix+"-wal")); err != nil {
			t.Error(err)
		}
	}))
	db, err := Open(root, "events.db", Options{})
	if db != nil {
		db.Close()
	}
	wantRule(t, err, "events.db"+tempSuffix+"-wal", ruleType)
}

// T-S-15: Open refuses a store.path when its temporary name is a reserved path.
// The case of the letters does not matter. Open makes no file.
func TestTS15ReservedTemporaryNameIsRefused(t *testing.T) {
	for _, reserved := range []string{"events.db" + tempSuffix, "EVENTS.DB.NEW"} {
		t.Run(reserved, func(t *testing.T) {
			root, state, _ := newState(t)
			db, err := Open(root, "events.db", Options{Reserved: []string{reserved}})
			if db != nil {
				db.Close()
			}
			wantRule(t, err, "store.path", ruleReserved)
			if es, err := os.ReadDir(state); err != nil || len(es) != 0 {
				t.Fatalf("Open made files: %v, %v", es, err)
			}
		})
	}
}

// T-S-15: a file that appears at the real name before the rename is never
// replaced. Open refuses, the file keeps its content, and the temporary file
// is gone.
func TestTS15FileAtRealNameBeforeRenameIsKept(t *testing.T) {
	root, state, _ := newState(t)
	file := filepath.Join(state, "events.db")
	const content = "other file"
	setHook(t, &beforeRename, func() {
		if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
			t.Error(err)
		}
	})
	openFails(t, root, ruleChanged)
	if b, err := os.ReadFile(file); err != nil || string(b) != content {
		t.Fatalf("the file is gone or changed: %q, %v", b, err)
	}
	for _, s := range suffixes {
		if _, err := os.Lstat(file + tempSuffix + s); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("events.db%s%s stays: %v", tempSuffix, s, err)
		}
	}
}
