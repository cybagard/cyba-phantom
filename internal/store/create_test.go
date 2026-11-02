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
	tmpName    = "events.db" + tempSuffix
)

// T-S-15: this is the helper process of the kill test. It stops itself with a
// panic at the kill point from the environment. Without the role, it skips.
func TestTS15CreateHelper(t *testing.T) {
	if os.Getenv(crashRoleEnv) != crashRoleHelp {
		t.Skip("helper process of TestTS15KilledStartLeavesNoFileAtRealName")
	}
	root, err := os.OpenRoot(os.Getenv(crashStateEnv))
	if err != nil {
		t.Fatal(err)
	}
	stop := func() { panic(crashMessage) }
	if os.Getenv(crashPointEnv) == killCreate {
		afterChecks = stop
	} else {
		beforeRename = stop
	}
	Open(root, "events.db", Options{})
	t.Fatal("the helper process did not stop")
}

func put(t *testing.T, path, content string) {
	t.Helper()
	must(t, os.WriteFile(path, []byte(content), 0o600))
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Error(err)
	}
}

func gone(path string) bool {
	_, err := os.Lstat(path)
	return errors.Is(err, fs.ErrNotExist)
}

// swap puts a file with content at path, over the file there.
func swap(t *testing.T, path, content string) {
	put(t, path+".other", content)
	must(t, os.Rename(path+".other", path))
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

// T-S-15: a start that stops after the create, or after the first write, leaves
// no file at the real name. The next Open removes the leftover and makes a
// database that Migrate accepts.
func TestTS15KilledStartLeavesNoFileAtRealName(t *testing.T) {
	for _, c := range []struct {
		name, point string
		written     bool // the leftover file has the first write
	}{
		{"after the create", killCreate, false},
		{"after the first write", killWrite, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			root, state, _ := newState(t)
			cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestTS15CreateHelper$")
			cmd.Env = append(os.Environ(), crashRoleEnv+"="+crashRoleHelp, crashPointEnv+"="+c.point, crashStateEnv+"="+state)
			out, err := cmd.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || !bytes.Contains(out, []byte("panic: "+crashMessage)) {
				t.Fatalf("helper error %v, output:\n%s", err, out)
			}
			file := filepath.Join(state, "events.db")
			if !gone(file) {
				t.Fatal("a file is at the real name")
			}
			if fi, err := os.Lstat(file + tempSuffix); err != nil || (fi.Size() > 0) != c.written {
				t.Fatalf("leftover file: %v, %v; want written %v", fi, err, c.written)
			}
			db := mustOpen(t, root, "events.db")
			defer db.Close()
			if err := Migrate(db, "origin"); err != nil {
				t.Fatal(err)
			}
			if !gone(file + tempSuffix) {
				t.Fatal("the leftover file stays")
			}
		})
	}
}

// T-S-15: Open syncs the file under the temporary name, renames it, and syncs
// the directory. The hook sees which names exist at each sync. After Open, no
// temporary file stays, and the database has auto_vacuum incremental.
func TestTS15NewDatabaseIsSyncedAndLeavesNoTemporaryFiles(t *testing.T) {
	root, state, _ := newState(t)
	file := filepath.Join(state, "events.db")
	var steps []string
	setHook(t, &syncFile, func(f *os.File) error {
		kind := "file"
		if fi, err := f.Stat(); err == nil && fi.IsDir() {
			kind = "directory"
		}
		steps = append(steps, fmt.Sprintf("%s: temporary %t, real %t", kind, !gone(file+tempSuffix), !gone(file)))
		return f.Sync()
	})
	db := mustOpen(t, root, "events.db")
	defer db.Close()
	want := []string{"file: temporary true, real false", "directory: temporary false, real true"}
	if !reflect.DeepEqual(steps, want) {
		t.Fatalf("sync steps %q, want %q", steps, want)
	}
	for _, s := range suffixes {
		if !gone(file + tempSuffix + s) {
			t.Errorf("events.db%s%s stays", tempSuffix, s)
		}
	}
	var vacuum int
	if err := db.QueryRow("PRAGMA auto_vacuum").Scan(&vacuum); err != nil || vacuum != 2 {
		t.Fatalf("auto_vacuum %d, %v; want 2", vacuum, err)
	}
	if fi, err := os.Lstat(file); err != nil || fi.Size() == 0 {
		t.Fatalf("the database file is empty or gone: %v, %v", fi, err)
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
	before, _ := os.Lstat(file)
	for _, s := range suffixes {
		put(t, file+tempSuffix+s, "x")
	}
	db = mustOpen(t, root, "events.db")
	defer db.Close()
	for _, s := range suffixes {
		if !gone(file + tempSuffix + s) {
			t.Errorf("events.db%s%s stays", tempSuffix, s)
		}
	}
	if after, err := os.Lstat(file); err != nil || !os.SameFile(before, after) {
		t.Fatalf("the database is gone or replaced: %v", err)
	}
	if _, err := db.Exec("INSERT INTO t VALUES (1)"); err != nil {
		t.Fatalf("the table of the database is gone: %v", err)
	}
}

// T-S-15: a refused open of an existing database keeps its -wal and -shm
// files, also when SQLite has opened the file. A second pool keeps the files
// after the refused pool closes. The same files must be there.
func TestTS15RefusedOpenOfExistingDatabaseKeepsItsSideFiles(t *testing.T) {
	root, state, _ := newState(t)
	file := filepath.Join(state, "events.db")
	first := mustOpen(t, root, "events.db")
	defer first.Close()
	if _, err := first.Exec("CREATE TABLE t (x)"); err != nil {
		t.Fatal(err)
	}
	before := map[string]fs.FileInfo{}
	for _, s := range suffixes[1:3] {
		before[s], _ = os.Lstat(file + s)
	}
	setHook(t, &afterVerify, nth(1, func() { must(t, os.Chmod(file, 0o640)) }))
	openFails(t, root, ruleMode)
	for s, fi := range before {
		if after, err := os.Lstat(file + s); fi == nil || err != nil || !os.SameFile(fi, after) {
			t.Errorf("events.db%s is gone or replaced: %v", s, err)
		}
	}
}

// validWAL returns the -wal file of another database that has a table.
func validWAL(t *testing.T) []byte {
	t.Helper()
	root, state, _ := newState(t)
	db := mustOpen(t, root, "events.db")
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec("CREATE TABLE planted (x)"); err != nil {
		t.Fatal(err)
	}
	wal, err := os.ReadFile(filepath.Join(state, "events.db-wal"))
	if err != nil || len(wal) == 0 {
		t.Fatalf("no -wal content: %d bytes, %v", len(wal), err)
	}
	return wal
}

// fdCheck counts descriptors of a refused start. The Linux tests set it.
var fdCheck func(t *testing.T, paths ...string)

// refusedStart is one refused start. arm sets the hooks and the files. at gives the
// path of a name in the state directory. Open must fail with the rule for
// errName. Each file in kept stays, with its content when it is not empty. Each
// file in gone does not exist. With same, the files do not change. With noFds,
// no descriptor points to the real or the temporary file.
type refusedStart struct {
	name, rel, errName, rule string
	opt                      Options
	arm                      func(t *testing.T, at func(string) string)
	kept                     map[string]string
	gone                     []string
	same, noFds              bool
}

func (r refusedStart) run(t *testing.T) {
	t.Helper()
	root, state, _ := newState(t)
	at := func(n string) string { return filepath.Join(state, n) }
	if r.arm != nil {
		r.arm(t, at)
	}
	if r.rel == "" {
		r.rel = "events.db"
	}
	before := snapshot(t, filepath.Dir(state))
	db, err := Open(root, r.rel, r.opt)
	if db != nil {
		db.Close()
	}
	wantRule(t, err, r.errName, r.rule)
	if after := snapshot(t, filepath.Dir(state)); r.same && after != before {
		t.Fatalf("Open changed the files:\n%s\nbefore:\n%s", after, before)
	}
	for n, c := range r.kept {
		if _, err := os.Lstat(at(n)); err != nil {
			t.Errorf("%s is gone: %v", n, err)
		} else if b, _ := os.ReadFile(at(n)); c != "" && string(b) != c {
			t.Errorf("%s changed: %q", n, b)
		}
	}
	for _, n := range r.gone {
		if !gone(at(n)) {
			t.Errorf("%s stays", n)
		}
	}
	if r.noFds && fdCheck != nil {
		fdCheck(t, at("events.db"), at(tmpName))
	}
}

// T-S-15: Open refuses in each row and keeps each file that it did not make.
func TestTS15RefusedStartKeepsOtherFiles(t *testing.T) {
	wal := validWAL(t)
	rows := []refusedStart{
		{name: "leftover symlink", errName: tmpName, rule: ruleType, same: true,
			arm: func(t *testing.T, at func(string) string) {
				put(t, at("../outside/target"), "target")
				must(t, os.Symlink(at("../outside/target"), at(tmpName)))
				put(t, at(tmpName+"-journal"), "x")
			}},
		{name: "leftover second link", errName: tmpName, rule: ruleLinks, same: true,
			arm: func(t *testing.T, at func(string) string) {
				put(t, at(tmpName), "x")
				must(t, os.Link(at(tmpName), at("../outside/link")))
				put(t, at(tmpName+"-journal"), "x")
			}},
		{name: "side file and leftover", errName: "events.db-wal", rule: ruleOrphan, same: true,
			arm: func(t *testing.T, at func(string) string) {
				put(t, at("events.db-wal"), "x")
				put(t, at(tmpName), "x")
			}},
		{name: "planted side files after the move", errName: "events.db-journal", rule: ruleType,
			kept: map[string]string{"events.db-wal": "planted", "events.db-journal": ""},
			arm: func(t *testing.T, at func(string) string) {
				onDirSync(t, func() {
					must(t, os.Rename(at("events.db"), at("events.db.moved")))
					put(t, at("events.db-wal"), "planted")
					must(t, os.Symlink("target", at("events.db-journal")))
				})
			}},
		{name: "wal before the rename", errName: "events.db-wal", rule: ruleOrphan,
			kept: map[string]string{"events.db-wal": "planted"}, gone: []string{"events.db", tmpName},
			arm: func(t *testing.T, at func(string) string) {
				setHook(t, &beforeRename, func() { put(t, at("events.db-wal"), "planted") })
			}},
		{name: "wal after the rename", errName: "events.db-wal", rule: ruleOrphan,
			kept: map[string]string{"events.db-wal": "planted"}, gone: []string{"events.db", tmpName},
			arm: func(t *testing.T, at func(string) string) {
				onDirSync(t, func() { put(t, at("events.db-wal"), "planted") })
			}},
		{name: "file at the temporary name before open", rel: "data/events.db", errName: "data/events.db",
			rule: ruleChanged, kept: map[string]string{"data/" + tmpName: "other file"},
			arm: func(t *testing.T, at func(string) string) {
				must(t, os.Mkdir(at("data"), 0o700))
				n := 0 // call 1 is in Open, call 2 is in open for the temporary name
				safefiletest.Set(t, safefiletest.Hooks{BeforeCheck: func(name string) {
					if name == "data" {
						if n++; n == 2 {
							put(t, at("data/"+tmpName), "other file")
						}
					}
				}})
			}},
		{name: "made file moved after the rename", errName: "events.db", rule: ruleChanged,
			kept: map[string]string{"events.db.moved": ""}, gone: []string{"events.db"},
			arm: func(t *testing.T, at func(string) string) {
				onDirSync(t, func() { must(t, os.Rename(at("events.db"), at("events.db.moved"))) })
			}},
		{name: "other file after the rename", errName: "events.db", rule: ruleChanged,
			kept: map[string]string{"events.db": "other file"},
			arm: func(t *testing.T, at func(string) string) {
				onDirSync(t, func() { swap(t, at("events.db"), "other file") })
			}},
		{name: "other file at the temporary name after the pool close", errName: "events.db",
			rule: ruleChanged, kept: map[string]string{tmpName: "other file"},
			arm: func(t *testing.T, at func(string) string) {
				n := 0 // call 1 is the second open in open, call 2 is the reopen
				safefiletest.Set(t, safefiletest.Hooks{BeforeCheck: func(name string) {
					if name == tmpName {
						if n++; n == 2 {
							swap(t, at(tmpName), "other file")
						}
					}
				}})
			}},
		{name: "error of a temporary side file", errName: tmpName + "-wal", rule: ruleType,
			arm: func(t *testing.T, at func(string) string) {
				setHook(t, &afterChecks, nth(1, func() { must(t, os.Symlink("target", at(tmpName+"-wal"))) }))
			}},
		{name: "reserved temporary name", errName: "store.path", rule: ruleReserved, same: true,
			opt: Options{Reserved: []string{tmpName}}},
		{name: "reserved temporary name, other case", errName: "store.path", rule: ruleReserved,
			same: true, opt: Options{Reserved: []string{"EVENTS.DB.NEW"}}},
		{name: "file at the real name before the rename", errName: "events.db", rule: ruleChanged,
			kept: map[string]string{"events.db": "other file"}, noFds: true,
			gone: []string{tmpName, tmpName + "-wal", tmpName + "-shm", tmpName + "-journal"},
			arm: func(t *testing.T, at func(string) string) {
				setHook(t, &beforeRename, func() { put(t, at("events.db"), "other file") })
			}},
		{name: "journal symlink after the rename", errName: "events.db-journal", rule: ruleType,
			kept: map[string]string{"events.db-journal": ""}, gone: []string{"events.db"}, noFds: true,
			arm: func(t *testing.T, at func(string) string) {
				onDirSync(t, func() { must(t, os.Symlink("target", at("events.db-journal"))) })
			}},
	}
	for _, s := range suffixes[1:] {
		content := "side file"
		if s == "-wal" {
			content = string(wal)
		}
		rows = append(rows, refusedStart{name: "side file " + s, errName: "events.db" + s, rule: ruleOrphan,
			same: true, arm: func(t *testing.T, at func(string) string) { put(t, at("events.db"+s), content) }})
	}
	for _, r := range rows {
		t.Run(r.name, r.run)
	}
}
