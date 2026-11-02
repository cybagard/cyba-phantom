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
	"strings"
	"testing"

	"github.com/cybagard/cyba-phantom/internal/safefile/safefiletest"
)

const (
	killCreate = "create" // after the create, before the first write
	killWrite  = "write"  // after the first write, before the rename
	tmpName    = "events.db" + tempSuffix
)

// T-S-15: helper process of the kill test. It panics at the kill point.
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

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Error(err)
	}
}

func put(t *testing.T, path, content string) {
	t.Helper()
	must(t, os.WriteFile(path, []byte(content), 0o600))
}

// swap puts a file with content at path, over the file there.
func swap(t *testing.T, path, content string) {
	t.Helper()
	put(t, path+".o", content)
	must(t, os.Rename(path+".o", path))
}

func gone(path string) bool {
	_, err := os.Lstat(path)
	return errors.Is(err, fs.ErrNotExist)
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
	}{{"after the create", killCreate, false}, {"after the first write", killWrite, true}} {
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
			if fi, err := os.Lstat(file + tempSuffix); !gone(file) || err != nil || (fi.Size() > 0) != c.written {
				t.Fatalf("real name gone %v; leftover %v, %v; want written %v", gone(file), fi, err, c.written)
			}
			db := mustOpen(t, root, "events.db")
			defer db.Close()
			if err := Migrate(db, "origin"); err != nil || !gone(file+tempSuffix) {
				t.Fatalf("Migrate %v; leftover gone %v", err, gone(file+tempSuffix))
			}
		})
	}
}

// T-S-15: Open syncs the file under the temporary name, renames it, and syncs
// the directory. No temporary file stays. The database has auto_vacuum 2.
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
	var vacuum int
	err := db.QueryRow("PRAGMA auto_vacuum").Scan(&vacuum)
	if !reflect.DeepEqual(steps, want) || err != nil || vacuum != 2 {
		t.Fatalf("sync steps %q, want %q; auto_vacuum %d, %v", steps, want, vacuum, err)
	}
	for _, s := range suffixes {
		if !gone(file + tempSuffix + s) {
			t.Errorf("events.db%s%s stays", tempSuffix, s)
		}
	}
}

// T-S-15: a leftover next to an existing database is removed, with its side
// files. The database stays the same file, with its table.
func TestTS15LeftoverNextToExistingDatabaseIsRemoved(t *testing.T) {
	root, state, _ := newState(t)
	file := filepath.Join(state, "events.db")
	db := mustOpen(t, root, "events.db")
	_, err := db.Exec("CREATE TABLE t (x)")
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
	after, serr := os.Lstat(file)
	if _, ierr := db.Exec("INSERT INTO t VALUES (1)"); err != nil || serr != nil || !os.SameFile(before, after) || ierr != nil {
		t.Fatalf("the database is gone or changed: %v, %v, %v", err, serr, ierr)
	}
}

// T-S-15: a refused open of an existing database keeps its -wal and -shm.
// A second pool keeps them after the refused pool closes. They stay the same.
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

// fdCheck counts descriptors of a refused start. The Linux tests set it.
var fdCheck func(t *testing.T, paths ...string)

// refusedStart is one refused start. plant lists the files that exist before
// Open: a name that ends with "/" is a directory, a content with "->" is a
// symlink, a content with "=>" is a hard link to the file named in the rest.
// then runs at the point on ("rename", "sync" of the directory, "checks"), or
// at the second check of the name onName. Open must fail with the rule for
// errName. A file in kept stays, with its content if it is not empty. A file in
// gone does not exist. With same, no file changes. With noFds, no descriptor
// points to the real or the temporary file.
type refusedStart struct {
	name, rel, errName, rule string
	opt                      Options
	plant                    [][2]string
	on, onName               string
	then                     func(t *testing.T, at func(string) string)
	kept                     map[string]string
	gone                     []string
	same, noFds              bool
}

func (r refusedStart) run(t *testing.T) {
	root, state, _ := newState(t)
	at := func(n string) string { return filepath.Join(state, n) }
	for _, p := range r.plant {
		switch n, c := p[0], p[1]; {
		case strings.HasSuffix(n, "/"):
			must(t, os.Mkdir(at(n), 0o700))
		case strings.HasPrefix(c, "->"):
			must(t, os.Symlink(c[2:], at(n)))
		case strings.HasPrefix(c, "=>"):
			must(t, os.Link(at(c[2:]), at(n)))
		default:
			put(t, at(n), c)
		}
	}
	call := func() { r.then(t, at) }
	switch r.on {
	case "rename":
		setHook(t, &beforeRename, call)
	case "sync":
		onDirSync(t, call)
	case "checks":
		setHook(t, &afterChecks, nth(1, call))
	}
	if r.onName != "" {
		second := nth(2, call) // call 1 is the open of the made file, call 2 the reopen
		safefiletest.Set(t, safefiletest.Hooks{BeforeCheck: func(name string) {
			if name == r.onName {
				second()
			}
		}})
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
	plantWal := func(t *testing.T, at func(string) string) { put(t, at("events.db-wal"), "planted") }
	moveDB := func(t *testing.T, at func(string) string) { must(t, os.Rename(at("events.db"), at("events.db.moved"))) }
	walKept := map[string]string{"events.db-wal": "planted"}
	other := map[string]string{"events.db": "other file"}
	rows := []refusedStart{
		{name: "leftover symlink", errName: tmpName, rule: ruleType, same: true,
			plant: [][2]string{{tmpName, "->target"}, {tmpName + "-journal", "x"}}},
		{name: "leftover second link", errName: tmpName, rule: ruleLinks, same: true,
			plant: [][2]string{{tmpName, "x"}, {"../outside/link", "=>" + tmpName}, {tmpName + "-journal", "x"}}},
		{name: "side file and leftover", errName: "events.db-wal", rule: ruleOrphan, same: true,
			plant: [][2]string{{"events.db-wal", "x"}, {tmpName, "x"}}},
		{name: "planted side files after the move", errName: "events.db-journal", rule: ruleType, on: "sync",
			kept: map[string]string{"events.db-wal": "planted", "events.db-journal": ""},
			then: func(t *testing.T, at func(string) string) {
				moveDB(t, at)
				plantWal(t, at)
				must(t, os.Symlink("target", at("events.db-journal")))
			}},
		{name: "wal after the rename", errName: "events.db-wal", rule: ruleOrphan, on: "sync",
			then: plantWal, kept: walKept, gone: []string{"events.db", tmpName}},
		{name: "file at the temporary name before open", rel: "data/events.db", errName: "data/events.db",
			rule: ruleChanged, plant: [][2]string{{"data/", ""}}, onName: "data",
			then: func(t *testing.T, at func(string) string) { put(t, at("data/"+tmpName), "other file") },
			kept: map[string]string{"data/" + tmpName: "other file"}},
		{name: "made file moved after the rename", errName: "events.db", rule: ruleChanged, on: "sync",
			then: moveDB, kept: map[string]string{"events.db.moved": ""}, gone: []string{"events.db"}},
		{name: "other file after the rename", errName: "events.db", rule: ruleChanged, on: "sync",
			then: func(t *testing.T, at func(string) string) { swap(t, at("events.db"), "other file") }, kept: other},
		{name: "other file at the temporary name after the pool close", errName: "events.db", rule: ruleChanged,
			onName: tmpName, kept: map[string]string{tmpName: "other file"},
			then: func(t *testing.T, at func(string) string) { swap(t, at(tmpName), "other file") }},
		{name: "error of a temporary side file", errName: tmpName + "-wal", rule: ruleType, on: "checks",
			then: func(t *testing.T, at func(string) string) { must(t, os.Symlink("target", at(tmpName+"-wal"))) }},
		{name: "reserved temporary name, other case", errName: "store.path", rule: ruleReserved, same: true,
			opt: Options{Reserved: []string{"EVENTS.DB.NEW"}}},
		{name: "file at the real name before the rename", errName: "events.db", rule: ruleChanged, on: "rename",
			kept: other, noFds: true,
			gone: []string{tmpName, tmpName + "-wal", tmpName + "-shm", tmpName + "-journal"},
			then: func(t *testing.T, at func(string) string) { put(t, at("events.db"), "other file") }},
		{name: "journal symlink after the rename", errName: "events.db-journal", rule: ruleType, on: "sync",
			kept: map[string]string{"events.db-journal": ""}, gone: []string{"events.db"}, noFds: true,
			then: func(t *testing.T, at func(string) string) { must(t, os.Symlink("target", at("events.db-journal"))) }},
	}
	for _, s := range suffixes[1:] {
		rows = append(rows, refusedStart{name: "side file " + s, errName: "events.db" + s, rule: ruleOrphan,
			same: true, plant: [][2]string{{"events.db" + s, "x"}}})
	}
	for _, r := range rows {
		t.Run(r.name, r.run)
	}
}
