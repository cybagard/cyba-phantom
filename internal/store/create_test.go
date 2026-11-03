//go:build unix

package store

import (
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
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

// hook reports the error of a step that runs in a hook.
func hook(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Error(err)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func put(t *testing.T, path, content string) {
	t.Helper()
	hook(t, os.WriteFile(path, []byte(content), 0o600))
}

// swap puts a file with content at path, over the file there.
func swap(t *testing.T, path, content string) {
	t.Helper()
	put(t, path+".o", content)
	hook(t, os.Rename(path+".o", path))
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
// the directory of the file. No temporary file stays. The database has
// auto_vacuum 2. The page size is 4096, the size that leftoverMax uses. The
// test runs for a file in the state directory and for a file in a directory
// below it.
func TestTS15NewDatabaseIsSyncedAndLeavesNoTemporaryFiles(t *testing.T) {
	for _, rel := range []string{"events.db", "data/events.db"} {
		t.Run(rel, func(t *testing.T) {
			root, state, _ := newState(t)
			must(t, os.Mkdir(filepath.Join(state, "data"), 0o700))
			file := filepath.Join(state, filepath.FromSlash(rel))
			parent, _ := os.Stat(filepath.Dir(file))
			var steps []string
			setHook(t, &syncFile, func(f *os.File) error {
				kind := "file"
				if fi, err := f.Stat(); err == nil && fi.IsDir() {
					kind = "other directory"
					if os.SameFile(fi, parent) {
						kind = "directory"
					}
				}
				steps = append(steps, fmt.Sprintf("%s: temporary %t, real %t", kind, !gone(file+tempSuffix), !gone(file)))
				return f.Sync()
			})
			db := mustOpen(t, root, rel)
			defer db.Close()
			want := []string{"file: temporary true, real false", "directory: temporary false, real true"}
			var vacuum int
			err := db.QueryRow("PRAGMA auto_vacuum").Scan(&vacuum)
			if !reflect.DeepEqual(steps, want) || err != nil || vacuum != 2 {
				t.Fatalf("sync steps %q, want %q; auto_vacuum %d, %v", steps, want, vacuum, err)
			}
			var page int64
			if err := db.QueryRow("PRAGMA page_size").Scan(&page); err != nil || page != leftoverMax[0] {
				t.Fatalf("page_size %d, %v; want %d, the page size of leftoverMax", page, err, leftoverMax[0])
			}
			for _, s := range suffixes {
				if !gone(file + tempSuffix + s) {
					t.Errorf("%s%s%s stays", rel, tempSuffix, s)
				}
			}
		})
	}
}

// T-S-15: a write to page 1 of a new database makes a -journal file. Its size
// is the -journal limit in leftoverMax. The WAL switch of Open removes its
// journal before the afterVerify hook runs. So the test uses the settings of
// Open, without WAL. It reads the journal file while the write is open.
func TestTS15CreateJournalSizeIsTheLeftoverLimit(t *testing.T) {
	file := filepath.Join(t.TempDir(), "events.db")
	db, err := sql.Open("sqlite", strings.Replace(dsn(file, true), "&_pragma=journal_mode(WAL)", "", 1))
	must(t, err)
	defer db.Close()
	db.SetMaxOpenConns(1)
	_, err = db.Exec("CREATE TABLE t (x)")
	must(t, err)
	tx, err := db.Begin()
	must(t, err)
	defer tx.Rollback()
	_, err = tx.Exec("PRAGMA user_version=1") // changes page 1 only
	must(t, err)
	j := slices.Index(suffixes[:], "-journal")
	fi, err := os.Stat(file + suffixes[j])
	must(t, err)
	if want := leftoverMax[j]; fi.Size() != want {
		t.Fatalf("journal size %d, want %d, the -journal limit of leftoverMax", fi.Size(), want)
	}
}

// T-S-15: a leftover next to an existing database is removed, with its side
// files. Each file is at its limit. The -shm file has no limit, and the test
// gives it 32768 bytes. The database stays the same file, with its table. The
// path has a directory.
func TestTS15LeftoverNextToExistingDatabaseIsRemoved(t *testing.T) {
	root, state, _ := newState(t)
	must(t, os.Mkdir(filepath.Join(state, "data"), 0o700))
	file := filepath.Join(state, "data", "events.db")
	db := mustOpen(t, root, "data/events.db")
	_, err := db.Exec("CREATE TABLE t (x)")
	db.Close()
	before, _ := os.Lstat(file)
	for i, size := range []int{4096, 32, 32768, 4616} {
		put(t, file+tempSuffix+suffixes[i], strings.Repeat("x", size))
	}
	db = mustOpen(t, root, "data/events.db")
	defer db.Close()
	for _, s := range suffixes {
		if !gone(file + tempSuffix + s) {
			t.Errorf("data/events.db%s%s stays", tempSuffix, s)
		}
	}
	after, serr := os.Lstat(file)
	if _, ierr := db.Exec("INSERT INTO t VALUES (1)"); err != nil || serr != nil || !os.SameFile(before, after) || ierr != nil {
		t.Fatalf("the database is gone or changed: %v, %v, %v", err, serr, ierr)
	}
}

// T-S-15: a refused open of an existing database keeps its -wal and -shm.
// The first pool is still open and keeps them after the refused pool closes.
// They stay the same files.
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
	setHook(t, &afterVerify, nth(1, func() { hook(t, os.Chmod(file, 0o640)) }))
	openFails(t, root, ruleMode)
	for s, fi := range before {
		if after, err := os.Lstat(file + s); fi == nil || err != nil || !os.SameFile(fi, after) {
			t.Errorf("events.db%s is gone or replaced: %v", s, err)
		}
	}
}

// T-S-15: a migrated database at the temporary name can hold store data. Open
// keeps it and refuses. The data is in the main file if the pool is closed.
// It is in the -wal file if the pool is open. The real name stays absent.
func TestTS15LeftoverWithStoreDataIsKept(t *testing.T) {
	for _, c := range []struct {
		name, errName string
		closed        bool
	}{{"pool closed", "data/events.db.new", true}, {"pool open", "data/events.db.new-wal", false}} {
		t.Run(c.name, func(t *testing.T) {
			root, state, _ := newState(t)
			must(t, os.Mkdir(filepath.Join(state, "data"), 0o700))
			old := mustOpen(t, root, "data/events.db.new")
			defer old.Close()
			must(t, Migrate(old, "origin"))
			if c.closed {
				must(t, old.Close())
			}
			before := snapshot(t, filepath.Dir(state))
			// The file has no read mode during Open. If the test does not
			// run as root, a read open fails. So the rule comes from the size,
			// not from an open of the file.
			leftover := filepath.Join(state, filepath.FromSlash(c.errName))
			fi, err := os.Lstat(leftover)
			must(t, err)
			must(t, os.Chmod(leftover, 0o200))
			db, err := Open(root, "data/events.db", Options{})
			if db != nil {
				db.Close()
			}
			must(t, os.Chmod(leftover, fi.Mode().Perm()))
			wantRule(t, err, c.errName, ruleData)
			if after := snapshot(t, filepath.Dir(state)); after != before || !gone(filepath.Join(state, "data", "events.db")) {
				t.Fatalf("Open changed the files or made the database:\n%s\nbefore:\n%s", after, before)
			}
		})
	}
}

// fdCheck counts descriptors of a refused start. The Linux tests set it.
var fdCheck func(t *testing.T, paths ...string)

// refusedStart is one refused start. plant lists the files that exist before
// Open. A name that ends with "/" is a directory. A content with "->" is a
// symlink. A content with "=>" is a hard link to the file named in the rest.
// then runs at the point on ("rename", "sync" of the directory, "checks",
// "checks2", "verify", "dsn"). It can also run at the second check of the name
// onName. Open must fail with the rule for errName. A file in kept stays, with
// its content if it is not empty. A file in gone does not exist. With same, no
// file changes. With noFds, no descriptor points to the real or the temporary
// file.
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
	case "checks2": // after the guard close, at the real name
		setHook(t, &afterChecks, nth(2, call))
	case "verify": // after the first connection, at the real name
		setHook(t, &afterVerify, nth(2, call))
	case "dsn": // with a bad connection string, at the real name
		n := 0
		setHook(t, &editDSN, func(s string) string {
			if n++; n == 2 {
				call()
				s += "&_pragma=%zz"
			}
			return s
		})
	}
	if r.onName != "" {
		// The hook sees a directory name in openDir of Open, open and each pool
		// check. It sees the temporary name at the second open and the reopen.
		second := nth(2, call)
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
		fdCheck(t, at(r.rel), at(r.rel+tempSuffix))
	}
}

// T-S-15: Open refuses in each row and keeps each file that it did not make.
func TestTS15RefusedStartKeepsOtherFiles(t *testing.T) {
	plantWal := func(t *testing.T, at func(string) string) { put(t, at("events.db-wal"), "planted") }
	moveDB := func(t *testing.T, at func(string) string) { hook(t, os.Rename(at("events.db"), at("events.db.moved"))) }
	planted := map[string]string{"events.db-wal": "planted", "events.db-shm": "planted", "events.db-journal": "planted"}
	plantAll := func(t *testing.T, at func(string) string) {
		for n := range planted {
			put(t, at(n), "planted")
		}
	}
	other := map[string]string{"events.db": "other file"}
	rows := []refusedStart{
		{name: "leftover symlink", errName: tmpName, rule: ruleType, same: true,
			plant: [][2]string{{tmpName, "->target"}, {tmpName + "-journal", "x"}}},
		{name: "leftover second link", errName: tmpName, rule: ruleLinks, same: true,
			plant: [][2]string{{tmpName, "x"}, {"../outside/link", "=>" + tmpName}, {tmpName + "-journal", "x"}}},
		{name: "planted side files after the move", errName: "events.db-journal", rule: ruleType, on: "sync",
			kept: map[string]string{"events.db-wal": "planted", "events.db-journal": ""},
			then: func(t *testing.T, at func(string) string) {
				moveDB(t, at)
				plantWal(t, at)
				hook(t, os.Symlink("target", at("events.db-journal")))
			}},
		{name: "planted side files before a failed connector", errName: "events.db", rule: ruleOpen, on: "dsn",
			kept: planted, gone: []string{"events.db"}, then: plantAll, noFds: true},
		{name: "wal after the guard close", errName: "events.db-wal", rule: ruleOrphan, on: "checks2",
			then: plantWal, kept: map[string]string{"events.db-wal": "planted"}, gone: []string{"events.db", tmpName},
			noFds: true},
		{name: "planted journal before a failed check", rel: "data/events.db", errName: "data/events.db",
			rule: ruleMode, on: "verify", plant: [][2]string{{"data/", ""}}, kept: map[string]string{"data/events.db-journal": "planted"},
			gone: []string{"data/events.db", "data/events.db-wal", "data/events.db-shm"},
			then: func(t *testing.T, at func(string) string) {
				put(t, at("data/events.db-journal"), "planted")
				hook(t, os.Chmod(at("data/events.db"), 0o640))
			}},
		{name: "file at the temporary name before open", rel: "data/events.db", errName: "data/events.db",
			rule: ruleChanged, plant: [][2]string{{"data/", ""}}, onName: "data",
			then: func(t *testing.T, at func(string) string) { put(t, at("data/"+tmpName), "other file") },
			kept: map[string]string{"data/" + tmpName: "other file"}},
		{name: "made file moved after the rename", errName: "events.db", rule: ruleChanged, on: "sync",
			then: moveDB, kept: map[string]string{"events.db.moved": ""}, gone: []string{"events.db"}},
		{name: "other file after the rename", errName: "events.db", rule: ruleChanged, on: "sync",
			then: func(t *testing.T, at func(string) string) { swap(t, at("events.db"), "other file") }, kept: other, noFds: true},
		{name: "other file at the temporary name after the pool close", errName: "events.db", rule: ruleChanged,
			onName: tmpName, kept: map[string]string{tmpName: "other file"},
			then: func(t *testing.T, at func(string) string) { swap(t, at(tmpName), "other file") }},
		{name: "error of a temporary side file", errName: tmpName + "-wal", rule: ruleType, on: "checks",
			then: func(t *testing.T, at func(string) string) { hook(t, os.Symlink("target", at(tmpName+"-wal"))) }},
		{name: "reserved temporary name, other case", errName: "store.path", rule: ruleReserved, same: true,
			opt: Options{Reserved: []string{"EVENTS.DB.NEW"}}},
		{name: "file at the real name before the rename", rel: "data/events.db", errName: "data/events.db",
			rule: ruleChanged, on: "rename", plant: [][2]string{{"data/", ""}}, noFds: true,
			kept: map[string]string{"data/events.db": "other file"},
			gone: []string{"data/" + tmpName, "data/" + tmpName + "-wal", "data/" + tmpName + "-shm", "data/" + tmpName + "-journal"},
			then: func(t *testing.T, at func(string) string) { put(t, at("data/events.db"), "other file") }},
		{name: "leftover database above one page", rel: "data/events.db", errName: "data/" + tmpName,
			rule: ruleData, same: true, plant: [][2]string{{"data/", ""}, {"data/events.db", "x"},
				{"data/" + tmpName, strings.Repeat("x", 4097)}}},
		{name: "leftover wal above its header", rel: "data/events.db", errName: "data/" + tmpName + "-wal",
			rule: ruleData, same: true, plant: [][2]string{{"data/", ""}, {"data/" + tmpName + "-wal", strings.Repeat("x", 33)}}},
		{name: "leftover journal above one page record", rel: "data/events.db", errName: "data/" + tmpName + "-journal",
			rule: ruleData, same: true, plant: [][2]string{{"data/", ""}, {"data/" + tmpName + "-journal", strings.Repeat("x", 4617)}}},
		{name: "leftover wal symlink in a directory", rel: "data/events.db", errName: "data/" + tmpName + "-wal",
			rule: ruleType, same: true, plant: [][2]string{{"data/", ""}, {"data/" + tmpName + "-wal", "->target"}}},
		{name: "journal symlink after the rename", rel: "data/events.db", errName: "data/events.db-journal",
			rule: ruleType, on: "sync", plant: [][2]string{{"data/", ""}}, noFds: true,
			kept: map[string]string{"data/events.db-journal": ""}, gone: []string{"data/events.db"},
			then: func(t *testing.T, at func(string) string) {
				hook(t, os.Symlink("target", at("data/events.db-journal")))
			}},
	}
	for _, s := range suffixes[1:] {
		rows = append(rows, refusedStart{name: "side file " + s + " and leftover", rel: "data/events.db",
			errName: "data/events.db" + s, rule: ruleOrphan, same: true,
			plant: [][2]string{{"data/", ""}, {"data/events.db" + s, "x"}, {"data/" + tmpName, "x"}}},
			refusedStart{name: "side file " + s + " after the rename", rel: "data/events.db", errName: "data/events.db" + s,
				rule: ruleOrphan, on: "sync", plant: [][2]string{{"data/", ""}}, noFds: true,
				kept: map[string]string{"data/events.db" + s: "planted"}, gone: []string{"data/events.db", "data/" + tmpName},
				then: func(t *testing.T, at func(string) string) { put(t, at("data/events.db"+s), "planted") }})
	}
	for _, r := range rows {
		t.Run(r.name, r.run)
	}
}
