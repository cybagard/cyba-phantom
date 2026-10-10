package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newState makes a state directory and a sibling directory outside it. It
// returns the root, the state directory (symlinks resolved), and the outside
// directory.
func newState(t *testing.T) (*os.Root, string, string) {
	t.Helper()
	top, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	state, outside := filepath.Join(top, "state"), filepath.Join(top, "outside")
	for _, d := range []string{state, outside} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	root, err := os.OpenRoot(state)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	return root, state, outside
}

func mustOpen(t *testing.T, root *os.Root, rel string) *sql.DB {
	t.Helper()
	db, err := Open(root, rel, Options{})
	if err != nil {
		t.Fatalf("open %s: %v", rel, err)
	}
	return db
}

// snapshot returns the type, mode, size and mtime of each entry below dir, and
// the content of each regular file. It does not follow a link.
func snapshot(t *testing.T, dir string) string {
	t.Helper()
	var sb strings.Builder
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		fmt.Fprintf(&sb, "%s %v %d", p, fi.Mode(), fi.Size())
		if !fi.IsDir() {
			fmt.Fprintf(&sb, " %d", fi.ModTime().UnixNano())
		}
		if fi.Mode().IsRegular() {
			b, err := os.ReadFile(p)
			fmt.Fprintf(&sb, " %x", b)
			if err != nil {
				return err
			}
		}
		sb.WriteString("\n")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return sb.String()
}

// wantRule checks that err is an *Error with the given name and rule, and that
// its text has no driver text and no connection string.
func wantRule(t *testing.T, err error, name, rule string) {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) || e.Name != name || e.Rule != rule || errors.Unwrap(err) != nil {
		t.Fatalf("want %q %q, got %v", name, rule, err)
	}
	for _, s := range []string{"sql", "_pragma", "_defensive", "_txlock", "?", "#", "file:"} {
		if strings.Contains(strings.ToLower(err.Error()), s) {
			t.Fatalf("error text %q has %q", err, s)
		}
	}
}

// T-S-15: a path part outside the permitted set, a reserved path, and a path
// that is empty, absolute, unclean or has a .. part are refused before anything
// is made or opened. A path with ? or # never reaches the driver.
func TestTS15RefusedPathsOpenNothing(t *testing.T) {
	opt := Options{Reserved: []string{"tlog", "certs", "bundle"}}
	cases := []struct{ rel, rule string }{
		{"", rulePathForm}, {"/etc/x.db", rulePathForm}, {"a/../x.db", rulePathForm},
		{"../x.db", rulePathForm}, {"..", rulePathForm}, {".", rulePathForm},
		{"./x.db", rulePathForm}, {"a//x.db", rulePathForm}, {"x.db/", rulePathForm},
		{"a b.db", ruleChars}, {"x?y.db", ruleChars}, {"x#y.db", ruleChars},
		{"x?_pragma=synchronous(OFF)", ruleChars}, {"x%41.db", ruleChars},
		{"x\ny.db", ruleChars}, {"é.db", ruleChars}, {"x:y", ruleChars}, {`x\y.db`, ruleChars},
		{"checkpoint.state", ruleReserved}, {"writer.stop", ruleReserved},
		{"tlog", ruleReserved}, {"tlog/events.db", ruleReserved},
		{"keys/events.db", ruleReserved}, {"checkpoints/events.db", ruleReserved},
		{"certs/events.db", ruleReserved}, {"bundle/x/events.db", ruleReserved},
	}
	root, state, outside := newState(t)
	before := snapshot(t, state) + snapshot(t, outside)
	// Every byte outside the permitted set, and some multi-byte characters.
	for b := 0; b < 256; b++ {
		if c := byte(b); c == '/' || c == '.' || c == '_' || c == '-' ||
			c >= '0' && c <= '9' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' {
			continue
		}
		rel, rule := "x"+string([]byte{byte(b)})+"y.db", ruleChars
		if !fs.ValidPath(rel) { // for example, a byte that is not valid UTF-8
			rule = rulePathForm
		}
		cases = append(cases, struct{ rel, rule string }{rel, rule})
	}
	for _, r := range []string{"é", "日", "‮", "\U0001F600"} {
		cases = append(cases, struct{ rel, rule string }{"x" + r + ".db", ruleChars})
	}
	for _, c := range cases {
		db, err := Open(root, c.rel, opt)
		if db != nil {
			db.Close()
		}
		wantRule(t, err, "store.path", c.rule)
	}
	if snapshot(t, state)+snapshot(t, outside) != before {
		t.Fatal("a refused open changed a file")
	}

	// A reserved directory that is not a clean relative path is refused too.
	_, err := Open(root, "events.db", Options{Reserved: []string{"/abs"}})
	wantRule(t, err, "reserved directory", rulePathForm)
	// "." as a reserved directory is the state directory: nothing is allowed.
	_, err = Open(root, "events.db", Options{Reserved: []string{"."}})
	wantRule(t, err, "store.path", ruleReserved)
	// A name that only starts like a reserved directory is allowed by the path
	// rules; the parent check then refuses it because it does not exist.
	_, err = Open(root, "tlog2/events.db", opt)
	wantRule(t, err, "tlog2", ruleParent)
}

// T-S-15: a state directory path with ? or # would reach the driver as a
// parameter, so it is refused.
func TestTS15StatePathWithQuestionMarkIsRefused(t *testing.T) {
	top := t.TempDir()
	dir := filepath.Join(top, "st?ate")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	_, err = Open(root, "events.db", Options{})
	wantRule(t, err, "state directory", ruleStateChars)
}

// T-S-15: a parent that is missing is an error, and Open makes no directory.
func TestTS15MissingParentIsAnError(t *testing.T) {
	root, state, _ := newState(t)
	before := snapshot(t, state)
	_, err := Open(root, "a/b/events.db", Options{})
	wantRule(t, err, "a", ruleParent)
	if snapshot(t, state) != before {
		t.Fatal("open made a directory")
	}
}

// T-S-15: the connection string is fixed text and the checked path.
func TestTS15ConnectionStringIsFixedText(t *testing.T) {
	const want = "/s/events.db?_defensive=1&_txlock=immediate" +
		"&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=cache_size(-8000)" +
		"&_pragma=temp_store(MEMORY)&_pragma=mmap_size(0)&_pragma=foreign_keys(OFF)" +
		"&_pragma=busy_timeout(5000)&_pragma=journal_size_limit(67108864)&_pragma=trusted_schema(OFF)"
	if got := dsn("/s/events.db", false); got != want {
		t.Fatalf("got %s", got)
	}
	// A file that Open made gets auto_vacuum before journal_mode(WAL).
	const first = "?_defensive=1&_txlock=immediate&_pragma=auto_vacuum(INCREMENTAL)&_pragma=journal_mode(WAL)"
	if !strings.Contains(dsn("/s/events.db", true), first) {
		t.Fatal("auto_vacuum is not first")
	}
}

// T-S-15, T-U-18: each pragma of 03 reads back its value on each new connection,
// the journal mode is wal, the writer pool has one connection, and the soft heap
// limit of the process is 16 MiB. The file that Open made has auto_vacuum 2: this
// shows that the driver applies the pragmas in order.
func TestTS15PragmasReadBackOnNewConnections(t *testing.T) {
	root, state, _ := newState(t)
	db := mustOpen(t, root, "events.db")
	defer db.Close()
	if n := db.Stats().MaxOpenConnections; n != 1 {
		t.Fatalf("pool has %d connections", n)
	}
	var heap string
	if err := db.QueryRow("PRAGMA soft_heap_limit").Scan(&heap); err != nil || heap != "16777216" {
		t.Fatalf("soft_heap_limit %q: %v", heap, err)
	}

	// A second pool with the same string, and two connections that are open at
	// the same time, so that the settings do not come from the first connection.
	fresh, err := sql.Open("sqlite", dsn(filepath.Join(state, "events.db"), false))
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	want := map[string]string{
		"journal_mode": "wal", "synchronous": "1", "cache_size": "-8000", "temp_store": "2",
		"mmap_size": "0", "foreign_keys": "0", "busy_timeout": "5000",
		"journal_size_limit": "67108864", "trusted_schema": "0", "auto_vacuum": "2",
	}
	for i := 0; i < 2; i++ {
		c, err := fresh.Conn(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		for name, v := range want {
			var got string
			if err := c.QueryRowContext(context.Background(), "PRAGMA "+name).Scan(&got); err != nil || got != v {
				t.Errorf("connection %d: %s is %q, want %q (%v)", i, name, got, v, err)
			}
		}
	}
}

// T-S-15: the embedded SQLite is 3.53.4. A driver change that changes it must
// change this test, and the change must cite the sqlite.org CVE list.
func TestTS15SQLiteVersion(t *testing.T) {
	root, _, _ := newState(t)
	db := mustOpen(t, root, "events.db")
	defer db.Close()
	var v string
	if err := db.QueryRow("SELECT sqlite_version()").Scan(&v); err != nil || v != "3.53.4" {
		t.Fatalf("version %q: %v", v, err)
	}
}

// T-S-15: a file that is not a database is refused. The error has no driver
// text, the file does not change, and a good file opens again.
func TestTS15NotADatabaseGivesFixedErrorClass(t *testing.T) {
	root, state, _ := newState(t)
	file := filepath.Join(state, "events.db")
	if err := os.WriteFile(file, []byte(strings.Repeat("not a database ", 20)), 0o600); err != nil {
		t.Fatal(err)
	}
	before := snapshot(t, state)
	db, err := Open(root, "events.db", Options{})
	if db != nil {
		db.Close()
	}
	wantRule(t, err, "events.db", ruleOpen)
	if want := "store: events.db cannot be opened as a database"; err.Error() != want {
		t.Fatalf("got %q", err)
	}
	if snapshot(t, state) != before {
		t.Fatal("a refused open changed a file")
	}
}

// T-S-15: Open makes a new file and opens an existing file again.
func TestTS15ReopenExistingDatabase(t *testing.T) {
	root, _, _ := newState(t)
	db := mustOpen(t, root, "events.db")
	if _, err := db.Exec("CREATE TABLE t (x)"); err != nil {
		t.Fatal(err)
	}
	db.Close()
	db = mustOpen(t, root, "events.db")
	defer db.Close()
	if _, err := db.Exec("INSERT INTO t VALUES (1)"); err != nil {
		t.Fatal(err)
	}
}
