package store

import (
	"database/sql"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"
)

func opened(t *testing.T) (*sql.DB, string) {
	t.Helper()
	root, state, _ := newState(t)
	db := mustOpen(t, root, "events.db")
	t.Cleanup(func() { db.Close() })
	return db, filepath.Join(state, "events.db")
}

func migrated(t *testing.T) *sql.DB {
	t.Helper()
	db, _ := opened(t)
	if err := Migrate(db, "origin"); err != nil {
		t.Fatal(err)
	}
	return db
}

// testSet is the embedded first migration plus the given files.
func testSet(extra map[string]string) fstest.MapFS {
	first, _ := migrationFiles.ReadFile("migrations/0001_schema_v1.sql")
	set := fstest.MapFS{"0001_schema_v1.sql": {Data: first}}
	for name, s := range extra {
		set[name] = &fstest.MapFile{Data: []byte(s)}
	}
	return set
}

func metaValue(t *testing.T, db *sql.DB, key string) string {
	t.Helper()
	var v string
	if err := db.QueryRow("SELECT value FROM meta WHERE key = ?", key).Scan(&v); err != nil {
		t.Fatalf("meta %s: %v", key, err)
	}
	return v
}

// content moves the WAL into the database file and returns the file bytes.
func content(t *testing.T, db *sql.DB, file string) string {
	t.Helper()
	_, err := db.Exec("PRAGMA wal_checkpoint(TRUNCATE)")
	data, err2 := os.ReadFile(file)
	if err != nil || err2 != nil {
		t.Fatal(err, err2)
	}
	return string(data)
}

// T-U-18: a bad migration name or a gap is an error and changes nothing.
func TestTU18MigrationNamesAreChecked(t *testing.T) {
	db, file := opened(t)
	before := content(t, db, file)
	bad := []fstest.MapFS{
		testSet(map[string]string{"0003_c.sql": "SELECT 1"}),
		testSet(map[string]string{"0002_b.sql": "SELECT 1", "0002_c.sql": "SELECT 1"}),
		testSet(map[string]string{"2_b.sql": "SELECT 1"}),
		testSet(map[string]string{"0002_b.txt": "SELECT 1"}),
		testSet(map[string]string{"0002_b.sql/x": "SELECT 1"}),
		{"0002_b.sql": {Data: []byte("SELECT 1")}},
		{},
	}
	for i, set := range bad {
		wantRule(t, migrate(db, set, "o"), schemaName, ruleNames)
		if content(t, db, file) != before {
			t.Fatalf("set %d changed the database", i)
		}
	}
}

// T-U-18: a failed migration leaves the old version and content.
func TestTU18FailedMigrationKeepsOldVersion(t *testing.T) {
	db, file := opened(t)
	empty := content(t, db, file)
	bad := testSet(map[string]string{"0002_bad.sql": "CREATE TABLE extra (a); INSERT INTO nope VALUES (1)"})
	wantRule(t, migrate(db, bad, "o"), schemaName, ruleMigrate)
	if content(t, db, file) != empty {
		t.Fatal("a failed run on a new database left content")
	}
	if err := Migrate(db, "o"); err != nil {
		t.Fatal(err)
	}
	v1 := content(t, db, file)
	wantRule(t, migrate(db, bad, "o"), schemaName, ruleMigrate)
	if content(t, db, file) != v1 || metaValue(t, db, "schema_version") != "1" {
		t.Fatal("a failed migration changed the database")
	}
}

// T-U-18: the origin is a bound value, written before schema_version, which is
// the last write. Later runs keep the origin; an equal version changes nothing.
func TestTU18OriginIsBoundAndVersionIsLast(t *testing.T) {
	const origin = "o'); DROP TABLE meta; --"
	db, file := opened(t)
	if err := migrate(db, testSet(nil), origin); err != nil {
		t.Fatal(err)
	}
	var order string
	if err := db.QueryRow("SELECT group_concat(key || '=' || value, ',') FROM (SELECT key, value FROM meta ORDER BY rowid)").Scan(&order); err != nil {
		t.Fatal(err)
	}
	if order != "tlog_origin="+origin+",schema_version=1" {
		t.Fatalf("meta rows %q", order)
	}
	set := testSet(map[string]string{"0002_more.sql": "CREATE TABLE more (a)"})
	if err := migrate(db, set, "other"); err != nil {
		t.Fatal(err)
	}
	if v, o := metaValue(t, db, "schema_version"), metaValue(t, db, "tlog_origin"); v != "2" || o != origin {
		t.Fatalf("version %s origin %q", v, o)
	}
	before := content(t, db, file)
	if err := migrate(db, set, "x"); err != nil || content(t, db, file) != before {
		t.Fatalf("equal version: %v", err)
	}
}

// T-U-18, T-S-15: a newer version and a foreign database are refused unchanged.
func TestTU18RefusedDatabasesAreNotChanged(t *testing.T) {
	const meta = "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL); "
	cases := []struct{ name, setup, rule string }{
		{"newer", "UPDATE meta SET value = '99' WHERE key = 'schema_version'", ruleNewer},
		{"no meta", "CREATE TABLE t (a); INSERT INTO t VALUES (1)", ruleForeign},
		{"no version", meta + "INSERT INTO meta VALUES ('install_id', 'x')", ruleForeign},
		{"text version", meta + "INSERT INTO meta VALUES ('schema_version', 'x')", ruleForeign},
	}
	for _, c := range cases {
		db, file := opened(t)
		if c.name == "newer" && Migrate(db, "o") != nil {
			t.Fatal("migrate")
		}
		if _, err := db.Exec(c.setup); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		before := content(t, db, file)
		wantRule(t, Migrate(db, "o"), schemaName, c.rule)
		if content(t, db, file) != before {
			t.Errorf("%s: the refused database changed", c.name)
		}
	}
}

// T-U-18: auto_vacuum other than 2 is refused (also an empty file from before Open).
func TestTU18ExistingDatabaseWithOtherAutoVacuumIsRefused(t *testing.T) {
	for _, full := range []bool{true, false} {
		root, state, _ := newState(t)
		file := filepath.Join(state, "events.db")
		if err := os.WriteFile(file, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if full {
			plain, err := sql.Open("sqlite", file)
			if err != nil {
				t.Fatal(err)
			}
			plain.SetMaxOpenConns(1)
			if _, err := plain.Exec("PRAGMA auto_vacuum = FULL; CREATE TABLE t (a)"); err != nil {
				t.Fatal(err)
			}
			plain.Close()
		}
		db := mustOpen(t, root, "events.db")
		before := content(t, db, file)
		wantRule(t, Migrate(db, "o"), schemaName, ruleVacuum)
		var v int
		if err := db.QueryRow("PRAGMA auto_vacuum").Scan(&v); err != nil || v != map[bool]int{true: 1, false: 0}[full] {
			t.Fatalf("full=%v: auto_vacuum %d: %v", full, v, err)
		}
		if content(t, db, file) != before {
			t.Fatalf("full=%v: the refused database changed", full)
		}
		db.Close()
	}
}

// T-U-18: no non-test Go file and no SQL file of the package has the word.
func TestTU18NoVacuumInSource(t *testing.T) {
	word := regexp.MustCompile(`\bVACUUM\b`)
	if !word.MatchString("VACUUM;") || word.MatchString("auto_vacuum incremental_vacuum") {
		t.Fatal("the pattern is wrong")
	}
	filepath.WalkDir(".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".sql") && (!strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go")) {
			return err
		}
		if b, err := os.ReadFile(p); err != nil || word.Match(b) {
			t.Errorf("%s has the word or cannot be read", p)
		}
		return nil
	})
}
