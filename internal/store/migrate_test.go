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
	cases := []struct {
		name string
		full bool
		want int
	}{
		{"full", true, 1},
		{"empty file", false, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root, state, _ := newState(t)
			file := filepath.Join(state, "events.db")
			if err := os.WriteFile(file, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if c.full {
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
			defer db.Close()
			before := content(t, db, file)
			wantRule(t, Migrate(db, "o"), schemaName, ruleVacuum)
			var v int
			if err := db.QueryRow("PRAGMA auto_vacuum").Scan(&v); err != nil || v != c.want {
				t.Fatalf("auto_vacuum %d: %v", v, err)
			}
			if content(t, db, file) != before {
				t.Fatal("the refused database changed")
			}
		})
	}
}

const eventRefusal = "store: database schema has no event table of this binary"

// firstMigration returns the text of the embedded first migration.
func firstMigration(t *testing.T) string {
	t.Helper()
	b, err := migrationFiles.ReadFile("migrations/0001_schema_v1.sql")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// schemaOne runs script on a new database and adds the meta rows that Migrate
// writes for schema version 1. It returns the database and its file.
func schemaOne(t *testing.T, script string) (*sql.DB, string) {
	t.Helper()
	db, file := opened(t)
	const meta = "INSERT INTO meta (key, value) VALUES ('tlog_origin', 'origin'), ('schema_version', '1')"
	if _, err := db.Exec(script); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(meta); err != nil {
		t.Fatal(err)
	}
	return db, file
}

// earlierDatabase makes a schema-1 database of the earlier binary. Its event
// table has no 'refused' in the kind lists.
func earlierDatabase(t *testing.T) (*sql.DB, string) {
	t.Helper()
	earlier := strings.ReplaceAll(firstMigration(t), "'refused',", "")
	if strings.Contains(earlier, "'refused'") || earlier == firstMigration(t) {
		t.Fatal("the earlier text still names the refused kind, or is the current text")
	}
	db, file := schemaOne(t, earlier)
	_, err := db.Exec("INSERT INTO event (ts, kind) VALUES (1, 'refused')")
	if err == nil || !strings.Contains(err.Error(), "CHECK constraint failed") {
		t.Fatalf("the earlier event table takes a refused row: %v", err)
	}
	return db, file
}

// wantEventRefusal checks the full error text, and that the database file has
// the same content as before.
func wantEventRefusal(t *testing.T, err error, db *sql.DB, file, before string) {
	t.Helper()
	wantRule(t, err, schemaName, ruleEvent)
	if err.Error() != eventRefusal {
		t.Fatalf("error text %q, want %q", err, eventRefusal)
	}
	if content(t, db, file) != before {
		t.Fatal("the refused database changed")
	}
}

// T-S-15: Migrate refuses a schema-1 database when its event table text differs
// from the text of the binary. It changes nothing in the database.
func TestTS15EventTableOfOtherTextIsRefused(t *testing.T) {
	cur := firstMigration(t)
	otherByte := strings.Replace(cur, "leaf_index >= 0", "leaf_index >= 1", 1)
	from, to := strings.Index(cur, "CREATE TABLE event"), strings.Index(cur, "CREATE TABLE token")
	if otherByte == cur || from < 0 || to < from {
		t.Fatal("the test cannot change the first migration")
	}
	noEvent := cur[:from] + cur[to:] + "CREATE INDEX event ON token (trap_id);"
	cases := []struct {
		name string
		make func(t *testing.T) (*sql.DB, string)
	}{
		{"earlier text, no rows", earlierDatabase},
		{"earlier text, one request row", func(t *testing.T) (*sql.DB, string) {
			db, file := earlierDatabase(t)
			if _, err := db.Exec("INSERT INTO event (ts, kind) VALUES (1, 'request')"); err != nil {
				t.Fatal(err)
			}
			return db, file
		}},
		{"one other byte", func(t *testing.T) (*sql.DB, string) { return schemaOne(t, otherByte) }},
		{"other letter case", func(t *testing.T) (*sql.DB, string) {
			return schemaOne(t, strings.Replace(cur, "ts            INTEGER NOT NULL", "ts            INTEGER not null", 1))
		}},
		{"space after the event text", func(t *testing.T) (*sql.DB, string) {
			// Only a write to sqlite_schema makes this text. It needs a
			// connection with no defensive mode.
			root, state, _ := newState(t)
			file := filepath.Join(state, "events.db")
			if err := os.WriteFile(file, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			plain, err := sql.Open("sqlite", file)
			if err != nil {
				t.Fatal(err)
			}
			plain.SetMaxOpenConns(1)
			for _, q := range []string{
				"PRAGMA auto_vacuum = INCREMENTAL", cur,
				"INSERT INTO meta (key, value) VALUES ('tlog_origin', 'origin'), ('schema_version', '1')",
				"PRAGMA writable_schema = ON",
				"UPDATE sqlite_schema SET sql = sql || ' ' WHERE type = 'table' AND name = 'event'",
			} {
				if _, err := plain.Exec(q); err != nil {
					t.Fatal(err)
				}
			}
			plain.Close()
			db := mustOpen(t, root, "events.db")
			t.Cleanup(func() { db.Close() })
			return db, file
		}},
		{"no event table, index named event", func(t *testing.T) (*sql.DB, string) { return schemaOne(t, noEvent) }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			db, file := c.make(t)
			before := content(t, db, file)
			wantEventRefusal(t, Migrate(db, "o"), db, file, before)
		})
	}
}

// T-S-15: the check reads the text of the table named event only. A trigger
// named event, made before the table, does not change the result.
func TestTS15EventCheckReadsTheTableOnly(t *testing.T) {
	cur := firstMigration(t)
	from := strings.Index(cur, "CREATE TABLE event")
	if from < 0 {
		t.Fatal("the first migration has no event table")
	}
	trigger := "CREATE TRIGGER event AFTER INSERT ON session BEGIN SELECT 1; END;\n"
	db, _ := schemaOne(t, cur[:from]+trigger+cur[from:])
	if err := Migrate(db, "o"); err != nil {
		t.Fatal(err)
	}
}

// T-S-15: Migrate checks the event text after the migrations and before the
// commit. It refuses a pending migration on a database with the earlier text.
func TestTS15EventCheckRunsBeforeCommitOfPendingMigration(t *testing.T) {
	db, file := earlierDatabase(t)
	before := content(t, db, file)
	set := testSet(map[string]string{"0002_more.sql": "CREATE TABLE more (a)"})
	wantEventRefusal(t, migrate(db, set, "o"), db, file, before)
	var n int
	if err := db.QueryRow("SELECT count(*) FROM sqlite_master WHERE name = 'more'").Scan(&n); err != nil || n != 0 {
		t.Fatalf("the new table is there: %d, %v", n, err)
	}
	if v := metaValue(t, db, "schema_version"); v != "1" {
		t.Fatalf("schema_version %s, want 1", v)
	}
}

// T-S-15: a database that Migrate made opens again, and migrates again, with
// no error.
func TestTS15DatabaseOfBinaryOpensAgain(t *testing.T) {
	root, _, _ := newState(t)
	first := mustOpen(t, root, "events.db")
	if err := Migrate(first, "origin"); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second := mustOpen(t, root, "events.db")
	t.Cleanup(func() { second.Close() })
	if err := Migrate(second, "origin"); err != nil {
		t.Fatal(err)
	}
}

// T-S-15: when the step in memory fails, migrate returns the migration rule and
// changes nothing. The second statement of the script fails in memory only.
func TestTS15FailedStepInMemoryIsRefused(t *testing.T) {
	db, file := schemaOne(t, firstMigration(t))
	before := content(t, db, file)
	set := testSet(nil)
	set["0001_schema_v1.sql"].Data = []byte("CREATE TABLE event (a); CREATE TABLE event (b);")
	wantRule(t, migrate(db, set, "o"), schemaName, ruleMigrate)
	if content(t, db, file) != before {
		t.Fatal("the refused database changed")
	}
}

// T-S-15: the step in memory applies all scripts, also a pending one that
// changes the event table. A second run with the same scripts has no error.
func TestTS15PendingChangeOfEventTableIsChecked(t *testing.T) {
	db := migrated(t)
	set := testSet(map[string]string{"0002_more.sql": "ALTER TABLE event ADD COLUMN z INTEGER"})
	for i := 0; i < 2; i++ {
		if err := migrate(db, set, "o"); err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
	}
}

// T-U-18: no non-test Go file and no SQL file of the package has the SQL keyword
// VACUUM, in any case.
func TestTU18NoVacuumInSource(t *testing.T) {
	word := regexp.MustCompile(`(?i)\bvacuum\b`)
	if !word.MatchString("VACUUM;") || !word.MatchString("vacuum;") || word.MatchString("auto_vacuum incremental_vacuum") {
		t.Fatal("the pattern is wrong")
	}
	scanned := map[string]bool{}
	err := filepath.WalkDir(".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".sql") && (!strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go")) {
			return err
		}
		scanned[filepath.ToSlash(p)] = true
		if b, err := os.ReadFile(p); err != nil || word.Match(b) {
			t.Errorf("%s has the word or cannot be read", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"migrate.go", "open.go", "migrations/0001_schema_v1.sql"} {
		if !scanned[p] {
			t.Errorf("%s was not scanned", p)
		}
	}
}
