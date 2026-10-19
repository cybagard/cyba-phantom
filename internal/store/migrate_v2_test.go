package store

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/cybagard/cyba-phantom/internal/event"
	"github.com/cybagard/cyba-phantom/internal/tlog"
)

const (
	eventDump = "SELECT group_concat(r, char(10)) FROM (SELECT quote(id)||'|'||quote(ts)||'|'||quote(session_id)||'|'||quote(kind)||'|'||" +
		"quote(vhost)||'|'||quote(method)||'|'||quote(path)||'|'||quote(status)||'|'||quote(trap_id)||'|'||quote(token_id)||'|'||" +
		"quote(surface)||'|'||quote(body_prefix)||'|'||quote(hash)||'|'||quote(leaf_index)||'|'||quote(detail)||'|'||quote(record) AS r " +
		"FROM event ORDER BY id)"
	checkpointDump = "SELECT group_concat(r, char(10)) FROM (SELECT quote(tree_size)||'|'||quote(root_hash)||'|'||quote(signed_note)||'|'||" +
		"quote(created_at) AS r FROM checkpoint ORDER BY tree_size)"
	schemaDump = "SELECT group_concat(name||'='||sql, char(10)) FROM (SELECT name, sql FROM sqlite_master ORDER BY name)"
	seededRows = 12
)

// dump returns the result of one of the dump queries.
func dump(t *testing.T, db *sql.DB, q string) string {
	t.Helper()
	var s string
	if err := db.QueryRow(q).Scan(&s); err != nil {
		t.Fatal(err)
	}
	return s
}

// rowsOf is every row of the event and checkpoint tables, with the type and the
// bytes of each value.
func rowsOf(t *testing.T, db *sql.DB) string {
	t.Helper()
	return dump(t, db, eventDump) + "\n--\n" + dump(t, db, checkpointDump)
}

// schemaOf is the name and the stored text of each schema entry.
func schemaOf(t *testing.T, db *sql.DB) string { return dump(t, db, schemaDump) }

// fakeSpace replaces the disk space of the store for one test. It returns the
// paths that the check asked for.
func fakeSpace(t *testing.T, size, fsSize, free uint64, ok bool) *[]string {
	t.Helper()
	var calls []string
	old := diskSpace
	diskSpace = func(_ *os.Root, rel string) (uint64, uint64, uint64, bool) {
		calls = append(calls, rel)
		return size, fsSize, free, ok
	}
	t.Cleanup(func() { diskSpace = old })
	return &calls
}

// noSpaceCall makes a test fail if the store reads the disk space.
func noSpaceCall(t *testing.T) {
	t.Helper()
	old := diskSpace
	diskSpace = func(*os.Root, string) (uint64, uint64, uint64, bool) {
		t.Error("the store read the disk space")
		return 0, 0, 0, false
	}
	t.Cleanup(func() { diskSpace = old })
}

// v1Database makes a database with the first migration only, with request,
// evidence and checkpoint rows. The hash of each evidence row is a leaf of the
// returned log. The ids are not in a row.
func v1Database(t *testing.T) (*sql.DB, *os.Root, *tlog.Log) {
	t.Helper()
	db, _, root := opened(t)
	if err := migrate(db, testSet(nil), "origin", nil); err != nil {
		t.Fatal(err)
	}
	const ins = "INSERT INTO event (id, ts, session_id, kind, vhost, method, path, status, trap_id, token_id, surface, body_prefix, hash, leaf_index, detail, record) " +
		"VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
	var hashes []tlog.EventHash
	for i := range seededRows {
		id, args := 10+i*3, []any{}
		if i%3 == 0 {
			kind := []string{"callback", "score_change", "retention", "alert_sent"}[i/3]
			rec := fmt.Appendf(nil, `{"v":1,"n":%d}`, i)
			h := sha256.Sum256(rec)
			hashes = append(hashes, h)
			args = []any{id, 100 + i, "sess-a", kind, "www.example.test", "GET", "/x", 200, "trap", "tok", "path", []byte("body"), h[:], len(hashes) - 1, `{"k":1}`, rec}
		} else {
			args = []any{id, 100 + i, "sess-b", "request", "www.example.test", "POST", "/y", 404, nil, nil, nil, []byte{0, 1, 2}, nil, nil, nil, nil}
		}
		if _, err := db.Exec(ins, args...); err != nil {
			t.Fatal(err)
		}
	}
	for _, size := range []int{4, 9} {
		if _, err := db.Exec("INSERT INTO checkpoint (tree_size, root_hash, signed_note, created_at) VALUES (?, ?, 'note', ?)", size, bytes.Repeat([]byte{byte(size)}, 32), size*7); err != nil {
			t.Fatal(err)
		}
	}
	l := realLog(t)
	if first, err := l.AppendBatch(hashes); err != nil || first != 0 {
		t.Fatalf("append: %d %v", first, err)
	}
	return db, root, l
}

// T-U-18: a version 1 database with request, evidence and checkpoint rows
// migrates to version 2. Each row keeps all columns, the four indexes exist, the
// leaf index is unique, and the start check of the writer passes.
func TestTU18MigrationTwoKeepsEachRow(t *testing.T) {
	db, root, l := v1Database(t)
	fakeSpace(t, 1, 1000, 1000, true)
	before := rowsOf(t, db)
	var n int
	if err := db.QueryRow("SELECT count(*) FROM event").Scan(&n); err != nil || n != seededRows {
		t.Fatalf("seeded %d rows: %v", n, err)
	}
	if err := Migrate(db, root, "events.db", "origin"); err != nil {
		t.Fatal(err)
	}
	if after := rowsOf(t, db); after != before {
		t.Fatalf("rows changed:\n%s\n%s", before, after)
	}
	if v := metaValue(t, db, "schema_version"); v != "2" {
		t.Fatalf("schema_version %s", v)
	}
	for name, want := range map[string]string{
		"event_session": "", "event_ts": "", "event_kind_ts": "",
		"event_leaf": "CREATE UNIQUE INDEX event_leaf ON event(leaf_index) WHERE leaf_index IS NOT NULL",
	} {
		var got string
		if err := db.QueryRow("SELECT sql FROM sqlite_master WHERE type = 'index' AND tbl_name = 'event' AND name = ?", name).Scan(&got); err != nil {
			t.Fatalf("index %s: %v", name, err)
		}
		if want != "" && got != want {
			t.Fatalf("index %s: %q", name, got)
		}
	}
	_, err := db.Exec("INSERT INTO event (ts, kind, hash, leaf_index) VALUES (1, 'callback', ?, 0)", bytes.Repeat([]byte{1}, 32))
	if err == nil || !strings.Contains(err.Error(), "UNIQUE constraint failed") {
		t.Fatalf("duplicate leaf index: %v", err)
	}
	c := event.NewCounters()
	q, err := event.NewQueue(10, c)
	if err != nil {
		t.Fatal(err)
	}
	w := NewWriter(db, q, l, c, false, nil, Recovery{State: root, Origin: "origin", Log: l})
	if err := w.start(); err != nil {
		t.Fatalf("start check: %v", err)
	}
}

// T-U-18: a 0002 that fails after the copy leaves version 1, the old event table,
// its rows and its schema text as they were.
func TestTU18FailedRebuildKeepsVersionOne(t *testing.T) {
	db, _, _ := v1Database(t)
	script, err := migrationFiles.ReadFile("migrations/0002_refused_kind.sql")
	if err != nil {
		t.Fatal(err)
	}
	bad := testSet(map[string]string{"0002_refused_kind.sql": string(script) + "INSERT INTO nope VALUES (1);\n"})
	rows, schema := rowsOf(t, db), schemaOf(t, db)
	wantRule(t, migrate(db, bad, "origin", nil), schemaName, ruleMigrate)
	if rowsOf(t, db) != rows || schemaOf(t, db) != schema {
		t.Fatal("a failed migration changed the database")
	}
	if v := metaValue(t, db, "schema_version"); v != "1" {
		t.Fatalf("schema_version %s", v)
	}
}

// T-U-18: the rebuild needs free space of 2 x the file size plus a tenth of the
// file system, on the file system of the database file. A refused database stays
// at version 1 with no change. An empty event table, a new database and a
// database at the newest version need no check.
func TestTU18RebuildChecksFreeSpace(t *testing.T) {
	const size, fsSize = 1000, 10000 // the bound is 2000 + 1000
	cases := []struct {
		name string
		free uint64
		ok   bool
		rule string
	}{
		{"at the bound", 3000, true, ""},
		{"above the bound", 3001, true, ""},
		{"below the bound", 2999, true, ruleSpace},
		{"no free space", 0, true, ruleSpace},
		{"space cannot be read", 1 << 40, false, ruleSpaceRead},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			db, root, _ := v1Database(t)
			calls := fakeSpace(t, size, fsSize, c.free, c.ok)
			rows, schema := rowsOf(t, db), schemaOf(t, db)
			err := Migrate(db, root, "events.db", "origin")
			want := "2"
			if c.rule != "" {
				wantRule(t, err, schemaName, c.rule)
				want = "1"
				if rowsOf(t, db) != rows || schemaOf(t, db) != schema {
					t.Fatal("a refused database changed")
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if v := metaValue(t, db, "schema_version"); v != want {
				t.Fatalf("schema_version %s, want %s", v, want)
			}
			if len(*calls) != 1 || (*calls)[0] != "events.db" {
				t.Fatalf("checks of the space: %v", *calls)
			}
		})
	}
	t.Run("no check without rows", func(t *testing.T) {
		db, _, root := opened(t)
		noSpaceCall(t)
		if err := migrate(db, testSet(nil), "origin", nil); err != nil {
			t.Fatal(err)
		}
		if err := Migrate(db, root, "events.db", "origin"); err != nil {
			t.Fatal(err)
		}
		if v := metaValue(t, db, "schema_version"); v != "2" {
			t.Fatalf("schema_version %s", v)
		}
		if err := Migrate(db, root, "events.db", "origin"); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("no check on a new database", func(t *testing.T) {
		db, _, root := opened(t)
		noSpaceCall(t)
		if err := Migrate(db, root, "events.db", "origin"); err != nil {
			t.Fatal(err)
		}
	})
}

// T-S-22: after 0002 the schema takes a refused row with no hash, leaf index and
// record, and refuses a refused row with one of them. A kind that is not in the
// list is still refused.
func TestTS22RefusedRowsHaveNoHashLeafOrRecord(t *testing.T) {
	const ev = "INSERT INTO event (ts, session_id, kind, hash, leaf_index, record, detail) VALUES (1, 's', ?, ?, ?, ?, ?)"
	h, rec, detail := bytes.Repeat([]byte{7}, 32), []byte("rec"), `{"reason":"bad_hello"}`
	cases := []struct {
		name string
		args []any
		ok   bool
	}{
		{"refused with none", []any{"refused", nil, nil, nil, detail}, true},
		{"refused with a hash", []any{"refused", h, nil, nil, detail}, false},
		{"refused with a leaf index", []any{"refused", nil, 7, nil, detail}, false},
		{"refused with a record", []any{"refused", nil, nil, rec, detail}, false},
		{"unknown kind", []any{"bogus", nil, nil, nil, detail}, false},
		{"evidence kind with a hash and a leaf", []any{"callback", h, 0, nil, detail}, true},
	}
	db := migrated(t)
	for _, c := range cases {
		_, err := db.Exec(ev, c.args...)
		switch {
		case c.ok && err != nil:
			t.Errorf("%s: %v", c.name, err)
		case !c.ok && (err == nil || !strings.Contains(err.Error(), "CHECK constraint failed")):
			t.Errorf("%s: want a CHECK error, got %v", c.name, err)
		}
	}
	var n int
	if err := db.QueryRow("SELECT count(*) FROM event WHERE kind = 'refused'").Scan(&n); err != nil || n != 1 {
		t.Fatalf("refused rows: %d %v", n, err)
	}
}
