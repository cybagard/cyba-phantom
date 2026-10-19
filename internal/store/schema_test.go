package store

import (
	"bytes"
	"io/fs"
	"strings"
	"testing"
)

// T-U-18: sqlite_master equals the embedded DDL; checkpoint has no publish column.
func TestTU18SchemaEqualsEmbeddedDDL(t *testing.T) {
	db := migrated(t)
	ddl, err := migrationFiles.ReadFile("migrations/0001_schema_v1.sql")
	if err != nil {
		t.Fatal(err)
	}
	var got string
	q := "SELECT group_concat(sql, ';') FROM (SELECT sql FROM sqlite_master WHERE sql IS NOT NULL ORDER BY rowid)"
	if err := db.QueryRow(q).Scan(&got); err != nil {
		t.Fatal(err)
	}
	// SQLite stores each statement without its final semicolon.
	want := strings.TrimSuffix(strings.Join(strings.Split(strings.TrimSpace(string(ddl)), ";\n"), ";"), ";")
	if got != want || strings.Count(want, "CREATE ") != 13 {
		t.Fatalf("sqlite_master differs from the embedded DDL:\n%q\n%q", got, want)
	}
	var n int
	q = "SELECT count(*) FROM pragma_table_info('checkpoint') WHERE name IN ('published_at', 'publish_target')"
	if err := db.QueryRow(q).Scan(&n); err != nil || n != 0 {
		t.Fatalf("publish column: %d %v", n, err)
	}
}

// eventSchemaText is the fixed text of the event table and of its four indexes.
const eventSchemaText = `CREATE TABLE event (
  id            INTEGER PRIMARY KEY,
  ts            INTEGER NOT NULL,
  session_id    TEXT REFERENCES session(id),
  kind          TEXT NOT NULL CHECK (kind IN ('request','refused','callback','beacon','score_change','bundle_load','bundle_rejected','alert_sent','retention')),
  vhost TEXT, method TEXT, path TEXT, status INTEGER,
  trap_id       TEXT,
  token_id      TEXT,
  surface       TEXT,
  body_prefix   BLOB,
  hash          BLOB,
  leaf_index    INTEGER,
  detail        TEXT,
  record        BLOB,
  CHECK ((kind IN ('request','refused','beacon') AND hash IS NULL AND leaf_index IS NULL AND record IS NULL)
      OR (kind NOT IN ('request','refused','beacon')
          AND hash IS NOT NULL AND typeof(hash) = 'blob' AND length(hash) = 32
          AND leaf_index IS NOT NULL AND typeof(leaf_index) = 'integer' AND leaf_index >= 0))
)
CREATE INDEX event_session ON event(session_id)
CREATE INDEX event_ts ON event(ts)
CREATE INDEX event_kind_ts ON event(kind, ts)
CREATE UNIQUE INDEX event_leaf ON event(leaf_index) WHERE leaf_index IS NOT NULL`

// T-U-18: a new database has the fixed text of the event table and of its
// indexes, not only the text of the embedded file.
func TestTU18EventSchemaEqualsFixedText(t *testing.T) {
	var got string
	q := "SELECT group_concat(sql, char(10)) FROM (SELECT sql FROM sqlite_master WHERE tbl_name = 'event' ORDER BY rowid)"
	if err := migrated(t).QueryRow(q).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != eventSchemaText {
		t.Fatalf("the event schema differs from the fixed text:\n%s\n%s", got, eventSchemaText)
	}
}

// T-U-18: the only migration is the first one, and a new database has
// schema_version 1.
func TestTU18OnlyFirstMigrationExists(t *testing.T) {
	files, err := fs.ReadDir(migrationFiles, "migrations")
	if err != nil || len(files) != 1 || files[0].Name() != "0001_schema_v1.sql" {
		t.Fatalf("migration files %v: %v", files, err)
	}
	if v := metaValue(t, migrated(t), "schema_version"); v != "1" {
		t.Fatalf("schema_version %s", v)
	}
}

// T-S-22: the schema refuses a refused row with a hash, a leaf index or a
// record, and takes a refused row with none of them.
func TestTS22RefusedRowHasNoHashLeafOrRecord(t *testing.T) {
	const ev = "INSERT INTO event (ts, kind, hash, leaf_index, record) VALUES (1, 'refused', ?, ?, ?)"
	h := bytes.Repeat([]byte{7}, 32)
	db := migrated(t)
	for name, args := range map[string][]any{
		"hash":       {h, nil, nil},
		"leaf index": {nil, 7, nil},
		"record":     {nil, nil, []byte("rec")},
	} {
		if _, err := db.Exec(ev, args...); err == nil || !strings.Contains(err.Error(), "CHECK constraint failed") {
			t.Errorf("refused row with a %s: %v", name, err)
		}
	}
	if _, err := db.Exec(ev, nil, nil, nil); err != nil {
		t.Fatalf("refused row with none: %v", err)
	}
}

// T-S-15: the schema refuses each bad row and takes the good rows, in order.
func TestTS15SchemaRefusesBadRows(t *testing.T) {
	const (
		ev  = "INSERT INTO event (ts, kind, hash, leaf_index, record) VALUES (1, ?, ?, ?, ?)"
		cp  = "INSERT INTO checkpoint (tree_size, root_hash, signed_note, created_at) VALUES (?, ?, 'n', 1)"
		ses = "INSERT INTO session (id, first_seen, last_seen, ip_hmac, band) VALUES ('s', 1, 1, 'h', ?)"
		chk = "CHECK constraint failed"
	)
	h, text := bytes.Repeat([]byte{7}, 32), strings.Repeat("a", 32)
	rec := []byte("rec")
	cases := []struct {
		name, q, want string
		args          []any
	}{
		{"evidence row", ev, "", []any{"callback", h, 0, rec}},
		{"request row", ev, "", []any{"request", nil, nil, nil}},
		{"checkpoint size 1", cp, "", []any{1, h}},
		{"band", ses, "", []any{"human"}},
		{"NULL hash and leaf", ev, chk, []any{"callback", nil, nil, nil}},
		{"hash, NULL leaf", ev, chk, []any{"callback", h, nil, nil}},
		{"NULL hash, leaf 7", ev, chk, []any{"callback", nil, 7, nil}},
		{"TEXT hash", ev, chk, []any{"callback", text, 7, nil}},
		{"leaf -1", ev, chk, []any{"callback", h, -1, nil}},
		{"31-byte hash", ev, chk, []any{"callback", h[:31], 7, nil}},
		{"REAL leaf", ev, chk, []any{"callback", h, 1.5, nil}},
		{"TEXT leaf", ev, chk, []any{"callback", h, "x", nil}},
		{"request with hash", ev, chk, []any{"request", h, nil, nil}},
		{"request with leaf", ev, chk, []any{"request", nil, 7, nil}},
		{"request with record", ev, chk, []any{"request", nil, nil, rec}},
		{"beacon with hash", ev, chk, []any{"beacon", h, nil, nil}},
		{"duplicate leaf", ev, "UNIQUE constraint failed", []any{"callback", h, 0, nil}},
		{"checkpoint size 0", cp, chk, []any{0, h}},
		{"checkpoint TEXT root", cp, chk, []any{2, text}},
		{"checkpoint 31-byte root", cp, chk, []any{2, h[:31]}},
		{"band", ses, chk, []any{"bogus"}},
	}
	db := migrated(t)
	for _, c := range cases {
		_, err := db.Exec(c.q, c.args...)
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%s: %v", c.name, err)
		case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
			t.Errorf("%s: want %q, got %v", c.name, c.want, err)
		}
	}
	// Retention sets record to NULL on an evidence row.
	res, err := db.Exec("UPDATE event SET record = NULL WHERE kind = 'callback'")
	if err != nil {
		t.Fatalf("retention update: %v", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		t.Fatalf("retention update: %d rows", n)
	}
}
