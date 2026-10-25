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

// schemaText is the fixed text of the schema of a new database. It has each
// statement as sqlite_master stores it, with no semicolon and no comment.
const schemaText = `CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)
CREATE TABLE session (
  id            TEXT PRIMARY KEY,
  first_seen    INTEGER NOT NULL,
  last_seen     INTEGER NOT NULL,
  ip            TEXT,
  ip_hmac       TEXT NOT NULL,
  ja4           TEXT, h2_fp TEXT, ua TEXT, hdr_order_hash TEXT,
  beacon_seen   INTEGER NOT NULL DEFAULT 0,
  req_count     INTEGER NOT NULL DEFAULT 0,
  band          TEXT NOT NULL CHECK (band IN ('human','crawler','agent-likely','agent-confirmed')),
  score         INTEGER NOT NULL DEFAULT 0,
  family        TEXT,
  alerted_at    INTEGER
)
CREATE INDEX session_band_last ON session(band, last_seen)
CREATE INDEX session_iphmac ON session(ip_hmac)
CREATE TABLE event (
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
CREATE UNIQUE INDEX event_leaf ON event(leaf_index) WHERE leaf_index IS NOT NULL
CREATE TABLE token (
  token_id      TEXT PRIMARY KEY,
  session_id    TEXT NOT NULL,
  trap_id       TEXT NOT NULL,
  issued_at     INTEGER NOT NULL,
  first_cb_at   INTEGER,
  cb_count      INTEGER NOT NULL DEFAULT 0
)
CREATE TABLE aggregate_day (
  day TEXT NOT NULL, vhost TEXT NOT NULL, band TEXT NOT NULL, family TEXT,
  sessions INTEGER NOT NULL, requests INTEGER NOT NULL, callbacks INTEGER NOT NULL,
  PRIMARY KEY (day, vhost, band, family)
)
CREATE TABLE ip_counter (
  day TEXT NOT NULL, ip_hmac TEXT NOT NULL, requests INTEGER NOT NULL, dropped INTEGER NOT NULL,
  PRIMARY KEY (day, ip_hmac)
)
CREATE TABLE checkpoint (
  tree_size INTEGER PRIMARY KEY CHECK (tree_size >= 1),
  root_hash BLOB NOT NULL CHECK (typeof(root_hash) = 'blob' AND length(root_hash) = 32),
  signed_note TEXT NOT NULL, created_at INTEGER NOT NULL
)`

// T-U-18: a new database has the fixed text of each table and index. The text
// of the embedded file is not the only proof.
func TestTU18SchemaEqualsFixedText(t *testing.T) {
	var got string
	q := "SELECT group_concat(sql, char(10)) FROM (SELECT sql FROM sqlite_master WHERE sql IS NOT NULL ORDER BY rowid)"
	if err := migrated(t).QueryRow(q).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != schemaText {
		t.Fatalf("the schema differs from the fixed text:\n%s\n%s", got, schemaText)
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

// T-S-22: the schema rejects a row of the `refused` kind with a hash, a leaf
// index or a record. It takes a row of this kind with none of them.
func TestTS22RefusedRowHasNoHashLeafOrRecord(t *testing.T) {
	const ev = "INSERT INTO event (ts, kind, hash, leaf_index, record) VALUES (1, 'refused', ?, ?, ?)"
	h := bytes.Repeat([]byte{7}, 32)
	db := migrated(t)
	for _, c := range []struct {
		name string
		args []any
	}{
		{"hash", []any{h, nil, nil}},
		{"leaf index", []any{nil, 7, nil}},
		{"record", []any{nil, nil, []byte("rec")}},
		{"hash, leaf index and record", []any{h, 7, []byte("rec")}},
	} {
		if _, err := db.Exec(ev, c.args...); err == nil || !strings.Contains(err.Error(), "CHECK constraint failed") {
			t.Errorf("refused row with a %s: %v", c.name, err)
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
