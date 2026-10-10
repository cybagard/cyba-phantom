package store

import (
	"bytes"
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
