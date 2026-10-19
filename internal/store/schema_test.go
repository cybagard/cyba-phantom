package store

import (
	"bytes"
	"maps"
	"regexp"
	"strings"
	"testing"
)

var createName = regexp.MustCompile(`^CREATE (?:UNIQUE )?(?:TABLE|INDEX) (\w+)`)

// ddlOf returns the CREATE statements of the embedded migrations by object name,
// without the final semicolon, as SQLite stores them. A statement of a later
// migration replaces the one of the same name.
func ddlOf(t *testing.T, files ...string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, f := range files {
		b, err := migrationFiles.ReadFile("migrations/" + f)
		if err != nil {
			t.Fatal(err)
		}
		for _, stmt := range strings.Split(strings.TrimSpace(string(b)), ";\n") {
			if m := createName.FindStringSubmatch(stmt); m != nil {
				out[m[1]] = strings.TrimSuffix(stmt, ";")
			}
		}
	}
	return out
}

// T-U-18: sqlite_master equals the embedded DDL of 0001 and 0002; checkpoint has
// no publish column. The compare is by object name because the rebuild gives the
// event table and its indexes new positions. 0002 renames the old table first and
// makes the new table with its own text, so sqlite_master holds that text as it
// is, with no quotes around the name.
func TestTU18SchemaEqualsEmbeddedDDL(t *testing.T) {
	db := migrated(t)
	want := ddlOf(t, "0001_schema_v1.sql", "0002_refused_kind.sql")
	got := map[string]string{}
	rows, err := db.Query("SELECT name, sql FROM sqlite_master WHERE sql IS NOT NULL")
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var name, stmt string
		if err := rows.Scan(&name, &stmt); err != nil {
			t.Fatal(err)
		}
		got[name] = stmt
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	if !maps.Equal(got, want) || len(want) != 13 || strings.Count(want["event"], "'refused'") != 3 {
		t.Fatalf("sqlite_master differs from the embedded DDL:\n%q\n%q", got, want)
	}
	var n int
	q := "SELECT count(*) FROM pragma_table_info('checkpoint') WHERE name IN ('published_at', 'publish_target')"
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
