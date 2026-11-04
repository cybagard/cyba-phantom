package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/cybagard/cyba-phantom/internal/event"
)

const (
	tokenMarker   = "TOKENTEXT-marker-0123456789"
	tokenIDMarker = "TOKENID-marker-0123456789"
)

func mintEvent(t *testing.T, ts int64, session string, m event.MintRange) *event.Event {
	t.Helper()
	e, err := event.NewEvent(func() time.Time { return time.UnixMilli(ts) },
		event.Input{Kind: event.KindRequest, Session: session, Path: "/p", Mint: &m})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

type mintRow struct {
	setID       string
	unit, first int64
	count       int64
	session     *string
	issuedAt    int64
}

func mintRows(t *testing.T, db *sql.DB) (out []mintRow) {
	t.Helper()
	rows, err := db.Query("SELECT set_id, unit, first, count, session_id, issued_at FROM mint ORDER BY set_id, first")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var m mintRow
		if err := rows.Scan(&m.setID, &m.unit, &m.first, &m.count, &m.session, &m.issuedAt); err != nil {
			t.Fatal(err)
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func wantMint(t *testing.T, got []mintRow, want ...mintRow) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%d mint rows, want %d: %+v", len(got), len(want), got)
	}
	for i := range got {
		g, w := got[i], want[i]
		if g.setID != w.setID || g.unit != w.unit || g.first != w.first || g.count != w.count || g.issuedAt != w.issuedAt ||
			(g.session == nil) != (w.session == nil) || g.session != nil && *g.session != *w.session {
			t.Errorf("row %d: %+v, want %+v", i, g, w)
		}
	}
}

func ptr(s string) *string { return &s }

var mintSet = [8]byte{0xAA, 1, 2, 3, 4, 5, 6, 0xBB}

// T-S-31: a database of the first migration with a row in each table gets the
// empty mint table. No other table or index changes: the SQL text and the root
// page stay, so no table is rebuilt. The row counts and the event table stay.
func TestTS31MigrationAddsMintWithoutRebuild(t *testing.T) {
	root, _, _ := newState(t)
	db := mustOpen(t, root, "events.db")
	first := fstest.MapFS{"0001_schema_v1.sql": testSet(nil)["0001_schema_v1.sql"]}
	if err := migrate(db, first, "origin"); err != nil {
		t.Fatal(err)
	}
	if metaValue(t, db, "schema_version") != "1" {
		t.Fatal("not a schema 1 database")
	}
	for _, s := range []string{
		"INSERT INTO session (id, first_seen, last_seen, ip_hmac, band) VALUES ('s1', 1, 2, 'h', 'human')",
		"INSERT INTO event (ts, session_id, kind, path) VALUES (1, 's1', 'request', '/a')",
		"INSERT INTO event (ts, session_id, kind, hash, leaf_index, record) VALUES (2, 's1', 'callback', zeroblob(32), 0, x'01')",
		"INSERT INTO token (token_id, session_id, trap_id, issued_at) VALUES ('t1', 's1', 'trap', 3)",
		"INSERT INTO aggregate_day (day, vhost, band, sessions, requests, callbacks) VALUES ('2026-01-01', 'v', 'human', 1, 1, 0)",
		"INSERT INTO ip_counter (day, ip_hmac, requests, dropped) VALUES ('2026-01-01', 'h', 1, 0)",
		"INSERT INTO checkpoint (tree_size, root_hash, signed_note, created_at) VALUES (1, zeroblob(32), 'note', 4)",
	} {
		if _, err := db.Exec(s); err != nil {
			t.Fatal(err)
		}
	}
	type entry struct {
		typ, sql string
		page     int64
		rows     int64
	}
	schema := func() map[string]entry {
		t.Helper()
		out := map[string]entry{}
		rows, err := db.Query("SELECT type, name, sql, rootpage FROM sqlite_schema")
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		for rows.Next() {
			var typ, name string
			var text sql.NullString
			var page int64
			if err := rows.Scan(&typ, &name, &text, &page); err != nil {
				t.Fatal(err)
			}
			out[name] = entry{typ: typ, sql: text.String, page: page}
		}
		for name, e := range out {
			if e.typ == "table" {
				if err := db.QueryRow(fmt.Sprintf("SELECT count(*) FROM %q", name)).Scan(&e.rows); err != nil {
					t.Fatal(err)
				}
				out[name] = e
			}
		}
		return out
	}
	before := schema()
	if before["event"].rows != 2 || before["session"].rows != 1 || before["token"].rows != 1 || before["ip_counter"].rows != 1 || before["checkpoint"].rows != 1 {
		t.Fatalf("setup rows: %+v", before)
	}
	if err := Migrate(db, "origin"); err != nil {
		t.Fatal(err)
	}
	after := schema()
	if metaValue(t, db, "schema_version") != "2" {
		t.Fatalf("schema_version %s", metaValue(t, db, "schema_version"))
	}
	for name, was := range before {
		if after[name] != was {
			t.Errorf("%s changed: %+v, was %+v", name, after[name], was)
		}
	}
	if len(after) != len(before)+1 || after["mint"].typ != "table" || after["mint"].rows != 0 {
		t.Errorf("new entries: %+v", after)
	}
	if n := len(mintRows(t, db)); n != 0 {
		t.Errorf("%d mint rows after the migration", n)
	}
	// The event table text is the text of the binary: a second open passes the
	// check of the event table.
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db = mustOpen(t, root, "events.db")
	t.Cleanup(func() { db.Close() })
	if err := Migrate(db, "origin"); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
}

// T-S-31: the file of the migration holds the table and nothing else.
func TestTS31MintMigrationIsOneTable(t *testing.T) {
	b, err := migrationFiles.ReadFile("migrations/0002_mint.sql")
	if err != nil {
		t.Fatal(err)
	}
	s := strings.ToUpper(string(b))
	if strings.Count(s, ";") != 1 || strings.Count(s, "CREATE ") != 1 || !strings.HasPrefix(s, "CREATE TABLE MINT") ||
		strings.Contains(s, "INDEX") || strings.Contains(s, "CHECK") || strings.Contains(s, "NOT NULL") || !strings.Contains(s, "WITHOUT ROWID") {
		t.Fatalf("unexpected migration text:\n%s", b)
	}
}

// T-S-31: a request event with a range goes through the queue and Run. It gives
// one mint row with the range and the session of the event row. The table has
// the six columns. No value holds token text or a token id.
func TestTS31RequestWithRangeGivesOneMintRow(t *testing.T) {
	r := newRig(t, 100)
	m := event.MintRange{SetID: mintSet, Unit: 4321, First: 1 << 40, Count: 68, IssuedAt: 1758300000123}
	e, err := event.NewEvent(func() time.Time { return time.UnixMilli(7) }, event.Input{
		Kind: event.KindRequest, Session: "sess-1", Path: "/" + tokenMarker, TokenID: tokenIDMarker, Mint: &m})
	if err != nil {
		t.Fatal(err)
	}
	stop := r.start()
	if !r.q.Enqueue(e) {
		t.Fatal("enqueue failed")
	}
	r.drained()
	r.fire()
	wantCommits(t, r, 1)
	if err := stop(); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	wantMint(t, mintRows(t, r.db), mintRow{setID: string(mintSet[:]), unit: 4321, first: 1 << 40, count: 68, session: ptr("sess-1"), issuedAt: 1758300000123})

	rows, err := r.db.Query("SELECT name FROM pragma_table_info('mint') ORDER BY cid")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var cols []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			t.Fatal(err)
		}
		cols = append(cols, c)
	}
	if want := []string{"set_id", "unit", "first", "count", "session_id", "issued_at"}; !slices.Equal(cols, want) {
		t.Fatalf("columns %v, want %v", cols, want)
	}
	var vals string
	if err := r.db.QueryRow("SELECT hex(set_id) || '|' || unit || '|' || first || '|' || count || '|' || coalesce(session_id, '') || '|' || issued_at FROM mint").Scan(&vals); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(vals, tokenMarker) || strings.Contains(vals, tokenIDMarker) {
		t.Fatalf("a token marker is in the row: %s", vals)
	}
}

// T-S-31: a request without a session gives a row with a NULL session. A
// request without a range gives no row.
func TestTS31MintRowSessionAndNoRange(t *testing.T) {
	r := newRig(t, 100)
	m := event.MintRange{SetID: mintSet, Unit: 1, First: 5, Count: 2, IssuedAt: 9}
	plain, err := event.NewEvent(nil, event.Input{Kind: event.KindRequest, Session: "s"})
	if err != nil {
		t.Fatal(err)
	}
	r.writeOK(mintEvent(t, 1, "", m), plain)
	wantMint(t, mintRows(t, r.db), mintRow{setID: string(mintSet[:]), unit: 1, first: 5, count: 2, issuedAt: 9})
}

// T-S-31: two events with one key (set_id, first) give no error and no stop.
// The test runs them in one batch, and in two batches. The first row stays.
// The writer counts one duplicate.
func TestTS31DuplicateMintKeyDoesNotStopTheWriter(t *testing.T) {
	a := event.MintRange{SetID: mintSet, Unit: 1, First: 100, Count: 10, IssuedAt: 11}
	b := event.MintRange{SetID: mintSet, Unit: 2, First: 100, Count: 20, IssuedAt: 22}
	other := event.MintRange{SetID: [8]byte{9}, Unit: 1, First: 100, Count: 10, IssuedAt: 33}
	want := []mintRow{
		{setID: string(mintSet[:]), unit: 1, first: 100, count: 10, session: ptr("first"), issuedAt: 11},
		{setID: string([]byte{9, 0, 0, 0, 0, 0, 0, 0}), unit: 1, first: 100, count: 10, session: ptr("o"), issuedAt: 33},
	}
	slices.SortFunc(want, func(x, y mintRow) int { return strings.Compare(x.setID, y.setID) })
	t.Run("one batch", func(t *testing.T) {
		r := newRig(t, 100)
		r.writeOK(mintEvent(t, 1, "first", a), mintEvent(t, 2, "second", b), mintEvent(t, 3, "o", other))
		wantMint(t, mintRows(t, r.db), want...)
		if n := r.w.MintDuplicates(); n != 1 {
			t.Errorf("%d duplicates, want 1", n)
		}
		if r.rows() != 3 {
			t.Errorf("%d event rows, want 3", r.rows())
		}
	})
	t.Run("two batches", func(t *testing.T) {
		r := newRig(t, 100)
		r.writeOK(mintEvent(t, 1, "first", a), mintEvent(t, 3, "o", other))
		if n := r.w.MintDuplicates(); n != 0 {
			t.Errorf("%d duplicates after the first batch, want 0", n)
		}
		r.writeOK(mintEvent(t, 2, "second", b))
		wantMint(t, mintRows(t, r.db), want...)
		if n := r.w.MintDuplicates(); n != 1 {
			t.Errorf("%d duplicates, want 1", n)
		}
	})
}

// T-S-31: a batch that is rolled back adds nothing to the duplicate count.
func TestTS31RolledBackBatchCountsNoDuplicate(t *testing.T) {
	r := newRig(t, 100)
	m := event.MintRange{SetID: mintSet, Unit: 1, First: 100, Count: 10, IssuedAt: 1}
	r.writeOK(mintEvent(t, 1, "s", m))
	r.w.beforeCommit = func(*sql.Tx) error { return errors.New("no commit") }
	r.w.flush([]*event.Event{mintEvent(t, 2, "s", m)})
	if r.w.Healthy() {
		t.Fatal("the writer did not stop at the failed COMMIT")
	}
	if n := r.w.MintDuplicates(); n != 0 {
		t.Fatalf("%d duplicates after a rolled-back batch, want 0", n)
	}
}

// T-S-31: a range that passes 2^42 gives two rows with the same set, unit,
// session and time.
func TestTS31WrappedRangeGivesTwoRows(t *testing.T) {
	r := newRig(t, 100)
	r.writeOK(mintEvent(t, 1, "w", event.MintRange{SetID: mintSet, Unit: 6, First: 1<<42 - 3, Count: 5, IssuedAt: 77}))
	s := string(mintSet[:])
	wantMint(t, mintRows(t, r.db),
		mintRow{setID: s, unit: 6, first: 0, count: 2, session: ptr("w"), issuedAt: 77},
		mintRow{setID: s, unit: 6, first: 1<<42 - 3, count: 3, session: ptr("w"), issuedAt: 77})
	// A range that ends at 2^42 exactly does not wrap.
	r.writeOK(mintEvent(t, 2, "w", event.MintRange{SetID: mintSet, Unit: 6, First: 1<<42 - 4, Count: 4, IssuedAt: 78}))
	if n := len(mintRows(t, r.db)); n != 3 {
		t.Errorf("%d rows, want 3", n)
	}
	// Two rows that are both duplicates count two.
	r.writeOK(mintEvent(t, 3, "w", event.MintRange{SetID: mintSet, Unit: 6, First: 1<<42 - 3, Count: 5, IssuedAt: 77}))
	if n := r.w.MintDuplicates(); n != 2 {
		t.Errorf("%d duplicates, want 2", n)
	}
}

// T-P-11: N renders with a range of 68 each give N mint rows. Each row takes
// at most 80 bytes in the b-tree (dbstat). The lookup of a counter searches the
// primary key.
// PHANTOM_TP11=1 sets N to 1 000 000.
func TestTP11MintRowsTakeAtMost80Bytes(t *testing.T) {
	n := 20_000
	if os.Getenv("PHANTOM_TP11") == "1" {
		n = 1_000_000
	}
	r := newRig(t, 100)
	sessions := []string{"aaaaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbbbb", "cccccccccccccccccccccccccc", "dddddddddddddddddddddddddd"}
	const base = 1758300000000
	batch := make([]*event.Event, 0, maxBatch)
	for i := range n {
		set := [8]byte{byte(1 + i*4/n), 0xCD, 3, 4, 5, 6, 7, 8}
		m := event.MintRange{SetID: set, Unit: uint32(i / 500), First: uint64(i%(n/4)) * 68, Count: 68, IssuedAt: base + int64(i)*7}
		batch = append(batch, mintEvent(t, base+int64(i), sessions[i%len(sessions)], m))
		if len(batch) == maxBatch || i == n-1 {
			r.writeOK(batch...)
			batch = batch[:0]
		}
	}
	var rows, bytes int64
	if err := r.db.QueryRow("SELECT (SELECT count(*) FROM mint), (SELECT sum(pgsize) FROM dbstat WHERE name = 'mint')").Scan(&rows, &bytes); err != nil {
		t.Fatal(err)
	}
	per := float64(bytes) / float64(rows)
	t.Logf("%d mint rows, %d bytes in the b-tree, %.1f bytes for each row", rows, bytes, per)
	if rows != int64(n) || per > 80 {
		t.Fatalf("rows %d (want %d), %.1f bytes for each row (want at most 80)", rows, n, per)
	}
	plan, err := r.db.Query("EXPLAIN QUERY PLAN SELECT session_id, issued_at FROM mint WHERE set_id = ? AND first <= ? ORDER BY first DESC LIMIT 1", mintSet[:], 1000)
	if err != nil {
		t.Fatal(err)
	}
	defer plan.Close()
	var details []string
	for plan.Next() {
		var id, parent, unused int
		var d string
		if err := plan.Scan(&id, &parent, &unused, &d); err != nil {
			t.Fatal(err)
		}
		details = append(details, d)
	}
	all := strings.Join(details, "; ")
	t.Logf("plan: %s", all)
	if !strings.Contains(all, "SEARCH mint USING PRIMARY KEY") || strings.Contains(all, "SCAN") || strings.Contains(all, "TEMP B-TREE") {
		t.Fatalf("plan %q", all)
	}
}
