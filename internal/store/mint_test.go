package store

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"slices"
	"strconv"
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
	rows, err := db.Query("SELECT set_id, unit, first, count, session_id, issued_at FROM mint ORDER BY set_id, unit, first")
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
	if err := migrate(db, testSet(nil), "origin"); err != nil {
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
	before := schemaEntries(t, db)
	if before["event"].rows != 2 || before["session"].rows != 1 || before["token"].rows != 1 || before["ip_counter"].rows != 1 || before["checkpoint"].rows != 1 {
		t.Fatalf("setup rows: %+v", before)
	}
	if err := migrate(db, schema2Set(t), "origin"); err != nil {
		t.Fatal(err)
	}
	after := schemaEntries(t, db)
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
	if err := migrate(db, schema2Set(t), "origin"); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
}

// schema2Set is the embedded first two migrations: the schema of version 2.
func schema2Set(tb testing.TB) fstest.MapFS {
	tb.Helper()
	set := testSet(nil)
	second, err := migrationFiles.ReadFile("migrations/0002_mint.sql")
	if err != nil {
		tb.Fatal(err)
	}
	set["0002_mint.sql"] = &fstest.MapFile{Data: second}
	return set
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

// T-S-31: two renders with one first counter in two time units keep both rows.
func TestTS31SameFirstCounterInTwoUnitsKeepsBothRows(t *testing.T) {
	r := newRig(t, 100)
	r.writeOK(
		mintEvent(t, 1, "five", event.MintRange{SetID: mintSet, Unit: 5, First: 500, Count: 10, IssuedAt: 11}),
		mintEvent(t, 2, "six", event.MintRange{SetID: mintSet, Unit: 6, First: 500, Count: 20, IssuedAt: 22}))
	s := string(mintSet[:])
	wantMint(t, mintRows(t, r.db),
		mintRow{setID: s, unit: 5, first: 500, count: 10, session: ptr("five"), issuedAt: 11},
		mintRow{setID: s, unit: 6, first: 500, count: 20, session: ptr("six"), issuedAt: 22})
	if n := r.w.MintDuplicates(); n != 0 {
		t.Errorf("%d duplicates, want 0", n)
	}
}

// T-S-31: two events with one key (set_id, unit, first) give no error and no
// stop. The test runs them in one batch, and in two batches. The kept row gets
// a NULL session and keeps its other values. No other row changes. That holds
// for a row of the same set and first in another unit. It holds for a row of
// the same set and unit at another first. The writer counts one duplicate. A
// later batch commits.
func TestTS31DuplicateMintKeyDoesNotStopTheWriter(t *testing.T) {
	s := string(mintSet[:])
	a := event.MintRange{SetID: mintSet, Unit: 1, First: 100, Count: 10, IssuedAt: 11}
	b := event.MintRange{SetID: mintSet, Unit: 1, First: 100, Count: 20, IssuedAt: 22}
	otherUnit := event.MintRange{SetID: mintSet, Unit: 2, First: 100, Count: 10, IssuedAt: 33}
	otherFirst := event.MintRange{SetID: mintSet, Unit: 1, First: 200, Count: 10, IssuedAt: 44}
	otherSet := event.MintRange{SetID: [8]byte{9}, Unit: 1, First: 100, Count: 10, IssuedAt: 55}
	later := event.MintRange{SetID: mintSet, Unit: 1, First: 300, Count: 10, IssuedAt: 66}
	want := []mintRow{
		{setID: string([]byte{9, 0, 0, 0, 0, 0, 0, 0}), unit: 1, first: 100, count: 10, session: ptr("o"), issuedAt: 55},
		{setID: s, unit: 1, first: 100, count: 10, issuedAt: 11},
		{setID: s, unit: 1, first: 200, count: 10, session: ptr("f"), issuedAt: 44},
		{setID: s, unit: 1, first: 300, count: 10, session: ptr("l"), issuedAt: 66},
		{setID: s, unit: 2, first: 100, count: 10, session: ptr("u"), issuedAt: 33},
	}
	check := func(t *testing.T, r *rig) {
		t.Helper()
		r.writeOK(mintEvent(t, 9, "l", later))
		wantMint(t, mintRows(t, r.db), want...)
		if n := r.w.MintDuplicates(); n != 1 {
			t.Errorf("%d duplicates, want 1", n)
		}
		if !r.w.Healthy() || r.rows() != 6 {
			t.Errorf("healthy %v, %d event rows, want a healthy writer and 6 rows", r.w.Healthy(), r.rows())
		}
	}
	t.Run("one batch", func(t *testing.T) {
		r := newRig(t, 100)
		r.writeOK(mintEvent(t, 1, "first", a), mintEvent(t, 2, "second", b), mintEvent(t, 3, "u", otherUnit),
			mintEvent(t, 4, "f", otherFirst), mintEvent(t, 5, "o", otherSet))
		check(t, r)
	})
	t.Run("two batches", func(t *testing.T) {
		r := newRig(t, 100)
		r.writeOK(mintEvent(t, 1, "first", a), mintEvent(t, 3, "u", otherUnit),
			mintEvent(t, 4, "f", otherFirst), mintEvent(t, 5, "o", otherSet))
		if n := r.w.MintDuplicates(); n != 0 {
			t.Errorf("%d duplicates after the first batch, want 0", n)
		}
		r.writeOK(mintEvent(t, 2, "second", b))
		check(t, r)
	})
}

// T-S-31: a duplicate key of a range that wraps marks the row of each part.
// The mark uses the first counter that the insert used.
func TestTS31DuplicateWrappedRangeMarksBothParts(t *testing.T) {
	r := newRig(t, 100)
	m := event.MintRange{SetID: mintSet, Unit: 6, First: 1<<42 - 3, Count: 5, IssuedAt: 77}
	r.writeOK(mintEvent(t, 1, "w", m), mintEvent(t, 2, "again", m))
	s := string(mintSet[:])
	wantMint(t, mintRows(t, r.db),
		mintRow{setID: s, unit: 6, first: 0, count: 2, issuedAt: 77},
		mintRow{setID: s, unit: 6, first: 1<<42 - 3, count: 3, issuedAt: 77})
	if n := r.w.MintDuplicates(); n != 2 {
		t.Errorf("%d duplicates, want 2", n)
	}
}

// T-S-31: an error of the update that marks a duplicate key stops the writer.
// An error of the insert does the same. The batch rolls back.
func TestTS31MintMarkErrorStopsTheWriter(t *testing.T) {
	m := event.MintRange{SetID: mintSet, Unit: 1, First: 5, Count: 2, IssuedAt: 9}
	for name, setup := range map[string]string{
		// The trigger runs when the update changes a row.
		"run": "CREATE TRIGGER no_mark BEFORE UPDATE ON mint BEGIN SELECT RAISE(ABORT,'x'); END",
		// SQLite compiles a trigger body with the statement that fires it.
		// So the prepare of the update fails, and the insert prepare does not.
		"prepare": "CREATE TRIGGER bad_mark BEFORE UPDATE ON mint BEGIN INSERT INTO missing_table VALUES (1); END",
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, 100)
			r.writeOK(mintEvent(t, 1, "s", m))
			if _, err := r.db.Exec(setup); err != nil {
				t.Fatal(err)
			}
			r.w.flush([]*event.Event{mintEvent(t, 2, "again", m)})
			wantRule(t, r.w.Err(), writerName, ruleDatabase)
			if r.w.Healthy() || r.rows() != 1 {
				t.Fatalf("healthy %v, %d event rows, want a stopped writer and 1 row", r.w.Healthy(), r.rows())
			}
			wantMint(t, mintRows(t, r.db), mintRow{setID: string(mintSet[:]), unit: 1, first: 5, count: 2, session: ptr("s"), issuedAt: 9})
			if n := r.w.MintDuplicates(); n != 0 {
				t.Errorf("%d duplicates after a rolled-back batch, want 0", n)
			}
		})
	}
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
// PHANTOM_TP11=1 sets N to 1 000 000. Run this form with 1 CPU, 512 MB of
// memory, no swap, GOMEMLIMIT=256MiB and no -race.
func TestTP11MintRowsTakeAtMost80Bytes(t *testing.T) {
	n := 20_000
	if os.Getenv("PHANTOM_TP11") == "1" {
		n = 1_000_000
	}
	r := newRig(t, 100)
	// The rig hook sends on a channel with room for 64 commits. Nobody reads it
	// here, so the hook only counts.
	commits := 0
	r.w.onCommit = func(int) { commits++ }
	sessions := []string{"aaaaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbbbb", "cccccccccccccccccccccccccc", "dddddddddddddddddddddddddd"}
	const base = 1758300000000
	batch := make([]*event.Event, 0, maxBatch)
	for i := range n {
		set := [8]byte{byte(1 + i*4/n), 0xCD, 3, 4, 5, 6, 7, 8}
		// The values are wide, as real values are. The first counter is near
		// 3e12 and the unit is near 495 000. No range wraps.
		m := event.MintRange{SetID: set, Unit: 495_000 + uint32(i/500), First: 3_000_000_000_000 + uint64(i%(n/4))*68, Count: 68, IssuedAt: base + int64(i)*7}
		batch = append(batch, mintEvent(t, base+int64(i), sessions[i%len(sessions)], m))
		if len(batch) == maxBatch || i == n-1 {
			r.writeOK(batch...)
			batch = batch[:0]
		}
	}
	if want := (n + maxBatch - 1) / maxBatch; commits != want || r.rows() != n {
		t.Fatalf("%d commits (want %d), %d event rows (want %d)", commits, want, r.rows(), n)
	}
	var rows, bytes int64
	if err := r.db.QueryRow("SELECT (SELECT count(*) FROM mint),(SELECT sum(pgsize) FROM dbstat WHERE name = 'mint')").Scan(&rows, &bytes); err != nil {
		t.Fatal(err)
	}
	per := float64(bytes) / float64(rows)
	t.Logf("%d mint rows, %d bytes in the b-tree, %.1f bytes for each row", rows, bytes, per)
	if rows != int64(n) || per > 80 {
		t.Fatalf("rows %d (want %d), %.1f bytes for each row (want at most 80)", rows, n, per)
	}
	all := strings.Join(queryPlan(t, r.db, lookupMint, mintSet[:], 495_000, 1000, 1000, 1000), "; ")
	t.Logf("plan: %s", all)
	if all != lookupPlan {
		t.Fatalf("plan %q, want %q", all, lookupPlan)
	}
	if n < 1_000_000 {
		return
	}
	// The large form also reads the RSS 30 s after the load, as the load
	// benchmark does. The pass line is rssLimit.
	time.Sleep(loadIdle)
	rss, hwm := procStatusBytes(t, "VmRSS"), procStatusBytes(t, "VmHWM")
	t.Logf("RSS 30 s after the load %d bytes, peak %d bytes", rss, hwm)
	if rss > rssLimit {
		t.Fatalf("RSS %d bytes, want at most %d", rss, rssLimit)
	}
}

// procStatusBytes returns a field of /proc/self/status in bytes. It copies
// procStatus of rows_bench_test.go, which needs a *testing.B.
func procStatusBytes(t *testing.T, field string) int64 {
	t.Helper()
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if rest, ok := strings.CutPrefix(line, field+":"); ok {
			kib, err := strconv.ParseInt(strings.Fields(rest)[0], 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			return kib * 1024
		}
	}
	t.Fatalf("no %s in /proc/self/status", field)
	return 0
}

// failingMint stores one request event with a range after the setup statement
// has changed the schema. The statement must make the mint insert, or its
// prepare, fail. The flag tableDropped is true when the setup drops the table.
func failingMint(t *testing.T, setup string, tableDropped bool) {
	t.Helper()
	r := newRig(t, 100)
	if _, err := r.db.Exec(setup); err != nil {
		t.Fatal(err)
	}
	m := event.MintRange{SetID: mintSet, Unit: 1, First: 5, Count: 2, IssuedAt: 9}
	r.w.flush([]*event.Event{mintEvent(t, 1, "s", m)})
	wantRule(t, r.w.Err(), writerName, ruleDatabase)
	if r.w.Healthy() || r.rows() != 0 {
		t.Fatalf("healthy %v, %d event rows, want a stopped writer and 0 rows", r.w.Healthy(), r.rows())
	}
	if d := r.w.Stats().Dropped; d != (Drops{Bulk: 1}) {
		t.Fatalf("drops %+v, want one bulk drop", d)
	}
	if !tableDropped {
		if n := len(mintRows(t, r.db)); n != 0 {
			t.Fatalf("%d mint rows, want 0", n)
		}
	}
}

// T-S-31: an error of the mint insert stops the writer. The transaction rolls
// back, so the batch has no event row and no mint row.
func TestTS31MintInsertErrorStopsTheWriter(t *testing.T) {
	failingMint(t, "CREATE TRIGGER no_mint BEFORE INSERT ON mint BEGIN SELECT RAISE(ABORT,'x'); END", false)
}

// T-S-31: an error at the prepare of the mint insert stops the writer in the
// same way.
func TestTS31MintPrepareErrorStopsTheWriter(t *testing.T) {
	failingMint(t, "DROP TABLE mint", true)
}
