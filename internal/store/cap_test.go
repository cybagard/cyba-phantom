package store

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cybagard/cyba-phantom/internal/token"
)

// capDay is the time of 10:00 UTC on a day of January 2027, in unix ms.
func capDay(n int) int64 { return utc(fmt.Sprintf("2027-01-%02dT10:00:00Z", n)) }

// capLabels lists the rows that the cap can remove, as kind@day, in order.
func capLabels(t *testing.T, db *sql.DB) []string {
	t.Helper()
	rows, err := db.Query(`SELECT l FROM (
		SELECT kind || '@' || strftime('%d', ts/1000, 'unixepoch') AS l FROM event UNION ALL
		SELECT 'session@' || strftime('%d', last_seen/1000, 'unixepoch') FROM session UNION ALL
		SELECT 'mint@' || strftime('%d', issued_at/1000, 'unixepoch') FROM mint) ORDER BY l`)
	check(t, err)
	defer rows.Close()
	var out []string
	for rows.Next() {
		var l string
		check(t, rows.Scan(&l))
		out = append(out, l)
	}
	return out
}

// removed returns the labels of before that are not in after.
func removed(before, after []string) string {
	var gone []string
	for _, l := range before {
		if i := slices.Index(after, l); i >= 0 {
			after = slices.Delete(slices.Clone(after), i, i+1)
		} else {
			gone = append(gone, l)
		}
	}
	return strings.Join(gone, " ")
}

// addMint inserts one mint row of the unit of the time at, with the counter
// first.
func addMint(t *testing.T, db *sql.DB, at, first int64) {
	t.Helper()
	mustExec(t, db, "INSERT INTO mint (set_id, unit, first, count, session_id, issued_at) VALUES (x'01', ?, ?, 1, 's', ?)",
		token.Unit(time.UnixMilli(at)), first, at)
}

// forcedCap makes the cap state of a test that has begun and is over the cap.
// The measure never reaches the target, so the steps evict all they can.
func forcedCap(r *rig) *capRun {
	c := newCapRun(r.w, 1000, rollTDel)
	c.begun, c.over = true, true
	c.measure = func(context.Context, *sql.Tx) (int64, error) { return 1 << 40, nil }
	return c
}

// T-U-11: the cap evicts in tiers, and in each tier the oldest UTC day first.
// Tier 1 has request, refused and beacon rows. On one day, a request row goes
// before a refused row. Tier 2 has mint and session rows. Tier 3 has evidence
// rows. Tier 1 can be empty, and then a request row can come. That row goes
// before the session and mint rows that are left. Each call takes one source.
func TestTU11CapEvictsInTiersOldestDayFirst(t *testing.T) {
	r := newRig(t, 100)
	for _, d := range []int{3, 1, 2} {
		addEvents(t, r.db, "request", 1, capDay(d), 0, nil, nil)
	}
	addEvents(t, r.db, "refused", 1, capDay(2), 0, nil, nil)
	addEvents(t, r.db, "beacon", 1, capDay(4), 0, nil, nil)
	addEventAt(t, r.db, "score_change", capDay(5))
	addEventAt(t, r.db, "callback", capDay(1))
	for _, d := range []int{3, 1} {
		mustExec(t, r.db, "INSERT INTO session (id, first_seen, last_seen, ip_hmac, band) VALUES (?, 0, ?, 'h', 'human')", d, capDay(d))
	}
	addMint(t, r.db, capDay(2), 0)
	c := forcedCap(r)
	want := []string{"request@01", "request@02", "refused@02", "request@03", "beacon@04", "request@06",
		"session@01", "mint@02", "session@03", "callback@01", "score_change@05", ""}
	for i, w := range want {
		if i == 5 {
			// A request row, stored between two chunks.
			addEvents(t, r.db, "request", 1, capDay(6), 0, nil, nil)
		}
		before := capLabels(t, r.db)
		if n := call(t, r.db, c.evict, chunkRows); (n == 0) != (w == "") {
			t.Fatalf("call %d returned %d, want the limit unless no row is left", i, n)
		}
		if got := removed(before, capLabels(t, r.db)); got != w {
			t.Fatalf("call %d removed %q, want %q", i, got, w)
		}
	}
	if aggregates(t, r.db) == "" {
		t.Fatal("the request rows went with no roll-up")
	}
}

// T-U-11: a flood of request rows evicts no evidence row while a request row is
// left. 400 more rows come in the first chunk, so they are rows between two
// chunks. The measure is the count of event rows. It is at most 5 when only the
// 5 evidence rows are left. The roll-up keeps the count of each request.
func TestTU11CapFloodEvictsNoEvidenceWhileBulkRowsRemain(t *testing.T) {
	r := newRig(t, 100)
	addEvents(t, r.db, "callback", 5, capDay(1), 1000, nil, nil)
	addEvents(t, r.db, "request", 3000, capDay(2), 1000, nil, "v")
	c := forcedCap(r)
	c.target = 5
	c.measure = func(ctx context.Context, tx *sql.Tx) (n int64, err error) {
		return n, tx.QueryRowContext(ctx, "SELECT count(*) FROM event").Scan(&n)
	}
	flood := onCall(c.evict, func(i int, tx *sql.Tx) {
		if i == 1 {
			_, err := tx.Exec(`WITH RECURSIVE c(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM c WHERE i < 399)
				INSERT INTO event (ts, kind, vhost) SELECT ? + i, 'request', 'v' FROM c`, capDay(3))
			check(t, err)
		}
	})
	runAgain(t, r, flood)
	if cb, req, sum := count(t, r.db, "SELECT count(*) FROM event WHERE kind = 'callback'"),
		count(t, r.db, "SELECT count(*) FROM event WHERE kind = 'request'"),
		count(t, r.db, "SELECT sum(requests) FROM aggregate_day"); cb != 5 || req != 0 || sum != 3400 {
		t.Fatalf("%d callbacks, %d requests left, %d counted; want 5, 0 and 3400", cb, req, sum)
	}
}

// T-U-11: the cap deletes whole mint units. 3 units have 3 rows each. A limit
// of 4 removes one unit. It does not delete a row of the next unit.
func TestTU11CapKeepsMintUnitsWhole(t *testing.T) {
	r := newRig(t, 100)
	for u := range 3 {
		for f := range 3 {
			addMint(t, r.db, capDay(1)+int64(u)*600_000, int64(f))
		}
	}
	call(t, r.db, forcedCap(r).evict, 4)
	if rows, odd := count(t, r.db, "SELECT count(*) FROM mint"), count(t, r.db,
		"SELECT count(*) FROM (SELECT unit FROM mint GROUP BY unit HAVING count(*) != 3)"); rows != 6 || odd != 0 {
		t.Fatalf("%d mint rows, %d split units; want 6 and 0", rows, odd)
	}
}

// capFixture seeds 3 000 young request rows with a body. It returns the bytes
// of the database file after a TRUNCATE checkpoint.
func capFixture(t *testing.T, r *rig) int64 {
	t.Helper()
	mustExec(t, r.db, `WITH RECURSIVE c(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM c WHERE i < 2999)
		INSERT INTO event (ts, kind, vhost, body_prefix) SELECT ?, 'request', 'v', randomblob(300) FROM c`, rollTDel.UnixMilli()-3600_000)
	return truncated(t, r)
}

// truncated checkpoints the WAL of r. It returns the size of the database file.
func truncated(t *testing.T, r *rig) int64 {
	t.Helper()
	mustExec(t, r.db, "PRAGMA wal_checkpoint(TRUNCATE)")
	return fileSize(filepath.Join(r.state, "events.db"))
}

// capRunOf runs the cap steps and a mark step through the writer, with a run
// record. It returns the record.
func capRunOf(t *testing.T, r *rig, max int64) *retentionRun {
	t.Helper()
	run := &retentionRun{}
	steps := withCap([]retentionStep{markStep(rollTDel)}, run, r.w, max, rollTDel)
	ctx, cancel := context.WithTimeout(withRun(context.Background(), run), waitFor)
	defer cancel()
	check(t, serveWithRun(r)(ctx, steps))
	return run
}

// T-U-11: a cap at the exact size of the files does not evict: the size must
// be above the cap. A cap one byte below evicts.
func TestTU11CapEvictsOnlyAboveTheCap(t *testing.T) {
	for _, c := range []struct{ below, evicted bool }{{false, false}, {true, true}} {
		r := newRig(t, 100)
		size := capFixture(t, r)
		if c.below {
			size--
		}
		if run := capRunOf(t, r, size); (run.counts.Evicted > 0) != c.evicted {
			t.Fatalf("cap 1 byte below the size %v: evicted %d, want evicted %v", c.below, run.counts.Evicted, c.evicted)
		}
	}
}

// churn rewrites the same rows many times, so the WAL grows and the live pages
// stay the same.
func churn(t *testing.T, r *rig) {
	t.Helper()
	for i := range 300 {
		mustExec(t, r.db, "UPDATE event SET vhost = ? WHERE id = ?", fmt.Sprint("v", i), i+1)
	}
}

// T-U-11: the run empties the WAL before it measures. The WAL of 300 commits
// would make the size more than the cap. After the checkpoint, the size is 5 %
// below the cap, so no row goes.
func TestTU11CapSettlesTheWALBeforeItMeasures(t *testing.T) {
	r := newRig(t, 100)
	size := capFixture(t, r)
	churn(t, r)
	if wal := fileSize(filepath.Join(r.state, "events.db-wal")); wal < size/4 {
		t.Fatalf("the WAL has %d bytes, want a large one", wal)
	}
	run := capRunOf(t, r, size+size/20)
	if left := count(t, r.db, "SELECT count(*) FROM event WHERE kind = 'request'"); run.counts.Evicted != 0 || left != 3000 {
		t.Fatalf("evicted %d rows, %d left; want 0 and 3000", run.counts.Evicted, left)
	}
}

// T-U-11: the size has the WAL bytes. A reader keeps a snapshot, so the
// checkpoint cannot empty the WAL. The file is below the cap and the file with
// the WAL is above it. The run evicts, and a busy checkpoint is not an error.
func TestTU11CapCountsTheWALInTheSize(t *testing.T) {
	r := newRig(t, 100)
	size := capFixture(t, r)
	rdb := mustOpen(t, r.root, "events.db")
	defer rdb.Close()
	conn, err := rdb.Conn(context.Background())
	check(t, err)
	defer conn.Close()
	_, err = conn.ExecContext(context.Background(), "BEGIN")
	check(t, err)
	var n int
	check(t, conn.QueryRowContext(context.Background(), "SELECT count(*) FROM event").Scan(&n))
	churn(t, r)
	if run := capRunOf(t, r, size+size/20); run.counts.Evicted == 0 || r.w.RetentionCheckpointBusy() != 1 {
		t.Fatalf("evicted %d rows, busy %d; want rows evicted and 1 busy checkpoint", run.counts.Evicted, r.w.RetentionCheckpointBusy())
	}
}

// T-U-11: the cap evicts to 90 % of the cap and the vacuum shrinks the file to
// that line. A request row that the cap removes is in aggregate_day and in
// evicted, not in rolled. The vacuum pages are in vacuumed.
func TestTU11CapEvictsToNinetyPercentAndCounts(t *testing.T) {
	r := newRig(t, 100)
	max := capFixture(t, r) * 6 / 10
	run := capRunOf(t, r, max)
	left := count(t, r.db, "SELECT count(*) FROM event WHERE kind = 'request'")
	sum := count(t, r.db, "SELECT sum(requests) FROM aggregate_day")
	got, c := truncated(t, r), run.counts
	if c.Evicted == 0 || c.Evicted != int64(3000-left) || int64(sum) != c.Evicted || c.Rolled != 0 || c.Vacuumed == 0 {
		t.Fatalf("evicted %d, rolled %d, vacuumed %d, %d counted, %d left; want evicted = counted = %d removed", c.Evicted, c.Rolled, c.Vacuumed, sum, left, 3000-left)
	}
	if got > max*9/10 || newCapRun(r.w, 1000, rollTDel).target != 900 {
		t.Fatalf("file %d bytes, want at most 90 %% of the cap %d; the target is 900 for a cap of 1000", got, max)
	}
}

// T-U-11: a cap of 0 adds no step and evicts nothing. With a cap, the cap steps
// come before the mark step, which stays last. The mark step writes its mark
// after the last row has gone.
func TestTU11CapStepsRunBeforeTheMarkStep(t *testing.T) {
	steps := []retentionStep{markStep(rollTDel)}
	if got := withCap(steps, nil, nil, 0, rollTDel); len(got) != 1 {
		t.Fatalf("a cap of 0 gave %d steps, want 1", len(got))
	}
	for _, max := range []int64{0, 1} {
		r, s, _ := prodRig(t, 0, nil)
		s.SetMaxBytes(max)
		addEvents(t, r.db, "request", 3, rollTDel.UnixMilli()-3600_000, 1, nil, nil)
		atMark := -1
		s.run = func(ctx context.Context, steps []retentionStep) error {
			wrapped := make([]retentionStep, len(steps))
			for i, step := range steps {
				wrapped[i] = func(ctx context.Context, tx *sql.Tx, limit int) (int, error) {
					n, err := step(ctx, tx, limit)
					if _, ok, _ := metaGet(ctx, tx, retentionLastKey); ok && atMark < 0 {
						check(t, tx.QueryRowContext(ctx, "SELECT count(*) FROM event WHERE kind = 'request'").Scan(&atMark))
					}
					return n, err
				}
			}
			return serveWithRun(r)(ctx, wrapped)
		}
		s.runOnce(context.Background())
		left := count(t, r.db, "SELECT count(*) FROM event WHERE kind = 'request'")
		if want := map[int64]int{0: 3, 1: 0}[max]; atMark != want || left != want {
			t.Fatalf("cap %d: %d rows when the mark came, %d at the end; want %d", max, atMark, left, want)
		}
	}
}

// capDataset seeds the 100 days before rollTDel. Each day has a session with
// an address, 100 request rows with a body, and a callback with a body.
func capDataset(t *testing.T, r *rig) {
	t.Helper()
	mustExec(t, r.db, `WITH RECURSIVE d(k) AS (SELECT 0 UNION ALL SELECT k+1 FROM d WHERE k < 99)
		INSERT INTO session (id, first_seen, last_seen, ip, ip_hmac, band)
		SELECT 's' || k, ?1 - k*86400000, ?1 - k*86400000, '192.0.2.1', 'h', 'human' FROM d`, rollTDel.UnixMilli())
	mustExec(t, r.db, `WITH RECURSIVE d(k) AS (SELECT 0 UNION ALL SELECT k+1 FROM d WHERE k < 99), n(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM n WHERE i < 99)
		INSERT INTO event (ts, kind, session_id, vhost, body_prefix) SELECT ?1 - k*86400000 - i - 1, 'request', 's' || k, 'v', randomblob(300) FROM d, n`, rollTDel.UnixMilli())
	mustExec(t, r.db, `WITH RECURSIVE d(k) AS (SELECT 0 UNION ALL SELECT k+1 FROM d WHERE k < 99)
		INSERT INTO event (ts, kind, session_id, detail, body_prefix, hash, leaf_index)
		SELECT ?1 - k*86400000 - 500, 'callback', 's' || k, '{}', randomblob(8), zeroblob(32), k FROM d`, rollTDel.UnixMilli())
}

// T-U-11: the whole run over 100 days of data, with the cap. The address is
// NULL after 7 d. The callback detail is NULL after 30 d. The request rows of
// 30 d and older are in aggregate_day. The cap removes the request rows of the
// oldest days that are left, and no evidence row. The newest days stay. A run
// with no cap removes none of them.
func TestTU11CapRunOverAHundredDays(t *testing.T) {
	r, s, _ := prodRig(t, 0, nil)
	s.run = serveWithRun(r)
	capDataset(t, r)
	s.runOnce(context.Background())
	const live = "SELECT count(*) FROM event WHERE kind = 'request'"
	if n := count(t, r.db, live); n != 3000 {
		t.Fatalf("%d request rows after a run with no cap, want 3000", n)
	}
	// The first run left free pages, so the cap is 95 % of the pages in use.
	tx, err := r.db.Begin()
	check(t, err)
	pc, free, ps, err := pages(context.Background(), tx)
	check(t, err)
	check(t, tx.Rollback())
	s.SetMaxBytes((pc - free) * ps * 95 / 100)
	s.runOnce(context.Background())
	days := rawText(t, r.db, fmt.Sprintf(`SELECT group_concat(k || ':' || n) FROM (SELECT (%d - ts) / 86400000 AS k, count(*) AS n
		FROM event WHERE kind = 'request' GROUP BY k ORDER BY k)`, rollTDel.UnixMilli()))
	parts := strings.Split(days, ",")
	for i, kn := range parts {
		var k, n int
		fmt.Sscanf(kn, "%d:%d", &k, &n)
		if k != i || n != 100 && i != len(parts)-1 {
			t.Fatalf("request days %s: want the newest days, whole, and a part of the last", days)
		}
	}
	cbs := fmt.Sprintf("SELECT count(*) FROM event WHERE kind = 'callback' AND ts > %d", rollCutoff(90))
	if left := count(t, r.db, live); left == 0 || left >= 3000 || count(t, r.db, cbs) != 90 {
		t.Fatalf("%d request rows left, request days %s", left, days)
	}
	if n, sum := count(t, r.db, fmt.Sprintf("SELECT count(*) FROM session WHERE ip IS NOT NULL AND first_seen < %d", rollCutoff(7))),
		count(t, r.db, "SELECT sum(requests) FROM aggregate_day"); n != 0 || sum+count(t, r.db, live) != 10000 {
		t.Fatalf("%d addresses older than 7 d, %d requests counted; want 0 and 10000 with the rows left", n, sum)
	}
	if n := count(t, r.db, fmt.Sprintf("SELECT count(*) FROM event WHERE kind = 'callback' AND (detail IS NOT NULL OR body_prefix IS NOT NULL) AND ts < %d", rollCutoff(30))); n != 0 {
		t.Fatalf("%d callbacks of more than 30 d keep a detail or a body", n)
	}
}

// T-I-13 (store level): the clock is 91 d ahead of the data and the cap is
// small. After the run, the file and the WAL on disk have at most the cap in
// bytes. The roll-up counts each request row.
func TestTI13RunWithAClockOf91DaysEndsUnderTheCap(t *testing.T) {
	r := newRig(t, 100)
	capDataset(t, r)
	start := rollTDel.Add(91 * 24 * time.Hour)
	s, _ := fakeSchedule(t, r, time.UTC, start, nil)
	s.run = serveWithRun(r)
	const max = 512 << 10
	s.SetMaxBytes(max)
	s.runOnce(context.Background())
	file, wal := fileSize(filepath.Join(r.state, "events.db")), fileSize(filepath.Join(r.state, "events.db-wal"))
	if sum := count(t, r.db, "SELECT sum(requests) FROM aggregate_day"); file+wal > max || sum != 10000 {
		t.Fatalf("file %d + WAL %d bytes, cap %d, %d requests counted; want the bytes within the cap and 10000", file, wal, max, sum)
	}
}

// T-U-11: the statements of the cap use an index. No plan has a SCAN of event,
// session or mint.
func TestTU11CapStatementsUseTheirIndexes(t *testing.T) {
	db := migrated(t)
	for _, c := range []struct {
		q    string
		args []any
		use  string
	}{
		{oldestEventSQL, []any{"callback"}, "event_kind_ts (kind=?)"},
		{oldestSessionSQL, []any{"human"}, "session_band_last (band=?)"},
		{evictEvidenceSQL, []any{"callback", 1, 1000}, "event_kind_ts (kind=? AND ts<?)"},
		{deleteRawSQL, []any{1, 1000}, "event_kind_ts"},
		{mintNextSQL, []any{""}, "PRIMARY KEY"},
		{mintUnitSQL, []any{"", 1, 2}, "PRIMARY KEY"},
	} {
		if plan := strings.Join(queryPlan(t, db, c.q, c.args...), "\n"); strings.Contains(plan, "SCAN") || !strings.Contains(plan, c.use) {
			t.Errorf("plan of %q:\n%s\nwant no SCAN and %q", c.q, plan, c.use)
		}
	}
}
