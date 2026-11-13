package store

import (
	"cmp"
	"context"
	"database/sql"
	"fmt"
	"os"
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
		SELECT 'counter@' || substr(day, 9, 2) FROM ip_counter UNION ALL
		SELECT 'token@' || strftime('%d', first_cb_at/1000, 'unixepoch') FROM token WHERE first_cb_at IS NOT NULL UNION ALL
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

// addMint inserts one mint row. The set is hex text. The unit is the unit of
// the time at. The counter is first.
func addMint(t *testing.T, db *sql.DB, set string, at, first int64) {
	t.Helper()
	mustExec(t, db, "INSERT INTO mint (set_id, unit, first, count, session_id, issued_at) VALUES (unhex(?), ?, ?, 1, 's', ?)",
		set, token.Unit(time.UnixMilli(at)), first, at)
}

// addHashed inserts n evidence rows of a kind with a hash and the leaf indexes
// from leaf0.
func addHashed(t *testing.T, db *sql.DB, kind string, n int, ts int64, leaf0 int) {
	t.Helper()
	mustExec(t, db, `WITH RECURSIVE c(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM c WHERE i < ?)
		INSERT INTO event (ts, kind, hash, leaf_index) SELECT ?, ?, zeroblob(32), ? + i FROM c`, n-1, ts, kind, leaf0)
}

// forcedCap makes the cap state of a test that has begun and is over the cap.
// The measure never reaches the target, so the steps evict all they can.
func forcedCap(r *rig, now time.Time) *capRun {
	c := newCapRun(r.w, 1000, "events.db", now)
	c.begun, c.over = true, true
	c.measure = func(context.Context, *sql.Tx) (int64, error) { return 1 << 40, nil }
	return c
}

// T-U-11: the cap evicts in tiers, and in each tier the oldest UTC day first.
// Tier 1 has request, refused, beacon and ip_counter rows. On one day, the
// first source goes first. Tier 2 has mint, session and token rows. A session
// of the band agent-confirmed is in it. Tier 3 has evidence rows. Tier 1 can be
// empty, and then a request row can come. That row goes before the rows of tier
// 2. Each call takes one source.
func TestTU11CapEvictsInTiersOldestDayFirst(t *testing.T) {
	r := newRig(t, 100)
	for _, d := range []int{3, 1, 2} {
		addEvents(t, r.db, "request", 1, capDay(d), 0, nil, nil)
	}
	addEvents(t, r.db, "refused", 1, capDay(2), 0, nil, nil)
	addEvents(t, r.db, "beacon", 1, capDay(4), 0, nil, nil)
	mustExec(t, r.db, "INSERT INTO ip_counter (day, ip_hmac, requests, dropped) VALUES ('2027-01-02', 'h', 1, 0)")
	addHashed(t, r.db, "score_change", 1, capDay(5), 0)
	addHashed(t, r.db, "callback", 1, capDay(1), 1)
	mustExec(t, r.db, "INSERT INTO session (id, first_seen, last_seen, ip_hmac, band) VALUES ('1', 0, ?, 'h', 'human')", capDay(1))
	mustExec(t, r.db, "INSERT INTO session (id, first_seen, last_seen, ip_hmac, band) VALUES ('3', 0, ?, 'h', 'agent-confirmed')", capDay(3))
	mustExec(t, r.db, "INSERT INTO token (token_id, session_id, trap_id, issued_at, first_cb_at) VALUES ('t', 's', 't', 1, ?)", capDay(2))
	addMint(t, r.db, "01", capDay(2), 0)
	c := forcedCap(r, rollTDel)
	want := []string{"request@01", "request@02", "refused@02", "counter@02", "request@03", "beacon@04", "request@06",
		"session@01", "mint@02", "token@02", "session@03", "callback@01", "score_change@05", ""}
	for i, w := range want {
		if i == 6 {
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
	c := forcedCap(r, rollTDel)
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
			addMint(t, r.db, "01", capDay(1)+int64(u)*600_000, int64(f))
		}
	}
	call(t, r.db, forcedCap(r, rollTDel).evict, 4)
	if rows, odd := count(t, r.db, "SELECT count(*) FROM mint"), count(t, r.db,
		"SELECT count(*) FROM (SELECT unit FROM mint GROUP BY unit HAVING count(*) != 3)"); rows != 6 || odd != 0 {
		t.Fatalf("%d mint rows, %d split units; want 6 and 0", rows, odd)
	}
}

// T-U-11: tier 2 sees each mint row. Tier 3 starts only after the last one.
// There are three cases. The rows are of the unit of the run. Or they are of
// later units: the wall clock stepped back. Or the run time is before the token
// epoch. A callback stays while a mint row is left.
func TestTU11CapSeesEveryMintRow(t *testing.T) {
	epoch := token.Epoch()
	for _, c := range []struct {
		name string
		now  time.Time
		rows []time.Time
	}{
		{"current unit", rollTDel, []time.Time{rollTDel}},
		{"later unit", rollTDel, []time.Time{rollTDel.Add(24 * time.Hour), rollTDel.Add(48 * time.Hour)}},
		{"run before the epoch", epoch.Add(-time.Hour), []time.Time{epoch.Add(-3 * time.Hour), epoch.Add(-time.Hour), epoch.Add(2 * time.Hour)}},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t, 100)
			addHashed(t, r.db, "callback", 1, capDay(1), 0)
			for i, at := range c.rows {
				addMint(t, r.db, "01", at.UnixMilli(), int64(i))
			}
			e := forcedCap(r, c.now)
			for range 10 {
				n := call(t, r.db, e.evict, chunkRows)
				mints := count(t, r.db, "SELECT count(*) FROM mint")
				if cb := count(t, r.db, "SELECT count(*) FROM event"); cb == 0 && mints > 0 {
					t.Fatalf("the callback went with %d mint rows left", mints)
				} else if n == 0 {
					if mints != 0 || cb != 0 {
						t.Fatalf("%d mint rows and %d events left at the end", mints, cb)
					}
					return
				}
			}
			t.Fatal("the cap did not end")
		})
	}
	t.Run("two sets", func(t *testing.T) {
		r := newRig(t, 100)
		addMint(t, r.db, "01", capDay(3), 0)
		addMint(t, r.db, "02", capDay(1), 0)
		addHashed(t, r.db, "callback", 1, capDay(1), 0)
		e := forcedCap(r, rollTDel)
		for i, w := range []string{"mint@01", "mint@03", "callback@01", ""} {
			before := capLabels(t, r.db)
			call(t, r.db, e.evict, chunkRows)
			if got := removed(before, capLabels(t, r.db)); got != w {
				t.Fatalf("call %d removed %q, want %q", i, got, w)
			}
		}
	})
}

// T-U-11: a source that has a row and removes none is not asked again. The step
// ends, and it does not spin. The stub stops the test if it is asked again.
func TestTU11CapStopsASourceThatRemovesNoRow(t *testing.T) {
	r := newRig(t, 100)
	calls := 0
	stub := &capSource{
		oldest: func(context.Context, *sql.Tx) (int64, bool, error) { return capDay(1), true, nil },
		evict: func(context.Context, *sql.Tx, int64, int) (int, error) {
			if calls++; calls > 3 {
				panic("the cap asks a source again that removed no row")
			}
			return 0, nil
		},
	}
	c := forcedCap(r, rollTDel)
	c.tiers = [][]*capSource{{stub}}
	if n := call(t, r.db, c.evict, chunkRows); n != 0 || calls != 1 {
		t.Fatalf("returned %d after %d calls of the source, want 0 and 1", n, calls)
	}
}

// T-U-11: the tier-3 delete removes at most the limit in one call. 600 callback
// rows and 600 score_change rows are of one day. A limit of 1 000 leaves 200.
func TestTU11CapEvidenceDeleteKeepsTheLimit(t *testing.T) {
	r := newRig(t, 100)
	addHashed(t, r.db, "callback", 600, capDay(1), 0)
	addHashed(t, r.db, "score_change", 600, capDay(1), 1000)
	call(t, r.db, forcedCap(r, rollTDel).evict, chunkRows)
	if n := count(t, r.db, "SELECT count(*) FROM event"); n != 200 {
		t.Fatalf("%d evidence rows left, want 200", n)
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

// capRunOf runs the steps through the writer, with a run record. The steps are
// the cap steps and a mark step, or the steps that first come from the caller.
// It returns the record.
func capRunOf(t *testing.T, r *rig, capBytes int64, first ...retentionStep) *retentionRun {
	t.Helper()
	run := &retentionRun{}
	steps := withCap(append(first, markStep(rollTDel)), run, r.w, capBytes, "events.db", rollTDel)
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

// T-U-11: as in a real run, a step before the cap step writes the WAL. It does
// this in the chunks of the run. Its last call is in the chunk of the cap
// step. The cap step must still measure after the checkpoint. So no row goes.
func TestTU11CapSettlesAfterTheStepsOfItsChunk(t *testing.T) {
	r := newRig(t, 100)
	size := capFixture(t, r)
	calls := 0
	churnStep := func(ctx context.Context, tx *sql.Tx, limit int) (int, error) {
		if calls++; calls > 300 {
			return 0, nil
		}
		_, err := tx.ExecContext(ctx, "UPDATE event SET vhost = ? WHERE id = ?", fmt.Sprint("v", calls), calls)
		return limit, err
	}
	run := capRunOf(t, r, size+size/20, churnStep)
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

// T-U-11: the cap evicts to 90 % of the cap and the shrink step makes the file
// that small. A request row that the cap removes is in aggregate_day and in
// evicted, not in rolled. The freed pages are in vacuumed.
func TestTU11CapEvictsToNinetyPercentAndCounts(t *testing.T) {
	r := newRig(t, 100)
	capBytes := capFixture(t, r) * 6 / 10
	run := capRunOf(t, r, capBytes)
	left := count(t, r.db, "SELECT count(*) FROM event WHERE kind = 'request'")
	sum := count(t, r.db, "SELECT sum(requests) FROM aggregate_day")
	got, c := truncated(t, r), run.counts
	if c.Evicted == 0 || c.Evicted != int64(3000-left) || int64(sum) != c.Evicted || c.Rolled != 0 || c.Vacuumed == 0 {
		t.Fatalf("evicted %d, rolled %d, vacuumed %d, %d counted, %d left; want evicted = counted = %d removed", c.Evicted, c.Rolled, c.Vacuumed, sum, left, 3000-left)
	}
	if got > capBytes*9/10 || newCapRun(r.w, 1000, "events.db", rollTDel).target != 900 {
		t.Fatalf("file %d bytes, want at most 90 %% of the cap %d; the target is 900 for a cap of 1000", got, capBytes)
	}
}

// freedFixture makes a rig with free pages: 1 500 of 3 000 rows are deleted.
func freedFixture(t *testing.T) *rig {
	t.Helper()
	r := newRig(t, 100)
	capFixture(t, r)
	mustExec(t, r.db, "DELETE FROM event WHERE id <= 1500")
	return r
}

// dbPages returns the page count, the free page count and the page size.
func dbPages(t *testing.T, db *sql.DB) (count, free, size int64) {
	t.Helper()
	tx, err := db.Begin()
	check(t, err)
	count, free, size, err = pages(context.Background(), tx)
	check(t, err)
	check(t, tx.Rollback())
	return count, free, size
}

// T-U-11: the shrink step stops when the file is at most 90 % of the cap, with
// free pages left. The first statement frees 16 pages, and vacuumed has that
// exact number. The target is 8 pages below the file, so one statement is
// enough. The second call frees nothing.
func TestTU11CapShrinkStopsAtTheTargetWithFreePagesLeft(t *testing.T) {
	r := freedFixture(t)
	count0, free0, size := dbPages(t, r.db)
	c := &capRun{w: r.w, over: true, target: (count0 - 8) * size}
	run, cur := &retentionRun{}, 0
	steps := []retentionStep{c.shrink}
	for range 2 {
		_, err := r.w.chunkRun(steps, &cur, run)
		check(t, err)
	}
	if count1, free1, _ := dbPages(t, r.db); run.counts.Vacuumed != 16 || free1 != free0-16 || count1 != count0-16 || cur != 1 {
		t.Fatalf("vacuumed %d, free %d of %d, pages %d of %d, step %d; want 16, %d, %d and 1", run.counts.Vacuumed, free1, free0, count1, count0, cur, free0-16, count0-16)
	}
}

// T-U-11: the pages of a shrink statement are from 1 to 16. After a fast
// statement, they grow at most twice, also for a time of 0. From 16 they stay
// 16. After a statement over 50 ms, they are half, at least 1. A statement at
// the budget is fast.
func TestTU11CapShrinkSizesItsStatementFromTheTime(t *testing.T) {
	for _, n := range []int{1, 2, 8, 15, 16} {
		for _, took := range []time.Duration{0, -time.Second, time.Microsecond, time.Millisecond, shrinkBudget} {
			if got := nextShrink(n, took); got < 1 || got > min(2*n, 16) {
				t.Errorf("nextShrink(%d, %v) = %d, want 1 to %d", n, took, got, min(2*n, 16))
			}
		}
		for _, took := range []time.Duration{shrinkBudget + time.Nanosecond, 51 * time.Millisecond, 2 * time.Second} {
			if got := nextShrink(n, took); got != max(n/2, 1) {
				t.Errorf("nextShrink(%d, %v) = %d, want %d", n, took, got, max(n/2, 1))
			}
		}
	}
	for _, c := range []struct {
		n    int
		took time.Duration
		want int
	}{{1, 0, 2}, {2, time.Microsecond, 4}, {4, 0, 8}, {8, 0, 16}, {16, 0, 16}, {16, shrinkBudget, 16}, {10, 40 * time.Millisecond, 12}} {
		if got := nextShrink(c.n, c.took); got != c.want {
			t.Errorf("nextShrink(%d, %v) = %d, want %d", c.n, c.took, got, c.want)
		}
	}
}

// T-U-11: the step has a fake clock. One fast and five slow statements use 16,
// 16, 8, 4, 2 and 1 pages. The next one has 1. Then five fast ones use 1, 2, 4,
// 8 and 16 pages. The next one has 16.
func TestTU11CapShrinkHalvesAfterASlowOneAndGrowsBack(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "plain.db"))
	check(t, err)
	defer db.Close()
	db.SetMaxOpenConns(1)
	mustExec(t, db, "PRAGMA auto_vacuum = INCREMENTAL")
	mustExec(t, db, "CREATE TABLE t (a BLOB)")
	mustExec(t, db, `WITH RECURSIVE c(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM c WHERE i < 599) INSERT INTO t SELECT zeroblob(3000) FROM c`)
	mustExec(t, db, "DELETE FROM t")
	slow, fast := 80*time.Millisecond, time.Millisecond
	took, calls, at := []time.Duration{fast, slow, slow, slow, slow, slow, fast, fast, fast, fast, fast}, 0, rollTDel
	w := &Writer{clock: func() time.Time {
		if calls++; calls%2 == 0 {
			at = at.Add(took[calls/2-1])
		}
		return at
	}}
	s := &capRun{w: w, over: true}
	var used []int
	for range took {
		used = append(used, cmp.Or(s.pages, shrinkFirst))
		call(t, db, s.shrink, chunkRows)
	}
	if fmt.Sprint(used) != "[16 16 8 4 2 1 1 2 4 8 16]" || s.pages != 16 {
		t.Fatalf("statements of %v pages, then %d; want [16 16 8 4 2 1 1 2 4 8 16] and 16", used, s.pages)
	}
}

// T-U-11: a database where incremental_vacuum frees no page makes the shrink
// step end. It does not loop.
func TestTU11CapShrinkEndsWhenNoPageIsFreed(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "plain.db"))
	check(t, err)
	defer db.Close()
	db.SetMaxOpenConns(1)
	mustExec(t, db, "CREATE TABLE t (a BLOB)")
	mustExec(t, db, `WITH RECURSIVE c(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM c WHERE i < 299) INSERT INTO t SELECT zeroblob(3000) FROM c`)
	mustExec(t, db, "DELETE FROM t")
	if _, free, _ := dbPages(t, db); free == 0 {
		t.Fatal("the database has no free page")
	}
	if n := call(t, db, (&capRun{w: &Writer{}, over: true}).shrink, chunkRows); n != 0 {
		t.Fatalf("returned %d, want 0", n)
	}
}

// T-U-11: a cap of 0 adds no step and evicts nothing. With a cap, the cap steps
// come before the mark step, which stays last. The mark step writes its mark
// after the last row has gone.
func TestTU11CapStepsRunBeforeTheMarkStep(t *testing.T) {
	steps := []retentionStep{markStep(rollTDel)}
	if got := withCap(steps, nil, nil, 0, "", rollTDel); len(got) != 1 {
		t.Fatalf("a cap of 0 gave %d steps, want 1", len(got))
	}
	for _, capBytes := range []int64{0, 1} {
		r, s, _ := prodRig(t, 0, nil)
		s.SetMaxBytes(capBytes, "events.db")
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
		if want := map[int64]int{0: 3, 1: 0}[capBytes]; atMark != want || left != want {
			t.Fatalf("cap %d: %d rows when the mark came, %d at the end; want %d", capBytes, atMark, left, want)
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

// livePages returns the bytes of the pages in use.
func livePages(t *testing.T, db *sql.DB) int64 {
	t.Helper()
	count, free, size := dbPages(t, db)
	return (count - free) * size
}

// T-U-11: the cap steps come after the 30-day and the 90-day steps. A run with
// no cap leaves some pages in use. A cap 20 % above that needs no eviction
// after those steps, so no young row goes. Before them, the pages in use would
// be far above the line, and the cap would evict.
func TestTU11CapRunsAfterTheOtherSteps(t *testing.T) {
	base, bs, _ := prodRig(t, 0, nil)
	bs.run = serveWithRun(base)
	capDataset(t, base)
	bs.runOnce(context.Background())
	r, s, _ := prodRig(t, 0, nil)
	capDataset(t, r)
	s.SetMaxBytes(livePages(t, base.db)*12/10, "events.db")
	var run *retentionRun
	s.run = func(ctx context.Context, steps []retentionStep) error {
		run, _ = ctx.Value(runKey{}).(*retentionRun)
		return serveWithRun(r)(ctx, steps)
	}
	s.runOnce(context.Background())
	if left := count(t, r.db, "SELECT count(*) FROM event WHERE kind = 'request'"); run.counts.Evicted != 0 || left != 3000 {
		t.Fatalf("evicted %d rows, %d request rows left; want 0 and 3000", run.counts.Evicted, left)
	}
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
	s.SetMaxBytes(livePages(t, r.db)*95/100, "events.db")
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

// ti13Run makes the run of T-I-13 with a cap of capBytes. The clock is 91 d
// ahead of the data. It returns the rig and the sums of aggregate_day.
func ti13Run(t *testing.T, capBytes int64) (*rig, string) {
	t.Helper()
	r := newRig(t, 100)
	capDataset(t, r)
	s, _ := fakeSchedule(t, r, time.UTC, rollTDel.Add(91*24*time.Hour), nil)
	s.run = serveWithRun(r)
	s.SetMaxBytes(capBytes, "events.db")
	s.runOnce(context.Background())
	return r, rawText(t, r.db, "SELECT sum(sessions) || '|' || sum(requests) || '|' || sum(callbacks) FROM aggregate_day")
}

// T-I-13 (store level): the clock is 91 d ahead of the data and the cap is
// small. After the run, the file and the WAL on disk have at most the cap in
// bytes. The sessions, requests and callbacks of aggregate_day are the same as
// in a run with no cap.
func TestTI13RunWithAClockOf91DaysEndsUnderTheCap(t *testing.T) {
	const capBytes = 512 << 10
	_, base := ti13Run(t, 0)
	r, got := ti13Run(t, capBytes)
	file, wal := fileSize(filepath.Join(r.state, "events.db")), fileSize(filepath.Join(r.state, "events.db-wal"))
	if file+wal > capBytes || got != base || !strings.HasPrefix(base, "100|10000|") || strings.HasSuffix(base, "|0") {
		t.Fatalf("file %d + WAL %d bytes, cap %d, sums %q, %q with no cap; want the bytes within the cap and the same sums, with 100 sessions, 10000 requests and callbacks", file, wal, capBytes, got, base)
	}
}

// T-U-11: the counts of a run with the cap are exact over 2 chunks and 2 runs.
// Run 1 ends early after its first eviction chunk. Run 2 ends at its end. The
// evicted rows of the 2 events add up to the rows that went. They also add up
// to the roll-up. Only run 2 frees pages.
func TestTU11CapCountsOverTwoChunksAndTwoRuns(t *testing.T) {
	r := newRig(t, 8)
	r.w.clock = func() time.Time { return rollTDel }
	size := capFixture(t, r)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s, _ := fakeSchedule(t, r, time.UTC, rollTDel, nil)
	s.SetMaxBytes(size*6/10, "events.db")
	s.run = func(ctx context.Context, steps []retentionStep) error {
		evict := len(steps) - 3
		steps[evict] = onCall(steps[evict], func(i int, _ *sql.Tx) {
			if i == 0 {
				cancel() // this chunk commits, and the run then ends
			}
		})
		return serveWithRun(r)(ctx, steps)
	}
	s.runOnce(ctx)
	s.run = serveWithRun(r)
	s.runOnce(context.Background())
	rows, err := r.db.Query(`SELECT json_extract(detail, '$.evicted'), json_extract(detail, '$.vacuumed'),
		json_extract(detail, '$.rolled') FROM event WHERE kind = 'retention' ORDER BY id`)
	check(t, err)
	var ev, va []int64
	for rows.Next() {
		var e, v, rolled int64
		check(t, rows.Scan(&e, &v, &rolled))
		if rolled != 0 {
			t.Errorf("run %d: rolled %d, want 0", len(ev)+1, rolled)
		}
		ev, va = append(ev, e), append(va, v)
	}
	check(t, rows.Err())
	check(t, rows.Close())
	left := int64(count(t, r.db, "SELECT count(*) FROM event WHERE kind = 'request'"))
	if len(ev) != 2 || ev[0] <= 0 || ev[1] <= 0 || ev[0]+ev[1] != 3000-left || va[0] != 0 || va[1] <= 0 ||
		int64(count(t, r.db, "SELECT sum(requests) FROM aggregate_day")) != 3000-left {
		t.Fatalf("evicted %v, vacuumed %v, %d request rows left; want 2 runs that add up to %d", ev, va, left, 3000-left)
	}
}

// T-U-11: the size of the files comes from the name that Open checked, through
// the root. A rename of the state directory after open does not stop a run with
// a cap.
func TestTU11CapDoesNotNeedThePathOfTheStateDirectory(t *testing.T) {
	r := newRig(t, 100)
	capFixture(t, r)
	check(t, os.Rename(r.state, r.state+"-moved"))
	run := capRunOf(t, r, 1)
	if !r.w.Healthy() || run.counts.Evicted == 0 {
		t.Fatalf("healthy %v, evicted %d; want a healthy writer and rows evicted", r.w.Healthy(), run.counts.Evicted)
	}
}

// T-U-11: the start of the unit of the run is the start of its 10-minute unit.
// This holds on a boundary, and before the token epoch with a remainder. The
// unit before and the unit after start 10 minutes earlier and later.
func TestTU11CapMintOrderStartsAtTheUnitOfTheRun(t *testing.T) {
	epoch := token.Epoch()
	const mask = 1<<20 - 1
	for _, c := range []struct {
		name       string
		now, start time.Time
	}{
		{"after the epoch", epoch.Add(time.Hour + 5*time.Second + 123*time.Millisecond), epoch.Add(time.Hour)},
		{"on a boundary", epoch.Add(time.Hour), epoch.Add(time.Hour)},
		{"1 ms before a boundary", epoch.Add(time.Hour - time.Millisecond), epoch.Add(50 * time.Minute)},
		{"before the epoch with a remainder", epoch.Add(-time.Hour - 7*time.Second), epoch.Add(-70 * time.Minute)},
		{"before the epoch on a boundary", epoch.Add(-time.Hour), epoch.Add(-time.Hour)},
	} {
		o, u := newMintOrder(c.now), int64(token.Unit(c.now))
		got := [3]int64{o.at((u - 1) & mask), o.at(u), o.at((u + 1) & mask)}
		if want := [3]int64{c.start.Add(-10 * time.Minute).UnixMilli(), c.start.UnixMilli(), c.start.Add(10 * time.Minute).UnixMilli()}; got != want {
			t.Errorf("%s: starts %v, want %v", c.name, got, want)
		}
	}
}

// T-U-11: the unit ranges are one range when the first unit is 0. With the
// wrap, they are two. The start of a unit is exact. This holds for the first
// rank, for the unit of the run, and for the top rank.
func TestTU11CapMintOrderRangesAndStarts(t *testing.T) {
	const top, half, start = 1<<20 - 1, 1 << 19, int64(1) << 40
	for _, c := range []struct {
		lo   int64
		want string
	}{{0, "[[0 1048575]]"}, {5, "[[5 1048575] [0 4]]"}} {
		o := mintOrder{lo: c.lo, start: start}
		if got := fmt.Sprint(o.ranges()); got != c.want {
			t.Errorf("lo %d: ranges %s, want %s", c.lo, got, c.want)
		}
		got := [3]int64{o.at(c.lo), o.at((c.lo + half - 1) & top), o.at((c.lo - 1) & top)}
		if want := [3]int64{start - (half-1)*mintUnitMs, start, start + half*mintUnitMs}; got != want {
			t.Errorf("lo %d: starts %v, want %v", c.lo, got, want)
		}
	}
}

// evictMint runs the evict of a mint order in one call.
func evictMint(t *testing.T, r *rig, o mintOrder, end int64, limit int) int {
	t.Helper()
	return call(t, r.db, func(ctx context.Context, tx *sql.Tx, _ int) (int, error) {
		return o.evict(ctx, tx, end, limit)
	}, chunkRows)
}

// addUnits inserts rows of set 01, n[i] rows in unit u[i].
func addUnits(t *testing.T, db *sql.DB, units, rows []int) {
	t.Helper()
	for i, u := range units {
		for f := range rows[i] {
			mustExec(t, db, "INSERT INTO mint (set_id, unit, first, count, session_id, issued_at) VALUES (x'01', ?, ?, 1, 's', 0)", u, f)
		}
	}
}

// T-U-11: the oldest mint unit is found on both sides of the wrap, and it goes
// first. With the first unit 0, the order has one range. Else it has two. The
// unit with the lower rank is oldest, also when it has the higher number.
func TestTU11CapMintOrderFindsTheOldestUnitAcrossTheWrap(t *testing.T) {
	for _, c := range []struct {
		lo            int64
		oldest, later int
	}{{0, 3, 1<<20 - 2}, {582681, 582684, 582679}} {
		r := newRig(t, 100)
		o := mintOrder{lo: c.lo, start: rollTDel.UnixMilli()}
		addUnits(t, r.db, []int{c.later, c.oldest}, []int{1, 1})
		tx, err := r.db.Begin()
		check(t, err)
		got, ok, err := o.oldest(context.Background(), tx)
		check(t, err)
		check(t, tx.Rollback())
		if want := o.at(int64(c.oldest)); !ok || got != want {
			t.Fatalf("lo %d: oldest %d %v, want %d", c.lo, got, ok, want)
		}
		if n, left := evictMint(t, r, o, o.at(int64(c.oldest))+mintUnitMs, chunkRows), count(t, r.db, "SELECT unit FROM mint"); n != 1 || left != c.later {
			t.Fatalf("lo %d: removed %d rows, unit %d left; want 1 and %d", c.lo, n, left, c.later)
		}
	}
}

// T-U-11: the evict of a mint order. A unit that starts at the end stays. A
// unit that starts 1 ms before goes. A unit with exactly the rows that are left
// goes whole. A unit with one more row stays, and the call returns the rows
// that it deleted. The call stops after the last row that fits.
func TestTU11CapMintEvictKeepsTheBoundaries(t *testing.T) {
	o := mintOrder{lo: 0, start: rollTDel.UnixMilli()}
	at := func(u int) int64 { return o.at(int64(u)) }
	for _, c := range []struct {
		name            string
		units, rows     []int
		end             int64
		limit           int
		wantN, wantLeft int
	}{
		{"unit at the end", []int{1000}, []int{2}, at(1000), 100, 0, 2},
		{"unit 1 ms before the end", []int{1000}, []int{2}, at(1000) + 1, 100, 2, 0},
		{"rows that fit", []int{1000, 1001}, []int{2, 2}, at(1002), 4, 4, 0},
		{"one row too many", []int{1000, 1001}, []int{2, 3}, at(1002), 4, 2, 3},
		{"stop after the last that fits", []int{1000, 1001, 1002}, []int{2, 2, 1}, at(1003), 4, 4, 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t, 100)
			addUnits(t, r.db, c.units, c.rows)
			if n, left := evictMint(t, r, o, c.end, c.limit), count(t, r.db, "SELECT count(*) FROM mint"); n != c.wantN || left != c.wantLeft {
				t.Fatalf("removed %d, %d rows left; want %d and %d", n, left, c.wantN, c.wantLeft)
			}
		})
	}
}

// T-U-11: the shrink step runs no statement when the database has no free page.
// It runs none when the file is at the target. One byte below, it runs.
func TestTU11CapShrinkStopsWithNoFreePageOrAtTheTarget(t *testing.T) {
	r := newRig(t, 100)
	if _, free, _ := dbPages(t, r.db); free != 0 {
		t.Fatalf("%d free pages in a new database, want 0", free)
	}
	s := &capRun{w: r.w, over: true}
	if n := call(t, r.db, s.shrink, chunkRows); n != 0 || s.pages != 0 {
		t.Fatalf("no free page: returned %d, %d pages; want 0 and 0", n, s.pages)
	}
	f := freedFixture(t)
	pc, _, size := dbPages(t, f.db)
	for _, c := range []struct {
		target int64
		ran    bool
	}{{pc * size, false}, {pc*size - 1, true}} {
		s := &capRun{w: f.w, over: true, target: c.target}
		call(t, f.db, s.shrink, chunkRows)
		if (s.pages != 0) != c.ran {
			t.Errorf("target %d: statement run %v, want %v", c.target, s.pages != 0, c.ran)
		}
	}
}

// T-U-11: the statements of the cap use an index. No plan scans event, session,
// token, ip_counter or mint.
func TestTU11CapStatementsUseTheirIndexes(t *testing.T) {
	db := migrated(t)
	for _, c := range []struct {
		q    string
		args []any
		use  string
	}{
		{oldestEventSQL, []any{"callback"}, "event_kind_ts (kind=?)"},
		{oldestSessionSQL, []any{"human"}, "session_band_last (band=?)"},
		{oldestCounterSQL, nil, "sqlite_autoindex_ip_counter_1"},
		{oldestTokenSQL, nil, "token_first_cb"},
		{evictEvidenceSQL, []any{"callback", 1, 1000}, "event_kind_ts (kind=? AND ts<?)"},
		{deleteRawSQL, []any{1, 1000}, "event_kind_ts"},
		{deleteCounterSQL, []any{"2027-01-02", 1000}, "sqlite_autoindex_ip_counter_1"},
		{deleteTokenSQL, []any{1, 1000}, "token_first_cb"},
		{mintNextSQL, []any{""}, "PRIMARY KEY"},
		{mintUnitSQL, []any{"", 1, 2}, "PRIMARY KEY"},
		{mintCountSQL, []any{"", 1, 2}, "PRIMARY KEY"},
		{mintDropSQL, []any{"", 1}, "PRIMARY KEY"},
		{mintDeleteSQL, []any{"", 1, 1000}, "PRIMARY KEY"},
	} {
		plan := strings.Join(queryPlan(t, db, c.q, c.args...), "\n")
		for _, table := range []string{"event", "session", "token", "ip_counter", "mint"} {
			if strings.Contains(plan, "SCAN "+table) {
				t.Errorf("plan of %q has a SCAN of %s:\n%s", c.q, table, plan)
			}
		}
		if !strings.Contains(plan, c.use) {
			t.Errorf("plan of %q:\n%s\nwant %q", c.q, plan, c.use)
		}
	}
}
