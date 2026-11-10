package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cybagard/cyba-phantom/internal/event"
)

// rollTDel is the time of the run in the tests. With 30 days, the cutoff is
// 2027-01-11 12:00:00.123 UTC, in the middle of a UTC day.
var rollTDel = time.Date(2027, 2, 10, 12, 0, 0, 123_000_000, time.UTC)

// rollCutoff is the cutoff of the steps for `days` x 24 h, in unix ms. The
// tests make it again from the definition, not from the code under test.
func rollCutoff(days int) int64 { return rollTDel.UnixMilli() - int64(days)*24*3600*1000 }

// utc returns the unix ms of an RFC 3339 time.
func utc(s string) int64 {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t.UnixMilli()
}

// addSession inserts a session row. A family of nil is NULL.
func addSession(tb testing.TB, db *sql.DB, id, band string, family any) {
	tb.Helper()
	mustExec(tb, db, "INSERT INTO session (id, first_seen, last_seen, ip_hmac, band, family) VALUES (?, 0, 0, 'h', ?, ?)", id, band, family)
}

// addEvents inserts n rows of kind with ts = ts0 + i*step. A session id or a
// vhost of nil is NULL. A callback row gets a hash and a leaf index.
func addEvents(tb testing.TB, db *sql.DB, kind string, n int, ts0, step int64, sid, vhost any) {
	tb.Helper()
	cb := kind == "callback"
	mustExec(tb, db, `WITH RECURSIVE c(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM c WHERE i < ?)
		INSERT INTO event (ts, session_id, kind, vhost, hash, leaf_index)
		SELECT ? + i*?, ?, ?, ?, CASE WHEN ? THEN zeroblob(32) END,
		CASE WHEN ? THEN i + (SELECT coalesce(max(leaf_index) + 1, 0) FROM event) END FROM c`,
		n-1, ts0, step, sid, kind, vhost, cb, cb)
}

// aggregates returns the rows of aggregate_day as text, in key order.
func aggregates(tb testing.TB, db *sql.DB) string {
	tb.Helper()
	var out string
	check(tb, db.QueryRow(`SELECT coalesce(group_concat(day || '|' || vhost || '|' || band || '|' || family || '|' ||
		sessions || '|' || requests || '|' || callbacks, ' ; '), '') FROM
		(SELECT * FROM aggregate_day ORDER BY day, vhost, band, family)`).Scan(&out))
	return out
}

// count returns the result of a query with one integer.
func count(tb testing.TB, db *sql.DB, q string) (n int) {
	tb.Helper()
	check(tb, db.QueryRow(q).Scan(&n))
	return n
}

// rollRig makes a rig with the steps and no seeded row. chunks gets the rows
// that each chunk changed.
func rollRig(t *testing.T, steps ...retentionStep) (r *rig, chunks *[]int) {
	t.Helper()
	r, _, chunks = chunkLog(t, 0, steps...)
	return r, chunks
}

// runDirect makes the writer of the rig serve one retention run in this
// goroutine. It does not start Run. The start check of Run reads the log, and
// the tests write callback rows with no leaf in the log. It returns the error
// of the run.
func (r *rig) runDirect() error {
	ctx, cancel := context.WithTimeout(context.Background(), waitFor)
	defer cancel()
	rq := retentionRequest{reply: make(chan error, 1), gone: ctx.Done()}
	r.w.serveRetention(ctx, r.tick, nil, rq)
	return <-rq.reply
}

// runOK makes one run of the rig. It fails the test on an error.
func runOK(t *testing.T, r *rig) {
	t.Helper()
	if err := r.runDirect(); err != nil {
		t.Fatal(err)
	}
}

// runAgain makes one more run of the rig with steps.
func runAgain(t *testing.T, r *rig, steps ...retentionStep) {
	t.Helper()
	setHook(t, &retentionSteps, steps)
	runOK(t, r)
}

// stops makes one run of the rig. It fails the test unless the run ends with an
// error and a stopped writer.
func stops(t *testing.T, r *rig) {
	t.Helper()
	if err := r.runDirect(); err == nil || r.w.Healthy() {
		t.Fatalf("run error %v, healthy %v; want an error and a stopped writer", err, r.w.Healthy())
	}
}

// failCommit makes the nth commit of the rig fail. The chunk rolls back, and
// the writer stops.
func failCommit(r *rig, nth int) {
	n, old := 0, r.w.beforeCommit
	r.w.beforeCommit = func(tx *sql.Tx) error {
		if n++; n == nth {
			return errors.New("commit refused")
		}
		return old(tx)
	}
}

// replaceWriter replaces the stopped writer of the rig by a new writer on the
// same database, as after a crash.
func replaceWriter(r *rig) {
	old := r.w
	r.w = NewWriter(r.db, r.q, false, nil, Recovery{State: r.root, Origin: "origin", Log: r.lg})
	r.w.tick, r.w.clock = r.tick, old.clock
}

// T-U-11: a run takes the old request rows in chunks of 1 000 and deletes them.
// The key rows add. The session with rows in both runs counts one time, as the
// cutoff splits its day. A row at the cutoff stays. A run again changes no
// count.
func TestTU11RollupMovesRowsInChunksAndAdds(t *testing.T) {
	r, chunks := rollRig(t, newRollupStep(rollTDel, 30))
	cut := rollCutoff(30)
	addSession(t, r.db, "s1", "human", "f")
	addSession(t, r.db, "s2", "crawler", nil)
	addEvents(t, r.db, "request", 1500, utc("2027-01-09T01:00:00Z"), 1000, "s1", "a")
	addEvents(t, r.db, "request", 3, utc("2027-01-09T05:00:00Z"), 1, "s2", "a")
	addEvents(t, r.db, "request", 10, utc("2027-01-11T00:00:00Z"), 1000, "s1", "a")
	addEvents(t, r.db, "request", 1, cut-1, 0, "s1", "a")
	addEvents(t, r.db, "request", 1, cut, 0, "s1", "a")
	addEvents(t, r.db, "request", 5, cut+1000, 1000, "s1", "a")
	runOK(t, r)
	want := "2027-01-09|a|crawler||1|3|0 ; 2027-01-09|a|human|f|1|1500|0 ; 2027-01-11|a|human|f|1|11|0"
	if got := aggregates(t, r.db); got != want || fmt.Sprint(*chunks) != "[1000 1000 1000 1000 546]" || r.events() != 6 {
		t.Fatalf("aggregates %q, chunks %v, %d rows left; want %q, [1000 1000 1000 1000 546], 6", got, *chunks, r.events(), want)
	}
	runAgain(t, r, newRollupStep(rollTDel.Add(12*time.Hour), 30))
	want = "2027-01-09|a|crawler||1|3|0 ; 2027-01-09|a|human|f|1|1500|0 ; 2027-01-11|a|human|f|1|17|0"
	if got := aggregates(t, r.db); got != want || r.events() != 0 {
		t.Fatalf("after the second run: aggregates %q, %d rows left; want %q, 0", got, r.events(), want)
	}
	runAgain(t, r, newRollupStep(rollTDel.Add(12*time.Hour), 30))
	if got := aggregates(t, r.db); got != want {
		t.Fatalf("a run again changed the counts: %q", got)
	}
}

// T-U-11: the cutoff is tDel minus days x 24 h. A row one ms before it rolls
// up. A row at the cutoff and a younger row stay. The day is the UTC date, also
// when the local zone is 5 h ahead. The step uses its own tDel, not the clock
// of the writer.
func TestTU11RollupBoundaryAndUTCDay(t *testing.T) {
	setHook(t, &time.Local, time.FixedZone("ahead", 5*3600))
	for _, days := range []int{1, 30} {
		t.Run(fmt.Sprint(days, " days"), func(t *testing.T) {
			r, _ := rollRig(t, newRollupStep(rollTDel, days))
			cut := rollCutoff(days)
			addEvents(t, r.db, "request", 1, cut-1, 0, nil, "before")
			addEvents(t, r.db, "request", 1, cut, 0, nil, "at")
			addEvents(t, r.db, "request", 1, cut+1, 0, nil, "after")
			addEvents(t, r.db, "request", 1, utc("2027-01-01T22:00:00Z"), 0, nil, "late")
			runOK(t, r)
			before := time.UnixMilli(cut - 1).UTC().Format("2006-01-02")
			want := "2027-01-01|late|human||0|1|0 ; " + before + "|before|human||0|1|0"
			if got := aggregates(t, r.db); got != want || r.events() != 2 {
				t.Fatalf("aggregates %q, %d rows left; want %q, 2", got, r.events(), want)
			}
		})
	}
}

// T-U-11: "exact for each key" means this. A session counts one time for each
// key (day, vhost, band, family) in which it has a row. One session has 2 500
// rows in 8 chunks. Its band changes after the first chunk of 333 rows. It
// counts one time under each band. The pairs stop a count for each chunk.
func TestTU11RollupSessionCountsOncePerKey(t *testing.T) {
	r, chunks := rollRig(t, newRollupStep(rollTDel, 30))
	addSession(t, r.db, "s1", "human", "f")
	addEvents(t, r.db, "request", 2500, utc("2027-01-09T01:00:00Z"), 1000, "s1", "a")
	n, old := 0, r.w.beforeCommit
	r.w.beforeCommit = func(tx *sql.Tx) error {
		if n++; n == 1 {
			if _, err := tx.Exec("UPDATE session SET band = 'crawler' WHERE id = 's1'"); err != nil {
				return err
			}
		}
		return old(tx)
	}
	runOK(t, r)
	want := "2027-01-09|a|crawler|f|1|2167|0 ; 2027-01-09|a|human|f|1|333|0"
	if got := aggregates(t, r.db); got != want || fmt.Sprint(*chunks) != "[1000 1000 1000 1000 1000 1000 1000 507]" {
		t.Fatalf("aggregates %q, chunks %v; want %q", got, *chunks, want)
	}
}

// T-S-34: a request row can have no vhost, no session row, or a session with
// no family. It rolls up to an empty vhost, the band human and an empty
// family. The writer stays healthy. A second run with more rows of the same
// keys gives one row for each key, with higher counts. A session with no
// row counts one time.
func TestTS34RollupNullKeys(t *testing.T) {
	r, _ := rollRig(t, newRollupStep(rollTDel, 30))
	ts := utc("2027-01-09T01:00:00Z")
	addSession(t, r.db, "nofamily", "agent-likely", nil)
	addEvents(t, r.db, "request", 2, ts, 1, nil, nil)
	addEvents(t, r.db, "request", 2, ts, 1, "ghost", "v")
	addEvents(t, r.db, "request", 2, ts, 1, "nofamily", nil)
	runOK(t, r)
	want := "2027-01-09||agent-likely||1|2|0 ; 2027-01-09||human||0|2|0 ; 2027-01-09|v|human||1|2|0"
	if got := aggregates(t, r.db); got != want || !r.w.Healthy() || r.events() != 0 {
		t.Fatalf("aggregates %q, healthy %v, %d rows left; want %q", got, r.w.Healthy(), r.events(), want)
	}
	addEvents(t, r.db, "request", 3, ts+10, 1, nil, nil)
	addEvents(t, r.db, "request", 3, ts+10, 1, "ghost", "v")
	addEvents(t, r.db, "request", 3, ts+10, 1, "nofamily", nil)
	runAgain(t, r, newRollupStep(rollTDel, 30))
	want = "2027-01-09||agent-likely||1|5|0 ; 2027-01-09||human||0|5|0 ; 2027-01-09|v|human||1|5|0"
	if got := aggregates(t, r.db); got != want || !r.w.Healthy() || r.events() != 0 {
		t.Fatalf("second run: aggregates %q, healthy %v, %d rows left; want %q", got, r.w.Healthy(), r.events(), want)
	}
}

// seedDays makes the rows of the day step tests. The day 2027-01-10 is done.
// It has 3 request rows. The day 2027-01-11 is not done. It has 2 request
// rows before the cutoff and 1 after it. The callbacks are 2 on 2027-01-02.
// They are 2 501 on 2027-01-10 (one has no vhost and no session). They are 4
// on 2027-01-11.
func seedDays(t *testing.T, db *sql.DB) {
	t.Helper()
	addSession(t, db, "s1", "human", "f")
	addEvents(t, db, "request", 3, utc("2027-01-10T01:00:00Z"), 1000, "s1", "a")
	addEvents(t, db, "request", 2, utc("2027-01-11T01:00:00Z"), 3_600_000, "s1", "a")
	addEvents(t, db, "request", 1, rollCutoff(30)+1000, 0, "s1", "a")
	addEvents(t, db, "callback", 2, utc("2027-01-02T10:00:00Z"), 1000, "s1", "a")
	addEvents(t, db, "callback", 2500, utc("2027-01-10T00:00:00Z"), 1000, "s1", "a")
	addEvents(t, db, "callback", 1, utc("2027-01-10T20:00:00Z"), 0, nil, nil)
	addEvents(t, db, "callback", 4, utc("2027-01-11T01:00:00Z"), 1000, "s1", "a")
}

// wantDays is the result of the day step tests after a full run. The callbacks
// of the two done days are counted. The other day has no callback count.
const wantDays = "2027-01-02|a|human|f|0|0|2 ; 2027-01-10||human||0|0|1 ; " +
	"2027-01-10|a|human|f|1|3|2500 ; 2027-01-11|a|human|f|1|2|0"

// T-U-11: the day step counts the callbacks of the done days and removes the
// seen rows of them. It skips the days with no data and keeps the day that is
// not done. The mark is the last done day, and no position stays.
func TestTU11RollupDayStepCountsCallbacksOnce(t *testing.T) {
	r, chunks := rollRig(t, newRollupStep(rollTDel, 30), newRollupDayStep(rollTDel, 30))
	seedDays(t, r.db)
	runOK(t, r)
	if got := aggregates(t, r.db); got != wantDays || fmt.Sprint(*chunks) != "[1000 1000 1000 1000 1000 27]" {
		t.Fatalf("aggregates %q, chunks %v; want %q, [1000 1000 1000 1000 1000 27]", got, *chunks, wantDays)
	}
	if m := metaValue(t, r.db, rollupDoneKey); m != "2027-01-10" || count(t, r.db, "SELECT count(*) FROM meta WHERE key = '"+rollupPosKey+"'") != 0 ||
		count(t, r.db, "SELECT count(*) FROM rollup_seen") != 1 || r.events() != 2508 {
		t.Fatalf("mark %q, %d seen rows, %d events", m, count(t, r.db, "SELECT count(*) FROM rollup_seen"), r.events())
	}
}

// T-U-11: a failed chunk in the middle of a day rolls back, with its
// position. A new writer on the same database counts each callback one time.
// It gives the result of a clean run. The first chunk holds 489 of the 2 501
// callbacks of the day. The second chunk fails.
func TestTU11RollupDayStepCrashBetweenChunks(t *testing.T) {
	r, _ := rollRig(t, newRollupStep(rollTDel, 30), newRollupDayStep(rollTDel, 30))
	seedDays(t, r.db)
	failCommit(r, 2)
	stops(t, r)
	if got := aggregates(t, r.db); !strings.Contains(got, "2027-01-10|a|human|f|1|3|489") || r.events() != 2508 {
		t.Fatalf("after the crash: aggregates %q, %d events", got, r.events())
	}
	replaceWriter(r)
	runOK(t, r)
	if got := aggregates(t, r.db); got != wantDays || metaValue(t, r.db, rollupDoneKey) != "2027-01-10" {
		t.Fatalf("after the new run: aggregates %q; want %q", got, wantDays)
	}
}

// T-U-11: a crash between two roll-up chunks gives the counts of a clean run.
// Two sessions have rows in many chunks. The failed chunk rolls back with its
// pairs and its deletes.
func TestTU11RollupCrashBetweenChunks(t *testing.T) {
	seed := func(r *rig) {
		addSession(t, r.db, "s1", "human", "f")
		addSession(t, r.db, "s2", "crawler", nil)
		addEvents(t, r.db, "request", 2500, utc("2027-01-09T01:00:00Z"), 1000, "s1", "a")
		addEvents(t, r.db, "request", 700, utc("2027-01-09T01:00:00Z")+1, 3000, "s2", "a")
	}
	clean, _ := rollRig(t, newRollupStep(rollTDel, 30))
	seed(clean)
	runOK(t, clean)
	r, _ := rollRig(t, newRollupStep(rollTDel, 30))
	seed(r)
	failCommit(r, 3)
	stops(t, r)
	if r.events() != 3200-666 {
		t.Fatalf("%d rows left after the crash; want 2 534", r.events())
	}
	replaceWriter(r)
	runOK(t, r)
	want := "2027-01-09|a|crawler||1|700|0 ; 2027-01-09|a|human|f|1|2500|0"
	if got, w := aggregates(t, r.db), aggregates(t, clean.db); got != want || w != want || r.events() != 0 {
		t.Fatalf("after a crash %q, clean %q; want %q", got, w, want)
	}
}

// T-U-11: a day step that runs before the roll-up step does nothing. A request
// row before the cutoff is left, so no day is done. No callback is counted, and
// no seen row or mark changes.
func TestTU11RollupDayStepWaitsForTheRollup(t *testing.T) {
	r, _ := rollRig(t, newRollupDayStep(rollTDel, 30), newRollupStep(rollTDel, 30))
	seedDays(t, r.db)
	runOK(t, r)
	want := "2027-01-10|a|human|f|1|3|0 ; 2027-01-11|a|human|f|1|2|0"
	if got := aggregates(t, r.db); got != want || count(t, r.db, "SELECT count(*) FROM rollup_seen") != 2 ||
		count(t, r.db, "SELECT count(*) FROM meta WHERE key LIKE 'retention_rollup%'") != 0 {
		t.Fatalf("aggregates %q; want %q, 2 seen rows and no mark", got, want)
	}
}

// call runs a step once in its own transaction with the limit. It commits.
func call(t *testing.T, db *sql.DB, step retentionStep, limit int) int {
	t.Helper()
	tx, err := db.Begin()
	check(t, err)
	n, err := step(context.Background(), tx, limit)
	check(t, err)
	check(t, tx.Commit())
	return n
}

// rollDay is the day step of the tests with the time rollTDel and 30 days.
var rollDay = newRollupDayStep(rollTDel, 30)

// T-U-11: the roll-up step uses the limit that the runner gives it. A request
// row costs 3. A limit of 7 takes 2 of 20 old rows and returns the limit. A
// limit of 2 takes no row and returns the limit. A limit of 30 takes 10 rows
// and returns the limit. The last 8 rows cost 24.
func TestTU11RollupStepUsesTheLimitOfTheRunner(t *testing.T) {
	db := migrated(t)
	addEvents(t, db, "request", 20, utc("2027-01-09T01:00:00Z"), 1, "s1", "a")
	step := newRollupStep(rollTDel, 30)
	for _, c := range []struct{ limit, want, left int }{{7, 7, 18}, {2, 2, 18}, {30, 30, 8}, {30, 24, 0}} {
		if n, left := call(t, db, step, c.limit), count(t, db, "SELECT count(*) FROM event"); n != c.want || left != c.left {
			t.Fatalf("limit %d: returned %d, %d rows left; want %d, %d", c.limit, n, left, c.want, c.left)
		}
	}
}

// totalChanges returns the rows that the connection of tx changed so far.
func totalChanges(t *testing.T, tx *sql.Tx) (n int) {
	t.Helper()
	check(t, tx.QueryRow("SELECT total_changes()").Scan(&n))
	return n
}

// seedMixed makes rows for both steps. Fifty request rows of distinct
// sessions and hosts are on two done days. Callbacks of distinct hosts are on
// two done days. Six seen rows are on an older day.
func seedMixed(t *testing.T, db *sql.DB) {
	t.Helper()
	for _, ts := range []int64{utc("2027-01-08T01:00:00Z"), utc("2027-01-09T01:00:00Z")} {
		mustExec(t, db, `WITH RECURSIVE c(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM c WHERE i < 24)
			INSERT INTO event (ts, session_id, kind, vhost) SELECT ? + i, 's' || i, 'request', 'h' || i FROM c`, ts)
		mustExec(t, db, `WITH RECURSIVE c(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM c WHERE i < 24)
			INSERT INTO event (ts, session_id, kind, vhost, hash, leaf_index) SELECT ? + i, 's' || i, 'callback', 'c' || i, zeroblob(32), i
			+ (SELECT coalesce(max(leaf_index) + 1, 0) FROM event) FROM c`, ts+3_600_000)
	}
	addSeen(t, db, "2027-01-05", 6)
}

// T-U-11: the count that a step returns is at least the rows that the call
// changed, and at most the limit. The data have distinct sessions and hosts,
// callbacks over two done days, and seen rows. The roll-up step runs with the
// limits 1000 and 7. The day step runs with 1000, 7 and 2.
func TestTU11RollupCountIsAnUpperBoundOfTheChangedRows(t *testing.T) {
	for _, c := range []struct {
		limit int
		both  bool
	}{{1000, true}, {7, true}, {2, false}} {
		t.Run(fmt.Sprint("limit ", c.limit), func(t *testing.T) {
			db := migrated(t)
			seedMixed(t, db)
			steps := []retentionStep{newRollupStep(rollTDel, 30), rollDay}
			if !c.both {
				steps = steps[1:]
				call(t, db, newRollupStep(rollTDel, 30), 1000)
			}
			for _, step := range steps {
				for calls, n := 0, 0; calls == 0 || n == c.limit; calls++ {
					tx, err := db.Begin()
					check(t, err)
					before := totalChanges(t, tx)
					n, err = step(context.Background(), tx, c.limit)
					check(t, err)
					if changed := totalChanges(t, tx) - before; changed > n || n > c.limit {
						t.Fatalf("limit %d: call returned %d and changed %d rows", c.limit, n, changed)
					}
					check(t, tx.Commit())
					if calls > 500 {
						t.Fatal("the step does not end")
					}
				}
			}
			if got := count(t, db, "SELECT count(*) FROM event WHERE kind = 'request'") + count(t, db, "SELECT count(*) FROM rollup_seen"); got != 0 ||
				metaValue(t, db, rollupDoneKey) != "2027-01-09" {
				t.Fatalf("%d request and seen rows left, mark %q", got, metaValue(t, db, rollupDoneKey))
			}
		})
	}
}

// addSeen adds n seen rows of a day. dayState returns the meta rows of the day
// step, the seen rows left and the callbacks counted.
func addSeen(t *testing.T, db *sql.DB, day string, n int) {
	t.Helper()
	mustExec(t, db, `WITH RECURSIVE c(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM c WHERE i < ?)
		INSERT INTO rollup_seen SELECT ?, 'a', 'human', '', 's' || i FROM c`, n, day)
}

func dayState(t *testing.T, db *sql.DB) string {
	t.Helper()
	var out string
	check(t, db.QueryRow(`SELECT coalesce((SELECT group_concat(key || '=' || value) FROM
		(SELECT * FROM meta WHERE key LIKE 'retention_rollup%' ORDER BY key)), '') ||
		' seen=' || (SELECT count(*) FROM rollup_seen) || ' cb=' || (SELECT coalesce(sum(callbacks), 0) FROM aggregate_day)`).Scan(&out))
	return out
}

// T-U-11: removing seen rows uses the row limit of a call, at a cost of 1 for
// each row. A done day has 5 seen rows and no callback. Two calls of 2 remove
// 4 of them. A call of 3 removes the last one, has room for the end of the day
// (cost 2) and sets the mark. A call that counts no callback saves no
// position. Then a day has 3 callbacks and 4 seen rows. A call of 5 counts 2
// callbacks. The next call counts the third and removes 3 seen rows. The last
// call removes 1 seen row and sets the mark.
func TestTU11RollupDayStepSeenRowsUseTheRowLimit(t *testing.T) {
	db := migrated(t)
	addSeen(t, db, "2027-01-08", 5)
	for i, want := range []string{" seen=3 cb=0", " seen=1 cb=0", "retention_rollup_done=2027-01-08 seen=0 cb=0"} {
		call(t, db, rollDay, min(2+i/2, 3))
		if got := dayState(t, db); got != want {
			t.Fatalf("state %q; want %q", got, want)
		}
	}
	addSeen(t, db, "2027-01-09", 4)
	ts := utc("2027-01-09T01:00:00Z")
	addEvents(t, db, "callback", 3, ts, 1000, nil, nil)
	for _, c := range []struct {
		n     int
		state string
	}{{5, "retention_rollup_done=2027-01-08,retention_rollup_pos=" + fmt.Sprint(ts+1000) + ":2 seen=4 cb=2"},
		{5, "retention_rollup_done=2027-01-08,retention_rollup_pos=" + fmt.Sprint(ts+2000) + ":3 seen=1 cb=3"},
		{3, "retention_rollup_done=2027-01-09 seen=0 cb=3"}} {
		if n, got := call(t, db, rollDay, 5), dayState(t, db); n != c.n || got != c.state {
			t.Fatalf("call gave %d, state %q; want %d, %q", n, got, c.n, c.state)
		}
	}
}

// T-U-11: a callback at the first or the last ms of a UTC day counts one time.
// It counts under its own day. Calls of 2 callbacks cross the midnights and a
// saved position.
func TestTU11RollupDayStepCountsDayEdges(t *testing.T) {
	db := migrated(t)
	addEvents(t, db, "callback", 2, utc("2027-01-09T00:00:00Z")-1, 1, nil, nil)
	addEvents(t, db, "callback", 2, utc("2027-01-10T00:00:00Z")-1, 1, nil, nil)
	for i := 0; i < 20 && call(t, db, rollDay, 2) > 0; i++ {
	}
	want := "2027-01-08||human||0|0|1 ; 2027-01-09||human||0|0|2 ; 2027-01-10||human||0|0|1"
	if got := aggregates(t, db); got != want {
		t.Fatalf("aggregates %q; want %q", got, want)
	}
}

// T-U-11: a day is done when its end is the cutoff. One ms later it is not.
func TestTU11RollupDayStepDoneAtTheCutoff(t *testing.T) {
	for _, c := range []struct {
		shift time.Duration
		want  int
	}{{0, 1}, {-time.Millisecond, 0}} {
		db := migrated(t)
		addEvents(t, db, "callback", 1, utc("2027-01-09T12:00:00Z"), 0, nil, nil)
		call(t, db, newRollupDayStep(time.Date(2027, 1, 11, 0, 0, 0, 0, time.UTC).Add(c.shift), 1), 10)
		if got := count(t, db, "SELECT coalesce(sum(callbacks), 0) FROM aggregate_day"); got != c.want {
			t.Fatalf("shift %v: %d callbacks counted; want %d", c.shift, got, c.want)
		}
	}
}

// T-U-11: a seen day older than the first callback day after the mark is done
// first. A call of 2 deletes its 2 seen rows and counts no callback. A call
// with limit 0 reads nothing, also with a bad mark.
func TestTU11RollupDayStepTakesTheOlderDayFirst(t *testing.T) {
	db := migrated(t)
	addSeen(t, db, "2027-01-05", 2)
	addEvents(t, db, "callback", 1, utc("2027-01-07T12:00:00Z"), 0, nil, nil)
	call(t, db, rollDay, 2)
	if got := dayState(t, db); got != " seen=0 cb=0" {
		t.Fatalf("after the first call: %q", got)
	}
	call(t, db, rollDay, 9)
	if got := dayState(t, db); got != "retention_rollup_done=2027-01-07 seen=0 cb=1" {
		t.Fatalf("after the second call: %q", got)
	}
	mustExec(t, db, metaSetSQL, rollupDoneKey, "bad")
	if n := call(t, db, rollDay, 0); n != 0 {
		t.Fatalf("a call with limit 0 gave %d", n)
	}
}

// T-U-11: a row that cannot be read stops the roll-up step with an error. Here
// the ts is a real number, so the scan fails. The rows are closed.
func TestTU11RollupStepReportsAScanError(t *testing.T) {
	db := migrated(t)
	mustExec(t, db, "INSERT INTO event (ts, kind) VALUES (1.5, 'request')")
	tx, err := db.Begin()
	check(t, err)
	defer tx.Rollback()
	if _, err := newRollupStep(rollTDel, 30)(context.Background(), tx, 10); err == nil {
		t.Fatal("no error for a row that cannot be read")
	}
}

// T-U-11: a days value below 1 or above 30, or a zero tDel, gives a step that
// runs no statement. The run stops the writer, and no row changes.
func TestTU11RollupRefusesBadParameters(t *testing.T) {
	for _, c := range []struct {
		name string
		tDel time.Time
		days int
	}{{"0 days", rollTDel, 0}, {"31 days", rollTDel, 31}, {"zero tDel", time.Time{}, 30}} {
		t.Run(c.name, func(t *testing.T) {
			for _, step := range []retentionStep{newRollupStep(c.tDel, c.days), newRollupDayStep(c.tDel, c.days)} {
				r, chunks := rollRig(t, step)
				addEvents(t, r.db, "request", 1, utc("2027-01-01T00:00:00Z"), 0, nil, "a")
				stops(t, r)
				if r.events() != 1 || aggregates(t, r.db) != "" || rowsChanged(*chunks) != 0 {
					t.Fatalf("%d rows left, aggregates %q; want 1 row and no change", r.events(), aggregates(t, r.db))
				}
			}
		})
	}
}

// T-U-11: each statement of the steps uses an index. No plan scans event,
// session, aggregate_day or rollup_seen. The two picks use event_kind_ts.
// Thus a call reads at most its limit.
func TestTU11RollupStatementsUseIndexes(t *testing.T) {
	db := migrated(t)
	for _, c := range []struct {
		q    string
		args []any
		use  string
	}{
		{rollupPickSQL, []any{1, 1000}, "event_kind_ts"},
		{rollupLeftSQL, []any{1}, "event_kind_ts"},
		{rollupCallbackSQL, []any{1, 2, 1, 0, 1000}, "event_kind_ts"},
		{rollupFirstCallbackSQL, []any{1}, "event_kind_ts"},
		{rollupFirstSeenSQL, []any{""}, "PRIMARY KEY"},
		{rollupDropSeenSQL, []any{"d", 1000}, "PRIMARY KEY"},
		{rollupSeenSQL, []any{"d", "v", "b", "f", "s"}, ""},
		{rollupAddSQL, []any{"d", "v", "b", "f", 1, 1, 1}, ""},
		{metaGetSQL, []any{"k"}, "sqlite_autoindex_meta_1"},
	} {
		plan := strings.Join(queryPlan(t, db, c.q, c.args...), "\n")
		if strings.Contains(plan, "SCAN event") || strings.Contains(plan, "SCAN s") || strings.Contains(plan, "SCAN aggregate_day") ||
			strings.Contains(plan, "SCAN rollup_seen") || !strings.Contains(plan, c.use) {
			t.Errorf("plan of %q:\n%s\nwant no SCAN and %q", c.q, plan, c.use)
		}
	}
}

const (
	// rollChildDir is the state directory of the child. rollChildTDel is
	// the tDel of the steps, in unix ms.
	rollChildDir  = "STORE_ROLLUP_CHILD_DIR"
	rollChildTDel = "STORE_ROLLUP_CHILD_TDEL"
)

// BenchmarkRollup measures the roll-up and day steps through the runner, as
// the ADR-032 table needs. The child process runs w.chunk until no row is
// left. It prints VmHWM, the total time and the longest chunk. It prints the
// rows changed, and the WAL and database bytes after. It prints the size of
// rollup_seen at its largest. This is when the roll-up step is done. Run it
// with -benchtime=1x:
//
//	PHANTOM_ROLLUP_ROWS=4000000 PHANTOM_ROLLUP_SHAPE=a \
//	  go test -run '^$' -bench '^BenchmarkRollup$' -benchtime=1x \
//	  ./internal/store
//
// PHANTOM_ROLLUP_ROWS gives the request rows (default 20 000). The rows cover
// 40 days that end at tDel. The shape is "a" or "b". Shape "a" (default) has 1
// session for each 5 requests. Shape "b" has 1 session for each request, the
// most pairs. A callback event follows each 200 requests. The steps use 30
// days.
func BenchmarkRollup(b *testing.B) {
	if _, err := os.Stat("/proc/self/status"); err != nil {
		b.Skip("no /proc/self/status: the benchmark reads RSS from it")
	}
	n, per := 20_000, 5
	if s := os.Getenv("PHANTOM_ROLLUP_ROWS"); s != "" {
		v, err := strconv.Atoi(s)
		if err != nil || v < chunkRows {
			b.Fatalf("PHANTOM_ROLLUP_ROWS %q: want a number of at least %d", s, chunkRows)
		}
		n = v
	}
	if os.Getenv("PHANTOM_ROLLUP_SHAPE") == "b" {
		per = 1
	}
	tDel := time.Now()
	state := rollBenchState(b, n, per, tDel)
	cmd := exec.Command(os.Args[0], "-test.run=^$", "-test.bench=^BenchmarkRollupChild$", "-test.benchtime=1x")
	cmd.Env = append(os.Environ(), rollChildDir+"="+state, rollChildTDel+"="+strconv.FormatInt(tDel.UnixMilli(), 10))
	out, err := cmd.CombinedOutput()
	m := map[string]float64{}
	for _, line := range strings.Split(string(out), "\n") {
		if fields, ok := strings.CutPrefix(line, "rollup-child "); ok && err == nil {
			for _, kv := range strings.Fields(fields) {
				k, v, _ := strings.Cut(kv, "=")
				m[k], _ = strconv.ParseFloat(v, 64)
			}
		}
	}
	if m["rss"] == 0 || m["rows"] == 0 {
		b.Fatalf("child: %v\n%s", err, out)
	}
	b.ReportMetric(m["rss"]/mib, "peak-rss-MiB")
	b.ReportMetric(m["ms"], "total-ms")
	b.ReportMetric(m["longest"], "chunk-max-ms")
	b.ReportMetric(m["wal"]/mib, "wal-MiB")
	b.ReportMetric(m["db"]/mib, "db-MiB")
	b.ReportMetric(m["seenrows"], "seen-rows-max")
	b.ReportMetric(m["seenbytes"]/mib, "seen-MiB-max")
}

// rollBenchState makes a database of n request rows with one session for each
// `per` requests, and n/200 callbacks. The rows cover 40 days that end at tDel.
// The setup runs in the parent, so a child process has its own peak.
func rollBenchState(b *testing.B, n, per int, tDel time.Time) string {
	top, err := filepath.EvalSymlinks(b.TempDir())
	check(b, err)
	state := filepath.Join(top, "state")
	check(b, os.Mkdir(state, 0o700))
	db := openState(b, state)
	defer db.Close()
	check(b, Migrate(db, "origin"))
	mustExec(b, db, "PRAGMA ignore_check_constraints=ON")
	span := int64(40 * 24 * time.Hour / time.Millisecond)
	base, step := tDel.UnixMilli()-span, max(1, span/int64(n))
	const rec = "WITH RECURSIVE c(i) AS (SELECT ? UNION ALL SELECT i+1 FROM c WHERE i < ?) "
	for off := 0; off < n; off += 100_000 {
		last := off + min(100_000, n-off) - 1
		mustExec(b, db, rec+`INSERT INTO event (ts, session_id, kind, vhost)
			SELECT ? + i*?, 's' || (i / ?), 'request', 'v' || (i % 3) FROM c`, off, last, base, step, per)
		mustExec(b, db, rec+`INSERT INTO session (id, first_seen, last_seen, ip_hmac, band) SELECT 's' || i, 0, 0, 'h',
			CASE i % 4 WHEN 0 THEN 'human' WHEN 1 THEN 'crawler' WHEN 2 THEN 'agent-likely' ELSE 'agent-confirmed' END FROM c`,
			off/per, last/per)
		mustExec(b, db, rec+`INSERT INTO event (ts, session_id, kind, vhost, hash, leaf_index)
			SELECT ? + i*?, 's' || (i % 7), 'callback', 'v' || (i % 3), zeroblob(32), i FROM c`, off/200, last/200, base, step*200)
	}
	mustExec(b, db, "PRAGMA ignore_check_constraints=OFF")
	return state
}

// check fails the test or benchmark on an error.
func check(tb testing.TB, err error) {
	tb.Helper()
	if err != nil {
		tb.Fatal(err)
	}
}

// mustExec runs a statement and fails the test or benchmark on an error.
func mustExec(tb testing.TB, db *sql.DB, q string, args ...any) {
	tb.Helper()
	_, err := db.Exec(q, args...)
	check(tb, err)
}

// openState opens the database of a state directory. The cleanup closes the
// directory.
func openState(b *testing.B, dir string) *sql.DB {
	b.Helper()
	root, err := os.OpenRoot(dir)
	check(b, err)
	b.Cleanup(func() { root.Close() })
	db, err := Open(root, "events.db", Options{})
	check(b, err)
	return db
}

// BenchmarkRollupChild is the child process of BenchmarkRollup. Without its
// environment variables, it skips.
func BenchmarkRollupChild(b *testing.B) {
	dir := os.Getenv(rollChildDir)
	if dir == "" {
		b.Skip("child process of BenchmarkRollup")
	}
	tms, err := strconv.ParseInt(os.Getenv(rollChildTDel), 10, 64)
	check(b, err)
	db := openState(b, dir)
	q, err := event.NewQueue(1, event.NewCounters())
	check(b, err)
	tDel := time.UnixMilli(tms)
	w := NewWriter(db, q, false, nil, Recovery{})
	steps := []retentionStep{newRollupStep(tDel, 30), newRollupDayStep(tDel, 30)}
	var total, longest time.Duration
	rows, seenRows, seenBytes := 0, 0, int64(0)
	for cur := 0; cur < len(steps); {
		begin, was := time.Now(), cur
		n, err := w.chunk(steps, &cur)
		check(b, err)
		took := time.Since(begin)
		total, longest, rows = total+took, max(longest, took), rows+n
		if was == 0 && cur == 1 {
			// The roll-up step is done: rollup_seen is at its largest.
			db.QueryRow("SELECT count(*) FROM rollup_seen").Scan(&seenRows)
			db.QueryRow("SELECT coalesce(sum(pgsize), 0) FROM dbstat WHERE name = 'rollup_seen'").Scan(&seenBytes)
		}
	}
	wal := fileSize(filepath.Join(dir, "events.db-wal"))
	fmt.Printf("rollup-child rss=%d ms=%.3f longest=%.3f rows=%d wal=%d db=%d seenrows=%d seenbytes=%d\n", procStatus(b, "VmHWM"),
		ms(total), ms(longest), rows, wal, fileSize(filepath.Join(dir, "events.db")), seenRows, seenBytes)
}
