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

// rollCutoff is the cutoff of the steps for `days` x 24 h, in unix ms. The tests
// make it again from the definition, not from the code under test.
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
	if _, err := db.Exec("INSERT INTO session (id, first_seen, last_seen, ip_hmac, band, family) VALUES (?, 0, 0, 'h', ?, ?)", id, band, family); err != nil {
		tb.Fatal(err)
	}
}

// addEvents inserts n rows of kind with ts = ts0 + i*step. A session id or a
// vhost of nil is NULL. A callback row gets a hash and a leaf index.
func addEvents(tb testing.TB, db *sql.DB, kind string, n int, ts0, step int64, sid, vhost any) {
	tb.Helper()
	var next int64
	if err := db.QueryRow("SELECT coalesce(max(leaf_index) + 1, 0) FROM event").Scan(&next); err != nil {
		tb.Fatal(err)
	}
	cb := kind == "callback"
	if _, err := db.Exec(`WITH RECURSIVE c(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM c WHERE i < ?)
		INSERT INTO event (ts, session_id, kind, vhost, hash, leaf_index)
		SELECT ? + i*?, ?, ?, ?, CASE WHEN ? THEN zeroblob(32) END, CASE WHEN ? THEN ? + i END FROM c`,
		n-1, ts0, step, sid, kind, vhost, cb, cb, next); err != nil {
		tb.Fatal(err)
	}
}

// aggregates returns the rows of aggregate_day as text, in key order.
func aggregates(tb testing.TB, db *sql.DB) string {
	tb.Helper()
	rows, err := db.Query("SELECT day, vhost, band, family, sessions, requests, callbacks FROM aggregate_day ORDER BY day, vhost, band, family")
	if err != nil {
		tb.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var d, v, b, f string
		var s, q, c int
		if err := rows.Scan(&d, &v, &b, &f, &s, &q, &c); err != nil {
			tb.Fatal(err)
		}
		out = append(out, fmt.Sprintf("%s|%s|%s|%s|%d|%d|%d", d, v, b, f, s, q, c))
	}
	return strings.Join(out, " ; ")
}

// count returns the result of a query with one integer.
func count(tb testing.TB, db *sql.DB, q string) (n int) {
	tb.Helper()
	if err := db.QueryRow(q).Scan(&n); err != nil {
		tb.Fatal(err)
	}
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

// runAgain makes one more run of the rig with steps.
func runAgain(t *testing.T, r *rig, steps ...retentionStep) {
	t.Helper()
	setHook(t, &retentionSteps, steps)
	if err := r.runDirect(); err != nil {
		t.Fatal(err)
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
	if err := r.runDirect(); err != nil {
		t.Fatal(err)
	}
	want := "2027-01-09|a|crawler||1|3|0 ; 2027-01-09|a|human|f|1|1500|0 ; 2027-01-11|a|human|f|1|11|0"
	if got := aggregates(t, r.db); got != want || fmt.Sprint(*chunks) != "[1000 514]" || r.events() != 6 {
		t.Fatalf("aggregates %q, chunks %v, %d rows left; want %q, [1000 514], 6", got, *chunks, r.events(), want)
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
			if err := r.runDirect(); err != nil {
				t.Fatal(err)
			}
			before := time.UnixMilli(cut - 1).UTC().Format("2006-01-02")
			want := "2027-01-01|late|human||0|1|0 ; " + before + "|before|human||0|1|0"
			if got := aggregates(t, r.db); got != want || r.events() != 2 {
				t.Fatalf("aggregates %q, %d rows left; want %q, 2", got, r.events(), want)
			}
		})
	}
}

// T-U-11: "exact for each key" means that a session counts one time for each key
// (day, vhost, band, family) in which it has a row. One session has 2 500 rows
// in 3 chunks. Its band changes after the first chunk. It counts one time under
// each band, and the pairs keep it from counting for each chunk.
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
	if err := r.runDirect(); err != nil {
		t.Fatal(err)
	}
	want := "2027-01-09|a|crawler|f|1|1500|0 ; 2027-01-09|a|human|f|1|1000|0"
	if got := aggregates(t, r.db); got != want || fmt.Sprint(*chunks) != "[1000 1000 500]" {
		t.Fatalf("aggregates %q, chunks %v; want %q", got, *chunks, want)
	}
}

// T-S-34: a request row with no vhost, with no session row, or with a session
// that has no family rolls up to ” , 'human' and ”. The writer stays healthy.
// A second run with more rows of the same keys gives the same rows with higher
// counts, and one row for each key. A session with no row counts one time.
func TestTS34RollupNullKeys(t *testing.T) {
	r, _ := rollRig(t, newRollupStep(rollTDel, 30))
	ts := utc("2027-01-09T01:00:00Z")
	addSession(t, r.db, "nofamily", "agent-likely", nil)
	addEvents(t, r.db, "request", 2, ts, 1, nil, nil)
	addEvents(t, r.db, "request", 2, ts, 1, "ghost", "v")
	addEvents(t, r.db, "request", 2, ts, 1, "nofamily", nil)
	if err := r.runDirect(); err != nil {
		t.Fatal(err)
	}
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

// seedDays makes the rows of the day step tests. The request rows are 3 in
// 2027-01-10, which is done, and 2 in 2027-01-11 before the cutoff, which is
// not done, and 1 after the cutoff. The callbacks are 2 on 2027-01-02, 2 501 on
// 2027-01-10 (one has no vhost and no session) and 4 on 2027-01-11.
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

// wantDays is the result of the day step tests after a full run: the callbacks
// of the two done days are counted, the other day has no callback count.
const wantDays = "2027-01-02|a|human|f|0|0|2 ; 2027-01-10||human||0|0|1 ; " +
	"2027-01-10|a|human|f|1|3|2500 ; 2027-01-11|a|human|f|1|2|0"

// T-U-11: the day step counts the callbacks of the done days and removes the
// seen rows of them. It skips the days with no data and keeps the day that is
// not done. The mark is the last done day, and no position stays.
func TestTU11RollupDayStepCountsCallbacksOnce(t *testing.T) {
	r, chunks := rollRig(t, newRollupStep(rollTDel, 30), newRollupDayStep(rollTDel, 30))
	seedDays(t, r.db)
	if err := r.runDirect(); err != nil {
		t.Fatal(err)
	}
	if got := aggregates(t, r.db); got != wantDays || fmt.Sprint(*chunks) != "[1000 1000 509]" {
		t.Fatalf("aggregates %q, chunks %v; want %q, [1000 1000 509]", got, *chunks, wantDays)
	}
	if m := metaValue(t, r.db, rollupDoneKey); m != "2027-01-10" || count(t, r.db, "SELECT count(*) FROM meta WHERE key = '"+rollupPosKey+"'") != 0 ||
		count(t, r.db, "SELECT count(*) FROM rollup_seen") != 1 || r.events() != 2508 {
		t.Fatalf("mark %q, %d seen rows, %d events", m, count(t, r.db, "SELECT count(*) FROM rollup_seen"), r.events())
	}
}

// T-U-11: a failed chunk in the middle of a day rolls back, with its position.
// A new writer on the same database counts each callback one time and gives
// the result of a clean run. The first chunk holds 995 of the 2 501 callbacks of
// the day. The second chunk fails.
func TestTU11RollupDayStepCrashBetweenChunks(t *testing.T) {
	r, _ := rollRig(t, newRollupStep(rollTDel, 30), newRollupDayStep(rollTDel, 30))
	seedDays(t, r.db)
	failCommit(r, 2)
	if err := r.runDirect(); err == nil || r.w.Healthy() {
		t.Fatalf("run error %v, healthy %v; want an error and a stopped writer", err, r.w.Healthy())
	}
	if got := aggregates(t, r.db); !strings.Contains(got, "2027-01-10|a|human|f|1|3|993") || r.events() != 2508 {
		t.Fatalf("after the crash: aggregates %q, %d events", got, r.events())
	}
	replaceWriter(r)
	if err := r.runDirect(); err != nil {
		t.Fatal(err)
	}
	if got := aggregates(t, r.db); got != wantDays || metaValue(t, r.db, rollupDoneKey) != "2027-01-10" {
		t.Fatalf("after the new run: aggregates %q; want %q", got, wantDays)
	}
}

// T-U-11: a crash between two roll-up chunks gives the counts of a clean run:
// two sessions have rows in each of 4 chunks. The failed chunk rolls back with
// its pairs and its deletes.
func TestTU11RollupCrashBetweenChunks(t *testing.T) {
	seed := func(r *rig) {
		addSession(t, r.db, "s1", "human", "f")
		addSession(t, r.db, "s2", "crawler", nil)
		addEvents(t, r.db, "request", 2500, utc("2027-01-09T01:00:00Z"), 1000, "s1", "a")
		addEvents(t, r.db, "request", 700, utc("2027-01-09T01:00:00Z")+1, 3000, "s2", "a")
	}
	clean, _ := rollRig(t, newRollupStep(rollTDel, 30))
	seed(clean)
	if err := clean.runDirect(); err != nil {
		t.Fatal(err)
	}
	r, _ := rollRig(t, newRollupStep(rollTDel, 30))
	seed(r)
	failCommit(r, 3)
	if err := r.runDirect(); err == nil || r.events() != 3200-2000 {
		t.Fatalf("run error %v, %d rows left; want an error and 1 200", err, r.events())
	}
	replaceWriter(r)
	if err := r.runDirect(); err != nil {
		t.Fatal(err)
	}
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
	if err := r.runDirect(); err != nil {
		t.Fatal(err)
	}
	want := "2027-01-10|a|human|f|1|3|0 ; 2027-01-11|a|human|f|1|2|0"
	if got := aggregates(t, r.db); got != want || count(t, r.db, "SELECT count(*) FROM rollup_seen") != 2 ||
		count(t, r.db, "SELECT count(*) FROM meta WHERE key LIKE 'retention_rollup%'") != 0 {
		t.Fatalf("aggregates %q; want %q, 2 seen rows and no mark", got, want)
	}
}

// T-U-11: each step uses the limit that the runner gives it. In one
// transaction, a limit of 7 over 20 old rows changes 7 rows. A limit of 5 over
// 12 callbacks of a done day gives 5, 5 and 3 rows: the third call counts 2
// callbacks and deletes 1 seen row. Then it sets the mark.
func TestTU11RollupStepsUseTheLimitOfTheRunner(t *testing.T) {
	r := newRig(t, 100)
	ctx := context.Background()
	addEvents(t, r.db, "request", 20, utc("2027-01-09T01:00:00Z"), 1, "s1", "a")
	addEvents(t, r.db, "callback", 12, utc("2027-01-09T02:00:00Z"), 1, "s1", "a")
	tx, err := r.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	var got []int
	for _, c := range []struct {
		step  retentionStep
		limit int
	}{{newRollupStep(rollTDel, 30), 7}, {newRollupStep(rollTDel, 30), 30}, {newRollupDayStep(rollTDel, 30), 5},
		{newRollupDayStep(rollTDel, 30), 5}, {newRollupDayStep(rollTDel, 30), 5}} {
		n, err := c.step(ctx, tx, c.limit)
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, n)
	}
	var mark string
	if err := tx.QueryRow("SELECT value FROM meta WHERE key = ?", rollupDoneKey).Scan(&mark); err != nil || fmt.Sprint(got) != "[7 13 5 5 3]" || mark != "2027-01-09" {
		t.Fatalf("rows by call %v, mark %q (%v); want [7 13 5 5 3] and 2027-01-09", got, mark, err)
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
				if err := r.runDirect(); err == nil || r.w.Healthy() {
					t.Fatalf("run error %v, healthy %v; want an error and a stopped writer", err, r.w.Healthy())
				}
				if r.events() != 1 || aggregates(t, r.db) != "" || rowsChanged(*chunks) != 0 {
					t.Fatalf("%d rows left, aggregates %q; want 1 row and no change", r.events(), aggregates(t, r.db))
				}
			}
		})
	}
}

// T-U-11: each statement of the steps uses an index. No plan scans event,
// session, aggregate_day or rollup_seen. The pick of the roll-up and the pick
// of the callbacks use event_kind_ts, so a call reads at most its limit.
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
	// rollChildDir is the state directory of the child. rollChildTDel is the tDel
	// of the steps, in unix ms.
	rollChildDir  = "STORE_ROLLUP_CHILD_DIR"
	rollChildTDel = "STORE_ROLLUP_CHILD_TDEL"
)

// BenchmarkRollup measures the roll-up and day steps through the runner, as
// the ADR-032 table needs. The child process runs w.chunk until no row is left.
// It prints VmHWM, the total time, the longest chunk, the rows changed, the WAL
// bytes and the database bytes after, and the size of rollup_seen at its
// largest, which is when the roll-up step is done. Run it with -benchtime=1x:
//
//	PHANTOM_ROLLUP_ROWS=4000000 PHANTOM_ROLLUP_SHAPE=a \
//	  go test -run '^$' -bench '^BenchmarkRollup$' -benchtime=1x ./internal/store
//
// PHANTOM_ROLLUP_ROWS gives the request rows (default 20 000). The rows cover 40
// days that end at tDel. The shape is "a" (1 session for each 5 requests,
// default) or "b" (1 session for each request, the most pairs). A callback
// event follows each 200 requests. The steps use 30 days.
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
	if m["rss"] == 0 {
		b.Fatalf("child: %v\n%s", err, out)
	}
	root, err := os.OpenRoot(state)
	if err != nil {
		b.Fatal(err)
	}
	defer root.Close()
	db, err := Open(root, "events.db", Options{})
	if err != nil {
		b.Fatal(err)
	}
	defer db.Close()
	var rolled int
	q := "SELECT coalesce(sum(requests), 0) FROM aggregate_day"
	if err := db.QueryRow(q).Scan(&rolled); err != nil || rolled == 0 || rolled+count(b, db, "SELECT count(*) FROM event WHERE kind = 'request'") != n {
		b.Fatalf("%d requests rolled, %d left of %d: %v", rolled, n-rolled, n, err)
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
	if err != nil {
		b.Fatal(err)
	}
	state := filepath.Join(top, "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		b.Fatal(err)
	}
	root, err := os.OpenRoot(state)
	if err != nil {
		b.Fatal(err)
	}
	defer root.Close()
	db, err := Open(root, "events.db", Options{})
	if err != nil {
		b.Fatal(err)
	}
	defer db.Close()
	if err := Migrate(db, "origin"); err != nil {
		b.Fatal(err)
	}
	if _, err := db.Exec("PRAGMA ignore_check_constraints=ON"); err != nil {
		b.Fatal(err)
	}
	span := int64(40 * 24 * time.Hour / time.Millisecond)
	base, step := tDel.UnixMilli()-span, max(1, span/int64(n))
	for off := 0; off < n; off += 100_000 {
		last := off + min(100_000, n-off) - 1
		if _, err := db.Exec(`WITH RECURSIVE c(i) AS (SELECT ? UNION ALL SELECT i+1 FROM c WHERE i < ?)
			INSERT INTO event (ts, session_id, kind, vhost) SELECT ? + i*?, 's' || (i / ?), 'request', 'v' || (i % 3) FROM c`,
			off, last, base, step, per); err != nil {
			b.Fatal(err)
		}
		if _, err := db.Exec(`WITH RECURSIVE c(i) AS (SELECT ? UNION ALL SELECT i+1 FROM c WHERE i < ?)
			INSERT INTO session (id, first_seen, last_seen, ip_hmac, band)
			SELECT 's' || i, 0, 0, 'h', CASE i % 4 WHEN 0 THEN 'human' WHEN 1 THEN 'crawler' WHEN 2 THEN 'agent-likely' ELSE 'agent-confirmed' END FROM c`,
			off/per, last/per); err != nil {
			b.Fatal(err)
		}
		if _, err := db.Exec(`WITH RECURSIVE c(i) AS (SELECT ? UNION ALL SELECT i+1 FROM c WHERE i < ?)
			INSERT INTO event (ts, session_id, kind, vhost, hash, leaf_index)
			SELECT ? + i*?, 's' || (i % 7), 'callback', 'v' || (i % 3), zeroblob(32), i FROM c`,
			off/200, last/200, base, step*200); err != nil {
			b.Fatal(err)
		}
	}
	if _, err := db.Exec("PRAGMA ignore_check_constraints=OFF"); err != nil {
		b.Fatal(err)
	}
	return state
}

// BenchmarkRollupChild is the child process of BenchmarkRollup. Without its
// environment variables, it skips.
func BenchmarkRollupChild(b *testing.B) {
	dir := os.Getenv(rollChildDir)
	if dir == "" {
		b.Skip("child process of BenchmarkRollup")
	}
	tms, err := strconv.ParseInt(os.Getenv(rollChildTDel), 10, 64)
	if err != nil {
		b.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		b.Fatal(err)
	}
	db, err := Open(root, "events.db", Options{})
	if err != nil {
		b.Fatal(err)
	}
	q, err := event.NewQueue(1, event.NewCounters())
	if err != nil {
		b.Fatal(err)
	}
	tDel := time.UnixMilli(tms)
	w := NewWriter(db, q, false, nil, Recovery{})
	steps := []retentionStep{newRollupStep(tDel, 30), newRollupDayStep(tDel, 30)}
	var total, longest time.Duration
	rows, seenRows, seenBytes := 0, 0, int64(0)
	for cur := 0; cur < len(steps); {
		begin, was := time.Now(), cur
		n, err := w.chunk(steps, &cur)
		if err != nil {
			b.Fatal(err)
		}
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
