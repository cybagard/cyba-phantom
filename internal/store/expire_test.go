package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"
)

// expireCase describes one 90-day step for the tests. add inserts per rows.
// Each row has the key `at`, and a young value in each other time column. bulk
// inserts n rows with the key `at`. cost is the cost of a deleted row, as the
// measurement gave it.
type expireCase struct {
	name, table, key, plan string
	stmt                   string
	mk                     func(time.Time, int) retentionStep
	cost                   int
	per, extra             int // rows of one add; rows of setup that stay
	setup                  func(tb testing.TB, db *sql.DB)
	add                    func(tb testing.TB, db *sql.DB, at int64)
	bulk                   func(tb testing.TB, db *sql.DB, n int, at int64)
}

var expireBands = []string{"human", "crawler", "agent-likely", "agent-confirmed"}

// expireCaseNamed returns the case with the name.
func expireCaseNamed(name string) expireCase {
	for _, c := range expireCases {
		if c.name == name {
			return c
		}
	}
	panic("no expire case " + name)
}

// addEventAt inserts one event row. A callback and a score_change row get a
// hash and a leaf index, as the schema needs.
func addEventAt(tb testing.TB, db *sql.DB, kind string, at int64) {
	tb.Helper()
	ev := kind != "request"
	mustExec(tb, db, `INSERT INTO event (ts, kind, hash, leaf_index) SELECT ?, ?, CASE WHEN ? THEN zeroblob(32) END,
		CASE WHEN ? THEN (SELECT coalesce(max(leaf_index) + 1, 0) FROM event) END`, at, kind, ev, ev)
}

var expireCases = []expireCase{
	{
		name: "event", table: "event", key: "ts", mk: newEventExpireStep, stmt: deleteEventSQL, cost: 1, per: 3,
		plan: "SEARCH event USING INTEGER PRIMARY KEY (rowid=?)\nLIST SUBQUERY 1\nSEARCH event USING COVERING INDEX event_ts (ts<?)",
		add: func(tb testing.TB, db *sql.DB, at int64) {
			for _, k := range []string{"request", "callback", "score_change"} {
				addEventAt(tb, db, k, at)
			}
		},
		bulk: func(tb testing.TB, db *sql.DB, n int, at int64) { addEvents(tb, db, "request", n, at, 0, nil, nil) },
	},
	{
		// The key is first_cb_at. issued_at is young for each row. A token
		// with no callback has a NULL key and an old issued_at. It stays.
		name: "token", table: "token", key: "first_cb_at", mk: newTokenExpireStep, stmt: deleteTokenSQL, cost: 1, per: 1, extra: 1,
		plan: "SEARCH token USING INTEGER PRIMARY KEY (rowid=?)\nLIST SUBQUERY 1\nSEARCH token USING COVERING INDEX token_first_cb (first_cb_at<?)",
		setup: func(tb testing.TB, db *sql.DB) {
			mustExec(tb, db, "INSERT INTO token (token_id, session_id, trap_id, issued_at) VALUES ('none', 's', 't', 1)")
		},
		add: func(tb testing.TB, db *sql.DB, at int64) {
			mustExec(tb, db, "INSERT INTO token (token_id, session_id, trap_id, issued_at, first_cb_at) VALUES (?, 's', 't', ?, ?)",
				fmt.Sprint("t", at), rollTDel.UnixMilli(), at)
		},
		bulk: func(tb testing.TB, db *sql.DB, n int, at int64) {
			mustExec(tb, db, `WITH RECURSIVE c(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM c WHERE i < ?)
				INSERT INTO token (token_id, session_id, trap_id, issued_at, first_cb_at) SELECT 't' || i, 's', 't', ?, ? FROM c`,
				n-1, rollTDel.UnixMilli(), at)
		},
	},
	{
		// The key is last_seen. first_seen is young for each row. Each band
		// has a row.
		name: "session", table: "session", key: "last_seen", mk: newSessionExpireStep, stmt: deleteSessionSQL, cost: 4, per: len(expireBands),
		plan: "SEARCH session USING INTEGER PRIMARY KEY (rowid=?)\nLIST SUBQUERY 1\nSEARCH session USING COVERING INDEX session_band_last (band=? AND last_seen<?)",
		add: func(tb testing.TB, db *sql.DB, at int64) {
			for _, b := range expireBands {
				mustExec(tb, db, "INSERT INTO session (id, first_seen, last_seen, ip_hmac, band) VALUES (?, ?, ?, 'h', ?)",
					fmt.Sprint(b, at), rollTDel.UnixMilli(), at, b)
			}
		},
		bulk: func(tb testing.TB, db *sql.DB, n int, at int64) { addSessions(tb, db, "s", 0, n, at, 0, nil) },
	},
}

// T-U-11: a row of 91 d is gone. A row at the cutoff and a row of 89 d stay.
// The event rows are of three kinds. The session rows are of the four bands.
// Each step uses its own column, as the other time columns are young.
func TestTU11ExpireStepsDeleteByTheirKey(t *testing.T) {
	cut := rollCutoff(90)
	for _, c := range expireCases {
		t.Run(c.name, func(t *testing.T) {
			r, chunks := rollRig(t, c.mk(rollTDel, 90))
			if c.setup != nil {
				c.setup(t, r.db)
			}
			for _, d := range []int64{-rawDay, -1, 0, rawDay} {
				c.add(t, r.db, cut+d)
			}
			runOK(t, r)
			q := fmt.Sprintf("SELECT count(*) FROM %s WHERE %s < %d", c.table, c.key, cut)
			if old, all := count(t, r.db, q), count(t, r.db, "SELECT count(*) FROM "+c.table); old != 0 || all != 2*c.per+c.extra ||
				fmt.Sprint(*chunks) != fmt.Sprint([]int{c.cost * 2 * c.per}) {
				t.Fatalf("%d old rows, %d rows in all, chunks %v; want 0, %d and [%d]", old, all, *chunks, 2*c.per+c.extra, c.cost*2*c.per)
			}
		})
	}
}

// expireChunks returns the chunks that the steps of cost `cost` make for n old
// rows. A chunk takes at most 1 000 / cost rows. A chunk with that many rows
// counts 1 000, and the last chunk counts cost x the rows left.
func expireChunks(n, cost int) (chunks []int) {
	most := chunkRows / cost
	for ; n >= most; n -= most {
		chunks = append(chunks, chunkRows)
	}
	return append(chunks, cost*n)
}

// T-U-11: 2 500 old rows go in chunks of at most 1 000 / cost rows. The young
// rows stay. With cost 1, the chunks are 1 000, 1 000 and 500. With cost 4,
// they are 10 chunks of 250 rows and one empty chunk.
func TestTU11ExpireStepsRunInChunks(t *testing.T) {
	cut := rollCutoff(90)
	for _, c := range expireCases {
		t.Run(c.name, func(t *testing.T) {
			r, chunks := rollRig(t, c.mk(rollTDel, 90))
			c.bulk(t, r.db, 2500, cut-rawDay)
			c.add(t, r.db, cut+rawDay)
			runOK(t, r)
			want := fmt.Sprint(expireChunks(2500, c.cost))
			if n := count(t, r.db, "SELECT count(*) FROM "+c.table); n != c.per || fmt.Sprint(*chunks) != want {
				t.Fatalf("%d rows left, chunks %v; want %d and %s", n, *chunks, c.per, want)
			}
		})
	}
}

// T-U-11: a step with a cost deletes at most limit / cost rows. It returns cost
// x the rows it deleted. When it took the most rows, it returns the limit.
// With a limit below the cost, it runs no statement and returns the limit. The
// transaction here is over, so any statement would fail.
func TestTU11ExpireStepCostsEachRow(t *testing.T) {
	db := migrated(t)
	cut := rollCutoff(90)
	step := newExpireStep(deleteEventSQL, 3, rollTDel, 90)
	addEvents(t, db, "request", 5, cut-rawDay, 0, nil, nil)
	addEvents(t, db, "request", 1, cut+rawDay, 0, nil, nil)
	for _, c := range []struct{ limit, want, left int }{
		{2, 2, 6},   // below the cost: no row
		{10, 10, 3}, // 3 rows, the most: the limit
		{10, 6, 1},  // 2 rows: cost 3 each
		{10, 0, 1},  // no old row
	} {
		if n, left := call(t, db, step, c.limit), count(t, db, "SELECT count(*) FROM event"); n != c.want || left != c.left {
			t.Fatalf("limit %d: returned %d, %d rows left; want %d and %d", c.limit, n, left, c.want, c.left)
		}
	}
	tx, err := db.Begin()
	check(t, err)
	check(t, tx.Rollback())
	if n, err := step(context.Background(), tx, 2); n != 2 || err != nil {
		t.Fatalf("limit 2 on a closed transaction: %d, %v; want 2 and no error", n, err)
	}
}

// T-U-11: the session step costs 4 for each row. A limit of 1 000 deletes 250
// of 400 old rows and returns the limit. The cost comes from the chunk time of
// a session row, as measured at 4 million rows.
func TestTU11SessionStepCostsFourPerRow(t *testing.T) {
	db := migrated(t)
	addSessions(t, db, "s", 0, 400, rollCutoff(90)-rawDay, 0, nil)
	if n, left := call(t, db, newSessionExpireStep(rollTDel, 90), 1000), count(t, db, "SELECT count(*) FROM session"); n != 1000 || left != 150 {
		t.Fatalf("returned %d, %d rows left; want 1000 and 150", n, left)
	}
}

// T-U-11: each new step keeps the limit that the runner gives it. That is 1 000
// minus the rows of the steps before it. With a limit of 7 and 20 old rows, a
// step of cost 1 deletes 7 rows. The session step deletes 1. A step that used
// the full chunk size would delete more.
func TestTU11ExpireStepsKeepTheLeftoverLimit(t *testing.T) {
	cut := rollCutoff(90)
	for _, c := range expireCases {
		t.Run(c.name, func(t *testing.T) {
			db := migrated(t)
			c.bulk(t, db, 20, cut-rawDay)
			if n, left := call(t, db, c.mk(rollTDel, 90), 7), count(t, db, "SELECT count(*) FROM "+c.table); n != 7 || left != 20-7/c.cost {
				t.Fatalf("returned %d, %d rows left; want 7 and %d", n, left, 20-7/c.cost)
			}
		})
	}
	t.Run("ip_counter", func(t *testing.T) {
		db := migrated(t)
		mustExec(t, db, `WITH RECURSIVE c(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM c WHERE i < 19)
			INSERT INTO ip_counter (day, ip_hmac, requests, dropped) SELECT '2000-01-01', 'h' || i, 1, 0 FROM c`)
		if n, left := call(t, db, newCounterDeleteStep(rollTDel, 30), 7), count(t, db, "SELECT count(*) FROM ip_counter"); n != 7 || left != 13 {
			t.Fatalf("returned %d, %d rows left; want 7 and 13", n, left)
		}
	})
}

// T-U-11: each statement uses its index, and no plan has a SCAN. The plan is
// compared as a whole.
func TestTU11ExpireStatementsUseTheirIndexes(t *testing.T) {
	db := migrated(t)
	for _, c := range expireCases {
		if p := strings.Join(queryPlan(t, db, c.stmt, 1, 1000), "\n"); p != c.plan {
			t.Errorf("plan of %s:\n%s\nwant:\n%s", c.name, p, c.plan)
		}
	}
	const want = "SEARCH ip_counter USING INTEGER PRIMARY KEY (rowid=?)\nLIST SUBQUERY 1\n" +
		"SEARCH ip_counter USING COVERING INDEX sqlite_autoindex_ip_counter_1 (day<?)"
	if p := strings.Join(queryPlan(t, db, deleteCounterSQL, "2026-03-01", 1000), "\n"); p != want {
		t.Errorf("plan of ip_counter:\n%s\nwant:\n%s", p, want)
	}
}

// T-U-11: the days 1 and 90 are in the range of each step. With 1 day, a row of
// 2 d goes and a row of 12 h stays. With 90 days, a row of 91 d goes and a row
// of 89.5 d stays.
func TestTU11ExpireStepsAcceptTheEdgesOfTheRange(t *testing.T) {
	for _, c := range expireCases {
		for _, days := range []int{1, 90} {
			t.Run(fmt.Sprint(c.name, " ", days, " days"), func(t *testing.T) {
				cut := rollCutoff(days)
				r, chunks := rollRig(t, c.mk(rollTDel, days))
				if c.setup != nil {
					c.setup(t, r.db)
				}
				c.add(t, r.db, cut-rawDay)
				c.add(t, r.db, cut+rawDay/2)
				runOK(t, r)
				q := fmt.Sprintf("SELECT count(*) FROM %s WHERE %s < %d", c.table, c.key, cut)
				if old, all := count(t, r.db, q), count(t, r.db, "SELECT count(*) FROM "+c.table); old != 0 || all != c.per+c.extra ||
					fmt.Sprint(*chunks) != fmt.Sprint([]int{c.cost * c.per}) {
					t.Fatalf("%d old rows, %d rows in all, chunks %v; want 0, %d and [%d]", old, all, *chunks, c.per+c.extra, c.cost*c.per)
				}
			})
		}
	}
}

// T-U-11: a days value outside the range of the step gives a step that
// runs no statement. A zero time does the same. The run stops the writer, and
// no row changes. The events days go from 1 to 90. The raw days go from 1 to
// 30.
func TestTU11ExpireStepsRefuseBadParameters(t *testing.T) {
	for _, c := range []struct {
		name, seed, rows string
		mk               func(time.Time, int) retentionStep
		hi               int
	}{
		{"event", "INSERT INTO event (ts, kind) VALUES (1, 'request')", "event", newEventExpireStep, 91},
		{"token", "INSERT INTO token (token_id, session_id, trap_id, issued_at, first_cb_at) VALUES ('t', 's', 't', 1, 1)", "token", newTokenExpireStep, 91},
		{"session", "INSERT INTO session (id, first_seen, last_seen, ip_hmac, band) VALUES ('s', 1, 1, 'h', 'human')", "session", newSessionExpireStep, 91},
		{"ip_counter", "INSERT INTO ip_counter (day, ip_hmac, requests, dropped) VALUES ('2000-01-01', 'h', 1, 0)", "ip_counter", newCounterDeleteStep, 31},
	} {
		for _, p := range []struct {
			name string
			t    time.Time
			days int
		}{{"0 days", rollTDel, 0}, {"too many days", rollTDel, c.hi}, {"zero time", time.Time{}, 30}} {
			t.Run(c.name+" "+p.name, func(t *testing.T) {
				r, chunks := rollRig(t, c.mk(p.t, p.days))
				mustExec(t, r.db, c.seed)
				stops(t, r)
				if n := count(t, r.db, "SELECT count(*) FROM "+c.rows); n != 1 || rowsChanged(*chunks) != 0 {
					t.Fatalf("%d rows left, %d changed; want 1 and 0", n, rowsChanged(*chunks))
				}
			})
		}
	}
}

// addCounterDays inserts one ip_counter row for each day.
func addCounterDays(tb testing.TB, db *sql.DB, days ...string) {
	tb.Helper()
	for _, d := range days {
		mustExec(tb, db, "INSERT INTO ip_counter (day, ip_hmac, requests, dropped) VALUES (?, 'h', 1, 0)", d)
	}
}

// counterDays returns the days of the ip_counter rows, in order.
func counterDays(tb testing.TB, db *sql.DB) string {
	tb.Helper()
	return rawText(tb, db, "SELECT coalesce(group_concat(day, ' '), '') FROM (SELECT day FROM ip_counter ORDER BY day)")
}

// T-U-11: tDel is 2026-03-31 12:00 UTC, and the days are 30. The cutoff date is
// 2026-03-01. The row of 2026-02-28 is gone. The rows of 2026-03-01 and later
// stay. The cutoff date is a UTC date. The test sets tDel and the local zone
// 13 h east of UTC. In that zone, the cutoff has the date 2026-03-02.
func TestTU11CounterDeleteKeepsTheDateOfTheCutoff(t *testing.T) {
	zone := time.FixedZone("east", 13*3600)
	setHook(t, &time.Local, zone)
	tDel := time.Date(2026, 3, 31, 12, 0, 0, 0, time.UTC).In(zone)
	r, chunks := rollRig(t, newCounterDeleteStep(tDel, 30))
	addCounterDays(t, r.db, "2026-02-27", "2026-02-28", "2026-03-01", "2026-03-02", "2026-03-31")
	runOK(t, r)
	if got, want := counterDays(t, r.db), "2026-03-01 2026-03-02 2026-03-31"; got != want || fmt.Sprint(*chunks) != "[2]" {
		t.Fatalf("days left %q, chunks %v; want %q and [2]", got, *chunks, want)
	}
}

// T-U-11: 2 500 old ip_counter rows go in chunks of 1 000, 1 000 and 500.
func TestTU11CounterDeleteRunsInChunks(t *testing.T) {
	r, chunks := rollRig(t, newCounterDeleteStep(rollTDel, 30))
	mustExec(t, r.db, `WITH RECURSIVE c(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM c WHERE i < 2499)
		INSERT INTO ip_counter (day, ip_hmac, requests, dropped) SELECT '2000-01-01', 'h' || i, 1, 0 FROM c`)
	addCounterDays(t, r.db, "2027-01-11")
	runOK(t, r)
	if n := count(t, r.db, "SELECT count(*) FROM ip_counter WHERE day = '2027-01-11'"); n != 1 ||
		count(t, r.db, "SELECT count(*) FROM ip_counter") != 1 || fmt.Sprint(*chunks) != "[1000 1000 500]" {
		t.Fatalf("%d rows of 2027-01-11, chunks %v; want 1 row left and [1000 1000 500]", n, *chunks)
	}
}

// T-U-11: the run of the writer deletes the old ip_counter rows. The step gets
// tDel, not tPriv, which is 2 d later. With tDel the cutoff date is 2027-01-11,
// and the row of 2027-01-12 stays. With tPriv it would go.
func TestTU11RunStepsDeletesOldIPCounterRows(t *testing.T) {
	r := newRig(t, 4000)
	addCounterDays(t, r.db, "2027-01-10", "2027-01-11", "2027-01-12")
	if err := runWith(t, r, runSteps(rollTDel, rollTDel, rollTDel.Add(48*time.Hour), 7, 30, 90)); err != nil {
		t.Fatal(err)
	}
	if got, want := counterDays(t, r.db), "2027-01-11 2027-01-12"; got != want {
		t.Fatalf("days left %q, want %q", got, want)
	}
}

// runWith runs steps through the writer of r, which Run serves. The writer
// has ended when it returns.
func runWith(t *testing.T, r *rig, steps []retentionStep) error {
	t.Helper()
	_, cancel := r.launchCancelable(context.Background())
	ctx, cancelRun := context.WithTimeout(context.Background(), waitFor)
	defer cancelRun()
	err := r.w.runSteps(ctx, steps)
	r.stopRun(cancel)
	return err
}

// evidenceRig seeds one evidence row for each kind and ts, each with a leaf in
// a real log. It returns a rig that restarts on the same database and log.
func evidenceRig(t *testing.T, kinds []string, ts []int64) *rig {
	t.Helper()
	l, r := realLog(t), newRig(t, 100)
	r.seed(l, len(ts))
	for i, k := range kinds {
		mustExec(t, r.db, "UPDATE event SET kind = ?, ts = ? WHERE leaf_index = ?", k, ts[i], i)
	}
	return r.restart(l, "origin")
}

// T-U-11: the run deletes the event, token and session rows of more than 45 d.
// It keeps the rows of 44 d. The events days are not 90 and not the raw days.
// The steps get tDel. tPriv is 2 d later, so the rows of 44 d are older than
// 45 d by tPriv. They stay only when each step uses tDel.
func TestTU11RunStepsDeletesTheRowsOlderThanTheEventsDays(t *testing.T) {
	tDel, cut := rollTDel, rollCutoff(45)
	r := evidenceRig(t, []string{"callback", "score_change", "alert_sent", "callback"},
		[]int64{cut - rawDay, cut - 1, cut - 40*rawDay, cut + rawDay})
	for _, name := range []string{"token", "session"} {
		c := expireCaseNamed(name)
		c.add(t, r.db, cut-rawDay)
		c.add(t, r.db, cut+rawDay)
	}
	// The event delete runs before the field clear. So the clear writes only
	// the row that stays.
	mustExec(t, r.db, "CREATE TABLE touched (id INTEGER)")
	mustExec(t, r.db, "CREATE TRIGGER note AFTER UPDATE ON event BEGIN INSERT INTO touched VALUES (old.id); END")
	if err := runWith(t, r, runSteps(tDel, tDel, tDel.Add(48*time.Hour), 7, 30, 45)); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ name, q string }{
		{"event", "SELECT count(*) FROM event WHERE ts = " + fmt.Sprint(cut+rawDay)},
		{"token", "SELECT count(*) FROM token WHERE first_cb_at = " + fmt.Sprint(cut+rawDay)},
		{"session", "SELECT count(*) FROM session WHERE last_seen = " + fmt.Sprint(cut+rawDay)},
	} {
		want := map[string]int{"event": 1, "token": 1, "session": 4}[c.name]
		if n, all := count(t, r.db, c.q), count(t, r.db, "SELECT count(*) FROM "+c.name); n != all || n != want {
			t.Errorf("%s: %d young rows, %d rows in all; want %d of each", c.name, n, all, want)
		}
	}
	if n := count(t, r.db, "SELECT count(*) FROM touched"); n != 1 {
		t.Errorf("the clear wrote %d rows, want the 1 young row", n)
	}
}

// T-U-11: a request row of more than 45 d that no run rolled up is counted
// in aggregate_day. The event delete removes it after that.
func TestTU11RunStepsRollsUpBeforeTheEventDelete(t *testing.T) {
	r := newRig(t, 100)
	addEvents(t, r.db, "request", 1, rollCutoff(45)-rawDay, 0, "s", "v")
	if err := runWith(t, r, runSteps(rollTDel, rollTDel, rollTDel, 7, 30, 45)); err != nil {
		t.Fatal(err)
	}
	if n, sum := count(t, r.db, "SELECT count(*) FROM event"), count(t, r.db, "SELECT coalesce(sum(requests), 0) FROM aggregate_day"); n != 0 || sum != 1 {
		t.Fatalf("%d event rows left, %d requests counted; want 0 and 1", n, sum)
	}
}

// T-U-11: events = raw, with 30 and with 1 days. The event step keeps the
// callbacks of the UTC day of the raw cutoff until the day step counts them.
// The cutoff is 2027-01-11 12:00. The callbacks of 05:00 on that day stay after
// run 1. After run 2, 24 h later, the day is done. Then they are counted in
// aggregate_day, and deleted. Run 1 counts and deletes the callbacks of the day
// before. It also deletes an evidence row older than the start of the cutoff
// day.
func TestTU11RunStepsKeepsTheCallbacksOfTheCutoffDayUntilCounted(t *testing.T) {
	for _, days := range []int{30, 1} {
		t.Run(fmt.Sprint(days, " days"), func(t *testing.T) {
			tDel := rollTDel.Add(-time.Duration(30-days) * oneDay)
			r, _ := rollRig(t, runSteps(tDel, tDel, tDel, 7, days, days)...)
			mustExec(t, r.db, "INSERT INTO session (id, first_seen, last_seen, ip_hmac, band, family) VALUES ('s1', 0, ?, 'h', 'human', 'f')",
				tDel.UnixMilli())
			addEvents(t, r.db, "callback", 2, utc("2027-01-11T05:00:00Z"), 1000, "s1", "a")
			addEvents(t, r.db, "callback", 3, utc("2027-01-10T05:00:00Z"), 1000, "s1", "a")
			addEventAt(t, r.db, "score_change", utc("2027-01-09T05:00:00Z"))
			runOK(t, r)
			if got, want := aggregates(t, r.db), "2027-01-10|a|human|f|0|0|3"; got != want || r.events() != 2 {
				t.Fatalf("after run 1: aggregates %q, %d events; want %q and 2", got, r.events(), want)
			}
			next := tDel.Add(oneDay)
			runAgain(t, r, runSteps(next, next, next, 7, days, days)...)
			if got, want := aggregates(t, r.db), "2027-01-10|a|human|f|0|0|3 ; 2027-01-11|a|human|f|0|0|2"; got != want || r.events() != 0 {
				t.Fatalf("after run 2: aggregates %q, %d events; want %q and 0", got, r.events(), want)
			}
		})
	}
}

// T-U-11: with raw days of 0 or 31, or a zero tDel, the event time is tDel.
func TestTU11EventTimeIsTDelForBadRawDays(t *testing.T) {
	for _, c := range []struct {
		name string
		tDel time.Time
		raw  int
	}{{"raw 0", rollTDel, 0}, {"raw 31", rollTDel, 31}, {"zero tDel", time.Time{}, 30}} {
		t.Run(c.name, func(t *testing.T) {
			if got := eventTime(c.tDel, c.raw, 45); !got.Equal(c.tDel) {
				t.Fatalf("event time %v, want %v", got, c.tDel)
			}
		})
	}
}

// T-U-11: an events days value of 0 or 91 gives the step for bad parameters.
// The run ends with an error and the writer stops. A token, a session and an
// evidence row of 100 d stay. No step before the three deletes has a row to
// change. So the result does not depend on the chunk size or the time.
func TestTU11RunStepsRefusesBadEventsDays(t *testing.T) {
	for _, days := range []int{0, 91} {
		t.Run(fmt.Sprint(days, " days"), func(t *testing.T) {
			r := newRig(t, 100)
			at := rollCutoff(90) - 10*rawDay
			expireCaseNamed("token").add(t, r.db, at)
			expireCaseNamed("session").add(t, r.db, at)
			addEventAt(t, r.db, "score_change", at)
			if err := runWith(t, r, runSteps(rollTDel, rollTDel, rollTDel, 7, 30, days)); err == nil || r.w.Healthy() {
				t.Fatalf("run error %v, healthy %v; want an error and a stopped writer", err, r.w.Healthy())
			}
			if tok, ses, ev := count(t, r.db, "SELECT count(*) FROM token"), count(t, r.db, "SELECT count(*) FROM session"),
				count(t, r.db, "SELECT count(*) FROM event"); tok != 1 || ses != 4 || ev != 1 {
				t.Fatalf("%d tokens, %d sessions, %d events left; want 1, 4 and 1", tok, ses, ev)
			}
		})
	}
}

// T-I-07: leaves of evidence rows that the event delete removed count as
// orphan leaves. After a run that deleted the newest evidence rows, a restart
// on the same database is healthy. It logs the count of the leaves above the
// newest row that is left.
func TestTI07RestartAfterTheEventDeleteLogsOrphanLeaves(t *testing.T) {
	cut := rollCutoff(45)
	n := evidenceRig(t, []string{"callback", "callback", "callback"}, []int64{cut + rawDay, cut - rawDay, cut - 2*rawDay})
	if err := runWith(t, n, runSteps(rollTDel, rollTDel, rollTDel, 7, 30, 45)); err != nil {
		t.Fatal(err)
	}
	if left := count(t, n.db, "SELECT count(*) FROM event"); left != 1 {
		t.Fatalf("%d evidence rows left, want 1", left)
	}
	m := n.restart(n.w.rec.Log, "origin")
	out := m.logTo()
	m.finish()
	if !m.w.Healthy() || out.count("orphan leaves") != 1 || out.count("count=2") != 1 {
		t.Fatalf("healthy %v, log:\n%s", m.w.Healthy(), out.b.String())
	}
}
