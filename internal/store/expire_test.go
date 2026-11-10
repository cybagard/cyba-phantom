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
// inserts n rows with the key `at`.
type expireCase struct {
	name, table, key, plan string
	stmt                   string
	mk                     func(time.Time, int) retentionStep
	per, extra             int // rows of one add; rows of setup that stay
	setup                  func(tb testing.TB, db *sql.DB)
	add                    func(tb testing.TB, db *sql.DB, at int64)
	bulk                   func(tb testing.TB, db *sql.DB, n int, at int64)
}

var expireBands = []string{"human", "crawler", "agent-likely", "agent-confirmed"}

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
		name: "event", table: "event", key: "ts", mk: newEventExpireStep, stmt: deleteEventSQL, per: 3,
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
		name: "token", table: "token", key: "first_cb_at", mk: newTokenExpireStep, stmt: deleteTokenSQL, per: 1, extra: 1,
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
		name: "session", table: "session", key: "last_seen", mk: newSessionExpireStep, stmt: deleteSessionSQL, per: len(expireBands),
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
				fmt.Sprint(*chunks) != fmt.Sprint([]int{2 * c.per}) {
				t.Fatalf("%d old rows, %d rows in all, chunks %v; want 0, %d and [%d]", old, all, *chunks, 2*c.per+c.extra, 2*c.per)
			}
		})
	}
}

// T-U-11: 2 500 old rows go in chunks of 1 000, 1 000 and 500. The young rows
// stay.
func TestTU11ExpireStepsRunInChunks(t *testing.T) {
	cut := rollCutoff(90)
	for _, c := range expireCases {
		t.Run(c.name, func(t *testing.T) {
			r, chunks := rollRig(t, c.mk(rollTDel, 90))
			c.bulk(t, r.db, 2500, cut-rawDay)
			c.add(t, r.db, cut+rawDay)
			runOK(t, r)
			if n := count(t, r.db, "SELECT count(*) FROM "+c.table); n != c.per || fmt.Sprint(*chunks) != "[1000 1000 500]" {
				t.Fatalf("%d rows left, chunks %v; want %d and [1000 1000 500]", n, *chunks, c.per)
			}
		})
	}
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

// T-U-11, T-S-34: a days value outside the range of the step gives a step that
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
	zone, was := time.FixedZone("east", 13*3600), time.Local
	time.Local = zone
	t.Cleanup(func() { time.Local = was })
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
	r.launchCancelable(context.Background())
	ctx, cancel := context.WithTimeout(context.Background(), waitFor)
	defer cancel()
	if err := r.w.runSteps(ctx, runSteps(rollTDel, rollTDel, rollTDel.Add(48*time.Hour), 7, 30)); err != nil {
		t.Fatal(err)
	}
	if got, want := counterDays(t, r.db), "2027-01-11 2027-01-12"; got != want {
		t.Fatalf("days left %q, want %q", got, want)
	}
}
