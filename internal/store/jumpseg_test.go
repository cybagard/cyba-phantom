package store

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"
)

const hourMs = int64(time.Hour / time.Millisecond)

// testJump is the correction of a clock_jump row of a test. Its event range and
// its session range are the same.
type testJump struct{ from, to, j int64 }

func addJumps(tb testing.TB, db *sql.DB, jumps []testJump) {
	tb.Helper()
	for i, k := range jumps {
		mustExec(tb, db, "INSERT INTO clock_jump VALUES (?, ?, ?, ?, ?, ?, ?)",
			i+1, k.from, k.to, k.from, k.to, k.j, math.MaxInt64)
	}
}

// sumAt is the sum of j of each jump that holds the rowid. It is the oracle of
// the tests: it does not cut the ranges.
func sumAt(jumps []testJump, id int64) (sum int64) {
	for _, k := range jumps {
		if k.from <= id && id <= k.to {
			sum += k.j
		}
	}
	return sum
}

// corrCase is one step of the correction tests. seed inserts one row with the
// rowid id and the row time ts. acted tells if the step changed the row.
type corrCase struct {
	name      string
	days      int
	corrected bool // false: the rows of the step have no rowid range
	mk        func() retentionStep
	setup     func(tb testing.TB, db *sql.DB)
	seed      func(tb testing.TB, db *sql.DB, id, ts int64)
	acted     func(tb testing.TB, db *sql.DB, id int64) bool
}

func rowGone(table, key string) func(testing.TB, *sql.DB, int64) bool {
	return func(tb testing.TB, db *sql.DB, id int64) bool {
		return count(tb, db, fmt.Sprintf("SELECT count(*) FROM %s WHERE %s = %d", table, key, id)) == 0
	}
}

func seedEvent(kind string) func(testing.TB, *sql.DB, int64, int64) {
	return func(tb testing.TB, db *sql.DB, id, ts int64) {
		mustExec(tb, db, "INSERT INTO event (id, ts, kind, body_prefix, detail) VALUES (?, ?, ?, x'62', '{}')", id, ts, kind)
	}
}

func seedSession(tb testing.TB, db *sql.DB, id, ts int64) {
	mustExec(tb, db, "INSERT INTO session (rowid, id, first_seen, last_seen, ip, ip_hmac, band) VALUES (?, ?, ?, ?, '192.0.2.1', 'h', 'human')",
		id, fmt.Sprint("s", id), ts, ts)
}

var corrCases = []corrCase{
	{name: "field clear", days: 30, corrected: true, seed: seedEvent("request"),
		mk: func() retentionStep { return newFieldClearStep(rollTDel, rollWall, 30) },
		acted: func(tb testing.TB, db *sql.DB, id int64) bool {
			return count(tb, db, fmt.Sprint("SELECT count(*) FROM event WHERE id = ", id, " AND body_prefix IS NULL")) == 1
		}},
	{name: "7-day step", days: 7, corrected: true, seed: seedSession,
		mk: func() retentionStep { return newIPStep(rollTDel, 7) },
		acted: func(tb testing.TB, db *sql.DB, id int64) bool {
			return count(tb, db, fmt.Sprint("SELECT count(*) FROM session WHERE rowid = ", id, " AND ip IS NULL")) == 1
		}},
	{name: "raw delete", days: 30, corrected: true, seed: seedEvent("refused"), acted: rowGone("event", "id"),
		mk: func() retentionStep { return newRawDeleteStep(rollTDel, 30) }},
	{name: "event delete", days: 90, corrected: true, seed: seedEvent("request"), acted: rowGone("event", "id"),
		mk:    func() retentionStep { return newEventExpireStep(rollTDel, 90) },
		setup: func(tb testing.TB, db *sql.DB) { mustExec(tb, db, metaSetSQL, rollupDoneKey, "9999-12-31") }},
	{name: "session delete", days: 90, corrected: true, seed: seedSession, acted: rowGone("session", "rowid"),
		mk: func() retentionStep { return newSessionExpireStep(rollTDel, 90) }},
	{name: "token delete", days: 90, acted: rowGone("token", "session_id"),
		mk: func() retentionStep { return newTokenExpireStep(rollTDel, 90) },
		seed: func(tb testing.TB, db *sql.DB, id, ts int64) {
			mustExec(tb, db, "INSERT INTO token (token_id, session_id, trap_id, issued_at, first_cb_at) VALUES (?, ?, 't', 1, ?)", fmt.Sprint("t", id), id, ts)
		}},
}

// checkCorrections runs each step over the rowids 1 to last. The clock_jump
// rows are the jumps. The rowids go in pairs. The odd row of a pair has its
// time 1 ms before the corrected cutoff. The even row has its time at it. A row
// acts when its time plus its sum is before the cutoff.
func checkCorrections(t *testing.T, jumps []testJump, last int64) {
	for _, c := range corrCases {
		t.Run(c.name, func(t *testing.T) {
			r, _ := rollRig(t, c.mk())
			if c.setup != nil {
				c.setup(t, r.db)
			}
			addJumps(t, r.db, jumps)
			ts := func(id int64) int64 { return rollCutoff(c.days) - sumAt(jumps, id) - (id & 1) }
			for id := int64(1); id <= last; id++ {
				c.seed(t, r.db, id, ts(id))
			}
			runOK(t, r)
			for id := int64(1); id <= last; id++ {
				corr := int64(0)
				if c.corrected {
					corr = sumAt(jumps, id)
				}
				if want := ts(id)+corr < rollCutoff(c.days); c.acted(t, r.db, id) != want {
					t.Errorf("row %d (sum %d ms, time %d ms from the cutoff): acted %v, want %v",
						id, sumAt(jumps, id), ts(id)-rollCutoff(c.days), !want, want)
				}
			}
		})
	}
}

// T-U-27: rows with a correction of +J act J later. Rows with -J act J earlier.
// Rows outside each range act at S - days. Each step is tested 1 ms before its
// cutoff and at it. The token delete has no correction.
func TestTU27ClockJumpCorrectionMovesTheCutoffOfEachStep(t *testing.T) {
	const j = 72 * 3600_000
	checkCorrections(t, []testJump{{3, 4, j}, {5, 6, -j}}, 8)
}

// T-U-27: three nested grace ranges of one host boot and one reset row. Each
// row acts at S - days - the sum of its j. The ranges overlap, so a row can
// hold the j of up to four rows.
func TestTU27NestedGraceRangesAndAResetRowSumTheirJ(t *testing.T) {
	h := hourMs
	checkCorrections(t, []testJump{{1, 14, 10 * h}, {1, 8, 20 * h}, {1, 4, 40 * h}, {3, 12, -5 * h}}, 16)
}

// T-U-27: the ranges of the nested rows give these segments. A range with its
// start after its end is not used. A range up to the largest rowid has no end
// edge. A table with no range gives no segment. Each kind reads its own
// columns.
func TestTU27SegmentsCutTheRangesWithoutOverlap(t *testing.T) {
	db := migrated(t)
	text := func(k rowKind) string {
		tx, err := db.Begin()
		check(t, err)
		defer tx.Rollback()
		segs, err := k.segments(context.Background(), tx)
		check(t, err)
		if segs == nil {
			return "none"
		}
		return fmt.Sprint(segs)
	}
	if got := text(eventRows); got != "none" {
		t.Fatalf("segments %s with no clock_jump row", got)
	}
	h := hourMs
	addJumps(t, db, []testJump{{1, 14, 10 * h}, {1, 8, 20 * h}, {1, 4, 40 * h}, {3, 12, -5 * h}, {50, 40, 99}, {100, math.MaxInt64, 1}})
	// The jump 9 has an empty event range and the session range 20 to 30.
	mustExec(t, db, "INSERT INTO clock_jump VALUES (9, 5, 4, 20, 30, 7, 5)")
	lo, hi := int64(math.MinInt64), int64(math.MaxInt64)
	nested := []segment{{lo, 0, 0}, {1, 2, 70 * h}, {3, 4, 65 * h}, {5, 8, 25 * h}, {9, 12, 5 * h}, {13, 14, 10 * h}}
	want := fmt.Sprint(append(nested, segment{15, 99, 0}, segment{100, hi, 1}))
	if got := text(eventRows); got != want {
		t.Errorf("event segments\n%s\nwant\n%s", got, want)
	}
	want = fmt.Sprint(append(nested, segment{15, 19, 0}, segment{20, 30, 7}, segment{31, 99, 0}, segment{100, hi, 1}))
	if got := text(sessionRows); got != want {
		t.Errorf("session segments\n%s\nwant\n%s", got, want)
	}
}

// T-U-27: the cutoff of a segment is the cutoff minus the sum. It does not pass
// the range of int64.
func TestTU27ShiftStaysInTheRangeOfInt64(t *testing.T) {
	for _, c := range []struct{ cutoff, sum, want int64 }{
		{10, 3, 7}, {10, -3, 13}, {math.MinInt64 + 1, 5, math.MinInt64}, {math.MaxInt64 - 1, -5, math.MaxInt64},
	} {
		if got := shift(c.cutoff, c.sum); got != c.want {
			t.Errorf("shift(%d, %d) = %d, want %d", c.cutoff, c.sum, got, c.want)
		}
	}
}

// T-U-27: a grace jump of +30 d, made through the clock. The rows of that host
// boot, written before the jump, keep their fields. They keep them until their
// true age passes the raw days. A row of an older host boot has no correction.
func TestTU27GraceJumpOf30DaysKeepsTheFieldsUntilTheTrueAge(t *testing.T) {
	r, f := newRig(t, 8), &fakeSrc{}
	full := seedEvent("request")
	full(t, r.db, 1, wall0-40*rawDay)
	if err := r.w.StartClock(f.source()); err != nil {
		t.Fatal(err)
	}
	full(t, r.db, 2, wall0+60_000)
	full(t, r.db, 3, wall0+90_000)
	stop := r.start()
	f.at(2 * time.Minute)
	f.skew.Store(30 * rawDay)
	r.twoTicks()
	stop()
	if got := jumpRows(t, r.db); !strings.HasPrefix(got, fmt.Sprint("1,2,3,1,0,", 30*rawDay)) {
		t.Fatalf("clock_jump rows %q", got)
	}
	s, err := r.w.clk.Now()
	if err != nil {
		t.Fatal(err)
	}
	// Row 2 has the true age of 30 d at S = wall0 + 60 d + 60 s. Row 3 has it
	// 30 s later.
	for _, c := range []struct {
		at   int64
		left string
	}{
		{s, "2 3"}, {wall0 + 60*rawDay + 60_000, "2 3"}, {wall0 + 60*rawDay + 60_001, "3"}, {wall0 + 60*rawDay + 90_000, "3"}, {wall0 + 60*rawDay + 90_001, ""},
	} {
		at := time.UnixMilli(c.at)
		call(t, r.db, newFieldClearStep(at, func() time.Time { return at }, 30), chunkRows)
		q := "SELECT coalesce(group_concat(id, ' '), '') FROM (SELECT id FROM event WHERE body_prefix IS NOT NULL ORDER BY id)"
		if got := rawText(t, r.db, q); got != c.left {
			t.Fatalf("S = %d ms after the jump: rows with fields %q, want %q", c.at-s, got, c.left)
		}
	}
}

// T-U-11: the clock_jump delete removes a row when neither range holds a row.
// A row with one range that holds a row stays. So does a row whose range ends
// or starts at a row. Each call deletes at most its limit. A count below the
// limit means that no row is left.
func TestTU11JumpExpireDeletesRowsWithNoRowInTheirRanges(t *testing.T) {
	db := migrated(t)
	for _, id := range []int{2, 4, 6} {
		seedEvent("request")(t, db, int64(id), 1)
	}
	seedSession(t, db, 7, 1)
	for _, k := range [][4]int{
		{2, 2, 100, 100}, // event only: stays
		{10, 11, 7, 7},   // session only: stays
		{3, 3, 8, 9},     // no row: goes
		{2, 6, 7, 7},     // both: stays
		{5, 4, 9, 8},     // ranges with no row: goes
		{1, 1, 6, 6},     // next to a row: goes
		{4, 4, 99, 99},   // event only: stays
		{5, 5, 8, 8},     // no row: goes
		{1, 2, 100, 100}, // the end holds a row: stays
		{4, 5, 100, 100}, // the start holds a row: stays
	} {
		mustExec(t, db, "INSERT INTO clock_jump (event_from, event_to, session_from, session_to, j, at) VALUES (?, ?, ?, ?, 5, 5)", k[0], k[1], k[2], k[3])
	}
	step := newJumpExpireStep()
	got := []int{call(t, db, step, 1), call(t, db, step, 1), call(t, db, step, 3), call(t, db, step, 3)}
	if left := rawText(t, db, "SELECT group_concat(id, ' ') FROM (SELECT id FROM clock_jump ORDER BY id)"); fmt.Sprint(got) != "[1 1 2 0]" || left != "1 2 4 7 9 10" {
		t.Fatalf("calls returned %v, rows left %q; want [1 1 2 0] and 1 2 4 7 9 10", got, left)
	}
}

// T-U-27: a segmented step changes at most limit rows in all segments. It
// returns fewer only when no row is left. 30 old rows are in three segments.
func TestTU27SegmentedStepKeepsTheLimit(t *testing.T) {
	db := migrated(t)
	mustExec(t, db, metaSetSQL, rollupDoneKey, "9999-12-31")
	jumps := []testJump{{1, 10, rawDay}, {5, 20, -rawDay}}
	addJumps(t, db, jumps)
	for id := int64(1); id <= 30; id++ {
		seedEvent("request")(t, db, id, rollCutoff(90)-sumAt(jumps, id)-1)
	}
	step := newEventExpireStep(rollTDel, 90)
	var got []int
	for range 6 {
		got = append(got, call(t, db, step, 7))
	}
	if fmt.Sprint(got) != "[7 7 7 7 2 0]" || count(t, db, "SELECT count(*) FROM event") != 0 {
		t.Fatalf("calls returned %v; want [7 7 7 7 2 0] and no row left", got)
	}
}

// T-U-27: while S is before the token epoch, each step runs except the mint
// step. S is in 2025 and in the first week of 1970. Each step changes its row.
// The mint row, which is old, stays.
func TestTU27EachStepRunsBeforeTheTokenEpoch(t *testing.T) {
	for _, st := range []time.Time{time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC), time.UnixMilli(5 * rawDay)} {
		t.Run(st.Format("2006-01-02"), func(t *testing.T) {
			ago := func(d int) int64 { return st.UnixMilli() - int64(d)*rawDay }
			r, _ := rollRig(t, runSteps(st, st, st, 7, 30, 90)...)
			addSessions(t, r.db, "ip", 0, 1, ago(8), 0, "192.0.2.1")
			addSessions(t, r.db, "old", 0, 1, ago(100), 0, nil)
			addEvents(t, r.db, "request", 1, ago(40), 0, nil, "v")
			addEvents(t, r.db, "refused", 1, ago(31), 0, nil, nil)
			addEvents(t, r.db, "callback", 1, ago(100), 0, nil, nil)
			addFull(t, r.db, "callback", 1, ago(40), 0)
			mustExec(t, r.db, "INSERT INTO ip_counter VALUES (?, 'h', 1, 0)", time.UnixMilli(ago(60)).UTC().Format(dayLayout))
			mustExec(t, r.db, "INSERT INTO token (token_id, session_id, trap_id, issued_at, first_cb_at) VALUES ('t', 's', 't', 1, ?)", ago(100))
			mustExec(t, r.db, "INSERT INTO clock_jump VALUES (1, 50, 49, 50, 49, 5, 5)")
			addMintRow(t, r.db, 1, 5, 1, ago(100))
			runOK(t, r)
			for q, want := range map[string]int{
				"SELECT count(*) FROM session WHERE ip IS NULL AND id = 'ip0'": 1,
				"SELECT count(*) FROM session":                                 1,
				"SELECT count(*) > 0 FROM aggregate_day":                       1,
				"SELECT count(*) FROM event WHERE kind = 'request'":            0,
				"SELECT count(*) FROM event WHERE kind = 'refused'":            0,
				"SELECT count(*) FROM event":                                   1,
				"SELECT count(*) FROM event WHERE " + rawCleared:               1,
				"SELECT count(*) FROM ip_counter":                              0,
				"SELECT count(*) FROM token":                                   0,
				"SELECT count(*) FROM clock_jump":                              0,
				"SELECT count(*) FROM mint":                                    1,
				"SELECT count(*) FROM meta WHERE key = 'retention_last'":       1,
			} {
				if got := count(t, r.db, q); got != want {
					t.Errorf("%s: %d, want %d", q, got, want)
				}
			}
		})
	}
}

// T-U-11: each statement of a segment uses an index, and none scans event or
// session. The clock_jump delete searches the rowids of event and session.
func TestTU11SegmentStatementsUseTheirIndexes(t *testing.T) {
	db := migrated(t)
	for _, c := range []struct {
		q, use string
		args   []any
	}{
		{clearIPSegSQL, "session_ip_first", []any{1, 1, 2, 1000}},
		{deleteRawSegSQL, "event_kind_ts", []any{1, 1, 2, 1000}},
		{deleteEventSegSQL, "event_ts", []any{1, 1, 2, 1000}},
		{deleteSessionSegSQL, "session_band_last", []any{1, 1, 2, 1000}},
		{clearPastSegSQL, "event_raw_ts", []any{1, 1, 2, 1000}},
		{clearFutureSegSQL, "event_raw_ts", []any{1, 1, 2, 1000}},
		{deleteJumpSQL, "INTEGER PRIMARY KEY (rowid>? AND rowid<?)", []any{1000}},
	} {
		plan := strings.Join(queryPlan(t, db, c.q, c.args...), "\n")
		if !strings.Contains(plan, c.use) || strings.Contains(plan, "SCAN event") || strings.Contains(plan, "SCAN session") {
			t.Errorf("plan of %q:\n%s\nwant %q and no SCAN of event or session", c.q, plan, c.use)
		}
	}
}
