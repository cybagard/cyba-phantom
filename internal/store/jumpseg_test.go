package store

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"slices"
	"strings"
	"testing"
	"time"
)

const hourMs = int64(time.Hour / time.Millisecond)

// testJump is the rowid range and the j of a clock_jump row of a test.
type testJump struct{ from, to, j int64 }

// addJumps adds one clock_jump row for each jump. The event range and the
// session range of a row are the same.
func addJumps(tb testing.TB, db *sql.DB, jumps []testJump) {
	tb.Helper()
	addRanges(tb, db, jumps, jumps)
}

// addRanges adds one clock_jump row for each pair of the two lists. The pair
// gives the event range and the session range. The j of the row is the j of the
// event jump.
func addRanges(tb testing.TB, db *sql.DB, event, session []testJump) {
	tb.Helper()
	for i, k := range event {
		mustExec(tb, db, "INSERT INTO clock_jump VALUES (?, ?, ?, ?, ?, ?, ?)",
			i+1, k.from, k.to, session[i].from, session[i].to, k.j, math.MaxInt64)
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
// rowid id and the row time ts. bulk inserts the rows from to last. Their row
// times are ts, ts + 1 and so on. acted tells if the step changed the row.
type corrCase struct {
	name      string
	days      int
	corrected bool // false: the step makes no clock_jump correction
	session   bool // true: the rows are session rows, with the session range
	mk        func() retentionStep
	setup     func(tb testing.TB, db *sql.DB)
	seed      func(tb testing.TB, db *sql.DB, id, ts int64)
	bulk      func(tb testing.TB, db *sql.DB, from, last, ts int64)
	acted     func(tb testing.TB, db *sql.DB, id int64) bool
}

// rowsFrom is a recursive query that gives the integers from `from` to `last`.
const rowsFrom = "WITH RECURSIVE c(i) AS (SELECT ? UNION ALL SELECT i + 1 FROM c WHERE i < ?) "

func bulkEvent(kind string) func(testing.TB, *sql.DB, int64, int64, int64) {
	return func(tb testing.TB, db *sql.DB, from, last, ts int64) {
		mustExec(tb, db, rowsFrom+"INSERT INTO event (id, ts, kind, body_prefix, detail) SELECT i, ? + i - ?, ?, x'62', '{}' FROM c",
			from, last, ts, from, kind)
	}
}

func bulkSession(tb testing.TB, db *sql.DB, from, last, ts int64) {
	mustExec(tb, db, rowsFrom+"INSERT INTO session (rowid, id, first_seen, last_seen, ip, ip_hmac, band) "+
		"SELECT i, 's' || i, ? + i - ?, ? + i - ?, '192.0.2.1', 'h', 'human' FROM c",
		from, last, ts, from, ts, from)
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
	{name: "field clear", days: 30, corrected: true, seed: seedEvent("request"), bulk: bulkEvent("request"),
		mk: func() retentionStep { return newFieldClearStep(rollTDel, rollWall, 30) },
		acted: func(tb testing.TB, db *sql.DB, id int64) bool {
			return count(tb, db, fmt.Sprint("SELECT count(*) FROM event WHERE id = ", id, " AND body_prefix IS NULL")) == 1
		}},
	{name: "7-day step", days: 7, corrected: true, session: true, seed: seedSession, bulk: bulkSession,
		mk: func() retentionStep { return newIPStep(rollTDel, 7) },
		acted: func(tb testing.TB, db *sql.DB, id int64) bool {
			return count(tb, db, fmt.Sprint("SELECT count(*) FROM session WHERE rowid = ", id, " AND ip IS NULL")) == 1
		}},
	{name: "raw delete", days: 30, corrected: true, seed: seedEvent("refused"), bulk: bulkEvent("refused"),
		acted: rowGone("event", "id"), mk: func() retentionStep { return newJumpRawDeleteStep(rollTDel, 30) }},
	{name: "event delete", days: 90, corrected: true, seed: seedEvent("request"), bulk: bulkEvent("request"),
		acted: rowGone("event", "id"), mk: func() retentionStep { return newEventExpireStep(rollTDel, 90) },
		setup: func(tb testing.TB, db *sql.DB) { mustExec(tb, db, metaSetSQL, rollupDoneKey, "9999-12-31") }},
	{name: "session delete", days: 90, session: true, seed: seedSession, acted: rowGone("session", "rowid"),
		mk: func() retentionStep { return newSessionExpireStep(rollTDel, 90) }},
	{name: "token delete", days: 90, acted: rowGone("token", "session_id"),
		mk: func() retentionStep { return newTokenExpireStep(rollTDel, 90) },
		seed: func(tb testing.TB, db *sql.DB, id, ts int64) {
			mustExec(tb, db, "INSERT INTO token (token_id, session_id, trap_id, issued_at, first_cb_at) VALUES (?, ?, 't', 1, ?)", fmt.Sprint("t", id), id, ts)
		}},
}

// checkCorrections runs each step over the rowids 1 to last. Each clock_jump
// row has the event range and the session range of the same place in the two
// lists. The rowids go in pairs. The odd row of a pair has its time 1 ms before
// the corrected cutoff. The even row has its time at it. A row acts when its
// time plus its sum is before the cutoff. A step of event rows takes its sums
// from the event ranges. A step of session rows takes them from the session
// ranges.
func checkCorrections(t *testing.T, event, session []testJump, last int64) {
	for _, c := range corrCases {
		t.Run(c.name, func(t *testing.T) {
			jumps := event
			if c.session {
				jumps = session
			}
			r, _ := rollRig(t, c.mk())
			if c.setup != nil {
				c.setup(t, r.db)
			}
			addRanges(t, r.db, event, session)
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
// cutoff and at it. The token delete and the session delete have no correction.
func TestTU27ClockJumpCorrectionMovesTheCutoffOfEachStep(t *testing.T) {
	const j = 72 * 3600_000
	jumps := []testJump{{3, 4, j}, {5, 6, -j}}
	checkCorrections(t, jumps, jumps, 8)
}

// T-U-27: three nested grace ranges of one host boot and one reset row. Each
// row acts at S - days - the sum of its j. The ranges overlap, so a row can
// hold the j of up to four rows.
func TestTU27NestedGraceRangesAndAResetRowSumTheirJ(t *testing.T) {
	h := hourMs
	jumps := []testJump{{1, 14, 10 * h}, {1, 8, 20 * h}, {1, 4, 40 * h}, {3, 12, -5 * h}}
	checkCorrections(t, jumps, jumps, 16)
}

// T-U-27: the event range and the session range of a clock_jump row differ.
// A step of event rows reads the event range. A step of session rows reads the
// session range. A step that reads the other range acts on the wrong rows.
func TestTU27EachStepReadsTheRangeOfItsOwnTable(t *testing.T) {
	const j = 72 * 3600_000
	event := []testJump{{1, 4, j}, {5, 6, -j}}
	session := []testJump{{5, 8, j}, {1, 2, -j}}
	checkCorrections(t, event, session, 8)
}

// T-U-27: a range that starts at the smallest rowid. The rows after it have no
// correction. The cut of the ranges must not wrap at the start of the range.
func TestTU27RangeFromTheSmallestRowidCorrectsItsRows(t *testing.T) {
	const j = 72 * 3600_000
	jumps := []testJump{{math.MinInt64, 4, j}}
	checkCorrections(t, jumps, jumps, 8)
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
		js, err := k.sums(context.Background(), tx)
		check(t, err)
		if js == nil {
			return "none"
		}
		return fmt.Sprint(js.segs)
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

// T-U-27: the time before which a row acts is the cutoff minus the sum. It does
// not pass the range of int64.
func TestTU27ShiftStaysInTheRangeOfInt64(t *testing.T) {
	for _, c := range []struct{ cutoff, sum, want int64 }{
		{10, 3, 7}, {10, -3, 13}, {math.MinInt64 + 1, 5, math.MinInt64}, {math.MaxInt64 - 1, -5, math.MaxInt64},
	} {
		if got := shift(c.cutoff, c.sum); got != c.want {
			t.Errorf("shift(%d, %d) = %d, want %d", c.cutoff, c.sum, got, c.want)
		}
	}
}

// T-U-27: a sum stays in the range of int64. Two j of the largest value give
// the largest value. The j of the smallest value plus 1, and -2, give the
// smallest value. A sum that wrapped would delete a fresh row at once.
func TestTU27SumOfJStaysInTheRangeOfInt64(t *testing.T) {
	for _, c := range []struct {
		name  string
		jumps []testJump
		want  int64
	}{
		{"largest twice", []testJump{{1, 1, math.MaxInt64}, {1, 1, math.MaxInt64}}, math.MaxInt64},
		{"largest and 2", []testJump{{1, 1, math.MaxInt64}, {1, 1, 2}}, math.MaxInt64},
		{"smallest", []testJump{{1, 1, math.MinInt64 + 1}, {1, 1, -2}}, math.MinInt64},
		{"overlap of the largest", []testJump{{1, 10, math.MaxInt64}, {1, 5, math.MaxInt64}}, math.MaxInt64},
	} {
		t.Run(c.name, func(t *testing.T) {
			db := migrated(t)
			addJumps(t, db, c.jumps)
			tx, err := db.Begin()
			check(t, err)
			defer tx.Rollback()
			js, err := eventRows.sums(context.Background(), tx)
			check(t, err)
			if got := js.at(1); got != c.want || js.low > 0 {
				t.Errorf("sum %d, smallest %d; want %d", got, js.low, c.want)
			}
		})
	}
}

// T-U-27: a fresh row in a range with two j that would wrap stays. The event
// delete reads the clamped sum.
func TestTU27EventDeleteKeepsAFreshRowWhenTheSumWouldWrap(t *testing.T) {
	db := migrated(t)
	mustExec(t, db, metaSetSQL, rollupDoneKey, "9999-12-31")
	addJumps(t, db, []testJump{{1, 1, math.MaxInt64}, {1, 1, 2}})
	seedEvent("request")(t, db, 1, rollTDel.UnixMilli())
	if n := call(t, db, newEventExpireStep(rollTDel, 90), 1000); n != 0 || count(t, db, "SELECT count(*) FROM event") != 1 {
		t.Fatalf("the call read %d entries; want 0 and the row kept", n)
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

// T-U-27: a corrected step returns the count of the entries that it read, at
// most the limit. A count below the limit means that no entry before the end is
// left. The rows 1 to 30 act, in four ranges of sums. The rows 31 to 35 are in
// a +1 d range and stay, but the step reads their entries. Thus 35 entries are
// read, and 30 rows are deleted.
func TestTU27CorrectedStepReturnsTheEntriesThatItRead(t *testing.T) {
	db := migrated(t)
	mustExec(t, db, metaSetSQL, rollupDoneKey, "9999-12-31")
	jumps := []testJump{{1, 10, rawDay}, {5, 20, -rawDay}, {31, 35, rawDay}}
	addJumps(t, db, jumps)
	for id := int64(1); id <= 35; id++ {
		ts := rollCutoff(90) - sumAt(jumps, id)
		if id <= 30 {
			ts-- // 1 ms before the corrected cutoff: the row acts
		}
		seedEvent("request")(t, db, id, ts)
	}
	step := newEventExpireStep(rollTDel, 90)
	var got []int
	for range 6 {
		got = append(got, call(t, db, step, 7))
	}
	if left := eventIDs(t, db); fmt.Sprint(got) != "[7 7 7 7 7 0]" || left != "31 32 33 34 35" {
		t.Fatalf("calls returned %v, rows left %q; want [7 7 7 7 7 0] and 31 32 33 34 35", got, left)
	}
}

// eventIDs returns the rowids of the event rows, in order, as text.
func eventIDs(tb testing.TB, db *sql.DB) string {
	tb.Helper()
	return rawText(tb, db, "SELECT coalesce(group_concat(id, ' '), '') FROM (SELECT id FROM event ORDER BY id)")
}

// bound is the number of rows that a +J range keeps in the read bound tests.
const bound = 5000

// T-U-27: each call of a corrected step reads at most the limit, also when a
// range keeps many rows. 5 000 rows are before the cutoff and in a +J range.
// Their entries come first in the index. 10 rows after them act. The calls read
// 1 000 entries each and reach the rows that act. No call reads an entry again.
func TestTU27CorrectedStepReadIsBoundedByTheLimit(t *testing.T) {
	for _, c := range corrCases {
		if c.bulk == nil {
			continue
		}
		t.Run(c.name, func(t *testing.T) {
			db := migrated(t)
			if c.setup != nil {
				c.setup(t, db)
			}
			addJumps(t, db, []testJump{{1, bound, 100 * rawDay}})
			cutoff := rollCutoff(c.days)
			c.bulk(t, db, 1, bound, cutoff-20_000)
			c.bulk(t, db, bound+1, bound+10, cutoff-100)
			step := c.mk()
			var got []int
			for range 8 {
				got = append(got, call(t, db, step, 1000))
			}
			if fmt.Sprint(got) != "[1000 1000 1000 1000 1000 10 0 0]" {
				t.Errorf("calls returned %v; want 5 calls of 1 000, then 10, then 0", got)
			}
			for _, id := range []int64{1, 2500, bound} {
				if c.acted(t, db, id) {
					t.Errorf("row %d acted; its +J range keeps it", id)
				}
			}
			for id := int64(bound + 1); id <= bound+10; id++ {
				if !c.acted(t, db, id) {
					t.Errorf("row %d did not act", id)
				}
			}
		})
	}
}

// T-U-27: 2 500 entries have one time. The cursor falls inside them. The rows 1
// to 1 250 are in a +J range and stay. The rows 1 251 to 2 500 act. With a
// limit of 1 000, the calls read 1 000, 1 000 and 500 entries. No row is
// missed, and no entry is read twice.
func TestTU27CorrectedStepReadsEntriesOfOneTimeAcrossTheCursor(t *testing.T) {
	for _, c := range corrCases {
		if c.bulk == nil {
			continue
		}
		t.Run(c.name, func(t *testing.T) {
			db := migrated(t)
			if c.setup != nil {
				c.setup(t, db)
			}
			addJumps(t, db, []testJump{{1, 1250, 100 * rawDay}})
			for id := int64(1); id <= 2500; id++ {
				c.seed(t, db, id, rollCutoff(c.days)-10)
			}
			step := c.mk()
			var got []int
			for range 4 {
				got = append(got, call(t, db, step, 1000))
			}
			if fmt.Sprint(got) != "[1000 1000 500 0]" {
				t.Errorf("calls returned %v; want [1000 1000 500 0]", got)
			}
			for _, id := range []int64{1, 1000, 1250} {
				if c.acted(t, db, id) {
					t.Errorf("row %d acted; its +J range keeps it", id)
				}
			}
			for _, id := range []int64{1251, 1500, 2000, 2001, 2500} {
				if !c.acted(t, db, id) {
					t.Errorf("row %d did not act", id)
				}
			}
		})
	}
}

// T-U-27: while S is before the token epoch, each step runs except the mint
// step. S is in 2025 and in the first week of 1970. Each step changes its row.
// The mint row, which is old, stays. A clock_jump row with a range of 1000
// rowids holds the rows, so the corrected steps run. The callback row that
// stays is in its event range, so the row stays too.
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
			mustExec(t, r.db, "INSERT INTO clock_jump VALUES (1, 1, 1000, 1, 1000, 5, 5)")
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
				"SELECT count(*) FROM clock_jump":                              1,
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

// T-U-27: the field clear keeps its bound `top` with a clock_jump row in place.
// The first call takes the largest rowid, 3. It reads 3 entries, which is its
// limit, so part 1 is not at its end. A row 4 that the writer stores after it
// keeps its fields, also when its rowid is in the range.
func TestTU27FieldClearKeepsItsTopWithAJumpRow(t *testing.T) {
	db := migrated(t)
	addJumps(t, db, []testJump{{1, math.MaxInt64, 10}})
	cutoff := rollCutoff(30)
	bulkEvent("request")(t, db, 1, 3, cutoff-100)
	step := newFieldClearStep(rollTDel, rollWall, 30)
	if n := call(t, db, step, 3); n != 3 {
		t.Fatalf("the first call read %d entries; want 3", n)
	}
	bulkEvent("request")(t, db, 4, 4, cutoff-50) // after the cursor
	call(t, db, step, 1000)
	if left := count(t, db, "SELECT count(*) FROM event WHERE body_prefix IS NOT NULL"); left != 1 ||
		count(t, db, "SELECT count(*) FROM event WHERE id = 4 AND body_prefix IS NOT NULL") != 1 {
		t.Fatalf("%d rows keep their fields; want only the row 4", left)
	}
}

// T-U-27: the raw delete takes the beacon rows and the refused rows of a range.
// The rows 3 and 4 are in a +3 d range. The rows 5 and 6 are in a -3 d range.
// A beacon row follows the same rule as a refused row. The request row 7 stays.
// The row 8 has no range and stays.
func TestTU27RawDeleteTakesBeaconAndRefusedRowsOfARange(t *testing.T) {
	db := migrated(t)
	const j = 72 * 3600_000
	addJumps(t, db, []testJump{{3, 4, j}, {5, 6, -j}})
	cutoff := rollCutoff(30)
	for _, r := range []struct {
		id   int64
		kind string
		ts   int64
	}{
		{1, "refused", cutoff - 1}, {2, "beacon", cutoff - 1}, {3, "beacon", cutoff - 1}, {4, "refused", cutoff - 1},
		{5, "beacon", cutoff + j - 1}, {6, "refused", cutoff + j - 1}, {7, "request", cutoff - 1}, {8, "beacon", cutoff + j - 1},
	} {
		seedEvent(r.kind)(t, db, r.id, r.ts)
	}
	call(t, db, newJumpRawDeleteStep(rollTDel, 30), 1000)
	if left := eventIDs(t, db); left != "3 4 7 8" {
		t.Fatalf("rows left %q; want 3 4 7 8", left)
	}
}

// T-U-27: the event delete with a negative sum keeps each row with a stored ts
// at or after the gate. The day step has not counted that day. The range has
// the sum -2 d, so the rows 10 to 12 reach the cutoff. The row 12 is before the
// day of the gate and goes. The rows 10 and 11 stay. The row 11 has the ts of
// the start of the day. The call reads only the entry of the row 12.
func TestTU27EventDeleteWithANegativeSumKeepsRowsAtTheGate(t *testing.T) {
	db := migrated(t)
	day := rollupDayStart(rollCutoff(90))
	mustExec(t, db, metaSetSQL, rollupDoneKey, rollupDay(day-1))
	for id, ts := range map[int64]int64{10: day + hourMs, 11: day, 12: day - 1} {
		mustExec(t, db, "INSERT INTO event (id, ts, kind, hash, leaf_index) VALUES (?, ?, 'callback', zeroblob(32), ?)", id, ts, id)
	}
	addJumps(t, db, []testJump{{10, 12, -48 * hourMs}})
	n := call(t, db, newEventExpireStep(rollTDel, 90), 1000)
	if left := eventIDs(t, db); n != 1 || left != "10 11" {
		t.Fatalf("the call read %d entries and left the rows %q; want 1 and 10 11", n, left)
	}
}

// T-U-11: the clock_jump delete runs after the event delete. One run deletes
// the last event row of a range and the clock_jump row of that range.
func TestTU11JumpExpireRunsAfterTheEventDeleteInOneRun(t *testing.T) {
	r, _ := rollRig(t, runSteps(rollTDel, rollTDel, rollTDel, 7, 30, 90)...)
	addEvents(t, r.db, "callback", 1, rollCutoff(90)-rawDay, 0, nil, nil)
	mustExec(t, r.db, "INSERT INTO clock_jump VALUES (1, 1, 1, 50, 49, 5, 5)")
	runOK(t, r)
	if e, c := count(t, r.db, "SELECT count(*) FROM event"), count(t, r.db, "SELECT count(*) FROM clock_jump"); e != 0 || c != 0 {
		t.Fatalf("%d event rows and %d clock_jump rows left; want none", e, c)
	}
}

// T-U-27: each read statement searches the index of its step. It has no SCAN
// and no temporary B-tree. Each statement that acts on a JSON array of rowids
// searches the table by rowid. The clock_jump delete searches the rowids of
// event and session.
func TestTU27ReadStatementsSearchTheirIndexes(t *testing.T) {
	db := migrated(t)
	type stmt struct {
		q, use string
		args   []any
	}
	var all []stmt
	for _, c := range []struct {
		use        string
		q          readSQL
		lead, tail []any
	}{
		{"event_ts", eventRead, nil, nil},
		{"event_kind_ts", rawRead, []any{"refused"}, nil},
		{"event_raw_ts", clearRead, nil, []any{1}},
		{"session_ip_first", ipRead, nil, nil},
	} {
		eq := slices.Concat(c.lead, []any{1, 1}, c.tail, []any{1000})
		gt := slices.Concat(c.lead, []any{1, 2}, c.tail, []any{1000})
		all = append(all, stmt{c.q.eq, c.use, eq}, stmt{c.q.gt, c.use, gt})
	}
	for _, q := range []string{deleteEventIDsSQL, clearIDsSQL} {
		all = append(all, stmt{q, "SEARCH event USING INTEGER PRIMARY KEY", []any{"[1]"}})
	}
	all = append(all, stmt{clearIPIDsSQL, "SEARCH session USING INTEGER PRIMARY KEY", []any{"[1]"}},
		stmt{deleteJumpSQL, "INTEGER PRIMARY KEY (rowid>? AND rowid<?)", []any{1000}})
	for _, c := range all {
		plan := strings.Join(queryPlan(t, db, c.q, c.args...), "\n")
		if !strings.Contains(plan, c.use) || strings.Contains(plan, "SCAN event") || strings.Contains(plan, "SCAN session") ||
			strings.Contains(plan, "TEMP B-TREE") {
			t.Errorf("plan of %q:\n%s\nwant %q, no SCAN of event or session, and no temporary B-tree", c.q, plan, c.use)
		}
	}
}

// T-U-11: the DB cap keeps the plain raw delete. The cap evicts by the oldest
// UTC day in stored time. A refused row at the day 1 is in a +200 d range. The
// corrected step would keep it, and the cap would stop. The cap evicts it, then
// the session row of the day 3, and it leaves no row.
func TestTU11CapEvictsARefusedRowOfAForwardJumpRange(t *testing.T) {
	r := newRig(t, 100)
	addEvents(t, r.db, "refused", 1, capDay(1), 0, nil, nil)
	mustExec(t, r.db, "INSERT INTO session (id, first_seen, last_seen, ip_hmac, band) VALUES ('1', 0, ?, 'h', 'human')", capDay(3))
	addJumps(t, r.db, []testJump{{1, 1, 200 * rawDay}})
	c := forcedCap(r, rollTDel)
	reasons := recordUnmet(c)
	var got []int
	for range 3 {
		got = append(got, callIn(t, r.db, c.evict, chunkRows))
	}
	if left := capLabels(t, r.db); fmt.Sprint(got) != "[1000 1000 0]" || len(left) != 0 {
		t.Fatalf("calls returned %v and left %v; want [1000 1000 0] and no row", got, left)
	}
	if got := strings.Join(*reasons, ","); got != "stuck" {
		t.Fatalf("counted %q, want one stuck at the end of the run", got)
	}
}

// T-U-27: the raw delete has two kinds that each have more than limit/2 entries
// that act. With the limit 10, the call reads 6 refused entries and then 4
// beacon entries. The next call reads the last 2. No count is above the limit.
func TestTU27RawDeleteKeepsTheLimitOverTwoKinds(t *testing.T) {
	db := migrated(t)
	addJumps(t, db, []testJump{{1, 12, hourMs}})
	ts := rollCutoff(30) - 2*hourMs
	bulkEvent("refused")(t, db, 1, 6, ts)
	bulkEvent("beacon")(t, db, 7, 12, ts)
	step := newJumpRawDeleteStep(rollTDel, 30)
	var got []int
	for range 3 {
		got = append(got, call(t, db, step, 10))
	}
	if left := eventIDs(t, db); fmt.Sprint(got) != "[10 2 0]" || left != "" {
		t.Fatalf("calls returned %v and left the rows %q; want [10 2 0] and none", got, left)
	}
}

// T-U-27: a cursor read that fails makes the step return the error, also when
// the next read succeeds. A bad eq statement is the failure. The first case
// fails in the first read, and the second case in the second read.
func TestTU27CursorReadErrorIsReturned(t *testing.T) {
	bad := readSQL{eq: "SELECT no_such_column FROM event", gt: eventRead.gt}
	for name, reads := range map[string][]*indexRead{
		"first read":  {newIndexRead(bad), newIndexRead(eventRead)},
		"second read": {newIndexRead(eventRead), newIndexRead(bad)},
	} {
		t.Run(name, func(t *testing.T) {
			db := migrated(t)
			addJumps(t, db, []testJump{{1, 1, hourMs}})
			seedEvent("refused")(t, db, 1, 0)
			c := &corrected{kind: eventRows, cutoff: rollCutoff(30), act: deleteEventIDsSQL, mem: memDeleted, reads: reads}
			tx, err := db.Begin()
			check(t, err)
			defer tx.Rollback()
			if _, err := c.step()(context.Background(), tx, 10); err == nil {
				t.Fatal("the step returned no error after a failed read")
			}
		})
	}
}

// T-U-27: a clock_jump row with j = 0 gives the sum 0. Each row of its range
// acts at S - days, as a row with no range does.
func TestTU27JumpRowWithJOfZeroChangesNoRow(t *testing.T) {
	jumps := []testJump{{3, 4, 0}}
	checkCorrections(t, jumps, jumps, 8)
}
