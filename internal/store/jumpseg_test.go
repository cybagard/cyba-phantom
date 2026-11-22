package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cybagard/cyba-phantom/internal/event"
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
	// The session delete has no bulk. A row costs 4 of the limit, so the tests
	// of the read bound do not fit it. A test of its cost covers it.
	{name: "session delete", days: 90, corrected: true, session: true, seed: seedSession,
		acted: rowGone("session", "rowid"), mk: func() retentionStep { return newJumpSessionExpireStep(rollTDel, 90) }},
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
	mustExec(t, db, "INSERT INTO clock_jump VALUES (9, 5, 4, 20, 30, 7, ?)", int64(resetAt))
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
	step := newJumpExpireStep(nil)
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
		{"session_band_last", sessionRead, []any{"human"}, nil},
	} {
		eq := slices.Concat(c.lead, []any{1, 1}, c.tail, []any{1000})
		gt := slices.Concat(c.lead, []any{1, 2}, c.tail, []any{1000})
		all = append(all, stmt{c.q.eq, c.use, eq}, stmt{c.q.gt, c.use, gt})
	}
	for _, q := range []string{deleteEventIDsSQL, clearIDsSQL} {
		all = append(all, stmt{q, "SEARCH event USING INTEGER PRIMARY KEY", []any{"[1]"}})
	}
	all = append(all, stmt{clearIPIDsSQL, "SEARCH session USING INTEGER PRIMARY KEY", []any{"[1]"}},
		stmt{deleteSessionIDsSQL, "SEARCH session USING INTEGER PRIMARY KEY", []any{"[1]"}},
		stmt{deleteJumpSQL, "INTEGER PRIMARY KEY (rowid>? AND rowid<?)", []any{math.MaxInt64, 1000}},
		stmt{moveEventEndSQL, "SEARCH event USING INTEGER PRIMARY KEY (rowid>? AND rowid<?)", []any{1, 1, 0, 1, math.MaxInt64}},
		stmt{moveSessionEndSQL, "SEARCH session USING INTEGER PRIMARY KEY (rowid>? AND rowid<?)", []any{1, 1, 0, 1, math.MaxInt64}})
	for _, c := range all {
		plan := strings.Join(queryPlan(t, db, c.q, c.args...), "\n")
		if !strings.Contains(plan, c.use) || strings.Contains(plan, "SCAN event") || strings.Contains(plan, "SCAN session") ||
			strings.Contains(plan, "TEMP B-TREE") {
			t.Errorf("plan of %q:\n%s\nwant %q, no SCAN of event or session, and no temporary B-tree", c.q, plan, c.use)
		}
	}
}

// addGrace adds a clock_jump row with an `at` test. Its event range and its
// session range are the same.
func addGrace(tb testing.TB, db *sql.DB, id, from, to, j, at int64) {
	tb.Helper()
	mustExec(tb, db, "INSERT INTO clock_jump VALUES (?, ?, ?, ?, ?, ?, ?)", id, from, to, from, to, j, at)
}

// evAt makes an event of kind k with the time ts and no session.
func evAt(t *testing.T, k event.Kind, ts int64) *event.Event {
	return sessEvent(t, k, "", "", "", ts)
}

// graceNow moves the wall clock ahead of the boot clock by skew at the boot
// clock `boot`. Then it runs one clock tick. The writer does not run. The test
// calls it in its own goroutine. It returns the `at` of the new grace jump.
func graceNow(t *testing.T, r *rig, f *fakeSrc, boot, skew time.Duration) int64 {
	t.Helper()
	f.at(boot)
	f.skew.Store(skew.Milliseconds())
	r.w.serveClock()
	if err := r.w.Err(); err != nil {
		t.Fatal(err)
	}
	return r.key().Jump.At
}

// ends returns the event_to and the session_to of each clock_jump row.
func ends(t *testing.T, db *sql.DB) string {
	t.Helper()
	return rawText(t, db, "SELECT coalesce(group_concat(event_to || '/' || session_to, ' '), '') FROM (SELECT * FROM clock_jump ORDER BY id)")
}

// eventDeleteAt runs the event delete with the cutoff `cutoff` in stored time.
// The day step has no work, so the delete has no gate.
func eventDeleteAt(t *testing.T, r *rig, cutoff int64) {
	t.Helper()
	mustExec(t, r.db, metaSetSQL, rollupDoneKey, "9999-12-31")
	call(t, r.db, newEventExpireStep(time.UnixMilli(cutoff).Add(90*24*time.Hour), 90), 1000)
}

// T-U-27, T-U-30: a row with a time before `at`, in a batch after the jump,
// moves the end. It takes J. The evidence lane goes first. So the
// evidence row has a time at or after `at` and the lower rowid. The bulk row
// with the time before `at` has the higher rowid. The row with the later time
// takes no J. A batch with no row before `at` runs no move. A batch of two rows
// before `at` moves the end to the larger rowid.
func TestTU27RowInFlightMovesTheEndAndTakesJ(t *testing.T) {
	r, f := clockRig(t)
	moves := 0
	r.w.beforeMove = func() { moves++ }
	at := graceNow(t, r, f, 2*time.Minute, 3*time.Hour)
	if got := ends(t, r.db); got != "0/0" {
		t.Fatalf("ends %q after the jump, want 0/0", got)
	}
	// The rowids are 1 and 2, then 3 with no move, then 4 and 5.
	r.writeOK(evAt(t, event.KindCallback, at+10), evAt(t, event.KindRequest, at-1))
	r.writeOK(evAt(t, event.KindRequest, at+5))
	r.writeOK(evAt(t, event.KindRequest, at-5), evAt(t, event.KindRequest, at-4))
	if got := ends(t, r.db); got != "5/0" || moves != 2 {
		t.Fatalf("ends %q after %d moves, want 5/0 after 2", got, moves)
	}
	// The cutoff is 1 h after `at`. A row with J = 3 h stays. A row with no J
	// acts.
	eventDeleteAt(t, r, at+hourMs)
	if left := eventIDs(t, r.db); left != "2 4 5" {
		t.Fatalf("rows left %q, want 2 4 5: the rows 1 and 3 have a time at or after `at`", left)
	}
}

// T-U-27, T-U-30: a new session row with a time before `at` moves the session
// end and takes J. A known session that keeps its old row moves no end. A new
// session with a time at or after `at` takes no J.
func TestTU27SessionRowInFlightMovesTheSessionEnd(t *testing.T) {
	r, f := clockRig(t)
	// The session row 1 is from before the jump.
	r.writeOK(sessEvent(t, event.KindRequest, "known", "", "", wall0+1000))
	at := graceNow(t, r, f, 2*time.Minute, 3*time.Hour)
	if got := ends(t, r.db); got != "1/1" {
		t.Fatalf("ends %q after the jump, want 1/1", got)
	}
	// The known session keeps its row. The writer skips the rowid 2 for it.
	r.writeOK(sessEvent(t, event.KindRequest, "known", "", "", at-1))
	if got := ends(t, r.db); got != "2/1" {
		t.Fatalf("ends %q after a known session, want 2/1: the event row moves, the session end stays", got)
	}
	// The session a has the rowids 3 and 3. The session b has the rowids 4 and
	// 4, and it moves no end.
	r.writeOK(sessEvent(t, event.KindRequest, "a", "", "", at-2))
	r.writeOK(sessEvent(t, event.KindRequest, "b", "", "", at+5))
	if got := ends(t, r.db); got != "3/3" {
		t.Fatalf("ends %q after a new session, want 3/3", got)
	}
	call(t, r.db, newJumpSessionExpireStep(time.UnixMilli(at+hourMs).Add(90*24*time.Hour), 90), 1000)
	if left := rawText(t, r.db, "SELECT group_concat(id, ' ') FROM (SELECT id FROM session ORDER BY rowid)"); left != "known a" {
		t.Fatalf("sessions left %q, want known and a: b has a time at or after `at`", left)
	}
}

// T-U-27, T-U-30: two grace jumps give two rows, with no read of S between
// them. A row with a time between the two `at` values moves only the end of the
// second row. It takes only the second J. A row before both takes both.
func TestTU30TwoGraceJumpsGiveTwoRowsAndEachRowTakesItsOwnJ(t *testing.T) {
	r, f := clockRig(t)
	at1 := graceNow(t, r, f, 2*time.Minute, 3*time.Hour)
	at2 := graceNow(t, r, f, 4*time.Minute, 5*time.Hour)
	if got, sizes := ends(t, r.db), rawText(t, r.db, "SELECT group_concat(j, ' ') FROM (SELECT j FROM clock_jump ORDER BY id)"); got != "0/0 0/0" ||
		sizes != fmt.Sprint(3*hourMs, " ", 2*hourMs) || at2 <= at1 {
		t.Fatalf("ends %q, sizes %q; want two rows 0/0 0/0 with the sizes 3 h and 2 h", got, sizes)
	}
	// The rowid 1 has a time between the two `at` values.
	r.writeOK(evAt(t, event.KindRequest, at1+1))
	if got := ends(t, r.db); got != "0/0 1/0" {
		t.Fatalf("ends %q, want 0/0 1/0", got)
	}
	// The rowid 2 has a time before both.
	r.writeOK(evAt(t, event.KindRequest, at1-1))
	if got := ends(t, r.db); got != "2/0 2/0" {
		t.Fatalf("ends %q, want 2/0 2/0", got)
	}
	// Row 1 has the time at1 + 1 and takes only the J of 2 h. It acts at the
	// cutoff at1 + 2 h + 2, and not 1 ms before. With no J, it acts at the
	// first cutoff. With both J, it stays at the second cutoff.
	// Row 2 has the time at1 - 1 and takes both J, 5 h in all. It acts at the
	// cutoff at1 + 5 h, and not 1 ms before. With the first J only, it acts at
	// the last two cutoffs.
	for _, c := range []struct {
		cutoff int64
		left   string
	}{{at1 + 2*hourMs + 1, "1 2"}, {at1 + 2*hourMs + 2, "2"}, {at1 + 5*hourMs - 1, "2"}, {at1 + 5*hourMs, ""}} {
		eventDeleteAt(t, r, c.cutoff)
		if left := eventIDs(t, r.db); left != c.left {
			t.Fatalf("cutoff at1 + %d ms: rows left %q, want %q", c.cutoff-at1, left, c.left)
		}
	}
}

// T-U-27, T-U-30: a grace row with empty ranges stays through the clock_jump
// delete of the running process. A row of an earlier process with empty ranges
// goes. A row in flight, written after the delete, moves the end and takes J.
func TestTU30GraceRowWithEmptyRangesStaysThroughTheJumpDelete(t *testing.T) {
	r, f := newRig(t, 8), &fakeSrc{}
	mustExec(t, r.db, "INSERT INTO clock_jump VALUES (1, 5, 4, 5, 4, 1, 5)")
	if err := r.w.StartClock(f.source()); err != nil {
		t.Fatal(err)
	}
	at := graceNow(t, r, f, 2*time.Minute, 3*time.Hour)
	if n := call(t, r.db, newJumpExpireStep(&r.w.knownJump), 10); n != 1 {
		t.Fatalf("the delete removed %d rows, want 1", n)
	}
	if got := rawText(t, r.db, "SELECT group_concat(id, ' ') FROM clock_jump"); got != "2" {
		t.Fatalf("clock_jump ids %q, want 2", got)
	}
	r.writeOK(evAt(t, event.KindRequest, at-1))
	if got := ends(t, r.db); got != "1/0" {
		t.Fatalf("ends %q, want 1/0", got)
	}
	eventDeleteAt(t, r, at+hourMs)
	if left := eventIDs(t, r.db); left != "1" {
		t.Fatalf("rows left %q, want 1: the row takes J", left)
	}
	// With no event row left, the row holds no row. The running process keeps
	// it. A writer with no clock has no row of its own: the delete removes it.
	mustExec(t, r.db, "DELETE FROM event")
	if n := call(t, r.db, newJumpExpireStep(&r.w.knownJump), 10); n != 0 {
		t.Fatalf("the delete removed %d rows of the running process, want 0", n)
	}
	if n := call(t, r.db, newJumpExpireStep(nil), 10); n != 1 {
		t.Fatalf("the delete with no known id removed %d rows, want 1", n)
	}
}

// T-U-27: a reset row has no test of the row time. Each row of its ranges takes
// its j. This includes a row with a time after the stored S of the reset. The
// J is -72 h, and the rows have a time 72 h after the cutoff. The row 1 acts.
// The row 2 has the time at the end and stays. A grace row has the same j and
// the `at` of the cutoff. It gives no j to the rows 3 and 4, which have the
// same times.
func TestTU27ResetRowGivesItsJToRowsAfterItsStoredTime(t *testing.T) {
	db := migrated(t)
	cutoff, j := rollCutoff(30), 72*hourMs
	addGrace(t, db, 100, 1, 2, -j, math.MaxInt64)
	addGrace(t, db, 101, 3, 4, -j, cutoff)
	for id, ts := range map[int64]int64{1: cutoff + j - 1, 2: cutoff + j, 3: cutoff + j - 1, 4: cutoff + j} {
		seedEvent("refused")(t, db, id, ts)
	}
	call(t, db, newJumpRawDeleteStep(rollTDel, 30), 1000)
	if left := eventIDs(t, db); left != "2 3 4" {
		t.Fatalf("rows left %q, want 2 3 4", left)
	}
}

// T-U-27: a row takes the j of a grace row only when its time is before `at`.
// The `at` is 1 h before the cutoff, and J is +72 h. The row 3 has the time
// 1 ms before `at`: it takes J and stays. The rows 4 and 5 have the time `at`
// and 1 ms after: they take no J, and they act.
func TestTU27GraceRowGivesItsJOnlyToRowsBeforeAt(t *testing.T) {
	db := migrated(t)
	cutoff := rollCutoff(30)
	at := cutoff - hourMs
	addGrace(t, db, 100, 3, 6, 72*hourMs, at)
	for id, ts := range map[int64]int64{3: at - 1, 4: at, 5: at + 1, 6: at - 1} {
		seedEvent("refused")(t, db, id, ts)
	}
	call(t, db, newJumpRawDeleteStep(rollTDel, 30), 1000)
	if left := eventIDs(t, db); left != "3 6" {
		t.Fatalf("rows left %q, want 3 6", left)
	}
}

// T-U-27: the read ends at the cutoff minus the smallest sum that a row can
// get. A reset row gives -72 h to the rows 7 to 9. A grace row with the `at` of
// the cutoff gives +72 h. A row with a time at or after `at` gets -72 h only.
// Thus the read must go 72 h past the cutoff. The row 7 has the time 1 ms
// before the end and acts. The row 8 has the time at the end and stays. The row
// 9 has the time before `at`, gets the sum 0, and acts.
func TestTU27ReadEndUsesTheSmallestSumWithTheAtTest(t *testing.T) {
	db := migrated(t)
	cutoff, j := rollCutoff(30), 72*hourMs
	addGrace(t, db, 100, 7, 9, -j, math.MaxInt64)
	addGrace(t, db, 101, 7, 9, j, cutoff)
	for id, ts := range map[int64]int64{7: cutoff + j - 1, 8: cutoff + j, 9: cutoff - 1} {
		seedEvent("refused")(t, db, id, ts)
	}
	call(t, db, newJumpRawDeleteStep(rollTDel, 30), 1000)
	if left := eventIDs(t, db); left != "8" {
		t.Fatalf("rows left %q, want 8", left)
	}
}

// T-U-27: the session delete takes last_seen with the `at` test. The `at` is 2
// h before the cutoff, and J is +72 h. A session seen again after the jump has
// last_seen at or after `at`. It goes at its last_seen + days: 1 ms before the
// cutoff, not at it. A session with last_seen before `at` goes J later: 1 ms
// before cutoff - J, not at it. Each of the four bands has the four cases.
func TestTU27SessionDeleteTakesLastSeenWithTheAtTest(t *testing.T) {
	db := migrated(t)
	cutoff, j := rollCutoff(90), 72*hourMs
	addGrace(t, db, 100, 1, 16, j, cutoff-2*hourMs)
	// The rows go, stay, go, and stay.
	times := []int64{cutoff - 1, cutoff, cutoff - j - 1, cutoff - j}
	for b, band := range sessionBands {
		for k, ts := range times {
			mustExec(t, db, "INSERT INTO session (rowid, id, first_seen, last_seen, ip, ip_hmac, band) VALUES (?, ?, ?, ?, '192.0.2.1', 'h', ?)",
				4*b+k+1, fmt.Sprint(band, k), ts, ts, band)
		}
	}
	step := newJumpSessionExpireStep(rollTDel, 90)
	if n := call(t, db, step, 1000); n != 48 {
		t.Fatalf("the call returned %d, want 48: 12 entries read, cost 4", n)
	}
	if left := rawText(t, db, "SELECT group_concat(rowid, ' ') FROM (SELECT rowid FROM session ORDER BY rowid)"); left != "2 4 6 8 10 12 14 16" {
		t.Fatalf("session rowids left %q, want 2 4 6 8 10 12 14 16", left)
	}
	if n := call(t, db, step, 1000); n != 0 {
		t.Fatalf("a second call returned %d, want 0", n)
	}
}

// T-U-27: a session row costs 4 of the limit. A call reads at most limit / 4
// entries, so it deletes at most that many rows. It returns the limit when it
// read the most, also with no clock_jump range. A limit below 4 runs no
// statement.
func TestTU27SessionDeleteCostsFourOfTheLimit(t *testing.T) {
	for _, ranged := range []bool{false, true} {
		t.Run(fmt.Sprint("range ", ranged), func(t *testing.T) {
			db := migrated(t)
			if ranged {
				addGrace(t, db, 100, 5000, 5001, hourMs, math.MaxInt64-1)
			}
			bulkSession(t, db, 1, 10, rollCutoff(90)-1000)
			step := newJumpSessionExpireStep(rollTDel, 90)
			var got, left []int
			for _, limit := range []int{3, 8, 8, 8, 8, 8, 8} {
				got = append(got, call(t, db, step, limit))
				left = append(left, count(t, db, "SELECT count(*) FROM session"))
			}
			if fmt.Sprint(got) != "[3 8 8 8 8 8 0]" || fmt.Sprint(left) != "[10 8 6 4 2 0 0]" {
				t.Fatalf("calls returned %v and left %v rows; want [3 8 8 8 8 8 0] and [10 8 6 4 2 0 0]", got, left)
			}
		})
	}
}

// T-U-11: the DB cap keeps the plain raw delete. The cap evicts by the oldest
// UTC day in stored time. A refused row on day 1 is in a +200 d range. The
// corrected step would keep it, and the cap would stop. The cap evicts it, then
// the session row of day 3, and it leaves no row.
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

// T-U-27, T-U-30: a batch that moves an end writes the key with the rowid floor
// in the same transaction, with synchronous=FULL. The floor is above the new
// rowids. A batch with a row at `at` moves no end and writes no key. A batch
// that rolls back leaves the key, the floor in memory and the ends unchanged.
func TestTU30MoveOfAnEndWritesTheKeyWithTheRowidFloor(t *testing.T) {
	r, f := clockRig(t)
	moves := 0
	var pragmas []string
	r.w.beforeMove = func() { moves++ }
	r.w.beforePragma = func(s string) error { pragmas = append(pragmas, s); return nil }
	at := graceNow(t, r, f, 2*time.Minute, 3*time.Hour)
	pragmas = nil
	before, floor := metaValue(t, r.db, sensorTimeKey), r.w.floorEvent
	// The row 1 has the time `at`: no row of the batch is before it.
	r.writeOK(evAt(t, event.KindRequest, at))
	if moves != 0 || len(pragmas) != 0 || metaValue(t, r.db, sensorTimeKey) != before {
		t.Fatalf("a row at `at`: %d moves, pragmas %v; want no move, no pragma and the same key", moves, pragmas)
	}
	r.w.beforeCommit = func(*sql.Tx) error { return errors.New("no commit") }
	if err := r.w.write([]*event.Event{evAt(t, event.KindRequest, at-1), sessEvent(t, event.KindRequest, "a", "", "", at-1)}); err == nil {
		t.Fatal("the write did not fail")
	}
	r.w.beforeCommit = nil
	if got := ends(t, r.db); got != "0/0" || metaValue(t, r.db, sensorTimeKey) != before || r.w.floorEvent != floor {
		t.Fatalf("after a rollback: ends %q, floor %d; want 0/0, the same key and the floor %d", got, r.w.floorEvent, floor)
	}
	// The rows 2 and 3 are event rows. The session has the rowid 1.
	pragmas = nil
	r.writeOK(evAt(t, event.KindRequest, at-1), sessEvent(t, event.KindRequest, "a", "", "", at-2))
	st := r.key()
	if got := ends(t, r.db); got != "3/1" || st.NextEvent <= 3 || st.NextSession <= 1 ||
		r.w.floorEvent != st.NextEvent || r.w.floorSession != st.NextSession || fmt.Sprint(pragmas) != "[PRAGMA synchronous=FULL PRAGMA synchronous=NORMAL]" {
		t.Fatalf("ends %q, key floors %d and %d, pragmas %v; want 3/1, floors above 3 and 1, FULL then NORMAL", got, st.NextEvent, st.NextSession, pragmas)
	}
}

// T-U-30: an earlier process wrote a grace row with empty ranges and an `at`
// far ahead. A row in flight is before that `at`. This process does not move
// the end of that row. It moves the end of its own grace row. That row has the
// id after the largest id at the start.
func TestTU30EndOfAnEarlierProcessRowDoesNotMove(t *testing.T) {
	r, f := newRig(t, 8), &fakeSrc{}
	addGrace(t, r.db, 1, 1, 0, hourMs, math.MaxInt64-1)
	if err := r.w.StartClock(f.source()); err != nil {
		t.Fatal(err)
	}
	at := graceNow(t, r, f, 2*time.Minute, 3*time.Hour)
	r.writeOK(evAt(t, event.KindRequest, at-1))
	if got := ends(t, r.db); got != "0/0 1/0" {
		t.Fatalf("ends %q, want 0/0 1/0: only the row of this process moves", got)
	}
}

// runAtMs makes the production run of a schedule of the rig at the time st, in
// unix ms. The writer serves the run in this goroutine.
func runAtMs(t *testing.T, r *rig, st int64) {
	t.Helper()
	s := NewSchedule(r.w, 7, 30, 90, nil)
	s.run = direct(r)
	s.runAt(context.Background(), time.UnixMilli(st))
	if n := s.EarlyEnds(); n != 0 {
		t.Fatalf("the run ended early %d times", n)
	}
}

// T-U-11, T-U-30: the run keeps a grace row of its own process that has empty
// ranges, 100 d after the jump. The run deletes an empty row of an earlier
// process.
func TestTU30ScheduleRunKeepsTheGraceRowOfThisProcess(t *testing.T) {
	r, f := newRig(t, 8), &fakeSrc{}
	mustExec(t, r.db, "INSERT INTO clock_jump VALUES (1, 5, 4, 5, 4, 1, 5)")
	if err := r.w.StartClock(f.source()); err != nil {
		t.Fatal(err)
	}
	at := graceNow(t, r, f, 2*time.Minute, 3*time.Hour)
	runAtMs(t, r, at+100*rawDay)
	if got := rawText(t, r.db, "SELECT coalesce(group_concat(id, ' '), '') FROM clock_jump"); got != "2" {
		t.Fatalf("clock_jump ids %q, want 2: the row of this process stays", got)
	}
}

// T-U-27, T-U-30: the run deletes a session with the clock_jump correction. The
// session has a last_seen before the `at` of a grace row of +3 h. The cutoff is
// 1 h after `at`. The plain session delete would remove the session. The
// corrected one keeps it.
func TestTU30ScheduleRunDeletesSessionsWithTheCorrection(t *testing.T) {
	r, f := clockRig(t)
	at := graceNow(t, r, f, 2*time.Minute, 3*time.Hour)
	r.writeOK(sessEvent(t, event.KindRequest, "a", "", "", at-2))
	runAtMs(t, r, at+hourMs+90*rawDay)
	if n := count(t, r.db, "SELECT count(*) FROM session"); n != 1 {
		t.Fatalf("%d sessions left, want 1: the grace row keeps the session", n)
	}
}

// T-U-27: the session delete returns the limit when it read the most entries.
// This holds also when the limit is not a multiple of 4. Else the run takes the
// step as done and ends the delete early. 300 sessions act. The limit 997 reads
// 249 entries, and the limit 7 reads 1.
func TestTU27SessionDeleteReturnsTheLimitForALimitThatIsNotAMultipleOf4(t *testing.T) {
	db := migrated(t)
	addGrace(t, db, 100, 5000, 5001, hourMs, math.MaxInt64-1)
	bulkSession(t, db, 1, 300, rollCutoff(90)-1000)
	step := newJumpSessionExpireStep(rollTDel, 90)
	got := []int{call(t, db, step, 997), call(t, db, step, 7)}
	if left := count(t, db, "SELECT count(*) FROM session"); fmt.Sprint(got) != "[997 7]" || left != 50 {
		t.Fatalf("calls returned %v and left %d rows; want [997 7] and 50", got, left)
	}
}
