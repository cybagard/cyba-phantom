package store

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cybagard/cyba-phantom/internal/event"
	"github.com/cybagard/cyba-phantom/internal/token"
)

const (
	rawDay = int64(24 * time.Hour / time.Millisecond)
	// rawCleared selects the rows whose three fields are all NULL. rawFull
	// selects the rows with a value in at least one field.
	rawCleared = "body_prefix IS NULL AND detail IS NULL AND record IS NULL"
	rawFull    = "(body_prefix IS NOT NULL OR detail IS NOT NULL OR record IS NOT NULL)"
)

// addFull inserts n rows of kind with ts = ts0 + i*step. Each row has a value
// in each field that the clear sets to NULL. A bulk row has no record (CHECK).
func addFull(tb testing.TB, db *sql.DB, kind string, n int, ts0, step int64) {
	tb.Helper()
	ev := kind == "callback"
	mustExec(tb, db, `WITH RECURSIVE c(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM c WHERE i < ?)
		INSERT INTO event (ts, kind, body_prefix, detail, record, hash, leaf_index)
		SELECT ? + i*?, ?, x'62', '{}', CASE WHEN ? THEN x'7b7d' END, CASE WHEN ? THEN zeroblob(32) END,
		CASE WHEN ? THEN i + (SELECT coalesce(max(leaf_index) + 1, 0) FROM event) END FROM c`,
		n-1, ts0, step, kind, ev, ev, ev)
}

// rawText returns the first column of a query as text.
func rawText(tb testing.TB, db *sql.DB, q string) (s string) {
	tb.Helper()
	check(tb, db.QueryRow(q).Scan(&s))
	return s
}

// rollWall is the wall clock of a step test. It always gives rollTDel.
func rollWall() time.Time { return rollTDel }

// T-U-11: a row with ts before the cutoff has the three fields NULL, also a
// callback row with a record. A row at the cutoff or after it keeps them. The
// step writes no meta key. A run with a later cutoff clears a row that has a
// value again.
func TestTU11FieldClearBeforeTheCutoff(t *testing.T) {
	r, chunks := rollRig(t, newFieldClearStep(rollTDel, rollWall, 30))
	cut := rollCutoff(30)
	for _, k := range []string{"callback", "request"} {
		for _, d := range []int64{-10_000, -1, 0, 1000} {
			addFull(t, r.db, k, 1, cut+d, 0)
		}
	}
	runOK(t, r)
	q := "SELECT group_concat(kind || ':' || (ts - " + strconv.FormatInt(cut, 10) + "), ' ') FROM (SELECT * FROM event WHERE " + rawCleared + " ORDER BY kind, ts)"
	if got, want := rawText(t, r.db, q), "callback:-10000 callback:-1 request:-10000 request:-1"; got != want || fmt.Sprint(*chunks) != "[4]" {
		t.Fatalf("cleared rows %q, chunks %v; want %q and [4]", got, *chunks, want)
	}
	if n := count(t, r.db, "SELECT count(*) FROM meta WHERE key LIKE 'retention%'"); n != 0 {
		t.Fatalf("the step wrote %d meta keys", n)
	}
	mustExec(t, r.db, "UPDATE event SET body_prefix = x'62' WHERE ts = ?", cut-1)
	later := rollTDel.Add(time.Hour)
	runAgain(t, r, newFieldClearStep(later, rollWall, 30))
	if n := count(t, r.db, "SELECT count(*) FROM event WHERE "+rawFull); n != 0 {
		t.Fatalf("%d rows with a value after the run with a later cutoff, want 0", n)
	}
}

// T-U-11: the filter of the clear statement has three terms. A row with only
// one of the three fields is cleared and counted. A row with none is skipped,
// so the count is 3 and not 4.
func TestTU11FieldClearFilterHasThreeTerms(t *testing.T) {
	r, _ := rollRig(t, newFieldClearStep(rollTDel, rollWall, 30))
	mustExec(t, r.db, "INSERT INTO event (ts, kind, body_prefix) VALUES (10, 'request', x'62')")
	mustExec(t, r.db, "INSERT INTO event (ts, kind, detail) VALUES (11, 'request', '{}')")
	mustExec(t, r.db, "INSERT INTO event (ts, kind, record, hash, leaf_index) VALUES (12, 'callback', x'7b7d', zeroblob(32), 1)")
	mustExec(t, r.db, "INSERT INTO event (ts, kind) VALUES (13, 'request')")
	var tl tally
	ctx := context.WithValue(context.Background(), tallyKey{}, &tl)
	tx, err := r.db.Begin()
	check(t, err)
	if _, err := newFieldClearStep(rollTDel, rollWall, 30)(ctx, tx, chunkRows); err != nil {
		t.Fatal(err)
	}
	check(t, tx.Commit())
	if n := count(t, r.db, "SELECT count(*) FROM event WHERE "+rawFull); n != 0 || tl[memFields] != 3 {
		t.Fatalf("%d rows keep a value, %d rows counted; want 0 and 3", n, tl[memFields])
	}
}

// callTally is callWithin that also returns the rows that the fields member
// counted.
func callTally(t *testing.T, db *sql.DB, step retentionStep, limit int) (n, fields int) {
	t.Helper()
	var tl tally
	ctx, cancel := context.WithTimeout(context.WithValue(context.Background(), tallyKey{}, &tl), 5*time.Second)
	defer cancel()
	tx, err := db.Begin()
	check(t, err)
	n, err = step(ctx, tx, limit)
	check(t, err)
	check(t, tx.Commit())
	return n, int(tl[memFields])
}

// T-U-11: 2 502 rows with one ts go in chunks of 1 000, 1 000 and 502. The
// last call returns 502, below the limit, as no row is left.
func TestTU11FieldClearManyRowsWithOneTS(t *testing.T) {
	r, chunks := rollRig(t, newFieldClearStep(rollTDel, rollWall, 30))
	cut := rollCutoff(30)
	addFull(t, r.db, "request", 2500, 5, 0)
	for _, ts := range []int64{0, cut - 1, cut} {
		addFull(t, r.db, "request", 1, ts, 0)
	}
	runOK(t, r)
	if n := count(t, r.db, "SELECT count(*) FROM event WHERE "+rawFull); n != 1 || fmt.Sprint(*chunks) != "[1000 1000 502]" {
		t.Fatalf("%d rows keep a value, chunks %v; want 1 and [1000 1000 502]", n, *chunks)
	}
}

// T-U-27: 3 rows before the cutoff, 5 after the future line, and a limit of 4.
// Part 1 comes first. The first call clears the 3 rows and 1 row of part 2, and
// returns 4, not 3. The next calls return 4 and 0. The fields count is the
// rows of both parts.
func TestTU27FieldClearTwoPartsCountAndOrder(t *testing.T) {
	db := migrated(t)
	addFull(t, db, "request", 3, 1, 1)
	addFull(t, db, "request", 5, rollTDel.UnixMilli()+2*3_600_000, 1)
	step := newFieldClearStep(rollTDel, rollWall, 30)
	n, fields := callTally(t, db, step, 4)
	if old := count(t, db, "SELECT count(*) FROM event WHERE ts < 100 AND "+rawFull); n != 4 || fields != 4 || old != 0 {
		t.Fatalf("first call returned %d, fields %d, %d old rows keep a value; want 4, 4 and 0", n, fields, old)
	}
	for i, want := range []int{4, 0} {
		if n, fields := callTally(t, db, step, 4); n != want || fields != want {
			t.Fatalf("call %d returned %d, fields %d; want %d", i+2, n, fields, want)
		}
	}
	if n := count(t, db, "SELECT count(*) FROM event WHERE "+rawFull); n != 0 {
		t.Fatalf("%d rows keep a value", n)
	}
}

// T-U-27: the step takes the largest id at its first call. After the first
// call, one row before the cutoff and one after the line are written. Both
// keep their fields. The last call returns 1, so the step ends.
func TestTU27FieldClearChangesNoRowAboveTheFirstCallRowid(t *testing.T) {
	db := migrated(t)
	late := rollTDel.UnixMilli() + 40*24*3_600_000
	addFull(t, db, "request", 6, 1, 1)
	addFull(t, db, "request", 3, late, 1)
	step := newFieldClearStep(rollTDel, rollWall, 30)
	if n := callWithin(t, db, step, 4); n != 4 {
		t.Fatalf("first call returned %d, want 4", n)
	}
	addFull(t, db, "request", 1, 1, 0)
	addFull(t, db, "request", 1, late, 0)
	for i, want := range []int{4, 1} {
		if n := callWithin(t, db, step, 4); n != want {
			t.Fatalf("call %d returned %d, want %d", i+2, n, want)
		}
	}
	if n := count(t, db, "SELECT count(*) FROM event WHERE id > 9 AND "+rawFull); n != 2 || count(t, db, "SELECT count(*) FROM event WHERE "+rawFull) != 2 {
		t.Fatalf("%d new rows keep a value, want 2 and no other row", n)
	}
}

// T-U-27: the future line is the later of the wall time and the stored
// retention_check, plus 1 h. A row at the line keeps its fields. A row 1 ms
// after it loses them. A bad value or a failed read gives the wall time alone.
func TestTU27FieldClearFutureLine(t *testing.T) {
	w := rollTDel.UnixMilli()
	for _, c := range []struct {
		name, prep string
		stored     any
		line       int64 // the ts that keeps its fields; 0: no row is future
	}{
		{"no value", "", nil, w + 3_600_000},
		{"after the wall time", "", w + 7_200_000, w + 10_800_000},
		{"before the wall time", "", w - 7_200_000, w + 3_600_000},
		{"bad value", "", "x", w + 3_600_000},
		{"failed read", "DROP TABLE meta", nil, w + 3_600_000},
		{"largest value", "", int64(math.MaxInt64), 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			db := migrated(t)
			if c.stored != nil {
				mustExec(t, db, metaSetSQL, retentionCheckKey, fmt.Sprint(c.stored))
			}
			if c.prep != "" {
				mustExec(t, db, c.prep)
			}
			for _, ts := range []int64{c.line - 1, c.line, c.line + 1, w + 100*24*3_600_000} {
				addFull(t, db, "request", 1, ts, 0)
			}
			callWithin(t, db, newFieldClearStep(rollTDel, rollWall, 30), chunkRows)
			got := rawText(t, db, "SELECT coalesce(group_concat(ts - "+strconv.FormatInt(w, 10)+", ' '), '') FROM (SELECT ts FROM event WHERE "+rawFull+" ORDER BY ts)")
			want := fmt.Sprintf("%d %d", c.line-1-w, c.line-w)
			if c.line == 0 {
				want = fmt.Sprintf("%d", 100*24*3_600_000)
			}
			if got != want {
				t.Fatalf("rows that keep a value (ts - wall) %q, want %q", got, want)
			}
		})
	}
}

// T-U-27: the step reads the wall time at its first call, not at its
// construction and not at each call. The clock gives 10 h more at each read,
// so the line must not move between the two calls.
func TestTU27FieldClearTakesTheWallTimeAtTheFirstCall(t *testing.T) {
	db := migrated(t)
	reads := 0
	step := newFieldClearStep(rollTDel, func() time.Time {
		reads++
		return rollTDel.Add(time.Duration(reads-1) * 10 * time.Hour)
	}, 30)
	if reads != 0 {
		t.Fatalf("%d clock reads at construction", reads)
	}
	addFull(t, db, "request", 2, rollTDel.UnixMilli()+2*3_600_000, 1)
	for i := 0; i < 2; i++ {
		if n := callWithin(t, db, step, 1); n != 1 {
			t.Fatalf("call %d returned %d, want 1", i+1, n)
		}
	}
	if n := count(t, db, "SELECT count(*) FROM event WHERE "+rawFull); n != 0 || reads != 1 {
		t.Fatalf("%d rows keep a value, %d clock reads; want 0 and 1", n, reads)
	}
}

// T-U-27: 5 000 cleared rows, then one row with a field. One call clears the
// row and returns 1: the cleared rows are not in the index.
func TestTU27FieldClearOneCallClearsTheRowAfterClearedRows(t *testing.T) {
	db := migrated(t)
	mustExec(t, db, `WITH RECURSIVE c(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM c WHERE i < 5000)
		INSERT INTO event (ts, kind) SELECT i, 'request' FROM c`)
	addFull(t, db, "request", 1, 6000, 0)
	if n, fields := callTally(t, db, newFieldClearStep(rollTDel, rollWall, 30), 1000); n != 1 || fields != 1 || count(t, db, "SELECT count(*) FROM event WHERE "+rawFull) != 0 {
		t.Fatalf("one call returned %d, fields %d; want 1, 1 and no row with a field", n, fields)
	}
}

// T-U-27: each clear statement names INDEXED BY event_raw_ts and repeats its
// WHERE text. Each plan uses it, with no SCAN and no temporary B-tree.
func TestTU27FieldClearUsesTheRawIndexInBothParts(t *testing.T) {
	db := migrated(t)
	def := rawText(t, db, "SELECT sql FROM sqlite_master WHERE name = 'event_raw_ts'")
	where := def[strings.Index(def, " WHERE ")+len(" WHERE "):]
	for name, q := range map[string]string{"part 1": clearPastSQL, "part 2": clearFutureSQL} {
		if !strings.Contains(q, "INDEXED BY event_raw_ts") || !strings.Contains(q, "("+where+")") {
			t.Fatalf("%s: no INDEXED BY, or no WHERE text %q of the index: %s", name, where, q)
		}
		p := strings.Join(queryPlan(t, db, q, 1, 5, 1000), "\n")
		if !strings.Contains(p, "USING INDEX event_raw_ts (ts") || strings.Contains(p, "SCAN event") || strings.Contains(p, "TEMP B-TREE") {
			t.Fatalf("plan of %s:\n%s", name, p)
		}
	}
}

// T-U-11: the delete takes refused and beacon rows before the cutoff. A row at
// the cutoff stays, and so does each request and callback row. 1 500 refused
// and 1 000 beacon rows go in chunks of 1 000, 1 000 and 500.
func TestTU11RawDeleteRefusedAndBeacon(t *testing.T) {
	r, chunks := rollRig(t, newRawDeleteStep(rollTDel, 30))
	cut := rollCutoff(30)
	for _, k := range []string{"refused", "beacon", "request", "callback"} {
		for _, d := range []int64{-rawDay, -1, 0, rawDay} {
			addEvents(t, r.db, k, 1, cut+d, 0, nil, nil)
		}
	}
	runOK(t, r)
	q := "SELECT group_concat(kind || ':' || n, ' ') FROM (SELECT kind, count(*) n FROM event GROUP BY kind ORDER BY kind)"
	if got, want := rawText(t, r.db, q), "beacon:2 callback:4 refused:2 request:4"; got != want || fmt.Sprint(*chunks) != "[4]" {
		t.Fatalf("rows left %q, chunks %v; want %q and [4]", got, *chunks, want)
	}
	if n := count(t, r.db, "SELECT count(*) FROM event WHERE kind IN ('refused', 'beacon') AND ts < "+strconv.FormatInt(cut, 10)); n != 0 {
		t.Fatalf("%d old refused and beacon rows left", n)
	}
	r, chunks = rollRig(t, newRawDeleteStep(rollTDel, 30))
	addEvents(t, r.db, "refused", 1500, 1, 1, nil, nil)
	addEvents(t, r.db, "beacon", 1000, 1, 1, nil, nil)
	runOK(t, r)
	if r.events() != 0 || fmt.Sprint(*chunks) != "[1000 1000 500]" {
		t.Fatalf("%d rows left, chunks %v; want 0 and [1000 1000 500]", r.events(), *chunks)
	}
}

// T-U-11, T-S-34: a days value outside 1 to 30 and a zero time give a step that
// runs no statement. The run stops the writer, and no row changes.
func TestTU11RawStepsRefuseBadParameters(t *testing.T) {
	for _, c := range []struct {
		name        string
		tPriv, tDel time.Time
		days        int
	}{{"0 days", rollTDel, rollTDel, 0}, {"31 days", rollTDel, rollTDel, 31}, {"zero time", time.Time{}, time.Time{}, 30}, {"zero tDel", rollTDel, time.Time{}, 30}} {
		for i, mk := range []func(tPriv, tDel time.Time, days int) retentionStep{
			func(tPriv, tDel time.Time, days int) retentionStep {
				// A zero tDel stands for a clock that is nil.
				var wall func() time.Time
				if !tDel.IsZero() {
					wall = func() time.Time { return tDel }
				}
				return newFieldClearStep(tPriv, wall, days)
			},
			func(_, tDel time.Time, days int) retentionStep { return newRawDeleteStep(tDel, days) },
			func(_, tDel time.Time, days int) retentionStep { return newMintStep(tDel, days) },
		} {
			t.Run(fmt.Sprint(c.name, " step ", i), func(t *testing.T) {
				r, chunks := rollRig(t, mk(c.tPriv, c.tDel, c.days))
				addFull(t, r.db, "refused", 1, 1, 0)
				mustExec(t, r.db, "INSERT INTO mint VALUES (x'01', 1, 1, 1, 's', 1)")
				stops(t, r)
				if r.events() != 1 || count(t, r.db, "SELECT count(*) FROM mint") != 1 || rowsChanged(*chunks) != 0 {
					t.Fatalf("rows changed %d; want no change", rowsChanged(*chunks))
				}
			})
		}
	}
}

// callWithin is call with a bound of 5 s. A step that loops for ever fails the
// test, as its statements return the error of the ended context.
func callWithin(t *testing.T, db *sql.DB, step retentionStep, limit int) int {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tx, err := db.Begin()
	check(t, err)
	n, err := step(ctx, tx, limit)
	check(t, err)
	check(t, tx.Commit())
	return n
}

// unitTime returns a time in the middle of the time unit u.
func unitTime(u int) time.Time {
	return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(u)*10*time.Minute + 5*time.Minute)
}

// addMintRow inserts a mint row of the set `set` with the counters first to
// first+9.
func addMintRow(t *testing.T, db *sql.DB, set byte, unit, first, issued int64) {
	t.Helper()
	mustExec(t, db, "INSERT INTO mint VALUES (?, ?, ?, 10, 's', ?)", []byte{set}, unit, first, issued)
}

// mintLeft returns the rows of mint as set/unit/first, in key order.
func mintLeft(t *testing.T, db *sql.DB) string {
	t.Helper()
	return rawText(t, db, `SELECT coalesce(group_concat(hex(set_id) || '/' || unit || '/' || first, ' '), '') FROM
		(SELECT * FROM mint ORDER BY set_id, unit, first)`)
}

// T-S-34: two rows of one unit cover one counter. A cutoff time between their
// issued_at deletes both or neither. With the cutoff in the unit of the rows,
// both stay. With the cutoff in the next unit, both go.
func TestTS34MintSplitUnitGoesTogether(t *testing.T) {
	const u = 400_000
	for _, c := range []struct {
		name string
		cut  int
		want string
	}{{"cutoff in the unit", u, "01/400000/500 01/400000/505"}, {"cutoff in the next unit", u + 1, ""}} {
		t.Run(c.name, func(t *testing.T) {
			db := migrated(t)
			cutTime := unitTime(c.cut)
			// The two rows are in unit u. In the first case, the cutoff is
			// between their issued_at.
			a, b := unitTime(u).Add(-time.Minute), unitTime(u).Add(time.Minute)
			if c.cut == u {
				a, b = cutTime.Add(-time.Second), cutTime.Add(time.Second)
			}
			if token.Unit(a) != u || token.Unit(b) != u || token.Unit(cutTime) != uint32(c.cut) {
				t.Fatal("the test times are not in the units that the test needs")
			}
			addMintRow(t, db, 1, u, 500, a.UnixMilli())
			addMintRow(t, db, 1, u, 505, b.UnixMilli())
			callWithin(t, db, newMintStep(cutTime.Add(30*24*time.Hour), 30), chunkRows)
			if got := mintLeft(t, db); got != c.want {
				t.Fatalf("rows left %q, want %q", got, c.want)
			}
		})
	}
}

// T-S-34: the compare of the unit is the signed 20-bit difference. The cutoff
// unit is kept. The 2^19 - 1 units before it go, also over the wrap of the
// unit. The unit 2^19 before it is a future unit, and it stays.
func TestTS34MintUnitsAtTheWrap(t *testing.T) {
	const top = event.MintUnitLimit
	for _, c := range []struct {
		cut   int
		units []int64
		want  string // the units that stay
	}{
		{3, []int64{top - 2, 3, 5}, "3 5"},
		{top - 3, []int64{1, top - 3, top - 5}, "1 " + strconv.Itoa(top-3)},
		{1_000_000, []int64{999_999, 1_000_000, 1_000_000 - 524_287, 1_000_000 - 524_288, 1_000_001}, "475712 1000000 1000001"},
		{0, []int64{top - 1, 0, 1, top - 524_287, top - 524_288}, "0 1 524288"},
	} {
		db := migrated(t)
		for _, u := range c.units {
			addMintRow(t, db, 1, u, u, 0)
		}
		callWithin(t, db, newMintStep(unitTime(c.cut).Add(30*24*time.Hour), 30), chunkRows)
		got := rawText(t, db, "SELECT coalesce(group_concat(unit, ' '), '') FROM (SELECT unit FROM mint ORDER BY unit)")
		if got != c.want {
			t.Errorf("cutoff unit %d: units left %q, want %q", c.cut, got, c.want)
		}
	}
}

// T-S-34: four set_ids, one of them with no row to delete, and a limit of 4.
// The position crosses set_ids and chunks. The cutoff unit is 3, so each set_id
// has rows in both unit ranges. The calls return the rows that they deleted.
func TestTS34MintPositionCrossesSetsAndChunks(t *testing.T) {
	db := migrated(t)
	for set := byte(1); set <= 4; set++ {
		for _, u := range []int64{3, 4} {
			addMintRow(t, db, set, u, u, 0)
		}
		if set == 3 {
			continue
		}
		for _, u := range []int64{event.MintUnitLimit - 3, event.MintUnitLimit - 2, event.MintUnitLimit - 1, 0, 1} {
			addMintRow(t, db, set, u, u, 0)
		}
	}
	step, total := newMintStep(unitTime(3).Add(30*24*time.Hour), 30), 0
	for n := 4; n == 4; {
		n = callWithin(t, db, step, 4)
		total += n
	}
	if want := "01/3/3 01/4/4 02/3/3 02/4/4 03/3/3 03/4/4 04/3/3 04/4/4"; mintLeft(t, db) != want || total != 15 {
		t.Fatalf("rows left %q, %d deleted; want %q and 15", mintLeft(t, db), total, want)
	}
}

// T-S-34: the statements of the mint step use the primary key.
func TestTS34MintStatementsUsePrimaryKey(t *testing.T) {
	db := migrated(t)
	for _, c := range []struct {
		q    string
		args []any
	}{{mintNextSQL, []any{""}}, {mintUnitSQL, []any{[]byte{1}, 0, 5}}, {mintCountSQL, []any{[]byte{1}, 5, 1000}},
		{mintDropSQL, []any{[]byte{1}, 5}}, {mintDeleteSQL, []any{[]byte{1}, 5, 1000}}} {
		if plan := strings.Join(queryPlan(t, db, c.q, c.args...), "\n"); !strings.Contains(plan, "PRIMARY KEY") || strings.Contains(plan, "SCAN mint") {
			t.Errorf("plan of %q:\n%s", c.q, plan)
		}
	}
}

// T-U-11, T-S-34: the run of the writer takes the three steps, and each step
// gets its own time. The delete and the mint step get tDel. The field clear
// gets tPriv, 2 d later. Rows of 31 d by tDel are gone. A row of 29 d by tDel
// is kept, and its fields are cleared, as tPriv makes it 31 d.
func TestTU11RunStepsRunsTheRawSteps(t *testing.T) {
	r := newRig(t, 4000)
	tDel, tPriv := rollTDel, rollTDel.Add(48*time.Hour)
	cut := rollCutoff(30)
	oldUnit, youngUnit := int64(token.Unit(time.UnixMilli(cut-3_600_000))), int64(token.Unit(time.UnixMilli(cut+rawDay)))
	for _, k := range []string{"refused", "beacon"} {
		addFull(t, r.db, k, 1, cut-1, 0)
		addFull(t, r.db, k, 1, cut+rawDay, 0)
	}
	addMintRow(t, r.db, 1, oldUnit, 1, 0)
	addMintRow(t, r.db, 1, youngUnit, 2, 0)
	// The trigger notes each row that an UPDATE changes. The delete runs before
	// the clear, so the clear never writes the two old rows.
	mustExec(t, r.db, "CREATE TABLE touched (id INTEGER)")
	mustExec(t, r.db, "CREATE TRIGGER note AFTER UPDATE ON event BEGIN INSERT INTO touched VALUES (old.id); END")
	if err := runWith(t, r, runSteps(tDel, tDel, tPriv, 7, 30, 90)); err != nil {
		t.Fatal(err)
	}
	q := "SELECT group_concat(kind || ':' || (ts - " + strconv.FormatInt(cut, 10) + ") || ':' || (" + rawCleared + "), ' ') FROM (SELECT * FROM event ORDER BY kind)"
	if got, want := rawText(t, r.db, q), fmt.Sprintf("beacon:%d:1 refused:%d:1", rawDay, rawDay); got != want {
		t.Fatalf("rows left %q, want %q", got, want)
	}
	if got, want := mintLeft(t, r.db), fmt.Sprintf("01/%d/2", youngUnit); got != want {
		t.Fatalf("mint rows left %q, want %q", got, want)
	}
	if n := count(t, r.db, "SELECT count(*) FROM touched"); n != 2 {
		t.Fatalf("the clear wrote %d rows, want the 2 young rows", n)
	}
}

// addMintRows inserts n rows of the unit with first = 0 to n-1.
func addMintRows(t *testing.T, db *sql.DB, set byte, unit int64, n int) {
	t.Helper()
	mustExec(t, db, `WITH RECURSIVE c(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM c WHERE i < ?)
		INSERT INTO mint SELECT ?, ?, i, 1, 's', 0 FROM c`, n-1, []byte{set}, unit)
}

// mintStepAfter returns the mint step with a cutoff unit after all test units.
func mintStepAfter() retentionStep {
	return newMintStep(unitTime(100).Add(30*24*time.Hour), 30)
}

// T-S-34: a unit that does not fit in the rest of a chunk is not split. Unit 5
// has 999 rows and unit 6 has 2 rows that cover one counter. The first call
// deletes unit 5, and it keeps both rows of unit 6. The next call deletes both.
func TestTS34MintUnitIsNotSplitByAChunk(t *testing.T) {
	db := migrated(t)
	addMintRows(t, db, 1, 5, 999)
	addMintRow(t, db, 1, 6, 500, 0)
	addMintRow(t, db, 1, 6, 505, 0)
	step := mintStepAfter()
	if n := callWithin(t, db, step, 1000); n != 1000 || mintLeft(t, db) != "01/6/500 01/6/505" {
		t.Fatalf("first call returned %d, %d rows left", n, count(t, db, "SELECT count(*) FROM mint"))
	}
	if n := callWithin(t, db, step, 1000); n != 2 || mintLeft(t, db) != "" {
		t.Fatalf("second call returned %d, rows left %q", n, mintLeft(t, db))
	}
}

// T-S-34: with a limit below a full chunk, a unit that does not fit stays. The
// call deletes no row and returns its limit.
func TestTS34MintUnitThatDoesNotFitStaysInASmallChunk(t *testing.T) {
	db := migrated(t)
	addMintRows(t, db, 1, 5, 999)
	if n := callWithin(t, db, mintStepAfter(), 998); n != 998 || count(t, db, "SELECT count(*) FROM mint") != 999 {
		t.Fatalf("returned %d, %d rows left; want 998 and 999", n, count(t, db, "SELECT count(*) FROM mint"))
	}
}

// T-S-34: a unit with more rows than one chunk is the only unit that splits. A
// full chunk deletes 1 000 rows in the order of the primary key, then 1 row.
func TestTS34MintUnitOfMoreThanAChunkSplits(t *testing.T) {
	db := migrated(t)
	addMintRows(t, db, 1, 5, 1001)
	step := mintStepAfter()
	if n := callWithin(t, db, step, 1000); n != 1000 || count(t, db, "SELECT count(*) FROM mint") != 1 ||
		mintLeft(t, db) != "01/5/1000" {
		t.Fatalf("first call returned %d, %d rows left", n, count(t, db, "SELECT count(*) FROM mint"))
	}
	if n := callWithin(t, db, step, 1000); n != 1 || mintLeft(t, db) != "" {
		t.Fatalf("second call returned %d, rows left %q", n, mintLeft(t, db))
	}
}

// T-S-34: the oldest unit goes first. With a limit of 1, unit 5 goes and unit 6
// stays.
func TestTS34MintOldestUnitGoesFirst(t *testing.T) {
	db := migrated(t)
	addMintRow(t, db, 1, 6, 6, 0)
	addMintRow(t, db, 1, 5, 5, 0)
	if n := callWithin(t, db, mintStepAfter(), 1); n != 1 || mintLeft(t, db) != "01/6/6" {
		t.Fatalf("returned %d, rows left %q", n, mintLeft(t, db))
	}
}

// T-S-34: a cutoff before the token epoch deletes nothing. The unit is modulo
// 2^20, so such a cutoff can read as a cutoff ahead. With the real time, the
// old row goes and the young rows stay.
func TestTS34MintCutoffBeforeTheEpochDeletesNothing(t *testing.T) {
	now := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		name string
		tDel time.Time
		left int
	}{
		{"2015", time.Date(2015, 2, 10, 0, 0, 0, 0, time.UTC), 3},
		{"1970", time.Unix(0, 0), 3},
		{"now", now, 2},
	} {
		t.Run(c.name, func(t *testing.T) {
			db := migrated(t)
			for i, age := range []time.Duration{24 * time.Hour, 2 * time.Hour, 31 * 24 * time.Hour} {
				addMintRow(t, db, 1, int64(token.Unit(now.Add(-age))), int64(i), 0)
			}
			callWithin(t, db, newMintStep(c.tDel, 30), chunkRows)
			if n := count(t, db, "SELECT count(*) FROM mint"); n != c.left {
				t.Fatalf("%d rows left, want %d", n, c.left)
			}
		})
	}
}

// T-U-11: ids that are not in ts order. Each row has a higher id and a lower
// ts than the row before. The first call clears the 1 000 rows with the lowest
// ts. The second call clears the rest.
func TestTU11FieldClearTakesRowsInTSOrder(t *testing.T) {
	db := migrated(t)
	addFull(t, db, "request", 1500, 2000, -1)
	step := newFieldClearStep(rollTDel, rollWall, 30)
	if n := callWithin(t, db, step, 1000); n != 1000 ||
		count(t, db, "SELECT count(*) FROM event WHERE "+rawCleared+" AND ts <= 1500") != 1000 ||
		count(t, db, "SELECT count(*) FROM event WHERE "+rawCleared) != 1000 {
		t.Fatalf("first call returned %d, %d rows cleared", n, count(t, db, "SELECT count(*) FROM event WHERE "+rawCleared))
	}
	if n := callWithin(t, db, step, 1000); n != 500 || count(t, db, "SELECT count(*) FROM event WHERE "+rawFull) != 0 {
		t.Fatalf("second call returned %d, %d rows keep a value", n, count(t, db, "SELECT count(*) FROM event WHERE "+rawFull))
	}
}
