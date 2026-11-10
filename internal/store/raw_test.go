package store

import (
	"context"
	"database/sql"
	"fmt"
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

// T-U-11: a row with ts in [mark, cutoff) has the three fields NULL, also a
// callback row with a record. A row before the mark, at the cutoff or after it
// keeps them. The step then writes the cutoff as the mark. A second run reads
// no row before the mark: a value that a test writes there again stays. A
// later cutoff takes the rows from the old cutoff on.
func TestTU11FieldClearWindowAndMark(t *testing.T) {
	r, chunks := rollRig(t, newFieldClearStep(rollTDel, 30))
	cut := rollCutoff(30)
	mustExec(t, r.db, metaSetSQL, rawDoneKey, strconv.FormatInt(cut-10_000, 10))
	for _, k := range []string{"callback", "request"} {
		for _, d := range []int64{-10_001, -10_000, -1, 0, 1000} {
			addFull(t, r.db, k, 1, cut+d, 0)
		}
	}
	runOK(t, r)
	q := "SELECT group_concat(kind || ':' || (ts - " + strconv.FormatInt(cut, 10) + "), ' ') FROM (SELECT * FROM event WHERE " + rawCleared + " ORDER BY kind, ts)"
	if got, want := rawText(t, r.db, q), "callback:-10000 callback:-1 request:-10000 request:-1"; got != want || fmt.Sprint(*chunks) != "[5]" {
		t.Fatalf("cleared rows %q, chunks %v; want %q and [5]", got, *chunks, want)
	}
	if got := metaValue(t, r.db, rawDoneKey); got != strconv.FormatInt(cut, 10) {
		t.Fatalf("mark %s, want %d", got, cut)
	}
	mustExec(t, r.db, "UPDATE event SET body_prefix = x'62' WHERE ts = ?", cut-1)
	runAgain(t, r, newFieldClearStep(rollTDel, 30))
	if n := count(t, r.db, "SELECT count(*) FROM event WHERE ts = "+strconv.FormatInt(cut-1, 10)+" AND body_prefix IS NOT NULL"); n != 2 {
		t.Fatalf("%d rows before the mark keep the new value, want 2", n)
	}
	runAgain(t, r, newFieldClearStep(rollTDel.Add(time.Hour), 30))
	if n := count(t, r.db, "SELECT count(*) FROM event WHERE "+rawFull); n != 4 {
		t.Fatalf("%d rows with a value after the run with a later cutoff, want the 4 rows before the old cutoff", n)
	}
	if got, want := metaValue(t, r.db, rawDoneKey), strconv.FormatInt(cut+3_600_000, 10); got != want {
		t.Fatalf("mark %s, want %s", got, want)
	}
}

// T-U-11: with no mark, the first run takes the oldest row. More rows with one
// ts than one chunk are all cleared. The chunks read each row one time. They
// change 1 000, 1 000 and 502 rows, and the mark costs 1.
func TestTU11FieldClearManyRowsWithOneTS(t *testing.T) {
	r, chunks := rollRig(t, newFieldClearStep(rollTDel, 30))
	cut := rollCutoff(30)
	addFull(t, r.db, "request", 2500, 5, 0)
	for _, ts := range []int64{0, cut - 1, cut} {
		addFull(t, r.db, "request", 1, ts, 0)
	}
	runOK(t, r)
	if n := count(t, r.db, "SELECT count(*) FROM event WHERE "+rawFull); n != 1 || fmt.Sprint(*chunks) != "[1000 1000 503]" {
		t.Fatalf("%d rows keep a value, chunks %v; want 1 and [1000 1000 503]", n, *chunks)
	}
}

// T-U-11: a run that ends early writes no mark. The next run starts at the old
// mark and clears the rest.
func TestTU11FieldClearEarlyEndWritesNoMark(t *testing.T) {
	r, _ := rollRig(t, newFieldClearStep(rollTDel, 30))
	addFull(t, r.db, "request", 2500, 5, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.w.beforeCommit = func(*sql.Tx) error { cancel(); return nil }
	rq := retentionRequest{reply: make(chan error, 1), gone: ctx.Done()}
	r.w.serveRetention(ctx, r.tick, nil, rq)
	if err := <-rq.reply; err == nil {
		t.Fatal("the run ended with no error")
	}
	if n, marks := count(t, r.db, "SELECT count(*) FROM event WHERE "+rawCleared), count(t, r.db, "SELECT count(*) FROM meta WHERE key = '"+rawDoneKey+"'"); n != chunkRows || marks != 0 {
		t.Fatalf("%d rows cleared, %d marks; want %d and 0", n, marks, chunkRows)
	}
	r.w.beforeCommit = nil
	runAgain(t, r, newFieldClearStep(rollTDel, 30))
	if n := count(t, r.db, "SELECT count(*) FROM event WHERE "+rawFull); n != 0 {
		t.Fatalf("%d rows keep a value after the next run", n)
	}
}

// T-U-11: a cutoff at or before the mark reads no row and writes no mark. A
// trigger refuses each write of meta.
func TestTU11FieldClearCutoffNotAfterTheMarkChangesNothing(t *testing.T) {
	for _, after := range []int64{0, 5000} {
		r, _ := rollRig(t, newFieldClearStep(rollTDel, 30))
		mark := strconv.FormatInt(rollCutoff(30)+after, 10)
		mustExec(t, r.db, metaSetSQL, rawDoneKey, mark)
		mustExec(t, r.db, "CREATE TRIGGER no_mark BEFORE INSERT ON meta BEGIN SELECT RAISE(ABORT, 'mark written'); END")
		addFull(t, r.db, "callback", 1, rollCutoff(30)-1000, 0)
		runOK(t, r)
		if n := count(t, r.db, "SELECT count(*) FROM event WHERE "+rawFull); n != 1 || metaValue(t, r.db, rawDoneKey) != mark {
			t.Fatalf("mark after %d: %d rows with a value, mark %s; want 1 and %s", after, n, metaValue(t, r.db, rawDoneKey), mark)
		}
	}
}

// T-U-11: the statement of the step uses event_ts with both bounds of ts. Thus
// a run reads only the rows of its window.
func TestTU11FieldClearUsesEventTSWithBothBounds(t *testing.T) {
	plan := strings.Join(queryPlan(t, migrated(t), clearRawSQL, 1, 2, 1, 0, 1000), "\n")
	if !strings.Contains(plan, "event_ts (ts>? AND ts<?)") || strings.Contains(plan, "SCAN event") {
		t.Fatalf("plan:\n%s", plan)
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
		name string
		t    time.Time
		days int
	}{{"0 days", rollTDel, 0}, {"31 days", rollTDel, 31}, {"zero time", time.Time{}, 30}} {
		for i, mk := range []func(time.Time, int) retentionStep{newFieldClearStep, newRawDeleteStep, newMintStep} {
			t.Run(fmt.Sprint(c.name, " step ", i), func(t *testing.T) {
				r, chunks := rollRig(t, mk(c.t, c.days))
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

// T-U-11: a mark that does not parse counts as no mark. The window starts at
// the oldest row, and the step writes the cutoff as the mark.
func TestTU11FieldClearUnparsableMarkTakesAllRows(t *testing.T) {
	r, _ := rollRig(t, newFieldClearStep(rollTDel, 30))
	mustExec(t, r.db, metaSetSQL, rawDoneKey, "x")
	addFull(t, r.db, "callback", 1, -5, 0) // before a mark that parses as 0
	runOK(t, r)
	if n := count(t, r.db, "SELECT count(*) FROM event WHERE "+rawFull); n != 0 {
		t.Fatalf("%d rows keep a value", n)
	}
	if got, want := metaValue(t, r.db, rawDoneKey), strconv.FormatInt(rollCutoff(30), 10); got != want {
		t.Fatalf("mark %s, want %s", got, want)
	}
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
	}{{mintNextSQL, []any{""}}, {mintDeleteSQL, []any{[]byte{1}, 0, 5, 1000}}} {
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
	r.launchCancelable(context.Background())
	ctx, cancel := context.WithTimeout(context.Background(), waitFor)
	defer cancel()
	if err := r.w.runSteps(ctx, runSteps(tDel, tDel, tPriv, 7, 30)); err != nil {
		t.Fatal(err)
	}
	q := "SELECT group_concat(kind || ':' || (ts - " + strconv.FormatInt(cut, 10) + ") || ':' || (" + rawCleared + "), ' ') FROM (SELECT * FROM event ORDER BY kind)"
	if got, want := rawText(t, r.db, q), fmt.Sprintf("beacon:%d:1 refused:%d:1", rawDay, rawDay); got != want {
		t.Fatalf("rows left %q, want %q", got, want)
	}
	if got, want := mintLeft(t, r.db), fmt.Sprintf("01/%d/2", youngUnit); got != want {
		t.Fatalf("mint rows left %q, want %q", got, want)
	}
}
