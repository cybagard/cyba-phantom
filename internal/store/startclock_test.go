package store

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cybagard/cyba-phantom/internal/event"
	"github.com/cybagard/cyba-phantom/internal/sensortime"
	"github.com/cybagard/cyba-phantom/internal/token"
)

// otherWall is a wall clock that is 40 days after S of a rig at boot clock 0.
// A writer that takes its times from S never shows it.
func otherWall() time.Time { return time.UnixMilli(wall0).Add(40 * 24 * time.Hour) }

// T-U-30: the batch date, the day key and the checkpoint time are of S. The
// test hook of the wall clock gives another date.
func TestTU30StoredTimesAreOfS(t *testing.T) {
	r, _ := clockRig(t)
	r.w.clock = otherWall
	s := time.UnixMilli(wall0)
	const ip = "198.51.100.23"
	key := r.w.dk.At(s)
	r.c.DropNoAddr()
	if got := r.refusedIDs(r.w, "", ip)[0]; got != *key.SessionID(ip, "") {
		t.Errorf("session id %q is not of the key of S", got)
	}
	if rows := r.counterRows(); len(rows) != 1 || rows[0].day != "2026-06-01" {
		t.Errorf("ip_counter rows %+v, want one row of 2026-06-01", rows)
	}
	if err := r.w.storeRow(rowRequest{size: 1, msg: []byte("note")}); err != nil {
		t.Fatal(err)
	}
	if got := count(t, r.db, fmt.Sprintf("SELECT count(*) FROM checkpoint WHERE created_at = %d", wall0)); got != 1 {
		t.Errorf("%d checkpoint rows with the time of S, want 1", got)
	}
}

// failingSrc is the source of f. Its boot clock fails while fail is true.
func failingSrc(f *fakeSrc, fail *atomic.Bool) sensortime.Source {
	src := f.source()
	boot := src.BootClock
	src.BootClock = func() (time.Duration, error) {
		if fail.Load() {
			return 0, errors.New("boot clock")
		}
		return boot()
	}
	return src
}

// T-U-30: a clock error in a batch stops the writer. A clock error in the
// schedule starts no run.
func TestTU30ClockErrorStopsTheWriterAndStartsNoRun(t *testing.T) {
	r, f, fail := newRig(t, 8), &fakeSrc{}, &atomic.Bool{}
	if err := r.w.StartClock(failingSrc(f, fail)); err != nil {
		t.Fatal(err)
	}
	s := NewSchedule(r.w, 7, 30, 90, nil)
	runs := 0
	s.run = func(context.Context, []retentionStep) error { runs++; return nil }
	fail.Store(true)
	s.begin(context.Background())
	s.check(context.Background())
	if runs != 0 {
		t.Errorf("%d runs after a clock error, want 0", runs)
	}
	r.w.flush([]*event.Event{rowEvent(t, event.KindRequest, false, 1)})
	if r.w.Healthy() || ruleOf(r.w.Err()) != ruleClock {
		t.Errorf("healthy %v, error %v, want a stop with the clock rule", r.w.Healthy(), r.w.Err())
	}
}

// ids gives the rowids of a query as text, in order.
func ids(t *testing.T, r *rig, table string) string {
	t.Helper()
	return rawText(t, r.db, "SELECT group_concat(rowid) FROM (SELECT rowid FROM "+table+" ORDER BY rowid)")
}

// batch writes one request event for each session id.
func (r *rig) batch(w *Writer, sessions ...string) {
	r.t.Helper()
	var evs []*event.Event
	for _, id := range sessions {
		evs = append(evs, sessEvent(r.t, event.KindRequest, id, "198.51.100.1", "", 1000))
	}
	if err := w.write(evs); err != nil {
		r.t.Fatal(err)
	}
}

// T-U-30: delete every event and session row. New rows then get rowids above
// every clock_jump range and above the floor. This holds after a restart that
// reads the key. A stored rowid above the floor wins.
func TestTU30NewRowsGetRowidsAboveTheRangesAndTheFloor(t *testing.T) {
	r, f := rangeRig(t)
	stop := r.start()
	graceJump(t, r, f) // the clock_jump row has events 4 to 6 and session 1
	stop()
	mustExec(t, r.db, "DELETE FROM event")
	mustExec(t, r.db, "DELETE FROM session")
	r.batch(r.w, "a", "b")
	if got, want := ids(t, r, "event")+" "+ids(t, r, "session"), "7,8 2,3"; got != want {
		t.Fatalf("rowids %q after the delete, want %q", got, want)
	}

	// No row stays, so the floor of the key comes from the values in memory.
	mustExec(t, r.db, "DELETE FROM event")
	mustExec(t, r.db, "DELETE FROM session")
	if err := r.w.writeSnapshot(); err != nil {
		t.Fatal(err)
	}
	f.at(time.Hour)
	w2 := NewWriter(r.db, r.q, false, nil, r.w.rec)
	if err := w2.StartClock(f.source()); err != nil {
		t.Fatal(err)
	}
	r.batch(w2, "c", "d")
	if got, want := ids(t, r, "event")+" "+ids(t, r, "session"), "9,10 4,5"; got != want {
		t.Fatalf("rowids %q after the restart, want %q", got, want)
	}

	// A stored rowid above the floor wins over the floor.
	mustExec(t, r.db, "INSERT INTO event (id, ts, kind) VALUES (1000, 1, 'request')")
	mustExec(t, r.db, "INSERT INTO session (rowid, id, first_seen, last_seen, ip_hmac, band) VALUES (500, 'x', 1, 1, 'h', 'human')")
	r.batch(w2, "e")
	if got, want := ids(t, r, "event")+" "+ids(t, r, "session"), "9,10,1000,1001 4,5,500,501"; got != want {
		t.Fatalf("rowids %q above a stored rowid, want %q", got, want)
	}
}

// sched is a schedule on a writer with a clock. S starts at start. Each run
// records the local time of S, S itself and the raw cutoff.
type sched struct {
	r    *rig
	s    *Schedule
	f    *fakeSrc
	runs []string
	raw  []int64
	at   []int64 // S of each run, in unix ms
}

func sSchedule(t *testing.T, start time.Time, loc *time.Location) *sched {
	t.Helper()
	return sScheduleAt(t, start, loc, 0)
}

// sScheduleAt is sSchedule with the boot clock of the start at boot.
func sScheduleAt(t *testing.T, start time.Time, loc *time.Location, boot time.Duration) *sched {
	t.Helper()
	c := &sched{r: newRig(t, 8), f: &fakeSrc{}}
	c.f.at(boot)
	c.f.skew.Store(start.UnixMilli() - wall0 - boot.Milliseconds())
	if err := c.r.w.StartClock(c.f.source()); err != nil {
		t.Fatal(err)
	}
	c.s = NewSchedule(c.r.w, 7, 30, 90, nil)
	c.s.loc = loc
	c.s.run = func(ctx context.Context, _ []retentionStep) error {
		c.runs = append(c.runs, c.local(loc).Format("01-02 15:04 -0700"))
		c.raw = append(c.raw, ctx.Value(runKey{}).(*retentionRun).counts.CutoffRaw)
		c.at = append(c.at, c.now().UnixMilli())
		return nil
	}
	return c
}

// now gives S.
func (c *sched) now() time.Time {
	ms, err := c.r.w.clk.Now()
	if err != nil {
		panic(err)
	}
	return time.UnixMilli(ms)
}

func (c *sched) local(loc *time.Location) time.Time { return c.now().In(loc) }

// minutes moves the boot clock by one minute and checks, n times.
func (c *sched) minutes(n int) {
	for range n {
		c.f.at(time.Duration(c.f.boot.Load()) + time.Minute)
		c.s.check(context.Background())
	}
}

// T-U-27: on S, each local date has one run. The DST gap of 2026-09-27 has no
// 03:15, so the run is at 03:45. The DST repeat of 2026-04-05 has 03:15 two
// times, and the date has one run.
func TestTU27SOneRunForEachLocalDateAtDST(t *testing.T) {
	loc := chatham(t)
	for _, c := range []struct {
		day  time.Time
		want string
	}{{time.Date(2026, 9, 27, 0, 0, 0, 0, loc), "09-27 03:45 +1345"},
		{time.Date(2026, 4, 5, 0, 0, 0, 0, loc), "04-05 03:15 +1345"}} {
		t.Run(c.day.Format(time.DateOnly), func(t *testing.T) {
			k := sSchedule(t, c.day, loc)
			setMark(t, k.r.db, c.day.Add(-time.Hour))
			k.s.begin(context.Background())
			for k.now().Before(c.day.AddDate(0, 0, 1)) {
				k.minutes(1)
			}
			if fmt.Sprint(k.runs) != fmt.Sprint([]string{c.want}) {
				t.Fatalf("runs %v, want [%s]", k.runs, c.want)
			}
		})
	}
}

// T-U-27: a start after 30 h with no run runs at once. So does a start with a
// mark after S. A start after 24 h runs nothing.
func TestTU27SStartRunsAtOnce(t *testing.T) {
	start := time.Date(2027, 2, 10, 12, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		name string
		mark time.Time
		runs int
	}{{"30h down", start.Add(-30 * time.Hour), 1}, {"mark after S", start.Add(40 * 24 * time.Hour), 1},
		{"mark 1 s after S", start.Add(time.Second), 1}, {"24h down", start.Add(-24 * time.Hour), 0}} {
		t.Run(c.name, func(t *testing.T) {
			k := sSchedule(t, start, time.UTC)
			setMark(t, k.r.db, c.mark)
			k.s.begin(context.Background())
			if len(k.runs) != c.runs {
				t.Fatalf("%d runs at the start, want %d", len(k.runs), c.runs)
			}
		})
	}
}

// T-U-27: 25 h of boot clock with no run give a run. The day rule gives none
// here, so only the boot clock rule can start it. The Go monotonic clock does
// not move in this test.
func TestTU27SBootClockOf25HoursGivesARun(t *testing.T) {
	k := sSchedule(t, time.Date(2027, 2, 10, 12, 0, 0, 0, time.UTC), time.UTC)
	setMark(t, k.r.db, k.now().Add(-time.Hour))
	k.s.begin(context.Background())
	k.s.lastDay = "9999-12-31"
	k.f.at(25*time.Hour - time.Minute)
	k.s.check(context.Background())
	if len(k.runs) != 0 {
		t.Fatalf("%d runs before 25 h, want 0", len(k.runs))
	}
	k.f.at(25 * time.Hour)
	k.s.check(context.Background())
	if len(k.runs) != 1 {
		t.Fatalf("%d runs after 25 h, want 1", len(k.runs))
	}
}

// T-U-27: a wall clock step of 40 days, forward or back, moves no cutoff. It
// starts no extra run. The next date gives one run. Its cutoff is of S.
func TestTU27SWallStepMovesNoCutoffAndStartsNoRun(t *testing.T) {
	for _, step := range []time.Duration{40 * 24 * time.Hour, -40 * 24 * time.Hour} {
		t.Run(step.String(), func(t *testing.T) {
			k := sSchedule(t, time.Date(2027, 2, 10, 12, 0, 0, 0, time.UTC), time.UTC)
			setMark(t, k.r.db, k.now().Add(-time.Hour))
			k.s.begin(context.Background())
			k.f.skew.Add(step.Milliseconds())
			k.minutes(10)
			if len(k.runs) != 0 {
				t.Fatalf("%d runs after the step, want 0", len(k.runs))
			}
			k.minutes(24 * 60)
			if len(k.runs) != 1 || k.raw[0] != k.at[0]-30*24*time.Hour.Milliseconds() {
				t.Fatalf("runs %v, cutoffs %v, S %v: want one run with the cutoff of S", k.runs, k.raw, k.at)
			}
		})
	}
}

// T-U-27: each run that ends writes retention_last as the S of its start. This
// holds when the old value is after S. A start with a mark 40 d after S runs
// once. The next start does not run at once.
func TestTU27SMarkIsTheSOfTheRunStart(t *testing.T) {
	start := time.Date(2027, 2, 10, 12, 0, 0, 0, time.UTC)
	k := sSchedule(t, start, time.UTC)
	setMark(t, k.r.db, start.Add(40*24*time.Hour))
	k.s.run = direct(k.r)
	k.s.begin(context.Background())
	if got, want := metaValue(t, k.r.db, retentionLastKey), fmt.Sprint(start.UnixMilli()); got != want {
		t.Fatalf("retention_last %s, want %s", got, want)
	}
	k.f.at(time.Minute)
	next := NewSchedule(k.r.w, 7, 30, 90, nil)
	runs := 0
	next.run = func(context.Context, []retentionStep) error { runs++; return nil }
	next.begin(context.Background())
	if runs != 0 {
		t.Fatalf("%d runs at the next start, want 0", runs)
	}
}

// T-U-27: on S, 10 days with a wall clock step back at each 03:14 change no
// run. Each step is 23 h 58 min. Each date has one run, at 03:15. The first run
// clears the address of 16 d.
func TestTU27SStepBackAt0314For10Days(t *testing.T) {
	start := time.Date(2027, 2, 10, 3, 13, 0, 0, time.UTC)
	k := sSchedule(t, start, time.UTC)
	setMark(t, k.r.db, start.Add(-time.Hour))
	addSessions(t, k.r.db, "old", 0, 1, start.Add(-16*oneDay).UnixMilli(), 0, "203.0.113.7")
	record, real := k.s.run, serveWithRun(k.r)
	k.s.run = func(ctx context.Context, steps []retentionStep) error {
		_ = record(ctx, steps)
		return real(ctx, steps)
	}
	k.s.begin(context.Background())
	for end := start.AddDate(0, 0, 10); k.now().Before(end); {
		k.minutes(1)
		if k.local(time.UTC).Format("15:04") == "03:14" {
			k.f.skew.Add(-(oneDay - 2*time.Minute).Milliseconds())
		}
	}
	var want []string
	for d := 10; d < 20; d++ {
		want = append(want, fmt.Sprintf("02-%02d 03:15 +0000", d))
	}
	if fmt.Sprint(k.runs) != fmt.Sprint(want) {
		t.Fatalf("runs %v, want %v", k.runs, want)
	}
	if got := nullIPs(t, k.r.db); !got["old0"] {
		t.Fatalf("the address of 16 d is not NULL: %v", got)
	}
}

// T-U-27: a real run of a writer with a clock takes each cutoff from S. The
// wall hook of the writer is 40 d ahead of S, or 40 d behind. Each step has a
// row on each side of its cutoff of S. The rows that stay are those of S.
func TestTU27SRealStepsTakeEachCutoffFromS(t *testing.T) {
	start := time.Date(2027, 2, 10, 12, 0, 0, 0, time.UTC)
	ago := func(d time.Duration) int64 { return start.Add(-d).UnixMilli() }
	ages := "SELECT coalesce(group_concat(((" + strconv.FormatInt(start.UnixMilli(), 10) +
		" - ts) / 86400000) || 'd', ' '), '') FROM (SELECT ts FROM event WHERE kind = '%s' %s ORDER BY ts)"
	for _, off := range []time.Duration{40 * oneDay, -40 * oneDay} {
		t.Run(off.String(), func(t *testing.T) {
			k := sSchedule(t, start, time.UTC)
			k.r.w.clock = func() time.Time { return start.Add(off) }
			k.r.app.next = 10_000 // above the leaf indexes of the seed
			addSessions(t, k.r.db, "s", 3, 1, ago(3*oneDay), 0, "203.0.113.7")
			addSessions(t, k.r.db, "s", 8, 1, ago(8*oneDay), 0, "203.0.113.8")
			for _, d := range []time.Duration{25 * oneDay, 35 * oneDay} {
				addEvents(t, k.r.db, "refused", 1, ago(d), 0, nil, nil)
			}
			for _, d := range []time.Duration{35 * oneDay, 25 * oneDay, oneDay, -2 * oneDay} {
				addFull(t, k.r.db, "callback", 1, ago(d), 0)
			}
			k.s.run = serveWithRun(k.r)
			k.s.runOnce(context.Background())
			if got, want := fmt.Sprint(nullIPs(t, k.r.db)), "map[s3:false s8:true]"; got != want {
				t.Errorf("addresses %s, want %s", got, want)
			}
			if got, want := rawText(t, k.r.db, fmt.Sprintf(ages, "refused", "")), "25d"; got != want {
				t.Errorf("refused rows %q, want %q", got, want)
			}
			if got, want := rawText(t, k.r.db, fmt.Sprintf(ages, "callback", "AND "+rawFull)), "25d 1d"; got != want {
				t.Errorf("callback rows with a field %q, want %q", got, want)
			}
		})
	}
}

// T-U-27: the cap step takes S as its time. S is at unit 500 000. For the wall
// hook, 40 d behind S, and for the time 0, the wrap point of the unit order is
// between the two mint units. With S, the first unit is older and goes. With
// one of those times, the second unit goes.
func TestTU27SCapStepOrdersMintUnitsByS(t *testing.T) {
	start := token.Epoch().Add(500_000 * 10 * time.Minute)
	k := sSchedule(t, start, time.UTC)
	k.r.w.clock = func() time.Time { return start.Add(-40 * oneDay) }
	first := start.Add(-30 * oneDay)
	addMint(t, k.r.db, "01", first.UnixMilli(), 1)
	addMint(t, k.r.db, "01", first.Add((1<<19)*mintUnitMs*time.Millisecond).UnixMilli(), 2)
	check(t, k.s.SetMaxBytes(1, "events.db"))
	k.s.tune = func(c *capRun) {
		c.begun, c.over = true, true
		c.measure = func(ctx context.Context, tx *sql.Tx) (int64, error) {
			var rows int64
			err := tx.QueryRowContext(ctx, "SELECT count(*) FROM mint").Scan(&rows)
			if rows > 1 {
				return 1 << 40, err
			}
			return 0, err
		}
	}
	k.s.run = serveWithRun(k.r)
	k.s.runOnce(context.Background())
	if got := rawText(t, k.r.db, "SELECT coalesce(group_concat(first), '') FROM mint"); got != "2" {
		t.Fatalf("mint rows left %q, want the second unit only", got)
	}
}

// T-U-27: a failed read of retention_last gives no mark, so the start runs at
// once. A mark of 1 h that the read gets gives no run.
func TestTU27SFailedMarkReadRunsAtOnce(t *testing.T) {
	start := time.Date(2027, 2, 10, 12, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		name string
		read time.Duration
		runs int
	}{{"read fails", time.Nanosecond, 1}, {"read works", readLimit, 0}} {
		t.Run(c.name, func(t *testing.T) {
			k := sSchedule(t, start, time.UTC)
			setMark(t, k.r.db, start.Add(-time.Hour))
			k.s.readTime = c.read
			k.s.begin(context.Background())
			if len(k.runs) != c.runs {
				t.Fatalf("%d runs at the start, want %d", len(k.runs), c.runs)
			}
		})
	}
}

// T-U-30: a stored rowid near math.MaxInt64 gives the fixed error, not a wrap.
// The batch stores no row and the writer stops.
func TestTU30RowidAtTheLimitStopsTheWriter(t *testing.T) {
	const (
		evBelow  = "INSERT INTO event (id, ts, kind) VALUES (9223372036854775806, 1, 'request')"
		evAt     = "INSERT INTO event (id, ts, kind) VALUES (9223372036854775807, 1, 'request')"
		sesBelow = "INSERT INTO session (rowid, id, first_seen, last_seen, ip_hmac, band) VALUES (9223372036854775806, 'x', 1, 1, 'h', 'human')"
		sesAt    = "INSERT INTO session (rowid, id, first_seen, last_seen, ip_hmac, band) VALUES (9223372036854775807, 'x', 1, 1, 'h', 'human')"
	)
	for _, c := range []struct{ name, insert string }{
		{"event below the limit", evBelow}, {"event at the limit", evAt},
		{"session below the limit", sesBelow}, {"session at the limit", sesAt}} {
		t.Run(c.name, func(t *testing.T) {
			r, _ := clockRig(t)
			mustExec(t, r.db, c.insert)
			var evs []*event.Event
			for _, id := range []string{"a", "b", "c"} {
				evs = append(evs, sessEvent(t, event.KindRequest, id, "198.51.100.1", "", 1000))
			}
			r.w.flush(evs)
			if ruleOf(r.w.Err()) != ruleStoredClock || r.w.Healthy() {
				t.Errorf("error %v, healthy %v, want a stop with the stored clock rule", r.w.Err(), r.w.Healthy())
			}
			if n := count(t, r.db, "SELECT (SELECT count(*) FROM event) + (SELECT count(*) FROM session)"); n != 1 {
				t.Errorf("%d rows, want only the stored row", n)
			}
		})
	}
}

// T-U-30: the top rows go and the writer writes no key. The next rows get
// rowids above the values that the writer gave. A key write between does not
// change this.
func TestTU30NewRowsAreAboveTheValuesThatTheWriterGave(t *testing.T) {
	t.Run("no key write", func(t *testing.T) {
		r, _ := clockRig(t)
		r.batch(r.w, "a", "b", "c")
		mustExec(t, r.db, "DELETE FROM event")
		mustExec(t, r.db, "DELETE FROM session")
		r.batch(r.w, "d")
		if got, want := ids(t, r, "event")+" "+ids(t, r, "session"), "4 4"; got != want {
			t.Fatalf("rowids %q, want %q", got, want)
		}
	})
	t.Run("key write", func(t *testing.T) {
		r, _ := clockRig(t)
		r.batch(r.w, "a", "b", "c")
		mustExec(t, r.db, "DELETE FROM event WHERE id > 1")
		mustExec(t, r.db, "DELETE FROM session WHERE rowid > 1")
		if err := r.w.writeSnapshot(); err != nil {
			t.Fatal(err)
		}
		r.batch(r.w, "d")
		if got, want := ids(t, r, "event")+" "+ids(t, r, "session"), "1,4 1,4"; got != want {
			t.Fatalf("rowids %q, want %q", got, want)
		}
	})
}

// T-U-27: the boot clock rule of 25 h counts from the boot clock of the start,
// not from 0. A start at a high boot clock gives no run before 25 h.
func TestTU27SBootClockRuleCountsFromTheStart(t *testing.T) {
	start := time.Date(2027, 2, 10, 12, 0, 0, 0, time.UTC)
	for _, boot := range []time.Duration{10 * time.Hour, 100 * time.Hour} {
		t.Run(boot.String(), func(t *testing.T) {
			k := sScheduleAt(t, start, time.UTC, boot)
			setMark(t, k.r.db, start.Add(-time.Hour))
			k.s.begin(context.Background())
			k.s.lastDay = "9999-12-31"
			k.f.at(boot + 24*time.Hour)
			k.s.check(context.Background())
			if len(k.runs) != 0 {
				t.Fatalf("%d runs 24 h after the start, want 0", len(k.runs))
			}
			k.f.at(boot + 25*time.Hour)
			k.s.check(context.Background())
			if len(k.runs) != 1 {
				t.Fatalf("%d runs 25 h after the start, want 1", len(k.runs))
			}
		})
	}
}

// T-U-30: a clock error, then a checkpoint row request. The reply is the clock
// error, the writer stops and it stores no checkpoint row.
func TestTU30CheckpointClockErrorStopsTheWriter(t *testing.T) {
	r, f, fail := newRig(t, 8), &fakeSrc{}, &atomic.Bool{}
	if err := r.w.StartClock(failingSrc(f, fail)); err != nil {
		t.Fatal(err)
	}
	fail.Store(true)
	rq := rowRequest{size: 1, msg: []byte("note"), reply: make(chan error, 1)}
	r.w.serveRow(rq)
	if err := <-rq.reply; ruleOf(err) != ruleClock || r.w.Healthy() {
		t.Fatalf("error %v, healthy %v, want a stop with the clock rule", err, r.w.Healthy())
	}
	if n := count(t, r.db, "SELECT count(*) FROM checkpoint"); n != 0 {
		t.Fatalf("%d checkpoint rows, want 0", n)
	}
}

// failAtSrc is the source of f. Its boot clock fails at call number failAt
// only. The calls count in n.
func failAtSrc(f *fakeSrc, n, failAt *atomic.Int64) sensortime.Source {
	src := f.source()
	boot := src.BootClock
	src.BootClock = func() (time.Duration, error) {
		if n.Add(1) == failAt.Load() {
			return 0, errors.New("boot clock")
		}
		return boot()
	}
	return src
}

// T-U-27: a run uses the S that the check read. A clock error at the read of
// begin or of check starts no run and loses no date. A read takes two boot
// clock calls: one in S and one for the boot clock. Each call can fail. The
// failure is off before the next check.
func TestTU27SClockErrorAtOneReadStartsNoRunAndLosesNoDate(t *testing.T) {
	start := time.Date(2027, 2, 10, 3, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		name  string
		mark  time.Duration // the age of the stored mark
		after int64         // the boot clock call that fails, from the read
		begin bool          // the failed read is the one of begin
	}{{"begin read", 30 * time.Hour, 1, true}, {"begin boot clock", 30 * time.Hour, 2, true},
		{"check read", time.Hour, 1, false}, {"check boot clock", time.Hour, 2, false},
		{"after the check read", time.Hour, 3, false}} {
		t.Run(c.name, func(t *testing.T) {
			r, f := newRig(t, 8), &fakeSrc{}
			n, failAt := &atomic.Int64{}, &atomic.Int64{}
			f.skew.Store(start.UnixMilli() - wall0)
			if err := r.w.StartClock(failAtSrc(f, n, failAt)); err != nil {
				t.Fatal(err)
			}
			s := NewSchedule(r.w, 7, 30, 90, nil)
			s.loc = time.UTC
			runs := 0
			s.run = func(context.Context, []retentionStep) error { runs++; return nil }
			setMark(t, r.db, start.Add(-c.mark))
			if c.begin {
				failAt.Store(n.Load() + c.after)
				s.begin(context.Background())
			} else {
				s.begin(context.Background())
				f.at(15 * time.Minute) // 03:15
				day, last := s.lastDay, s.lastRun
				failAt.Store(n.Load() + c.after)
				s.check(context.Background())
				if c.after < 3 && (s.lastDay != day || s.lastRun != last) {
					t.Errorf("last run day %q and boot clock %v after the failed read, want %q and %v",
						s.lastDay, s.lastRun, day, last)
				}
			}
			want := 0
			if c.after > 2 {
				want = 1 // the run does not read the clock again
			}
			if runs != want {
				t.Fatalf("%d runs at the failed read, want %d", runs, want)
			}
			failAt.Store(0)
			f.at(16 * time.Minute)
			s.check(context.Background())
			if runs != 1 {
				t.Fatalf("%d runs after the next good check, want 1", runs)
			}
		})
	}
}

// T-U-27: runOnce on a writer with a clock makes a run with S. S is the base of
// the cutoffs and the mark. A clock error gives no run.
func TestTU27SRunOnceReadsS(t *testing.T) {
	start := time.Date(2027, 2, 10, 12, 0, 0, 0, time.UTC)
	t.Run("good clock", func(t *testing.T) {
		k := sSchedule(t, start, time.UTC)
		k.s.runOnce(context.Background())
		if len(k.runs) != 1 || k.raw[0] != start.UnixMilli()-30*24*time.Hour.Milliseconds() {
			t.Fatalf("runs %v, cutoffs %v, want one run with the cutoff of S", k.runs, k.raw)
		}
	})
	t.Run("clock error", func(t *testing.T) {
		r, f, fail := newRig(t, 8), &fakeSrc{}, &atomic.Bool{}
		if err := r.w.StartClock(failingSrc(f, fail)); err != nil {
			t.Fatal(err)
		}
		s := NewSchedule(r.w, 7, 30, 90, nil)
		runs := 0
		s.run = func(context.Context, []retentionStep) error { runs++; return nil }
		fail.Store(true)
		s.runOnce(context.Background())
		if runs != 0 {
			t.Fatalf("%d runs after a clock error, want 0", runs)
		}
	})
}

// T-U-27: a clock error writes one fixed log line, also after two errors.
func TestTU27SClockErrorWritesOneLogLine(t *testing.T) {
	r, f, fail := newRig(t, 8), &fakeSrc{}, &atomic.Bool{}
	if err := r.w.StartClock(failingSrc(f, fail)); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	s := NewSchedule(r.w, 7, 30, 90, slog.New(slog.NewTextHandler(&buf, nil)))
	fail.Store(true)
	s.begin(context.Background())
	s.check(context.Background())
	if got := strings.Count(buf.String(), "retention cannot read the clock"); got != 1 {
		t.Fatalf("%d log lines after two errors, want 1: %q", got, buf.String())
	}
}
