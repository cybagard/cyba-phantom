package store

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cybagard/cyba-phantom/internal/event"
	"github.com/cybagard/cyba-phantom/internal/sensortime"
)

// otherWall is a wall clock that is 40 days after S of a rig at boot clock 0.
// A writer that takes its times from S never shows it.
func otherWall() time.Time { return time.UnixMilli(wall0).Add(40 * 24 * time.Hour) }

// T-U-30: the batch date, the day key, the checkpoint time and the time of the
// retention event are of S. The test hook of the wall clock gives another date.
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
	if err := r.w.endRun(&retentionRun{}, nil); err != nil {
		t.Fatal(err)
	}
	if got := count(t, r.db, fmt.Sprintf("SELECT count(*) FROM event WHERE kind = 'retention' AND ts = %d", wall0)); got != 1 {
		t.Errorf("%d retention events with the time of S, want 1", got)
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

	// The key takes the rowids that the writer gave, not the stored rows only.
	if err := r.w.writeSnapshot(); err != nil {
		t.Fatal(err)
	}
	mustExec(t, r.db, "DELETE FROM event")
	mustExec(t, r.db, "DELETE FROM session")
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
	c := &sched{r: newRig(t, 8), f: &fakeSrc{}}
	c.f.skew.Store(start.UnixMilli() - wall0)
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

// T-U-30: with the stop marker, StartClock returns ErrStopMarker. The caller
// tests for it with errors.Is. The writer has no clock, and the stored key
// stays as it is.
func TestTU30StartClockWithStopMarkerReturnsTheSentinel(t *testing.T) {
	r, f := clockRig(t)
	if err := r.w.writeSnapshot(); err != nil {
		t.Fatal(err)
	}
	key := metaValue(t, r.db, sensorTimeKey)
	if err := makeMarker(r.root); err != nil {
		t.Fatal(err)
	}
	w := NewWriter(r.db, r.q, false, nil, r.w.rec)
	if err := w.StartClock(f.source()); !errors.Is(err, ErrStopMarker) || w.clk != nil {
		t.Fatalf("error %v, clock %v, want ErrStopMarker and no clock", err, w.clk)
	}
	if got := metaValue(t, r.db, sensorTimeKey); got != key {
		t.Fatalf("key %q after the refusal, want %q", got, key)
	}
}
