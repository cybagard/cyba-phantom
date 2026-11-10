package store

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeClock is the wall clock and the monotonic clock of a schedule test.
// The monotonic time is the time since the anchor. A jump moves only the wall
// clock.
type fakeClock struct {
	mu          sync.Mutex
	anchor, now time.Time
	skew        time.Duration
}

func (f *fakeClock) wall() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now.Add(f.skew)
}

func (f *fakeClock) mono() time.Duration {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now.Sub(f.anchor)
}

func (f *fakeClock) advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = f.now.Add(d)
}

func (f *fakeClock) jump(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.skew += d
}

func (f *fakeClock) local(l *time.Location) string { return f.wall().In(l).Format("15:04 -0700") }

// fakeSchedule makes a schedule of the rig at the time start. The run function
// is the one of the caller.
func fakeSchedule(t *testing.T, r *rig, loc *time.Location, start time.Time, lg *slog.Logger) (*Schedule, *fakeClock) {
	t.Helper()
	s := NewSchedule(r.w, 7, 30, lg)
	f := &fakeClock{anchor: start, now: start}
	s.loc, s.clock.anchor, s.clock.wall, s.clock.mono = loc, start, f.wall, f.mono
	return s, f
}

func setMark(t *testing.T, db *sql.DB, at time.Time) {
	t.Helper()
	mustExec(t, db, metaSetSQL, retentionLastKey, strconv.FormatInt(at.UnixMilli(), 10))
}

func chatham(t *testing.T) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation("Pacific/Chatham")
	if err != nil {
		t.Fatal(err)
	}
	return loc
}

// direct is the run function of a test that has no running writer. The writer
// serves the run in this goroutine, as runDirect does.
func direct(r *rig) func(context.Context, []retentionStep) error {
	return func(ctx context.Context, steps []retentionStep) error {
		rq := retentionRequest{reply: make(chan error, 1), gone: ctx.Done(), steps: steps}
		r.w.serveRetention(ctx, r.tick, nil, rq)
		return <-rq.reply
	}
}

// T-U-27: each local date gets one run, at the first minute check at or after
// 03:15. The DST gap of 2026-09-27 has no 03:15, so the run is at 03:45. The
// DST repeat of 2026-04-05 has 03:15 two times, and the day runs one time.
func TestTU27OneRunForEachLocalDate(t *testing.T) {
	loc := chatham(t)
	for _, c := range []struct {
		y    int
		m    time.Month
		d    int
		want string
	}{{2026, 9, 27, "03:45 +1345"}, {2026, 4, 5, "03:15 +1345"}, {2026, 6, 10, "03:15 +1245"}} {
		t.Run(fmt.Sprintf("%d-%02d-%02d", c.y, c.m, c.d), func(t *testing.T) {
			r := newRig(t, 8)
			start := time.Date(c.y, c.m, c.d, 0, 0, 0, 0, loc)
			end := time.Date(c.y, c.m, c.d+1, 0, 0, 0, 0, loc)
			setMark(t, r.db, start.Add(-time.Hour))
			s, f := fakeSchedule(t, r, loc, start, nil)
			var runs []string
			s.run = func(context.Context, []retentionStep) error { runs = append(runs, f.local(loc)); return nil }
			s.begin(context.Background())
			for ; f.wall().Before(end); f.advance(time.Minute) {
				s.check(context.Background())
			}
			if len(runs) != 1 || runs[0] != c.want {
				t.Fatalf("runs %v, want [%s]", runs, c.want)
			}
		})
	}
}

// T-U-27: a start with no mark, or a mark of more than 25 h, runs at once. The
// next check of the same retention day runs nothing.
func TestTU27StartRunsAtOnceAfter25Hours(t *testing.T) {
	loc := chatham(t)
	start := time.Date(2026, 6, 10, 10, 0, 0, 0, loc)
	for _, c := range []struct {
		name string
		age  time.Duration // 0 is no mark
		runs int
	}{{"none", 0, 1}, {"30h", 30 * time.Hour, 1}, {"25h1m", 25*time.Hour + time.Minute, 1}, {"24h30m", 24*time.Hour + 30*time.Minute, 0}} {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t, 8)
			if c.age > 0 {
				setMark(t, r.db, start.Add(-c.age))
			}
			s, f := fakeSchedule(t, r, loc, start, nil)
			runs := 0
			s.run = func(context.Context, []retentionStep) error { runs++; return nil }
			s.begin(context.Background())
			if runs != c.runs {
				t.Fatalf("%d runs before the first tick, want %d", runs, c.runs)
			}
			f.advance(time.Minute)
			s.check(context.Background())
			if c.runs == 1 && runs != 1 {
				t.Fatalf("%d runs after the next tick, want 1", runs)
			}
		})
	}
}

// T-U-27: a step of the wall clock to an earlier time gives a run for each new
// retention day. The check does not wait until the day is later than the last.
func TestTU27WallStepBackRunsForNewDays(t *testing.T) {
	loc := chatham(t)
	r := newRig(t, 8)
	s, f := fakeSchedule(t, r, loc, time.Date(2026, 6, 10, 10, 0, 0, 0, loc), nil)
	runs := 0
	s.run = func(context.Context, []retentionStep) error { runs++; return nil }
	ctx := context.Background()
	s.begin(ctx)
	f.jump(-48 * time.Hour)
	f.advance(time.Minute)
	s.check(ctx)
	f.advance(time.Minute)
	s.check(ctx)
	if runs != 2 {
		t.Fatalf("%d runs after the step back and a second check, want 2", runs)
	}
	f.jump(72 * time.Hour)
	s.check(ctx)
	if runs != 3 {
		t.Fatalf("%d runs after a step forward, want 3", runs)
	}
}

// T-U-27: each run has a deadline of at most 6 h. A run can return an error
// that is not the stop of the schedule. Then 1 is added to the early-end count.
// The first one writes one log line.
func TestTU27RunHasDeadlineAndEarlyEndIsCounted(t *testing.T) {
	loc := chatham(t)
	r := newRig(t, 8)
	var buf bytes.Buffer
	s, _ := fakeSchedule(t, r, loc, time.Date(2026, 6, 10, 10, 0, 0, 0, loc), slog.New(slog.NewTextHandler(&buf, nil)))
	var left time.Duration
	s.run = func(ctx context.Context, _ []retentionStep) error {
		dl, ok := ctx.Deadline()
		if !ok {
			t.Error("the run context has no deadline")
		}
		left = time.Until(dl)
		return context.DeadlineExceeded
	}
	s.runOnce(context.Background())
	s.runOnce(context.Background())
	if left < 5*time.Hour || left > runLimit {
		t.Errorf("time left %v, want 5 h to 6 h", left)
	}
	if s.EarlyEnds() != 2 || strings.Count(buf.String(), "retention run ended early") != 1 {
		t.Errorf("%d early ends, log %q; want 2 and one line", s.EarlyEnds(), buf.String())
	}
}

// T-U-27: the stop of the schedule ends a run that waits. No writer runs, so
// the request waits for a reply. The stop is not an early end.
func TestTU27StopEndsAScheduleThatWaitsInARun(t *testing.T) {
	r := newRig(t, 8)
	s := NewSchedule(r.w, 7, 30, nil)
	entered := make(chan struct{})
	inner := s.run
	s.run = func(ctx context.Context, steps []retentionStep) error { close(entered); return inner(ctx, steps) }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	select {
	case <-entered:
	case <-time.After(waitFor):
		t.Fatal("the schedule made no run")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(waitFor):
		t.Fatal("the schedule did not end after the stop")
	}
	if s.EarlyEnds() != 0 {
		t.Errorf("%d early ends after the stop, want 0", s.EarlyEnds())
	}
}

// T-U-27: the tick drives the checks. The ticks before 03:15 run nothing, and
// the ticks after it run once. A send returns after the check before it ended.
func TestTU27TickDrivesTheChecks(t *testing.T) {
	loc := chatham(t)
	r := newRig(t, 8)
	start := time.Date(2026, 6, 10, 3, 14, 0, 0, loc)
	setMark(t, r.db, start.Add(-time.Hour))
	s, f := fakeSchedule(t, r, loc, start, nil)
	tick := make(chan time.Time)
	s.tick = tick
	runs := 0
	s.run = func(context.Context, []retentionStep) error { runs++; return nil }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	tick <- time.Time{}
	tick <- time.Time{}
	f.advance(time.Minute)
	tick <- time.Time{}
	tick <- time.Time{}
	cancel()
	<-done
	if runs != 1 {
		t.Fatalf("%d runs, want 1", runs)
	}
}

// T-U-27: deletes take the earlier time and the address step takes the later
// time. A difference of more than 1 h counts for each run. The first one writes
// one log line, with the difference in seconds.
func TestTU27ClockGuardTimes(t *testing.T) {
	t0 := time.Date(2027, 2, 10, 12, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		skew  time.Duration
		diffs uint64
	}{{48 * time.Hour, 1}, {-48 * time.Hour, 1}, {time.Hour, 0}, {-time.Hour, 0}, {time.Hour + time.Second, 1}, {90 * time.Minute, 1}} {
		g := newClockGuard(nil)
		f := &fakeClock{anchor: t0, now: t0, skew: c.skew}
		g.anchor, g.wall, g.mono = t0, f.wall, f.mono
		f.advance(time.Minute)
		_, tDel, tPriv := g.reading()
		mono := t0.Add(time.Minute)
		if want := f.wall(); c.skew < 0 && (!tDel.Equal(want) || !tPriv.Equal(mono)) || c.skew > 0 && (!tDel.Equal(mono) || !tPriv.Equal(want)) {
			t.Errorf("skew %v: tDel %v, tPriv %v", c.skew, tDel, tPriv)
		}
		if g.Diffs() != c.diffs {
			t.Errorf("skew %v: %d counts, want %d", c.skew, g.Diffs(), c.diffs)
		}
	}
	var buf bytes.Buffer
	g := newClockGuard(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
		if a.Key == slog.TimeKey {
			return slog.Attr{}
		}
		return a
	}})))
	f := &fakeClock{anchor: t0, now: t0, skew: 48 * time.Hour}
	g.anchor, g.wall, g.mono = t0, f.wall, f.mono
	for range 3 {
		g.reading()
	}
	if want := "level=WARN msg=\"wall clock differs from monotonic clock\" seconds=172800\n"; g.Diffs() != 3 || buf.String() != want {
		t.Errorf("%d counts, log %q; want 3 and %q", g.Diffs(), buf.String(), want)
	}
}

// prodRig makes a schedule of the production step list on a real database. The
// writer serves the run in this goroutine. The wall clock is `skew` from the
// monotonic clock. The time of the anchor is rollTDel.
func prodRig(t *testing.T, skew time.Duration, lg *slog.Logger) (*rig, *Schedule, *fakeClock) {
	t.Helper()
	r := newRig(t, 8)
	s, f := fakeSchedule(t, r, time.UTC, rollTDel, lg)
	f.jump(skew)
	s.run = direct(r)
	return r, s, f
}

// msAgo returns the unix ms of the time that is `back` before t.
func msAgo(t time.Time, back time.Duration) int64 { return t.Add(-back).UnixMilli() }

const oneDay = 24 * time.Hour

// T-U-27 (feeds T-C-06): the wall clock is 2 d ahead. A request row of 29 d by
// the monotonic time stays. A row of 31 d goes.
func TestTU27WallPlusTwoDaysDeletesNothingEarly(t *testing.T) {
	r, s, _ := prodRig(t, 48*time.Hour, nil)
	addEvents(t, r.db, "request", 1, msAgo(rollTDel, 29*oneDay), 0, nil, nil)
	addEvents(t, r.db, "request", 1, msAgo(rollTDel, 31*oneDay), 0, nil, nil)
	s.runOnce(context.Background())
	if n := count(t, r.db, "SELECT count(*) FROM event WHERE ts = "+strconv.FormatInt(msAgo(rollTDel, 29*oneDay), 10)); n != 1 || r.events() != 1 {
		t.Fatalf("%d rows of 29 d, %d rows in all; want 1 and 1", n, r.events())
	}
}

// T-U-27 (feeds T-C-06): the wall clock is 2 d behind. The address of a
// session of 7 d and 1 h by the monotonic time is NULL. A session of 6 d keeps
// its address.
func TestTU27WallMinusTwoDaysClearsAddressesOnTime(t *testing.T) {
	r, s, _ := prodRig(t, -48*time.Hour, nil)
	addSessions(t, r.db, "old", 0, 1, msAgo(rollTDel, 7*oneDay+time.Hour), 0, "203.0.113.7")
	addSessions(t, r.db, "new", 0, 1, msAgo(rollTDel, 6*oneDay), 0, "203.0.113.8")
	s.runOnce(context.Background())
	if got := nullIPs(t, r.db); !got["old0"] || got["new0"] {
		t.Fatalf("null addresses %v; want old0 only", got)
	}
}

// T-U-27: the mark does not move back after a run with a wall clock that is 2 d
// behind. Each run with a difference counts, and the log has one line.
func TestTU27MarkNeverMovesBackAndDifferencesCount(t *testing.T) {
	var buf bytes.Buffer
	r, s, f := prodRig(t, 48*time.Hour, slog.New(slog.NewTextHandler(&buf, nil)))
	s.runOnce(context.Background())
	want := strconv.FormatInt(f.wall().UnixMilli(), 10)
	f.jump(-96 * time.Hour)
	s.runOnce(context.Background())
	if got := metaValue(t, r.db, retentionLastKey); got != want || s.ClockDiffs() != 2 || strings.Count(buf.String(), "\n") != 1 {
		t.Fatalf("mark %s, %d counts, log %q; want %s, 2 and one line", got, s.ClockDiffs(), buf.String(), want)
	}
}

// T-U-27: a run that ends early writes no mark, and the count shows it. The
// mark step is the last step. The ctx of the run ends after the first chunk of
// the address step.
func TestTU27EarlyEndWritesNoMark(t *testing.T) {
	r, s, _ := prodRig(t, 0, nil)
	addSessions(t, r.db, "x", 0, 2500, msAgo(rollTDel, 30*oneDay), 0, "203.0.113.7")
	var cancelRun context.CancelFunc
	r.w.beforeCommit = func(*sql.Tx) error { cancelRun(); return nil }
	run := s.run
	s.run = func(ctx context.Context, steps []retentionStep) error {
		ctx, cancelRun = context.WithCancel(ctx)
		return run(ctx, steps)
	}
	s.runOnce(context.Background())
	nulls := 0
	for _, null := range nullIPs(t, r.db) {
		if null {
			nulls++
		}
	}
	if marks := count(t, r.db, "SELECT count(*) FROM meta WHERE key = 'retention_last'"); marks != 0 || s.EarlyEnds() != 1 || nulls != chunkRows {
		t.Fatalf("%d marks, %d early ends, %d cleared; want 0, 1 and %d", marks, s.EarlyEnds(), nulls, chunkRows)
	}
}

// T-U-27: the roll-up step runs before the day step. The day step counts the
// callbacks of a day only when no request row of the day is left.
func TestTU27RollupStepRunsBeforeTheDayStep(t *testing.T) {
	r, s, _ := prodRig(t, 0, nil)
	addSession(t, r.db, "s1", "human", "f")
	addEvents(t, r.db, "request", 3, utc("2027-01-10T01:00:00Z"), 1000, "s1", "a")
	addEvents(t, r.db, "callback", 2, utc("2027-01-10T10:00:00Z"), 1000, "s1", "a")
	s.runOnce(context.Background())
	if got, want := aggregates(t, r.db), "2027-01-10|a|human|f|1|3|2"; got != want {
		t.Fatalf("aggregates %q, want %q", got, want)
	}
}
