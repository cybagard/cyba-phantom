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
	s := NewSchedule(r.w, 7, 30, 90, lg)
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
		age  time.Duration // 0 is no mark, -1 is a mark that is not a number
		runs int
	}{{"none", 0, 1}, {"corrupt", -1, 1}, {"30h", 30 * time.Hour, 1}, {"25h1m", 25*time.Hour + time.Minute, 1},
		{"25h", 25 * time.Hour, 0}, {"24h30m", 24*time.Hour + 30*time.Minute, 0}} {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t, 8)
			if c.age > 0 {
				setMark(t, r.db, start.Add(-c.age))
			} else if c.age < 0 {
				mustExec(t, r.db, metaSetSQL, retentionLastKey, "x12")
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

// The tests of the steps of the wall clock use UTC. The mark is 1 h before the
// start, or none when markAge is 0. The run function records the time of each
// run.
func stepRig(t *testing.T, start time.Time, markAge time.Duration) (*Schedule, *fakeClock, *[]string) {
	t.Helper()
	r := newRig(t, 8)
	if markAge != 0 {
		setMark(t, r.db, start.Add(-markAge))
	}
	s, f := fakeSchedule(t, r, time.UTC, start, nil)
	runs := &[]string{}
	s.run = func(context.Context, []retentionStep) error {
		*runs = append(*runs, f.wall().Format("01-02 15:04"))
		return nil
	}
	s.begin(context.Background())
	return s, f, runs
}

// minutes advances the clock by one minute and checks, n times.
func minutes(s *Schedule, f *fakeClock, n int) {
	for range n {
		f.advance(time.Minute)
		s.check(context.Background())
	}
}

func wantRuns(t *testing.T, got *[]string, want ...string) {
	t.Helper()
	if fmt.Sprint(*got) != fmt.Sprint(want) {
		t.Fatalf("runs %v, want %v", *got, want)
	}
}

var day10 = time.Date(2027, 2, 10, 12, 0, 0, 0, time.UTC)

// T-U-27: a mark after the wall time is old. The start runs at once, and then
// each retention day has one run.
func TestTU27FutureMarkRunsAtOnceThenEachDay(t *testing.T) {
	s, f, runs := stepRig(t, day10, -48*time.Hour)
	minutes(s, f, 3*24*60)
	wantRuns(t, runs, "02-10 12:00", "02-11 03:15", "02-12 03:15", "02-13 03:15")
}

// T-U-27 (feeds T-C-06): a run with the wall clock 2 d ahead writes a mark 2 d
// ahead. After a restart with the right clock, the start runs at once. It
// clears the address of a session of 7 d and 1 h. A session of 4 d keeps its
// address. It is 6 d old by the mark. The mark keeps its value.
func TestTU27RestartAfterWallPlusTwoDaysClearsAddresses(t *testing.T) {
	r, s, _ := prodRig(t, 48*time.Hour, nil)
	s.runOnce(context.Background())
	mark := metaValue(t, r.db, retentionLastKey)
	restart := rollTDel.Add(time.Hour)
	addSessions(t, r.db, "old", 0, 1, msAgo(restart, 7*oneDay+time.Hour), 0, "203.0.113.7")
	addSessions(t, r.db, "new", 0, 1, msAgo(restart, 4*oneDay), 0, "203.0.113.8")
	s2, _ := fakeSchedule(t, r, time.UTC, restart, nil)
	s2.run = direct(r)
	s2.begin(context.Background())
	if got := nullIPs(t, r.db); !got["old0"] || got["new0"] {
		t.Fatalf("null addresses %v; want old0 only", got)
	}
	if got := metaValue(t, r.db, retentionLastKey); got != mark {
		t.Fatalf("mark %s after the restart, want %s", got, mark)
	}
}

// T-U-27: a step of the wall clock to an earlier time starts no run. A step of
// 2 min after the run of 03:15 and 120 checks around 03:15 give one run.
func TestTU27SmallStepsBackGiveOneRunForEachDate(t *testing.T) {
	start := time.Date(2027, 2, 10, 3, 14, 0, 0, time.UTC)
	s, f, runs := stepRig(t, start, time.Hour)
	minutes(s, f, 1)
	f.jump(-2 * time.Minute)
	s.check(context.Background())
	minutes(s, f, 60)
	wantRuns(t, runs, "02-10 03:15")
	s, f, runs = stepRig(t, start, time.Hour)
	minutes(s, f, 1)
	for range 60 {
		f.jump(-time.Minute)
		s.check(context.Background())
		f.jump(time.Minute)
		s.check(context.Background())
	}
	wantRuns(t, runs, "02-10 03:15")
}

// T-U-27: a step back of 2 d gives one run on each later retention day.
func TestTU27WallStepBackRunsOnEachLaterDay(t *testing.T) {
	s, f, runs := stepRig(t, day10, time.Hour)
	minutes(s, f, 5)
	f.jump(-48 * time.Hour)
	minutes(s, f, 3*24*60)
	wantRuns(t, runs, "02-09 03:15", "02-10 03:15", "02-11 03:15")
}

// T-U-27: the process has more than 2 d of uptime. Then the wall clock steps
// +2 d and then -2 d. The step forward gives no run 9 h after a run. After the
// step back, each later day gives one run.
func TestTU27StepsForwardAndBackInTheProcess(t *testing.T) {
	s, f, runs := stepRig(t, day10, time.Hour)
	minutes(s, f, 24*60)
	f.jump(48 * time.Hour)
	s.check(context.Background())
	wantRuns(t, runs, "02-11 03:15")
	minutes(s, f, 24*60)
	f.jump(-48 * time.Hour)
	s.check(context.Background())
	minutes(s, f, 48*60)
	wantRuns(t, runs, "02-11 03:15", "02-14 03:15", "02-13 03:15", "02-14 03:15")
}

// T-U-27: a later day starts a run after 20 h of monotonic time since the last
// run. A step of +2 d, 1 h after a run, gives no run. The next retention day,
// 23 h later, gives one run.
func TestTU27GapHoldsBackTheRunAfterAStepForward(t *testing.T) {
	s, f, runs := stepRig(t, time.Date(2027, 2, 10, 3, 14, 0, 0, time.UTC), time.Hour)
	minutes(s, f, 1)
	minutes(s, f, 60)
	f.jump(48 * time.Hour)
	s.check(context.Background())
	wantRuns(t, runs, "02-10 03:15")
	minutes(s, f, 23*60)
	wantRuns(t, runs, "02-10 03:15", "02-13 03:15")
}

// T-U-27: a run at the start, at 04:00 or 10:00, does not hold back the next
// run. That run is at 03:15 on the next day.
func TestTU27StartRunDoesNotHoldBackTheNextDay(t *testing.T) {
	for _, h := range []int{4, 10} {
		s, f, runs := stepRig(t, time.Date(2027, 2, 10, h, 0, 0, 0, time.UTC), 0)
		minutes(s, f, 24*60)
		wantRuns(t, runs, fmt.Sprintf("02-10 %02d:00", h), "02-11 03:15")
	}
}

// T-U-27: a step back of 23 h 58 min at each wall 03:14 gives no later day.
// The wall clock never gets to 03:15 of it. In 10 d, the rule of 25 h gives a
// run in each 25 h of monotonic time. The address of a session of 16 d is NULL
// at the end.
func TestTU27StepBackEachDayStillRunsEach25Hours(t *testing.T) {
	r := newRig(t, 8)
	start := time.Date(2027, 2, 10, 3, 13, 0, 0, time.UTC)
	setMark(t, r.db, start.Add(-time.Hour))
	addSessions(t, r.db, "old", 0, 1, msAgo(start, 6*oneDay), 0, "203.0.113.7")
	s, f := fakeSchedule(t, r, time.UTC, start, nil)
	run := direct(r)
	var at []time.Duration
	s.run = func(ctx context.Context, steps []retentionStep) error {
		at = append(at, f.mono())
		return run(ctx, steps)
	}
	s.begin(context.Background())
	for range 10 * 24 * 60 {
		minutes(s, f, 1)
		if w := f.wall(); w.Hour() == 3 && w.Minute() == 14 {
			f.jump(-(oneDay - 2*time.Minute))
			s.check(context.Background())
		}
	}
	prev := time.Duration(0)
	for _, a := range at {
		if a-prev > catchUp {
			t.Fatalf("runs at %v: a gap of %v, want at most 25 h", at, a-prev)
		}
		prev = a
	}
	if len(at) < 9 || 10*oneDay-prev > catchUp {
		t.Fatalf("%d runs at %v in 10 d, want 9 or more", len(at), at)
	}
	if got := nullIPs(t, r.db); !got["old0"] {
		t.Fatalf("the address of 16 d is not NULL: %v", got)
	}
}

// T-U-27: the mark is of the retention day before the start. The wall clock
// steps back 1 h before the first check. The last run day stays the day
// before. So the next check runs for the retention day of the start.
func TestTU27StepBackBeforeTheFirstCheckRunsTheStartDay(t *testing.T) {
	s, f, runs := stepRig(t, day10, 23*time.Hour)
	f.jump(-time.Hour)
	s.check(context.Background())
	minutes(s, f, 1)
	wantRuns(t, runs, "02-10 11:01")
}

// T-U-27: a normal week gives one run for each date. The rule of 25 h adds no
// run. In Pacific/Chatham, the day of the DST repeat is 25 h long. The run of
// the next date is 25 h after it, and that date gives one run.
func TestTU27NormalWeekAndDSTRepeatDayGiveOneRunForEachDate(t *testing.T) {
	s, f, runs := stepRig(t, day10, time.Hour)
	minutes(s, f, 7*24*60)
	wantRuns(t, runs, "02-11 03:15", "02-12 03:15", "02-13 03:15", "02-14 03:15", "02-15 03:15", "02-16 03:15", "02-17 03:15")

	loc := chatham(t)
	r := newRig(t, 8)
	start := time.Date(2026, 4, 4, 0, 0, 0, 0, loc)
	setMark(t, r.db, start.Add(-time.Hour))
	cs, cf := fakeSchedule(t, r, loc, start, nil)
	var got []string
	cs.run = func(context.Context, []retentionStep) error { got = append(got, cf.local(loc)); return nil }
	cs.begin(context.Background())
	for end := time.Date(2026, 4, 7, 0, 0, 0, 0, loc); cf.wall().Before(end); cf.advance(time.Minute) {
		cs.check(context.Background())
	}
	if want := "[03:15 +1345 03:15 +1345 03:15 +1245]"; fmt.Sprint(got) != want {
		t.Fatalf("runs %v, want %s", got, want)
	}
}

// frozen advances the monotonic clock by n minutes and checks at each minute.
// The wall clock steps back by the same time, so it does not move.
func frozen(s *Schedule, f *fakeClock, n int) {
	for range n {
		f.advance(time.Minute)
		f.jump(-time.Minute)
		s.check(context.Background())
	}
}

// T-U-27: a process with no run gets a run 25 h after its start, and no run
// 1 min before. The wall clock does not move, so no later day starts a run.
// The next run is 25 h after the start of that run.
func TestTU27ProcessWithNoRunGetsARunAfter25Hours(t *testing.T) {
	s, f, runs := stepRig(t, day10, time.Hour)
	frozen(s, f, 25*60-1)
	wantRuns(t, runs)
	frozen(s, f, 1)
	wantRuns(t, runs, "02-10 12:00")
	frozen(s, f, 25*60-1)
	wantRuns(t, runs, "02-10 12:00")
	frozen(s, f, 1)
	wantRuns(t, runs, "02-10 12:00", "02-10 12:00")
}

// T-U-27: the run at the start counts for the rule of 25 h. It starts at 10 h
// of monotonic time. The next run is 25 h later, not 15 h after it.
func TestTU27StartRunCountsForThe25HourRule(t *testing.T) {
	r := newRig(t, 8)
	s, f := fakeSchedule(t, r, time.UTC, day10, nil)
	runs := &[]string{}
	s.run = func(context.Context, []retentionStep) error {
		*runs = append(*runs, f.wall().Format("01-02 15:04"))
		return nil
	}
	f.advance(10 * time.Hour)
	f.jump(-10 * time.Hour)
	s.begin(context.Background())
	wantRuns(t, runs, "02-10 12:00")
	frozen(s, f, 25*60-1)
	wantRuns(t, runs, "02-10 12:00")
	frozen(s, f, 1)
	wantRuns(t, runs, "02-10 12:00", "02-10 12:00")
}

// T-U-27: a run of the rule of 25 h counts for the gap of 20 h. A step of the
// wall clock to the next retention day, right after the run, gives no run.
func TestTU27RunOf25HoursCountsForTheGap(t *testing.T) {
	s, f, runs := stepRig(t, day10, time.Hour)
	frozen(s, f, 25*60)
	wantRuns(t, runs, "02-10 12:00")
	f.jump(16 * time.Hour)
	s.check(context.Background())
	wantRuns(t, runs, "02-10 12:00")
}

// T-U-27: the rule of 25 h applies at a check with a step back. The last run
// day then takes the retention day of the check, and not the earlier day.
func TestTU27RuleOf25HoursRunsAtAStepBack(t *testing.T) {
	s, f, runs := stepRig(t, day10, 23*time.Hour)
	f.advance(25 * time.Hour)
	f.jump(-26 * time.Hour)
	s.check(context.Background())
	wantRuns(t, runs, "02-10 11:00")
	if s.StepBacks() != 1 || s.lastDay != "2027-02-10" {
		t.Fatalf("%d step backs, last run day %s; want 1 and 2027-02-10", s.StepBacks(), s.lastDay)
	}
}

// T-U-27: a check starts at most one run. A check 25 h after the start is
// both of a later retention day and after 25 h.
func TestTU27CheckStartsOneRun(t *testing.T) {
	s, f, runs := stepRig(t, day10, time.Hour)
	f.advance(25 * time.Hour)
	s.check(context.Background())
	wantRuns(t, runs, "02-11 13:00")
}

// T-U-27: each step back adds 1 to the count and writes one fixed log line. No
// line has a digit, so none has a time or a duration.
func TestTU27StepBacksCountAndWriteOneLineEach(t *testing.T) {
	var buf bytes.Buffer
	lg := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
		if a.Key == slog.TimeKey {
			return slog.Attr{}
		}
		return a
	}}))
	r := newRig(t, 8)
	setMark(t, r.db, day10.Add(-time.Hour))
	s, f := fakeSchedule(t, r, time.UTC, day10, lg)
	s.run = func(context.Context, []retentionStep) error { return nil }
	s.begin(context.Background())
	for range 11 {
		f.advance(time.Minute)
		s.check(context.Background())
		f.jump(-time.Minute)
		s.check(context.Background())
	}
	want := strings.Repeat("level=WARN msg=\"wall clock stepped back\"\n", 11)
	if got := buf.String(); s.StepBacks() != 11 || got != want || strings.ContainsAny(got, "0123456789") {
		t.Fatalf("%d step backs, log %q; want 11 and %q", s.StepBacks(), got, want)
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
	if left < 5*time.Hour || left > 6*time.Hour || s.limit != 6*time.Hour || s.gap != 20*time.Hour {
		t.Errorf("time left %v, limit %v, gap %v; want 5 h to 6 h, 6 h and 20 h", left, s.limit, s.gap)
	}
	if s.EarlyEnds() != 2 || strings.Count(buf.String(), "retention run ended early") != 1 {
		t.Errorf("%d early ends, log %q; want 2 and one line", s.EarlyEnds(), buf.String())
	}
}

// T-U-27: the run limit ends a run that waits for its context. The run is an
// early end, and it writes no mark. The stop of the schedule has not happened.
func TestTU27RunLimitEndsTheRunWithNoMark(t *testing.T) {
	r, s, _ := prodRig(t, 0, nil)
	s.limit = time.Millisecond
	s.run = func(ctx context.Context, _ []retentionStep) error { <-ctx.Done(); return ctx.Err() }
	s.runOnce(context.Background())
	if marks := count(t, r.db, "SELECT count(*) FROM meta WHERE key = 'retention_last'"); marks != 0 || s.EarlyEnds() != 1 {
		t.Fatalf("%d marks, %d early ends; want 0 and 1", marks, s.EarlyEnds())
	}
}

// T-U-27: the stop of the schedule ends a run that a check started. The tick
// gives the check, and the run waits for a writer that does not run. The stop
// ends the wait. It is not an early end.
func TestTU27StopEndsARunOfACheck(t *testing.T) {
	r := newRig(t, 8)
	start := time.Date(2027, 2, 10, 3, 14, 0, 0, time.UTC)
	setMark(t, r.db, start.Add(-time.Hour))
	s, f := fakeSchedule(t, r, time.UTC, start, nil)
	tick, entered := make(chan time.Time), make(chan struct{}, 1)
	s.tick = tick
	inner := s.run
	s.run = func(ctx context.Context, steps []retentionStep) error {
		entered <- struct{}{}
		return inner(ctx, steps)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	f.advance(time.Minute)
	sendTick(t, tick)
	select {
	case <-entered:
	case <-time.After(waitFor):
		t.Fatal("the check made no run")
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

func sendTick(t *testing.T, tick chan<- time.Time) {
	t.Helper()
	select {
	case tick <- time.Time{}:
	case <-time.After(waitFor):
		t.Fatal("the schedule took no tick")
	}
}

// T-U-27: the stop of the schedule ends a run that waits. No writer runs, so
// the request waits for a reply. The stop is not an early end.
func TestTU27StopEndsAScheduleThatWaitsInARun(t *testing.T) {
	r := newRig(t, 8)
	s := NewSchedule(r.w, 7, 30, 90, nil)
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

// T-U-11: the run of the schedule deletes by the events days it got. It does
// not use the ip, raw or 90-day values. With 45 days, a token of 46 d is gone
// and a token of 44 d stays. With no mark, the run at the start runs at once.
func TestTU11ScheduleRunsWithTheEventsDays(t *testing.T) {
	r := newRig(t, 100)
	r.launchCancelable(context.Background())
	for _, d := range []int{44, 46} {
		mustExec(t, r.db, "INSERT INTO token (token_id, session_id, trap_id, issued_at, first_cb_at) VALUES (?, 's', 't', 1, ?)",
			d, time.Now().Add(-time.Duration(d)*24*time.Hour).UnixMilli())
	}
	s := NewSchedule(r.w, 7, 30, 45, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	select {
	case <-s.Began():
	case <-time.After(waitFor):
		t.Fatal("the schedule did not end its start check")
	}
	cancel()
	<-done
	if got := rawText(t, r.db, "SELECT coalesce(group_concat(token_id), '') FROM token"); got != "44" {
		t.Fatalf("tokens left %q, want 44", got)
	}
}

// T-U-27: the tick drives the checks. The ticks before 03:15 run nothing, and
// the ticks after it run once. The run is at 03:15 local time.
func TestTU27TickDrivesTheChecks(t *testing.T) {
	loc := chatham(t)
	r := newRig(t, 8)
	start := time.Date(2026, 6, 10, 3, 14, 0, 0, loc)
	setMark(t, r.db, start.Add(-time.Hour))
	s, f := fakeSchedule(t, r, loc, start, nil)
	tick := make(chan time.Time)
	s.tick = tick
	var runs []string
	s.run = func(context.Context, []retentionStep) error { runs = append(runs, f.local(loc)); return nil }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	sendTick(t, tick)
	sendTick(t, tick)
	f.advance(time.Minute)
	sendTick(t, tick)
	sendTick(t, tick)
	cancel()
	select {
	case <-done:
	case <-time.After(waitFor):
		t.Fatal("the schedule did not end")
	}
	if fmt.Sprint(runs) != "[03:15 +1245]" {
		t.Fatalf("runs %v, want [03:15 +1245]", runs)
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
		_, tDel, tPriv := g.reading(time.Time{})
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
		g.reading(time.Time{})
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
// the monotonic time stays. A row of 31 d goes. The events days are 90. An
// evidence row, a token and a session of 89 d stay. They are younger than the
// events cutoff by tDel. They are older than it by tPriv.
func TestTU27WallPlusTwoDaysDeletesNothingEarly(t *testing.T) {
	r, s, _ := prodRig(t, 48*time.Hour, nil)
	addEvents(t, r.db, "request", 1, msAgo(rollTDel, 29*oneDay), 0, nil, nil)
	addEvents(t, r.db, "request", 1, msAgo(rollTDel, 31*oneDay), 0, nil, nil)
	young := msAgo(rollTDel, 89*oneDay)
	addEventAt(t, r.db, "score_change", young)
	expireCaseNamed("token").add(t, r.db, young)
	expireCaseNamed("session").add(t, r.db, young)
	s.runOnce(context.Background())
	if n := count(t, r.db, "SELECT count(*) FROM event WHERE ts = "+strconv.FormatInt(msAgo(rollTDel, 29*oneDay), 10)); n != 1 || r.events() != 2 {
		t.Fatalf("%d rows of 29 d, %d rows in all; want 1 and 2", n, r.events())
	}
	if tok, ses := count(t, r.db, "SELECT count(*) FROM token"), count(t, r.db, "SELECT count(*) FROM session"); tok != 1 || ses != 4 {
		t.Fatalf("%d tokens, %d sessions left; want 1 and 4", tok, ses)
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

// T-U-27 (feeds T-C-06): a restart has a wall clock 2 d behind. The anchor is
// wrong too. The mark is 1 h before the true time. The start run sets the
// address of a session to NULL. The session is 7 d and 2 h old by the true
// time. A session of 6 d keeps its address.
func TestTU27RestartWithWallMinusTwoDaysUsesTheMark(t *testing.T) {
	r := newRig(t, 8)
	trueNow := rollTDel
	setMark(t, r.db, trueNow.Add(-time.Hour))
	addSessions(t, r.db, "old", 0, 1, msAgo(trueNow, 7*oneDay+2*time.Hour), 0, "203.0.113.7")
	addSessions(t, r.db, "new", 0, 1, msAgo(trueNow, 6*oneDay), 0, "203.0.113.8")
	s, _ := fakeSchedule(t, r, time.UTC, trueNow.Add(-48*time.Hour), nil)
	s.run = direct(r)
	s.begin(context.Background())
	if got := nullIPs(t, r.db); !got["old0"] || got["new0"] {
		t.Fatalf("null addresses %v; want old0 only", got)
	}
}

// T-U-27: the mark is 2 d after the wall time. The address of a session of 5 d
// and 1 h by the wall time is NULL. A session of 4 d and 23 h keeps its
// address. Each row is just inside its delete age by tDel, so no row goes.
func TestTU27MarkAheadClearsAddressesAndDeletesNothingEarly(t *testing.T) {
	r, s, _ := prodRig(t, 0, nil)
	setMark(t, r.db, rollTDel.Add(48*time.Hour))
	addSessions(t, r.db, "old", 0, 1, msAgo(rollTDel, 5*oneDay+time.Hour), 0, "203.0.113.7")
	addSessions(t, r.db, "new", 0, 1, msAgo(rollTDel, 4*oneDay+23*time.Hour), 0, "203.0.113.8")
	addEvents(t, r.db, "request", 1, msAgo(rollTDel, 30*oneDay-time.Hour), 0, nil, nil)
	young := msAgo(rollTDel, 90*oneDay-time.Hour)
	addEventAt(t, r.db, "score_change", young)
	expireCaseNamed("token").add(t, r.db, young)
	expireCaseNamed("session").add(t, r.db, young)
	q := func() [3]int {
		return [3]int{r.events(), count(t, r.db, "SELECT count(*) FROM token"), count(t, r.db, "SELECT count(*) FROM session")}
	}
	before := q()
	s.begin(context.Background())
	if got := nullIPs(t, r.db); !got["old0"] || got["new0"] {
		t.Fatalf("null addresses %v; want old0 only", got)
	}
	if after := q(); after != before {
		t.Fatalf("events, tokens and sessions %v after the run, %v before", after, before)
	}
}

// T-U-27: a run that ends early does not change the mark in memory. The next
// run uses the old mark. The start sets the mark to 2 d after the wall time. A
// run with the wall clock 4 d ahead fails. Then the wall clock is right again.
// The read of the mark in the next run fails, so only the mark in memory
// counts. An address of 5 d and 1 h is NULL, so the mark is not reset. An
// address of 4 d stays, so the mark did not take the wall time of the failed
// run.
func TestTU27EarlyEndKeepsTheMarkInMemory(t *testing.T) {
	r, s, f := prodRig(t, 0, nil)
	setMark(t, r.db, rollTDel.Add(48*time.Hour))
	s.begin(context.Background())
	ok := s.run
	s.run = func(context.Context, []retentionStep) error { return errors.New("early end") }
	f.jump(96 * time.Hour)
	s.runOnce(context.Background())
	f.jump(-96 * time.Hour)
	addSessions(t, r.db, "old", 0, 1, msAgo(rollTDel, 5*oneDay+time.Hour), 0, "203.0.113.7")
	addSessions(t, r.db, "new", 0, 1, msAgo(rollTDel, 4*oneDay), 0, "203.0.113.8")
	s.readTime = 50 * time.Millisecond
	conn, err := r.db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	s.run = func(ctx context.Context, steps []retentionStep) error {
		conn.Close() // the writer connection is free for the run
		return ok(ctx, steps)
	}
	s.runOnce(context.Background())
	if got := nullIPs(t, r.db); !got["old0"] || got["new0"] || s.markRead || s.EarlyEnds() != 1 {
		t.Fatalf("null addresses %v, read of the mark %v, %d early ends; want old0 only, a failed read and 1", got, s.markRead, s.EarlyEnds())
	}
}

// T-U-27: a run can store its mark and still end with an error. This occurs
// when the run limit ends while the run waits for the reply. The next run
// reads the stored mark again. The first run has the wall clock 2 d ahead.
// Then the wall clock is right again. The stored mark is the wall time of that
// run. An address of 5 d and 1 h is NULL by the mark. The run counts a mark
// ahead.
func TestTU27LostReplyAfterTheMarkIsStoredReadsTheMarkAgain(t *testing.T) {
	r, s, f := prodRig(t, 0, nil)
	s.begin(context.Background())
	ok := s.run
	s.run = func(ctx context.Context, steps []retentionStep) error {
		if err := ok(ctx, steps); err != nil {
			return err
		}
		return context.DeadlineExceeded
	}
	f.jump(48 * time.Hour)
	ahead := strconv.FormatInt(f.wall().UnixMilli(), 10)
	s.runOnce(context.Background())
	f.jump(-48 * time.Hour)
	s.run = ok
	addSessions(t, r.db, "old", 0, 1, msAgo(rollTDel, 5*oneDay+time.Hour), 0, "203.0.113.7")
	s.runOnce(context.Background())
	if got, mark := nullIPs(t, r.db), metaValue(t, r.db, retentionLastKey); !got["old0"] || mark != ahead || s.MarkAhead() != 1 || s.EarlyEnds() != 1 {
		t.Fatalf("null addresses %v, mark %s, %d marks ahead, %d early ends; want old0, %s, 1 and 1", got, mark, s.MarkAhead(), s.EarlyEnds(), ahead)
	}
}

// T-U-27: a read of the mark that fails at the start is made again in a run.
// The restart has the wall clock 2 d behind. The mark is 1 h before the true
// time. A session of 7 d and 2 h has an address. A session of 7 d and 30 min
// has one. The read at the start fails, and so does the read in the start run.
// That run leaves both addresses, as it has no mark. The next run reads the
// mark. The address of 7 d and 2 h is NULL. The other stays: it is 6 d, 23 h
// and 30 min old by the mark.
func TestTU27FailedStartReadIsMadeAgain(t *testing.T) {
	r := newRig(t, 8)
	trueNow := rollTDel
	setMark(t, r.db, trueNow.Add(-time.Hour))
	addSessions(t, r.db, "old", 0, 1, msAgo(trueNow, 7*oneDay+2*time.Hour), 0, "203.0.113.7")
	addSessions(t, r.db, "near", 0, 1, msAgo(trueNow, 7*oneDay+30*time.Minute), 0, "203.0.113.8")
	s, _ := fakeSchedule(t, r, time.UTC, trueNow.Add(-48*time.Hour), nil)
	s.readTime = 50 * time.Millisecond
	conn, err := r.db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	run := direct(r)
	s.run = func(ctx context.Context, steps []retentionStep) error {
		conn.Close() // the writer connection is free for the run
		return run(ctx, steps)
	}
	s.begin(context.Background())
	if got := nullIPs(t, r.db); s.markRead || got["old0"] || got["near0"] {
		t.Fatalf("read of the mark %v, null addresses %v; want a failed read and none", s.markRead, got)
	}
	s.readTime = readLimit
	s.runOnce(context.Background())
	if got := nullIPs(t, r.db); !s.markRead || !got["old0"] || got["near0"] {
		t.Fatalf("read of the mark %v, null addresses %v; want a read and old0 only", s.markRead, got)
	}
}

// T-U-27: each run with a mark more than 1 h after the wall time adds 1 to the
// count. The first one writes one fixed log line with no digit. A mark of
// exactly 1 h gives no count. The mark adds nothing to the clock differences.
func TestTU27MarkAheadCountsAndLogsOnce(t *testing.T) {
	for _, c := range []struct {
		ahead time.Duration
		want  uint64
	}{{48 * time.Hour, 2}, {time.Hour + time.Millisecond, 2}, {time.Hour, 0}, {0, 0}} {
		var buf bytes.Buffer
		lg := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return a
		}}))
		r, s, _ := prodRig(t, 0, lg)
		setMark(t, r.db, rollTDel.Add(c.ahead))
		s.begin(context.Background())
		s.runOnce(context.Background())
		line := "level=WARN msg=\"retention mark is ahead of the wall clock\"\n"
		if c.want == 0 {
			line = ""
		}
		if got := buf.String(); s.MarkAhead() != c.want || got != line || strings.ContainsAny(got, "0123456789") || s.ClockDiffs() != 0 {
			t.Errorf("ahead %v: %d counts, %d clock differences, log %q; want %d, 0 and %q", c.ahead, s.MarkAhead(), s.ClockDiffs(), got, c.want, line)
		}
	}
}

// T-U-27: the mark does not move back after a run with a wall clock that is 2 d
// behind. Each run with a difference counts, and the log has one line of the
// clock difference. The mark ahead of the second run has its own line.
func TestTU27MarkNeverMovesBackAndDifferencesCount(t *testing.T) {
	var buf bytes.Buffer
	r, s, f := prodRig(t, 48*time.Hour, slog.New(slog.NewTextHandler(&buf, nil)))
	s.runOnce(context.Background())
	want := strconv.FormatInt(f.wall().UnixMilli(), 10)
	f.jump(-96 * time.Hour)
	s.runOnce(context.Background())
	if got := metaValue(t, r.db, retentionLastKey); got != want || s.ClockDiffs() != 2 || strings.Count(buf.String(), "wall clock differs") != 1 {
		t.Fatalf("mark %s, %d counts, log %q; want %s, 2 and one line", got, s.ClockDiffs(), buf.String(), want)
	}
	f.jump(120 * time.Hour)
	s.runOnce(context.Background())
	if got, want := metaValue(t, r.db, retentionLastKey), strconv.FormatInt(f.wall().UnixMilli(), 10); got != want {
		t.Fatalf("mark %s after a later run, want %s", got, want)
	}
}

// T-U-27: the mark is the wall time of the run, not the later of the two
// times. The wall clock is 2 d behind, so the mono time is later. The mark in
// memory is the wall time too: a second run has no mark ahead.
func TestTU27MarkIsTheWallTimeOfTheRun(t *testing.T) {
	r, s, f := prodRig(t, -48*time.Hour, nil)
	s.runOnce(context.Background())
	s.runOnce(context.Background())
	if got, want := metaValue(t, r.db, retentionLastKey), strconv.FormatInt(f.wall().UnixMilli(), 10); got != want || s.MarkAhead() != 0 {
		t.Fatalf("mark %s, %d marks ahead; want %s and 0", got, s.MarkAhead(), want)
	}
}

// T-U-27: the production sources of the clock guard. Right after the guard
// starts, both times are the time now, and there is no count.
func TestTU27ClockGuardProductionSources(t *testing.T) {
	g := newClockGuard(nil)
	_, tDel, tPriv := g.reading(time.Time{})
	now := time.Now()
	if tDel.Sub(now).Abs() > time.Second || tPriv.Sub(now).Abs() > time.Second || g.Diffs() != 0 {
		t.Fatalf("tDel %v, tPriv %v, %d counts; now %v", tDel, tPriv, g.Diffs(), now)
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
// callbacks of a day only when no request row of the day is left. The session
// has last_seen 0, so the run deletes it. So the test also guards the place of
// the session step. It comes after the day step, which reads the session.
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

// T-U-27: the writer stores a request row before the raw cutoff after the
// roll-up step and before the day step. The day step stops, so it counts no
// callback of the day. The event delete of the same run, with events equal to
// raw, keeps the callbacks of that day. The next run counts them in
// aggregate_day, and then deletes them.
func TestTU27LateRequestRowKeepsTheCallbacksOfADayNotDone(t *testing.T) {
	r, s, _ := prodRig(t, 0, nil)
	s.events = 30
	addSession(t, r.db, "s1", "human", "f")
	mustExec(t, r.db, "UPDATE session SET last_seen = ?", rollTDel.UnixMilli())
	day := msAgo(rollTDel, 40*oneDay)
	addEvents(t, r.db, "request", 1, day, 0, "s1", "a")
	addEvents(t, r.db, "callback", 2, day+1000, 1000, "s1", "a")
	run, late := s.run, false
	s.run = func(ctx context.Context, steps []retentionStep) error {
		dayStep := steps[1]
		steps[1] = func(ctx context.Context, tx *sql.Tx, limit int) (int, error) {
			if !late {
				late = true
				_, err := tx.ExecContext(ctx, "INSERT INTO event (ts, session_id, kind, vhost) VALUES (?, 's1', 'request', 'a')", day+500)
				if err != nil {
					return 0, err
				}
			}
			return dayStep(ctx, tx, limit)
		}
		return run(ctx, steps)
	}
	s.runOnce(context.Background())
	if cb, req := count(t, r.db, "SELECT count(*) FROM event WHERE kind = 'callback'"), count(t, r.db, "SELECT count(*) FROM event WHERE kind = 'request'"); !late || cb != 2 || req != 1 {
		t.Fatalf("%d callbacks and %d requests after the first run; want 2 and 1", cb, req)
	}
	s.run = run
	s.runOnce(context.Background())
	if got, want := aggregates(t, r.db), rollupDay(day)+"|a|human|f|1|2|2"; got != want || r.events() != 0 {
		t.Fatalf("aggregates %q, %d events; want %q and 0", got, r.events(), want)
	}
}

// T-U-27: a database has no callback row and no seen row. It has no done mark
// and no day for the day step. The event delete still removes its old
// score_change row. The raw delete removes the old refused and beacon rows
// before the event step runs.
func TestTU27EventDeleteRunsWithNoCallbackAndNoSeenRow(t *testing.T) {
	r, s, _ := prodRig(t, 0, nil)
	old := msAgo(rollTDel, 100*oneDay)
	addEventAt(t, r.db, "score_change", old)
	addEvents(t, r.db, "refused", 1, old, 0, nil, nil)
	addEvents(t, r.db, "beacon", 1, old, 0, nil, nil)
	addEventAt(t, r.db, "score_change", msAgo(rollTDel, oneDay))
	s.runOnce(context.Background())
	if r.events() != 1 || count(t, r.db, "SELECT count(*) FROM meta WHERE key = 'retention_rollup_done'") != 0 {
		t.Fatalf("%d events left, want 1 with no done mark", r.events())
	}
}
