package store

import (
	"context"
	"database/sql"
	"log/slog"
	"strconv"
	"sync/atomic"
	"time"
)

const (
	// The run is at 03:15 local time (SEC-40).
	runHour, runMinute = 3, 15

	// runLimit is the time that one run can take, with its checkpoint. When it
	// ends, the run ends early and the next run continues from the marks.
	runLimit = 6 * time.Hour

	// readLimit is the time that the read of the mark at the start can take.
	readLimit = 30 * time.Second

	// catchUp is the age of the last run above which the start runs at once.
	catchUp = 25 * time.Hour

	// retentionLastKey is the meta key of the wall time of the last run, in
	// unix ms as decimal text.
	retentionLastKey = "retention_last"
)

// Schedule starts one retention run for each local date (SEC-40). The run is
// at the first minute check at or after 03:15. It never starts two runs at the
// same time. A start after more than 25 h without a run gives a run at once.
type Schedule struct {
	w        *Writer
	clock    *clockGuard
	loc      *time.Location
	ip, raw  int // the days of the address step and of the raw rows
	lg       *slog.Logger
	tick     <-chan time.Time // nil means a ticker of one minute
	run      func(ctx context.Context, steps []retentionStep) error
	lastDay  string    // the retention day of the last run
	lastWall time.Time // the wall time of the last check

	earlyEnds atomic.Uint64
	earlyLog  atomic.Bool
}

// NewSchedule makes the schedule of w. The days are the values of
// store.retention_days.ip and store.retention_days.raw. The location is the
// local time zone.
func NewSchedule(w *Writer, ipDays, rawDays int, lg *slog.Logger) *Schedule {
	if lg == nil {
		lg = slog.New(slog.DiscardHandler)
	}
	return &Schedule{w: w, clock: newClockGuard(lg), loc: time.Local, ip: ipDays, raw: rawDays,
		lg: lg, run: w.runSteps}
}

// ClockDiffs returns the number of runs whose wall clock and monotonic clock
// differed by more than 1 h. It is safe to call from any goroutine.
func (s *Schedule) ClockDiffs() uint64 { return s.clock.Diffs() }

// EarlyEnds returns the number of runs that ended early, with an error that is
// not the stop of the schedule. It is safe to call from any goroutine.
func (s *Schedule) EarlyEnds() uint64 { return s.earlyEnds.Load() }

// Run starts with the catch-up check, then checks each minute until ctx ends.
// A run is part of the loop, so a check that comes in a run is lost. The next
// check sees the same day.
func (s *Schedule) Run(ctx context.Context) {
	tick := s.tick
	if tick == nil {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		tick = t.C
	}
	s.begin(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick:
			s.check(ctx)
		}
	}
}

// retentionDay returns the retention day of t. It is the local date of t when
// the local time is at or after 03:15. Else it is the date before. It compares
// the hour and the minute. The time 03:15 can be missing in a DST gap. It can
// occur twice in a DST repeat.
func retentionDay(t time.Time, loc *time.Location) string {
	l := t.In(loc)
	y, m, d := l.Date()
	if l.Hour()*60+l.Minute() < runHour*60+runMinute {
		d--
	}
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC).Format(time.DateOnly)
}

// begin reads the mark of the last run. With no mark, or a mark that is more
// than 25 h old, it runs at once. A mark that cannot be read counts as no mark.
func (s *Schedule) begin(ctx context.Context) {
	wall := s.clock.wall()
	s.lastWall = wall
	rctx, cancel := context.WithTimeout(ctx, readLimit)
	defer cancel()
	var v string
	err := s.w.db.QueryRowContext(rctx, metaGetSQL, retentionLastKey).Scan(&v)
	ms, perr := strconv.ParseInt(v, 10, 64)
	if err != nil || perr != nil || wall.Sub(time.UnixMilli(ms)) > catchUp {
		s.runOnce(ctx)
		s.lastDay = retentionDay(wall, s.loc)
		return
	}
	s.lastDay = retentionDay(time.UnixMilli(ms), s.loc)
}

// check runs when the retention day of the wall time is new. In normal time,
// a new day is a later day. A local time that goes back in a DST repeat gives
// an earlier day, and that day has run. After a step of the wall clock to an
// earlier time, each other day is new. Then a run follows each day.
func (s *Schedule) check(ctx context.Context) {
	wall := s.clock.wall()
	day, back := retentionDay(wall, s.loc), wall.Before(s.lastWall)
	s.lastWall = wall
	if (back && day != s.lastDay) || day > s.lastDay {
		s.lastDay = day
		s.runOnce(ctx)
	}
}

// runOnce makes one run with a step list for the clock readings of the run. A
// run can end with an error that is not the stop of the schedule. Then it adds
// 1 to the early-end count. The first one writes one log line.
func (s *Schedule) runOnce(stop context.Context) {
	wall, tDel, tPriv := s.clock.reading()
	ctx, cancel := context.WithTimeout(stop, runLimit)
	defer cancel()
	err := s.run(ctx, runSteps(wall, tDel, tPriv, s.ip, s.raw))
	if err != nil && stop.Err() == nil {
		s.earlyEnds.Add(1)
		if s.earlyLog.CompareAndSwap(false, true) {
			s.lg.Warn("retention run ended early")
		}
	}
}

// runSteps returns the steps of one run in order. The roll-up step and the day
// step come first: they read the session and event rows that later deletes
// remove. The mark step is last, so a run that ends early writes no mark.
func runSteps(wall, tDel, tPriv time.Time, ip, raw int) []retentionStep {
	return []retentionStep{
		newRollupStep(tDel, raw),
		newRollupDayStep(tDel, raw),
		newIPStep(tPriv, ip),
		markStep(wall),
	}
}

// markStep sets the meta key retention_last to the later of its value and the
// wall time of the run. The mark does not move back after a step back of the
// wall clock.
func markStep(wall time.Time) retentionStep {
	return func(ctx context.Context, tx *sql.Tx, limit int) (int, error) {
		ms := wall.UnixMilli()
		if v, ok, err := metaGet(ctx, tx, retentionLastKey); err != nil {
			return 0, err
		} else if old, perr := strconv.ParseInt(v, 10, 64); ok && perr == nil {
			ms = max(ms, old)
		}
		return execN(ctx, tx, metaSetSQL, retentionLastKey, strconv.FormatInt(ms, 10))
	}
}
