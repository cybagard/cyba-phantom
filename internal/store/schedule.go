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

	// runLimit is the time that one run can take, with its checkpoint. When
	// this time ends, the run ends early. The next run continues from marks.
	runLimit = 6 * time.Hour

	// runGap is the monotonic time between two runs that checks start. Days are
	// 23 h to 25 h apart, so a normal run is not held back. A step of the wall
	// clock can be held back.
	runGap = 20 * time.Hour

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
	w         *Writer
	clock     *clockGuard
	loc       *time.Location
	ip, raw   int // the days of the address step and of the raw rows
	lg        *slog.Logger
	tick      <-chan time.Time // nil means a ticker of one minute
	run       func(ctx context.Context, steps []retentionStep) error
	lastDay   string        // the retention day of the last run
	lastWall  time.Time     // the wall time of the last check
	limit     time.Duration // the time that one run can take
	gap       time.Duration // the monotonic time between two runs of new days
	began     chan struct{} // closed when the start check ends
	ran       bool          // a check made a run
	ranAt     time.Duration // the monotonic time of the last run of a check
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
		lg: lg, run: w.runSteps, limit: runLimit, gap: runGap,
		began: make(chan struct{})}
}

// ClockDiffs returns the number of runs whose wall clock and monotonic clock
// differed by more than 1 h. It is safe to call from any goroutine.
func (s *Schedule) ClockDiffs() uint64 { return s.clock.Diffs() }

// EarlyEnds returns the number of runs that ended early, with an error that is
// not the stop of the schedule. It is safe to call from any goroutine.
func (s *Schedule) EarlyEnds() uint64 { return s.earlyEnds.Load() }

// Began returns a channel. Run closes it when the check at the start and its
// run, if any, end.
func (s *Schedule) Began() <-chan struct{} { return s.began }

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
	close(s.began)
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
// the local time is at or after 03:15. If not, it is the date before. It
// compares the hour and the minute. The time 03:15 can be missing in a DST gap.
// It can occur twice in a DST repeat.
func retentionDay(t time.Time, loc *time.Location) string {
	l := t.In(loc)
	y, m, d := l.Date()
	if l.Hour()*60+l.Minute() < runHour*60+runMinute {
		d--
	}
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC).Format(time.DateOnly)
}

// begin reads the mark of the last run. With no mark, or a mark that is more
// than 25 h old, it runs at once. A mark that cannot be read or is not a number
// is 0, so it is old. A mark after the wall time is old too: the wall clock
// was ahead at the last run. The run keeps the mark, and it does not move back.
func (s *Schedule) begin(ctx context.Context) {
	wall := s.clock.wall()
	s.lastWall = wall
	rctx, cancel := context.WithTimeout(ctx, readLimit)
	defer cancel()
	var v string
	_ = s.w.db.QueryRowContext(rctx, metaGetSQL, retentionLastKey).Scan(&v)
	ms, _ := strconv.ParseInt(v, 10, 64)
	mark := time.UnixMilli(ms)
	if wall.Sub(mark) > catchUp || mark.After(wall) {
		s.runOnce(ctx)
		s.lastDay = retentionDay(wall, s.loc)
		return
	}
	s.lastDay = retentionDay(mark, s.loc)
}

// check starts a run when the retention day of the wall time is later than the
// last run day. A local time that goes back in a DST repeat gives an earlier
// day, and that day has run. The wall clock can step to an earlier time. Then
// the last run day becomes the day of the new wall time, and no run starts.
// Each later day then starts a run. A run needs 20 h of monotonic time since
// the last run that a check started. The run at the start does not count. Thus
// a wall clock that steps back and forth around 03:15 starts no extra run.
func (s *Schedule) check(ctx context.Context) {
	wall := s.clock.wall()
	day, back := retentionDay(wall, s.loc), wall.Before(s.lastWall)
	s.lastWall = wall
	switch {
	case back:
		s.lastDay = day
	case day > s.lastDay:
		s.lastDay = day
		if !s.ran || s.clock.mono()-s.ranAt >= s.gap {
			s.ran, s.ranAt = true, s.clock.mono()
			s.runOnce(ctx)
		}
	}
}

// runOnce makes one run with a step list for the clock readings of the run. A
// run can end with an error that is not the stop of the schedule. Then it adds
// 1 to the early-end count. The first early end writes one log line.
func (s *Schedule) runOnce(stop context.Context) {
	wall, tDel, tPriv := s.clock.reading()
	ctx, cancel := context.WithTimeout(stop, s.limit)
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
// remove. The delete of the refused and beacon rows comes before the field
// clear. Thus the clear does not write rows that the delete removes. The mark
// step is last, so a run that ends early writes no mark.
func runSteps(wall, tDel, tPriv time.Time, ip, raw int) []retentionStep {
	return []retentionStep{
		newRollupStep(tDel, raw),
		newRollupDayStep(tDel, raw),
		newIPStep(tPriv, ip),
		newRawDeleteStep(tDel, raw),
		newCounterDeleteStep(tDel, raw),
		newFieldClearStep(tPriv, raw),
		newMintStep(tDel, raw),
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
		} else if ok {
			old, _ := strconv.ParseInt(v, 10, 64)
			ms = max(ms, old)
		}
		return execN(ctx, tx, metaSetSQL, retentionLastKey, strconv.FormatInt(ms, 10))
	}
}
