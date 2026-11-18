package store

import (
	"context"
	"database/sql"
	"errors"
	"io/fs"
	"log/slog"
	"path/filepath"
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

	// catchUp is the age of the last run above which the start runs at once. A
	// check also starts a run when this monotonic time has passed since the
	// start of the last run.
	catchUp = 25 * time.Hour

	// retentionLastKey is the meta key of the wall time of the last run, in
	// unix ms as decimal text.
	retentionLastKey = "retention_last"
)

// Schedule starts one retention run for each local date (SEC-40). The run is
// at the first minute check at or after 03:15. It never starts two runs at the
// same time. A start after more than 25 h without a run gives a run at once.
// A check also starts a run after 25 h of monotonic time since the start of
// the last run. Thus a wall clock that steps back cannot stop the runs.
type Schedule struct {
	w         *Writer
	clock     *clockGuard
	loc       *time.Location
	ip, raw   int // the days of the address step and of the raw rows
	events    int // the days of the event, token and session rows
	lg        *slog.Logger
	tick      <-chan time.Time // nil means a ticker of one minute
	run       func(ctx context.Context, steps []retentionStep) error
	lastDay   string        // the retention day of the last run
	lastWall  time.Time     // the wall time of the last check
	limit     time.Duration // the time that one run can take
	gap       time.Duration // the monotonic time between two runs of new days
	readTime  time.Duration // the time that a read of the mark can take
	markRead  bool          // a read of the mark has succeeded
	began     chan struct{} // closed when the start check ends
	ran       bool          // a check made a run
	ranAt     time.Duration // the monotonic time of the last run of a check
	lastRun   time.Duration // the monotonic time of the start of the last run
	stepBacks atomic.Uint64
	earlyEnds atomic.Uint64
	earlyLog  atomic.Bool
	mark      time.Time // the mark of the last run, in memory
	markAhead atomic.Uint64
	markLog   atomic.Bool
	clockLog  atomic.Bool
	maxBytes  int64  // store.max_bytes; 0 means no cap step
	dbRel     string // the name that SetMaxBytes checked, relative to the root
	capLog    atomic.Bool
	// The runs that did not meet the cap, for each reason.
	capKept, capSlow, capStuck, capFaults atomic.Uint64
	// tune changes the cap state of each run. A test sets it. It is nil in
	// production.
	tune func(*capRun)
}

// errCapName is the refusal of SetMaxBytes for a bad database name.
var errCapName = errors.New("store: the cap needs the name of the database file in the state directory")

// mainFileSQL gives the file of the main database of a connection.
const mainFileSQL = "SELECT file FROM pragma_database_list WHERE name = 'main'"

// SetMaxBytes sets the database cap (store.max_bytes) for the next runs. A cap
// of 0 or less gives no cap step, and rel can be any text. Else rel must be the
// name of the open database, relative to the state root. It is the name that
// the caller gave to Open. The call checks that rel is a valid relative name.
// It checks that an Lstat through the root gives a regular file. It also checks
// that the path of rel is the main file in the database list of SQLite. If not,
// it returns an error and sets nothing. Call it before Run starts.
func (s *Schedule) SetMaxBytes(n int64, rel string) error {
	if n <= 0 {
		s.maxBytes, s.dbRel = 0, ""
		return nil
	}
	if !fs.ValidPath(rel) || rel == "." || s.w.rec.State == nil {
		return errCapName
	}
	if fi, err := s.w.rec.State.Lstat(rel); err != nil || !fi.Mode().IsRegular() || !s.isOpenDatabase(rel) {
		return errCapName
	}
	s.maxBytes, s.dbRel = n, rel
	return nil
}

// isOpenDatabase tells if the path of rel in the state directory is the main
// file of the writer's database. Open builds that path in the same way.
func (s *Schedule) isOpenDatabase(rel string) bool {
	base, err := stateBase(s.w.rec.State)
	if err != nil || s.w.db == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), readLimit)
	defer cancel()
	var file string
	if err := s.w.db.QueryRowContext(ctx, mainFileSQL).Scan(&file); err != nil {
		return false
	}
	return file == filepath.Join(base, filepath.FromSlash(rel))
}

// capUnmet counts a run that does not meet the cap, with the reason. A fault
// is that the files of the cap cannot be measured at the trigger. The run then
// evicts nothing. The schedule writes one fixed log line for it, one time only.
// A kept skip or a slow read of the kept bytes writes one fixed line in each
// run. No line has a path or a row value.
func (s *Schedule) capUnmet(reason string) {
	switch reason {
	case reasonKept:
		s.capKept.Add(1)
		s.lg.Error("retention cap not met: kept rows over the cap")
	case reasonSlow:
		s.capSlow.Add(1)
		s.lg.Error("retention cap not met: kept read too slow")
	case reasonStuck:
		s.capStuck.Add(1)
	case reasonFault:
		s.capFaults.Add(1)
		if s.capLog.CompareAndSwap(false, true) {
			s.lg.Error("retention cap not applied: database file not measured")
		}
	}
}

// CapUnmet returns the counts of the runs that did not meet the cap, for each
// reason. It is safe to call from any goroutine.
func (s *Schedule) CapUnmet() CapUnmet {
	return CapUnmet{Kept: s.capKept.Load(), Slow: s.capSlow.Load(), Stuck: s.capStuck.Load(), Fault: s.capFaults.Load()}
}

// NewSchedule makes the schedule of w. The days are the values of
// store.retention_days.ip, store.retention_days.raw and
// store.retention_days.events. The location is the local time zone.
func NewSchedule(w *Writer, ipDays, rawDays, eventsDays int, lg *slog.Logger) *Schedule {
	if lg == nil {
		lg = slog.New(slog.DiscardHandler)
	}
	return &Schedule{w: w, clock: newClockGuard(lg), loc: time.Local, ip: ipDays, raw: rawDays,
		events: eventsDays, lg: lg, run: w.runSteps, limit: runLimit, gap: runGap,
		readTime: readLimit, began: make(chan struct{})}
}

// ClockDiffs returns the number of runs whose wall clock and monotonic clock
// differed by more than 1 h. It is safe to call from any goroutine.
func (s *Schedule) ClockDiffs() uint64 { return s.clock.Diffs() }

// MarkAhead returns the number of runs with a mark more than 1 h after the wall
// time of the run. It is safe to call from any goroutine.
func (s *Schedule) MarkAhead() uint64 { return s.markAhead.Load() }

// StepBacks returns the number of checks whose wall time was before the wall
// time of the check before. It is safe to call from any goroutine.
func (s *Schedule) StepBacks() uint64 { return s.stepBacks.Load() }

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
// The value that it read stays in memory as the mark of the last run. This is
// true also when the value is after the wall time. If the read fails, runOnce
// reads the mark again. See runOnce. This run counts for the rule of 25 h in
// check. It does not count for the gap of 20 h.
//
// A writer with a clock gives S as the wall time and its boot clock as the
// monotonic time (ADR-043). A clock error starts no run. The last run day then
// stays empty, so the first good check starts a run. The boot clock of the
// start counts as the start of the last run, also when no run starts.
func (s *Schedule) begin(ctx context.Context) {
	wall, mono, err := s.read()
	if err != nil {
		s.clockFailed()
		return
	}
	s.lastWall = wall
	if s.w.clk != nil {
		s.lastRun = mono
	}
	mark, ok := s.readMark(ctx)
	s.mark, s.markRead = mark, ok
	if wall.Sub(mark) > catchUp || mark.After(wall) {
		if s.w.clk == nil {
			s.lastRun = mono
		}
		s.runOnce(ctx)
		s.lastDay = retentionDay(wall, s.loc)
		return
	}
	s.lastDay = retentionDay(mark, s.loc)
}

// readMark reads the stored mark of the last run. No mark, or text that is not
// a number, gives the time 0. The flag is false only when the read fails.
func (s *Schedule) readMark(ctx context.Context) (time.Time, bool) {
	rctx, cancel := context.WithTimeout(ctx, s.readTime)
	defer cancel()
	var v string
	err := s.w.db.QueryRowContext(rctx, metaGetSQL, retentionLastKey).Scan(&v)
	ms, _ := strconv.ParseInt(v, 10, 64)
	return time.UnixMilli(ms), err == nil || errors.Is(err, sql.ErrNoRows)
}

// check starts a run when the retention day of the wall time is later than the
// last run day. A local time that goes back in a DST repeat gives an earlier
// day, and that day has run. A run of a later day needs 20 h of monotonic time
// since the last run that a check started. The run at the start does not count.
// Thus a wall clock that steps back and forth around 03:15 starts no extra run.
//
// A check also starts a run 25 h of monotonic time after the start of the last
// run. Each kind of run counts. The time counts from the process start when no
// run has started. This holds also at a check with a step back. A check starts
// at most one run.
//
// The wall time of a check can be before the one of the check before. Then the
// check adds 1 to the step-back count and writes one fixed log line. The last
// run day becomes the earlier of its value and the day of the new wall time.
// A step back starts no run by the day rule. A run of the rule of 25 h also
// sets the last run day. It takes the later of its value and the day of the
// check.
//
// A writer with a clock has S and its boot clock. S does not step back. So the
// check has no step-back rule and no gap of 20 h. A run starts in two cases.
// The day is later than the last run day. Or 25 h of boot clock have passed
// since the start of the last run. A clock error starts no run.
func (s *Schedule) check(ctx context.Context) {
	wall, now, err := s.read()
	if err != nil {
		s.clockFailed()
		return
	}
	if s.w.clk != nil {
		s.lastWall = wall
		day := retentionDay(wall, s.loc)
		if day > s.lastDay || now-s.lastRun >= catchUp {
			s.lastDay = max(s.lastDay, day)
			s.lastRun = now
			s.runOnce(ctx)
		}
		return
	}
	day, back := retentionDay(wall, s.loc), wall.Before(s.lastWall)
	s.lastWall = wall
	due, started := now-s.lastRun >= catchUp, false
	switch {
	case back:
		s.stepBacks.Add(1)
		s.lg.Warn("wall clock stepped back")
		s.lastDay = min(s.lastDay, day)
	case day > s.lastDay:
		s.lastDay = day
		if !s.ran || now-s.ranAt >= s.gap {
			s.checkRun(ctx, now)
			started = true
		}
	}
	if due && !started {
		s.lastDay = max(s.lastDay, day)
		s.checkRun(ctx, now)
	}
}

// read gives the wall time and the monotonic time of one check. A writer with
// a clock gives S and the boot clock of its source. A writer with no clock
// gives the readings of the clock guard.
func (s *Schedule) read() (wall time.Time, mono time.Duration, err error) {
	if s.w.clk == nil {
		return s.clock.wall(), s.clock.mono(), nil
	}
	ms, err := s.w.clk.Now()
	if err == nil {
		mono, err = s.w.src.BootClock()
	}
	return time.UnixMilli(ms), mono, err
}

// clockFailed writes one fixed log line for a clock error, one time only.
func (s *Schedule) clockFailed() {
	if s.clockLog.CompareAndSwap(false, true) {
		s.lg.Error("retention clock does not read")
	}
}

// checkRun makes a run that a check started at the monotonic time now. The run
// counts for the gap of 20 h and for the rule of 25 h.
func (s *Schedule) checkRun(ctx context.Context, now time.Duration) {
	s.ran, s.ranAt, s.lastRun = true, now, now
	s.runOnce(ctx)
}

// runOnce makes one run with a step list for the clock readings of the run. A
// run can end with an error that is not the stop of the schedule. Then it adds
// 1 to the early-end count. The first early end writes one log line. The mark
// in memory bounds tPriv from below. A mark more than 1 h after the wall time
// adds 1 to the mark-ahead count. The first one writes one fixed log line with
// no time value. A run can end with no error. Then the mark in memory becomes
// the later of the mark and the wall time of the run. A run with an error does
// not change it. After an error, the next run reads the stored mark again.
// Before a read of the mark has succeeded, the run reads it again. It keeps the
// later of the two marks.
func (s *Schedule) runOnce(stop context.Context) {
	if !s.markRead {
		if m, ok := s.readMark(stop); ok {
			s.markRead = true
			if m.After(s.mark) {
				s.mark = m
			}
		}
	}
	clocked := s.w.clk != nil
	var wall, tDel, tPriv time.Time
	clockNow := s.clock.wall
	if clocked {
		// S is the one base of the cutoffs and of the mark. It has no
		// correction here, and it does not step with the wall clock.
		var err error
		if wall, _, err = s.read(); err != nil {
			s.clockFailed()
			return
		}
		tDel, tPriv = wall, wall
		clockNow = func() time.Time {
			if t, _, err := s.read(); err == nil {
				return t
			}
			return wall
		}
	} else {
		wall, tDel, tPriv = s.clock.reading(s.mark)
		if s.mark.Sub(wall) > clockLimit {
			s.markAhead.Add(1)
			if s.markLog.CompareAndSwap(false, true) {
				s.lg.Warn("retention mark is ahead of the wall clock")
			}
		}
	}
	ctx, cancel := context.WithTimeout(stop, s.limit)
	defer cancel()
	run := &retentionRun{}
	run.counts.CutoffIP, _ = retentionCutoff(tPriv, s.ip, 7)
	run.counts.CutoffRaw, _ = rollupCutoff(tDel, s.raw)
	// The mint order takes tDel, as the deletes do. A step forward of the wall
	// clock must not make mint units look old.
	steps := runStepsClock(wall, clockNow, tDel, tPriv, s.ip, s.raw, s.events)
	if clocked {
		steps[len(steps)-1] = markSet(wall)
	}
	steps = withCap(steps, run, s.w, s.maxBytes, s.dbRel, tDel, s.capUnmet, s.tune)
	err := s.run(withRun(ctx, run), steps)
	if err == nil && (clocked || wall.After(s.mark)) {
		s.mark = wall
	}
	if err != nil {
		s.markRead = false
	}
	if err != nil && stop.Err() == nil {
		s.earlyEnds.Add(1)
		if s.earlyLog.CompareAndSwap(false, true) {
			s.lg.Warn("retention run ended early")
		}
	}
}

// eventTime returns the time that the event step takes in place of tDel. The
// day step counts the callbacks of a UTC day only when the day is done. With
// events equal to raw, the event cutoff is the raw cutoff. Then the event step
// can delete the callbacks of that UTC day before the cutoff. The day step has
// not counted them yet. So the event cutoff is not later than the start of
// that UTC day. With events above raw, the cap has no effect. The writer can
// store a request row before the raw cutoff during the run. This occurs only
// when the wall clock steps back by raw days or more. Such a row that comes
// after the roll-up step and before the day step ends stops the day step. The
// event step then caps its cutoff in each chunk: see newEventExpireStep. The
// event step can delete such a row that comes after the day step, with no
// roll-up. With bad raw days or a zero tDel, the time is tDel. The event step
// itself refuses bad events days, for any time.
func eventTime(tDel time.Time, raw, events int) time.Time {
	cut, ok := rollupCutoff(tDel, raw)
	if !ok {
		return tDel
	}
	capped := time.UnixMilli(rollupDayStart(cut) + int64(events)*rollupDayMs)
	if capped.Before(tDel) {
		return capped
	}
	return tDel
}

// runSteps returns the steps of one run in order. The roll-up step and the day
// step come first: they read the session and event rows that later deletes
// remove. The delete of the refused and beacon rows comes before the field
// clear. Thus the clear does not write rows that the delete removes. The event,
// token and session deletes, which use retention_days.events, come after the
// roll-up steps. A request row that the run finds at its start rolls up
// before the event delete removes it. The configuration keeps the events days
// not below the raw days (internal/config/validate.go). The event step has a
// capped cutoff: see eventTime. It also caps the cutoff in each chunk at the
// day that the day step works on next. These three deletes come before the
// field clear, for the same reason as the raw delete. The clear does not write
// rows that the event delete removes. The clear takes the tPriv cutoff for its
// rows before the cutoff. The mark step is last, so a run that ends early
// writes no retention_last.
//
// The wall time of the run is `wall`. The mark step takes it. The field clear
// also takes it, as its wall time at its first call. This form is for tests
// that need no clock. See runStepsClock.
func runSteps(wall, tDel, tPriv time.Time, ip, raw, events int) []retentionStep {
	return runStepsClock(wall, func() time.Time { return wall }, tDel, tPriv, ip, raw, events)
}

// runStepsClock is runSteps with a clock. The mark step takes `wall`, the wall
// time at the start of the run. The field clear takes the time of `clock` at
// its first call. That call comes after the steps before it, so it can be
// long after the run start. With the run start, rows that the writer stores
// in between could lie after the future line. The schedule passes its wall
// clock as `clock`.
func runStepsClock(wall time.Time, clock func() time.Time, tDel, tPriv time.Time, ip, raw, events int) []retentionStep {
	return []retentionStep{
		newRollupStep(tDel, raw),
		newRollupDayStep(tDel, raw),
		newIPStep(tPriv, ip),
		newRawDeleteStep(tDel, raw),
		newCounterDeleteStep(tDel, raw),
		newEventExpireStep(eventTime(tDel, raw, events), events),
		newTokenExpireStep(tDel, events),
		newSessionExpireStep(tDel, events),
		newFieldClearStep(tPriv, clock, raw),
		newMintStep(tDel, raw),
		markStep(wall),
	}
}

// markSet is the mark step of a writer with a clock. It sets retention_last to
// the S of the run start, also when the old value is later. A mark that is
// after S is a mark of a clock that was wrong, so it must not stay.
func markSet(s time.Time) retentionStep {
	return func(ctx context.Context, tx *sql.Tx, limit int) (int, error) {
		return execN(ctx, tx, metaSetSQL, retentionLastKey, strconv.FormatInt(s.UnixMilli(), 10))
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
