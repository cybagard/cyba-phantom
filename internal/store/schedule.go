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

	// readLimit is the time that the read of the mark at the start can take.
	readLimit = 30 * time.Second

	// catchUp is the age of the last run above which the start runs at once. A
	// check also starts a run when this boot clock time has passed since the
	// start of the last run.
	catchUp = 25 * time.Hour

	// retentionLastKey is the meta key of S at the start of the last run, in
	// unix ms as decimal text.
	retentionLastKey = "retention_last"
)

// Schedule starts one retention run for each local date of S (SEC-40, ADR-043).
// The run is at the first minute check at or after 03:15. It never starts two
// runs at the same time. A start after more than 25 h without a run gives a run
// at once. A check also starts a run after 25 h of boot clock since the start
// of the last run.
type Schedule struct {
	w         *Writer
	loc       *time.Location
	ip, raw   int // the days of the address step and of the raw rows
	events    int // the days of the event, token and session rows
	lg        *slog.Logger
	tick      <-chan time.Time // nil means a ticker of one minute
	run       func(ctx context.Context, steps []retentionStep) error
	lastDay   string        // the retention day of the last run
	limit     time.Duration // the time that one run can take
	readTime  time.Duration // the time that a read of the mark can take
	began     chan struct{} // closed when the start check ends
	lastRun   time.Duration // the boot clock time of the start of the last run
	earlyEnds atomic.Uint64
	earlyLog  atomic.Bool
	clockLog  atomic.Bool
	// mono is the time since NewSchedule. It is not a boot clock. A writer with
	// no clock uses it in place of one. A test replaces it.
	mono     func() time.Duration
	maxBytes int64  // store.max_bytes; 0 means no cap step
	dbRel    string // the name that SetMaxBytes checked, relative to the root
	capLog   atomic.Bool
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
	start := time.Now()
	return &Schedule{w: w, loc: time.Local, ip: ipDays, raw: rawDays,
		events: eventsDays, lg: lg, run: w.runSteps, limit: runLimit,
		readTime: readLimit, began: make(chan struct{}),
		mono: func() time.Duration { return time.Since(start) }}
}

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
// is 0, so it is old. A mark after S is old too: S was ahead at the last run.
// The run sets the mark to S. This run counts for the rule of 25 h in check.
//
// The schedule reads S and the boot clock in read. A clock error starts no run.
// The last run day then stays empty, so the first good check starts a run. The
// boot clock of the start counts as the start of the last run, also when no run
// starts.
func (s *Schedule) begin(ctx context.Context) {
	st, mono, err := s.read()
	if err != nil {
		s.clockFailed()
		return
	}
	s.lastRun = mono
	mark := s.readMark(ctx)
	if st.Sub(mark) > catchUp || mark.After(st) {
		s.runAt(ctx, st)
		s.lastDay = retentionDay(st, s.loc)
		return
	}
	s.lastDay = retentionDay(mark, s.loc)
}

// readMark reads the stored mark of the last run. No mark, a failed read, or
// text that is not a number, gives the time 0.
func (s *Schedule) readMark(ctx context.Context) time.Time {
	rctx, cancel := context.WithTimeout(ctx, s.readTime)
	defer cancel()
	var v string
	_ = s.w.db.QueryRowContext(rctx, metaGetSQL, retentionLastKey).Scan(&v)
	ms, _ := strconv.ParseInt(v, 10, 64)
	return time.UnixMilli(ms)
}

// check starts a run in two cases. The retention day of S is later than the
// last run day. Or 25 h of boot clock have passed since the start of the last
// run. Each kind of run counts. The time counts from the start of the
// schedule when no run has started. A local time that goes back in a DST
// repeat gives an earlier day, and that day has run. A check starts at most
// one run. A clock error starts no run.
func (s *Schedule) check(ctx context.Context) {
	st, now, err := s.read()
	if err != nil {
		s.clockFailed()
		return
	}
	day := retentionDay(st, s.loc)
	if day > s.lastDay || now-s.lastRun >= catchUp {
		s.lastDay = max(s.lastDay, day)
		s.lastRun = now
		s.runAt(ctx, st)
	}
}

// read gives S and the boot clock time of one check. A writer with a clock
// gives S and the boot clock of its source. A writer with no clock gives
// w.stored and the time since NewSchedule.
func (s *Schedule) read() (st time.Time, mono time.Duration, err error) {
	st, err = s.w.stored()
	if err != nil {
		return st, 0, err
	}
	if s.w.clk == nil {
		return st, s.mono(), nil
	}
	mono, err = s.w.src.BootClock()
	return st, mono, err
}

// clockFailed writes one fixed log line for a clock error, one time only.
func (s *Schedule) clockFailed() {
	if s.clockLog.CompareAndSwap(false, true) {
		s.lg.Error("retention cannot read the clock")
	}
}

// runOnce makes one run with S as its time. It reads S first. A clock error
// then starts no run. A run can end with an error that is not the stop of the
// schedule. Then it adds 1 to the early-end count. The first early end writes
// one log line.
func (s *Schedule) runOnce(stop context.Context) {
	st, _, err := s.read()
	if err != nil {
		s.clockFailed()
		return
	}
	s.runAt(stop, st)
}

// runAt is runOnce with the S that begin or check read. S is the run date.
// It is also the base of the cutoffs and of the mark. So the run does not read
// it again. It has no correction here, and it does not step with the wall
// clock.
func (s *Schedule) runAt(stop context.Context, st time.Time) {
	clockNow := func() time.Time {
		if t, _, err := s.read(); err == nil {
			return t
		}
		return st
	}
	ctx, cancel := context.WithTimeout(stop, s.limit)
	defer cancel()
	run := &retentionRun{}
	run.counts.CutoffIP, _ = retentionCutoff(st, s.ip, 7)
	run.counts.CutoffRaw, _ = rollupCutoff(st, s.raw)
	steps := runStepsClock(st, clockNow, st, st, s.ip, s.raw, s.events)
	steps = withCap(steps, run, s.w, s.maxBytes, s.dbRel, st, s.capUnmet, s.tune)
	err := s.run(withRun(ctx, run), steps)
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
// store a request row before the raw cutoff during the run. The S of a writer
// with a clock does not step back in one process. So such a row has a time
// from another clock, for example time.Now in the bait handler. Such a row
// that comes after the roll-up step and before the day step ends stops the day
// step. The event step then caps its cutoff in each chunk: see
// newEventExpireStep. The event step can delete such a row that comes after
// the day step, with no roll-up. With bad raw days or a zero tDel, the time is
// tDel. The event step itself refuses bad events days, for any time.
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
// rows that the event delete removes. The clear takes its cutoff from tPriv.
// The mark step is last, so a run that ends early writes no retention_last.
//
// The time of the run is `st`. The mark step takes it. The field clear also
// takes it, as its time at its first call. This form is for tests that need no
// clock. See runStepsClock.
func runSteps(st, tDel, tPriv time.Time, ip, raw, events int) []retentionStep {
	return runStepsClock(st, func() time.Time { return st }, tDel, tPriv, ip, raw, events)
}

// runStepsClock is runSteps with a clock. The mark step takes `st`, the S at
// the start of the run. The field clear takes the time of `clock` at its first
// call. That call comes after the steps before it, so it can be long after the
// run start. With the run start, rows that the writer stores in between could
// lie after the future line. The schedule passes a function that reads S as
// `clock`.
func runStepsClock(st time.Time, clock func() time.Time, tDel, tPriv time.Time, ip, raw, events int) []retentionStep {
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
		markStep(st),
	}
}

// markStep is the mark step. It sets retention_last to the S of the run start,
// also when the old value is later. A mark that is after S is a mark of a clock
// that was wrong, so it must not stay.
func markStep(s time.Time) retentionStep {
	return func(ctx context.Context, tx *sql.Tx, limit int) (int, error) {
		return execN(ctx, tx, metaSetSQL, retentionLastKey, strconv.FormatInt(s.UnixMilli(), 10))
	}
}
