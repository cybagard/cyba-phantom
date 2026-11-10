package store

import (
	"log/slog"
	"sync/atomic"
	"time"
)

// clockLimit is the largest difference of the two clocks that a run accepts
// with no count (SEC-40).
const clockLimit = time.Hour

// clockGuard bounds the cutoffs of a retention run with a monotonic anchor
// (SEC-40). The anchor is one reading of time.Now at the start. T_mono is the
// wall time of the anchor plus the monotonic time since the anchor. A step of
// the wall clock does not move T_mono. On Linux a host suspend does not count
// in the monotonic clock. The difference is then a count, not a stop.
//
// A wall clock that is wrong at the start moves the anchor too. The guard does
// not see this error.
type clockGuard struct {
	anchor time.Time // the wall time of the anchor, with no monotonic part
	wall   func() time.Time
	mono   func() time.Duration // the monotonic time since the anchor
	lg     *slog.Logger

	diffs  atomic.Uint64
	logged atomic.Bool
}

// newClockGuard takes the anchor now. A test replaces the wall and mono fields.
func newClockGuard(lg *slog.Logger) *clockGuard {
	if lg == nil {
		lg = slog.New(slog.DiscardHandler)
	}
	a := time.Now()
	return &clockGuard{
		anchor: a.Round(0),
		wall:   func() time.Time { return time.Now().Round(0) },
		mono:   func() time.Duration { return time.Since(a) },
		lg:     lg,
	}
}

// reading returns the times of one run. Deletes use tDel, the earlier time, so
// no row goes before its age. The address and field steps use tPriv, the later
// time, so no address stays longer than its age. A difference of more than 1 h
// adds 1 to the count of the run. The first one writes one log line, with the
// difference in whole seconds as the only value.
func (c *clockGuard) reading() (wall, tDel, tPriv time.Time) {
	wall = c.wall()
	mono := c.anchor.Add(c.mono())
	tDel, tPriv = wall, mono
	if mono.Before(wall) {
		tDel, tPriv = mono, wall
	}
	if diff := tPriv.Sub(tDel); diff > clockLimit {
		c.diffs.Add(1)
		if c.logged.CompareAndSwap(false, true) {
			c.lg.Warn("wall clock differs from monotonic clock", "seconds", int64(diff/time.Second))
		}
	}
	return wall, tDel, tPriv
}

// Diffs returns the number of runs whose wall clock and monotonic clock
// differed by more than 1 h. It is safe to call from any goroutine.
func (c *clockGuard) Diffs() uint64 { return c.diffs.Load() }
