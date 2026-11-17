package sensortime

import (
	"log/slog"
	"sync/atomic"
	"time"
)

const (
	// epochMS is the token epoch, 2026-01-01T00:00:00Z, in unix ms. The
	// package does not import the token package. A test checks the value.
	epochMS int64 = 1767225600000
	// jumpMinMS is the size of a move of S that is not a jump. A move of
	// more than this is a jump.
	jumpMinMS int64 = 3600000
	// graceBoot is the grace G: the boot clock time in which a check
	// follows the wall clock.
	graceBoot = 6 * time.Hour
	// catchUpMaxMS is the most catch-up that one host boot may use.
	catchUpMaxMS int64 = 86400000
	// catchUpRate is the most that S gains for each unit of boot clock time.
	catchUpRate = 4
)

// Fixed texts of the log lines (ADR-043 decision 16). Each line has level
// Warn. Its attributes are integers, and kind of a jump is KindStart or
// KindGrace.
const (
	logJump      = "sensortime: forward jump of S"
	logStepBack  = "sensortime: wall clock step back"
	logDiffers   = "sensortime: wall clock differs from S"
	logExhausted = "sensortime: catch-up budget used"
)

// Kinds of a jump.
const (
	KindStart = "start"
	KindGrace = "grace"
)

// JumpResult is a forward jump of S of more than 1 h that a start or a check
// made. The State of the same Result holds it as its last forward jump. The
// store writes the jump and the State in one transaction.
type JumpResult struct {
	ID   int64
	Size int64 // J in ms
	Kind string
}

// Result is what a start or a check gives to the writer.
type Result struct {
	// State is at the boot clock of the call. Its rowid floor is the value
	// of the start. The writer sets the floor before it writes the state.
	State State
	Jump  *JumpResult // nil when the call made no jump
}

// StartInput is the input of Start.
type StartInput struct {
	Stored      *State // nil when there is no stored state
	NextEvent   int64  // next rowid of event, from the store
	NextSession int64  // next rowid of session, from the store
	KnownJumpID int64  // largest clock_jump id that the caller knows, or 0
	// Log gets the lines of the clock (jump, wall step back, wall differs,
	// catch-up budget used). Nil means no lines.
	Log *slog.Logger
}

// base is one value of S at one boot clock. It never changes after the store.
type base struct {
	s    int64
	boot time.Duration
}

// at gives S at the boot clock bc. A boot clock below the base counts as
// the base, so S never goes below the base.
func (b *base) at(bc time.Duration) int64 {
	return clampMS(b.s + max(bc-b.boot, 0).Milliseconds())
}

// Clock is the running sensor time.
//
// Now is safe from many goroutines. Check and Snapshot are for one
// goroutine, the check goroutine (the writer). They read fields
// that only Check changes.
type Clock struct {
	src  Source
	base atomic.Pointer[base]
	// The fields below are for the check goroutine only.
	st     State // the state of the start. Check keeps the jump in it.
	lastID int64 // the largest jump id that this clock gave or knew
	log    *slog.Logger
	// The boot clock of the last Check, or of the start.
	lastBoot time.Duration
	// The wall time of the last Check. It is valid when haveWall is true.
	lastWall int64
	haveWall bool
}

func clampMS(v int64) int64 { return min(max(v, 0), maxMS) }

func wallMS(src Source) int64 { return clampMS(src.Wall().UnixMilli()) }

// Start sets the sensor time at a process start (ADR-043 decisions 4 and 5).
// With the same host boot, S is the stored S plus the boot clock time since
// the stored value. Start does not read the wall clock then. Else S is the
// larger of the stored S and the wall clock. The stored catch-up used stays
// with the same host boot, and is 0 after another one. A jump of the start
// gives one log line. These cases refuse the start. A boot id error. A boot
// clock error. A bad stored state. A known jump id out of range. A new jump
// id above 9223372036854.
func Start(src Source, in StartInput) (*Clock, Result, error) {
	id, err := src.BootID()
	if err != nil {
		return nil, Result{}, err
	}
	if id != "" && !validUUID(id, false) {
		return nil, Result{}, ErrBootID
	}
	bc, err := src.BootClock()
	if err != nil {
		return nil, Result{}, err
	}
	if in.KnownJumpID < 0 || in.KnownJumpID > maxMS {
		return nil, Result{}, ErrState
	}
	st := in.Stored
	var n State
	if st != nil {
		if err := st.validate(); err != nil {
			return nil, Result{}, err
		}
		n = *st
	}
	n.BootID, n.BootClock = id, bc
	n.NextEvent = max(in.NextEvent, n.NextEvent)
	n.NextSession = max(in.NextSession, n.NextSession)
	c := &Clock{src: src, lastID: max(in.KnownJumpID, n.Jump.ID),
		log: in.Log, lastBoot: bc}
	if c.log == nil {
		c.log = slog.New(slog.DiscardHandler)
	}
	var jump *JumpResult
	if st != nil && id != "" && id == st.BootID && bc >= st.BootClock {
		n.S = clampMS(st.S + (bc - st.BootClock).Milliseconds())
		c.st = n
	} else {
		n.S = wallMS(src)
		if st != nil {
			n.S = max(st.S, n.S)
		}
		n.FirstEvent, n.FirstSession = n.NextEvent, n.NextSession
		n.CatchUp = 0
		c.st = n
		if st != nil && n.S-st.S > jumpMinMS {
			jump = c.record(n.S, n.S-st.S, KindStart)
			n = c.st
		}
	}
	if err := n.validate(); err != nil {
		return nil, Result{}, err
	}
	c.base.Store(&base{s: n.S, boot: bc})
	c.logJump(jump)
	return c, Result{State: n, Jump: jump}, nil
}

// logJump writes the line of a jump. A nil jump gives no line.
func (c *Clock) logJump(j *JumpResult) {
	if j != nil {
		c.log.Warn(logJump, "kind", j.Kind, "id", j.ID, "size_ms", j.Size)
	}
}

// record makes the last forward jump of size ms that ends at S = at. Its
// id is above every id that this clock gave or knew. Start sets lastID to
// at least the stored jump id.
func (c *Clock) record(at, size int64, kind string) *JumpResult {
	c.lastID++
	c.st.Jump = Jump{
		ID: c.lastID, Size: size, At: at,
		FirstEvent: c.st.FirstEvent, FirstSession: c.st.FirstSession,
	}
	return &JumpResult{ID: c.lastID, Size: size, Kind: kind}
}

// Now gives S. It is one boot clock read and one load, in that order. It
// reads no wall clock and makes no catch-up: S moves only at a Check. On
// Linux and darwin, the boot clock of the source is not the Go monotonic
// clock. That clock stops in a host suspend. A boot
// clock error, or a boot clock below 0, is returned with no S. A call that
// starts after another call has returned never gets a lower S. This holds
// while the boot clock does not go down.
func (c *Clock) Now() (int64, error) {
	bc, err := c.bootClock()
	if err != nil {
		return 0, err
	}
	return c.base.Load().at(bc), nil
}

// bootClock reads the boot clock of the source. A value below 0 is ErrState.
func (c *Clock) bootClock() (time.Duration, error) {
	bc, err := c.src.BootClock()
	if err != nil {
		return 0, err
	}
	if bc < 0 {
		return 0, ErrState
	}
	return bc, nil
}

// Snapshot gives the state for the hourly write and the stop write. S and
// the boot clock are of the same read. The rowid floor is the value of the
// start: the writer sets it before the write. It is for the check goroutine.
func (c *Clock) Snapshot() (State, error) {
	bc, err := c.bootClock()
	if err != nil {
		return State{}, err
	}
	return c.snapshot(c.base.Load().at(bc), bc), nil
}

func (c *Clock) snapshot(s int64, bc time.Duration) State {
	st := c.st
	st.S, st.BootClock = s, bc
	return st
}

// Check runs the grace and the catch-up (ADR-043 decisions 6 and 7). It is
// for the check goroutine only. It reads the wall clock one time.
//
// The grace has two cases: the boot clock is under 6 h, or S is before the
// token epoch. Then S becomes the larger of S and the wall clock. A move of
// more than 1 h is a jump of kind grace.
//
// In other cases, let d be wall minus S. When d is over 1 h, S gains the
// least of three values. The first is 4 times the boot clock time since the
// last Check (or the start). The second is d minus 1 h. The third is 24 h
// less the catch-up used. The state adds the gain to its catch-up used.
// The gain is no jump.
//
// Check then writes lines at level Warn. One is for a jump. One is for a
// wall time before that of the last Check. One is for |wall - S| over 1 h
// after the move. One is for the Check where the catch-up used reaches 24 h.
func (c *Clock) Check() (Result, error) {
	b := c.base.Load()
	bc, err := c.bootClock()
	if err != nil {
		return Result{}, err
	}
	wall := wallMS(c.src)
	s := b.at(bc)
	e := max(bc-c.lastBoot, 0)
	c.lastBoot = bc
	var jump *JumpResult
	exhausted := false
	if bc < graceBoot || s < epochMS {
		if wall > s {
			c.base.Store(&base{s: wall, boot: bc})
			if wall-s > jumpMinMS {
				jump = c.record(wall, wall-s, KindGrace)
			}
			s = wall
		}
	} else if d := wall - s; d > jumpMinMS {
		g := min(catchUpRate*e.Milliseconds(), d-jumpMinMS,
			catchUpMaxMS-c.st.CatchUp)
		if g > 0 {
			s += g
			c.base.Store(&base{s: s, boot: bc})
			c.st.CatchUp += g
			exhausted = c.st.CatchUp == catchUpMaxMS
		}
	}
	c.logJump(jump)
	if c.haveWall && wall < c.lastWall {
		c.log.Warn(logStepBack, "back_ms", c.lastWall-wall)
	}
	c.lastWall, c.haveWall = wall, true
	if off := wall - s; off > jumpMinMS || off < -jumpMinMS {
		c.log.Warn(logDiffers, "offset_ms", off, "s_ms", s)
	}
	if exhausted {
		c.log.Warn(logExhausted, "used_ms", c.st.CatchUp)
	}
	return Result{State: c.snapshot(s, bc), Jump: jump}, nil
}
