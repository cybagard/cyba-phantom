package sensortime

import (
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
}

func clampMS(v int64) int64 { return min(max(v, 0), maxMS) }

func wallMS(src Source) int64 { return clampMS(src.Wall().UnixMilli()) }

// Start sets the sensor time at a process start (ADR-043 decisions 4 and 5).
// With the same host boot, S is the stored S plus the boot clock time since
// the stored value. Start does not read the wall clock then. Else S is the
// larger of the stored S and the wall clock. These cases refuse the start:
// a boot id error, a boot clock error, a bad stored state, or a known jump
// id out of range.
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
	c := &Clock{src: src, lastID: max(in.KnownJumpID, n.Jump.ID)}
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
	return c, Result{State: n, Jump: jump}, nil
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

// Now gives S. It is one load and one boot clock read. It reads no wall
// clock. On Linux and darwin, the boot clock of the source is not the Go
// monotonic clock, which stops in a host suspend. A boot clock error is
// returned, with no S. Two reads of one goroutine never go down while the
// boot clock does not go down.
func (c *Clock) Now() (int64, error) {
	b := c.base.Load()
	bc, err := c.src.BootClock()
	if err != nil {
		return 0, err
	}
	return b.at(bc), nil
}

// Snapshot gives the state for the hourly write and the stop write. S and
// the boot clock are of the same read. The rowid floor is the value of the
// start: the writer sets it before the write. It is for the check goroutine.
func (c *Clock) Snapshot() (State, error) {
	b := c.base.Load()
	bc, err := c.src.BootClock()
	if err != nil {
		return State{}, err
	}
	return c.snapshot(b.at(bc), bc), nil
}

func (c *Clock) snapshot(s int64, bc time.Duration) State {
	st := c.st
	st.S, st.BootClock = s, bc
	return st
}

// Check runs the grace (ADR-043 decision 6). It is for the check goroutine
// only. Take the two cases: the boot clock is under 6 h, or S is before
// the token epoch. Then S becomes the larger of S and the wall clock. A move
// of more than 1 h is a jump of kind grace. In other cases Check keeps S.
func (c *Clock) Check() (Result, error) {
	b := c.base.Load()
	bc, err := c.src.BootClock()
	if err != nil {
		return Result{}, err
	}
	s := b.at(bc)
	var jump *JumpResult
	if bc < graceBoot || s < epochMS {
		if wall := wallMS(c.src); wall > s {
			c.base.Store(&base{s: wall, boot: bc})
			if wall-s > jumpMinMS {
				jump = c.record(wall, wall-s, KindGrace)
			}
			s = wall
		}
	}
	return Result{State: c.snapshot(s, bc), Jump: jump}, nil
}
