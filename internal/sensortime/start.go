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
	// catchUpRate is the most that the catch-up adds for each unit of boot
	// clock time. S then moves at most 5 times as fast as the boot clock.
	catchUpRate = 4
	// writeMaxMS is the most that grace and catch-up moves may add up to
	// since the last key commit. More needs a write.
	writeMaxMS int64 = 600000
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
// made. The size of a grace jump is the grace sum U plus the move. The State
// of the same Result holds it as its last forward jump. The store writes the
// jump and the State in one transaction.
type JumpResult struct {
	ID   int64
	Size int64 // J in ms
	Kind string
}

// Result is what a start or a check gives to the writer.
type Result struct {
	// State is at the boot clock of the call. Its rowid floor is the value
	// of the start. The writer sets the floor before it writes the state.
	// Its S is the newest S, also the S of a move that waits. A read of this
	// S sets no read mark. Readers, metrics included, take S from Now.
	State State
	Jump  *JumpResult // nil when the call made no jump
	// Write is true when the writer must write the key. At a start, it is
	// always true. At a check, it is true for a jump. It is also true when
	// the move takes the moves since the last key commit over 10 min.
	// Readers get such a move only after the writer calls Committed. Start
	// is different: it publishes its S at once.
	Write bool
	// Read is set only at a check that gives a jump. It is true when a Now
	// marked a read since the Check of the last jump. It is also true for a
	// Now that was in flight at that Check. Before the first jump, it means
	// since Start. It can show more reads than there were. A read near the
	// swap of the mark can be in more than one report. Each read is in one or
	// more reports. A merge of two jumps is safe only when Read and Committed
	// of the later jump are both false.
	Read bool
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
// Now is safe from many goroutines. Check, Snapshot and Committed are for one
// goroutine, the check goroutine (the writer). They read and change the
// fields below that are for this goroutine.
type Clock struct {
	src  Source
	base atomic.Pointer[base]
	// read is the read mark. Now sets it before it loads the base. Check
	// swaps it to false at a jump, and sets it again when a Now is active.
	// Committed only reads it.
	read atomic.Bool
	// active counts the Now calls from before their mark to after their
	// load.
	active atomic.Int64
	// The fields below are for the check goroutine only.
	st     State // the state of the start. Check keeps the jump in it.
	lastID int64 // the largest jump id that this clock gave or knew
	log    *slog.Logger
	// The boot clock of the last Check, or of the start.
	lastBoot time.Duration
	// The wall time of the last Check. At the first Check, lastWall is 0.
	// A wall time is never below 0, so the first Check gives no step back.
	lastWall int64
	// pending is the newest base when a move waits for its key write. Now
	// does not see it. Snapshot works from it, and Check refuses.
	pending     *base
	pendingJump bool // pending holds a jump
	// w is W: the moves of S by the grace and the catch-up since the last
	// key commit. It is in memory only.
	w int64
}

func clampMS(v int64) int64 { return min(max(v, 0), maxMS) }

func wallMS(src Source) int64 { return clampMS(src.Wall().UnixMilli()) }

// Start sets the sensor time at a process start (ADR-043 decisions 4 and 5).
// With the same host boot, S is the stored S plus the boot clock time since
// the stored value. Start does not read the wall clock then. Else S is the
// larger of the stored S and the wall clock. The stored catch-up used stays
// in the first case, and is 0 in all other cases. A jump of the start gives
// one log line. These cases refuse the start. A boot id error. A boot clock
// error. A bad stored state. A known jump id out of range. A new jump id
// above 9223372036854.
//
// The grace sum of the stored state stays in the first case. In all other
// cases it is 0. A move of the start never adds to it. The result has Write
// set: the writer writes the key before it serves. Start publishes its base
// at once, because no reader exists before it returns. The caller must not
// give the clock to readers before the start key commits.
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
		n.CatchUp, n.GraceSum = 0, 0
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
	return c, Result{State: n, Jump: jump, Write: true}, nil
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

// Now gives S. It adds 1 to active, marks a read, reads the boot clock, and
// loads the base, in that order. Then it subtracts 1. The count lets a Check
// keep the mark of a Now that has not loaded yet. It reads no wall clock and
// makes no catch-up. The grace and the catch-up move S only at a Check. Now
// does not get a move that needs a key write until the writer calls
// Committed. On Linux and darwin, the boot clock of the source is not the Go
// monotonic clock. That clock stops in a host suspend. Now returns no S for a
// boot clock error or a boot clock below 0. A call that starts after
// another call has returned never gets a lower S. This holds while the boot
// clock does not go down.
func (c *Clock) Now() (int64, error) {
	// Add before the mark. Then a Check that swaps the mark away before
	// this Now marks still sees this Now in active.
	c.active.Add(1)
	// The decrement must run after the load. The defer does that.
	defer c.active.Add(-1)
	c.read.Store(true)
	bc, err := c.bootClock()
	if err != nil {
		return 0, err
	}
	return c.base.Load().at(bc), nil
}

// cur is the newest base: the pending base, or else the published one.
func (c *Clock) cur() *base {
	if c.pending != nil {
		return c.pending
	}
	return c.base.Load()
}

// Committed publishes the base of the move that waits, if any, and sets W to
// 0. The writer calls it only after a key commits. That key is of the last
// Check with Write, or of a later Snapshot. Between that Check or Snapshot
// and Committed, the writer calls no Check. After a failed COMMIT, the writer
// does not call Committed.
//
// Committed never changes the read mark. For a base that holds a jump, it
// returns true when a Now marked since the Check of this jump. For all other
// bases, it returns false. A read near the publish can be in this value and
// in the Read of the next jump. Each read is in one or more reports. Both
// values can show more reads than there were. A merge of two jumps is safe
// only when Read and Committed of the later jump are both false. It is for
// the check goroutine only.
func (c *Clock) Committed() bool {
	c.w = 0
	p := c.pending
	if p == nil {
		return false
	}
	// Store before the mark load. A Now that loads the old base has
	// marked before this load, so the load sees its mark.
	c.base.Store(p)
	jump := c.pendingJump
	c.pending, c.pendingJump = nil, false
	return jump && c.read.Load()
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
// the boot clock are of the same read. S is of the newest base, also when a
// move waits for its key write. A read of this S sets no read mark. Readers,
// metrics included, take S from Now. The rowid floor is the value of the
// start: the writer sets it before the write. It is for the check goroutine.
// The writer calls Committed after it commits this state. Between this
// Snapshot and that Committed, the writer calls no Check.
func (c *Clock) Snapshot() (State, error) {
	bc, err := c.bootClock()
	if err != nil {
		return State{}, err
	}
	return c.snapshot(c.cur().at(bc), bc), nil
}

func (c *Clock) snapshot(s int64, bc time.Duration) State {
	st := c.st
	st.S, st.BootClock = s, bc
	return st
}

// Check runs the grace and the catch-up (ADR-043 decisions 6 and 7). It is
// for the check goroutine only. It reads the wall clock one time.
//
// While a move waits for its key write, Check gives ErrPending at once. It
// reads no clock and changes nothing. The doc of Committed gives the order of
// the writer calls.
//
// The grace has two cases: the boot clock is under 6 h, or S is before the
// token epoch. Then S becomes the larger of S and the wall clock. Let m be
// the move. When the grace sum U plus m is over 1 h, the move is a jump of
// kind grace. Its size is U plus m, and U becomes 0. Else U becomes U plus m.
//
// In other cases, let d be wall minus S. When d is over 1 h, S gains the
// least of three values. The first is 4 times the boot clock time since the
// last Check (or the start). The second is d minus 1 h. The third is 24 h
// less the catch-up used. The state adds the gain to its catch-up used.
// The gain is no jump, and it adds nothing to U.
//
// A jump needs a key write. So does a move that takes W over 10 min. Then
// Write is true, and the move waits for Committed. Check publishes a move that
// needs no write at once. W is the grace and catch-up moves since the last key
// commit. One Check can gain up to 24 h. A gain over 10 min also waits for
// Committed. Read is set only for a jump.
//
// A jump needs a new jump id. When no id up to 9223372036854 is left, Check
// gives ErrState. It then changes nothing and writes no line.
//
// Check then writes lines at level Warn. One is for a jump. One is for a
// wall time before that of the last Check. One is for |wall - S| over 1 h
// after the move. One is for the Check where the catch-up used reaches 24 h.
func (c *Clock) Check() (Result, error) {
	if c.pending != nil {
		return Result{}, ErrPending
	}
	b := c.base.Load()
	bc, err := c.bootClock()
	if err != nil {
		return Result{}, err
	}
	wall := wallMS(c.src)
	s := b.at(bc)
	e := max(bc-c.lastBoot, 0)
	var jump *JumpResult
	var m int64
	exhausted, write, read := false, false, false
	if bc < graceBoot || s < epochMS {
		if wall > s {
			m = wall - s
			if u := c.st.GraceSum + m; u > jumpMinMS {
				if c.lastID >= maxMS {
					return Result{}, ErrState
				}
				jump = c.record(wall, u, KindGrace)
				c.st.GraceSum = 0
			} else {
				c.st.GraceSum = u
			}
			s = wall
		}
	} else if d := wall - s; d > jumpMinMS {
		// The gain cuts e to whole ms first, as Now does. A check of under
		// 1 ms gains 0. This is for liveness only: checks are minutes apart.
		m = min(catchUpRate*e.Milliseconds(), d-jumpMinMS,
			catchUpMaxMS-c.st.CatchUp)
		if m > 0 {
			s += m
			c.st.CatchUp += m
			exhausted = c.st.CatchUp == catchUpMaxMS
		}
	}
	// A boot clock that went down does not lower lastBoot. Else the time
	// from the low value back to lastBoot would count again in e.
	c.lastBoot = max(c.lastBoot, bc)
	if m > 0 {
		write = c.move(&base{s: s, boot: bc}, m, jump != nil)
	}
	if jump != nil {
		// Swap before the active load. A Now that adds after the load has
		// marked after the swap, so its mark stays.
		read = c.read.Swap(false)
		// A Now that marked before the swap can still load a later base.
		// The kept mark shows it again at the next jump.
		if c.active.Load() > 0 {
			c.read.Store(true)
		}
	}
	c.logJump(jump)
	if wall < c.lastWall {
		c.log.Warn(logStepBack, "back_ms", c.lastWall-wall)
	}
	c.lastWall = wall
	if off := wall - s; off > jumpMinMS || off < -jumpMinMS {
		c.log.Warn(logDiffers, "offset_ms", off, "s_ms", s)
	}
	if exhausted {
		c.log.Warn(logExhausted, "used_ms", c.st.CatchUp)
	}
	return Result{State: c.snapshot(s, bc), Jump: jump, Write: write,
		Read: read}, nil
}

// move adds the move of m ms to W and sets the new base nb. It reports if the
// move needs a key write. That is so for a jump and for W over 10 min. A move
// that needs a write is the pending base. Else it is published at once. Check
// calls move only when no move waits.
func (c *Clock) move(nb *base, m int64, jump bool) bool {
	c.w += m
	if !jump && c.w <= writeMaxMS {
		c.base.Store(nb)
		return false
	}
	c.pending = nb
	c.pendingJump = jump
	return true
}
