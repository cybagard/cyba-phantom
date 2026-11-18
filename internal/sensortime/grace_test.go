package sensortime

import (
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// graceSim starts a clock on the same host boot at boot clock 1 h, S = s0.
func graceSim(t *testing.T) *sim {
	return newSim(t, s0, time.Hour, goodID, stored(s0, goodID, time.Hour))
}

// T-U-30 (grace sum): 359 checks, each with the wall 59 min ahead. The
// simulated writer calls Committed after each result with Write. Each second
// check is a grace jump of more than 1 h and at most 2 h. A start that takes
// the reboot rule sets U to 0. A start on the same host boot keeps U.
func TestTU30_GraceSumRamp(t *testing.T) {
	m := newSim(t, s0, 0, goodID, nil)
	for i := 1; i <= 359; i++ {
		r := m.set(minute, m.res.State.S+hourMS)
		wantU := int64(59 * 60000)
		if i%2 == 0 {
			wantU = 0
			if r.Jump == nil || r.Jump.Size <= hourMS || r.Jump.Size > 2*hourMS ||
				r.State.Jump.Size != r.Jump.Size {
				t.Fatalf("check %d: jump %+v", i, r.Jump)
			}
		} else if r.Jump != nil {
			t.Fatalf("check %d: jump %+v", i, r.Jump)
		}
		if !r.Write || r.State.GraceSum != wantU {
			t.Fatalf("check %d: write %v, U %d", i, r.Write, r.State.GraceSum)
		}
	}
	if len(m.jumps) != 179 {
		t.Fatalf("%d jumps, want 179", len(m.jumps))
	}
	// Check 359 left U at 59 min. It survives a restart on the same host boot.
	n := restart(t, m)
	if n.res.State.GraceSum != 59*60000 || !n.res.Write || n.res.Jump != nil {
		t.Fatalf("restart: %+v", n.res)
	}
	// A reboot start sets U to 0. Its move of 30 min does not add to U.
	snap, _ := n.c.Snapshot()
	n.f.id = otherID
	n.f.wall.Store(snap.S + 30*60000)
	k := startSim(t, n.f, &snap)
	if k.res.State.GraceSum != 0 || k.res.State.S != snap.S+30*60000 ||
		k.res.Jump != nil {
		t.Fatalf("reboot: %+v", k.res)
	}
}

// A sum of exactly 1 h is no jump. One more ms is a jump with J = U + m.
func TestTU30_GraceSumEdge(t *testing.T) {
	m := graceSim(t)
	m.set(0, s0+30*60000)
	m.set(0, s0+hourMS)
	if m.res.Jump != nil || m.res.State.GraceSum != hourMS {
		t.Fatalf("sum of 1 h: %+v", m.res)
	}
	m.set(0, s0+hourMS+1)
	if m.res.Jump == nil || m.res.Jump.Size != hourMS+1 ||
		m.res.State.GraceSum != 0 || m.res.State.Jump.Size != hourMS+1 {
		t.Fatalf("sum over 1 h: %+v", m.res)
	}
}

// The catch-up adds nothing to U.
func TestTU30_CatchUpKeepsGraceSum(t *testing.T) {
	st := stored(s0, goodID, 7*time.Hour)
	st.GraceSum = 30 * 60000
	m := newSim(t, s0+3*dayMS, 7*time.Hour, goodID, st)
	m.tick(minute)
	if m.res.State.GraceSum != 30*60000 || m.res.State.S != s0+5*60000 {
		t.Fatalf("state %+v", m.res.State)
	}
}

// Two grace jumps with no Now between them report no read. With a Now between
// them they report a read. A Now between the Check of a jump and Committed
// shows in the value of Committed. It also shows in the Read of the next jump.
func TestTU30_ReadMarkAtJump(t *testing.T) {
	m := graceSim(t)
	m.set(0, s0+2*hourMS)
	m.set(0, s0+4*hourMS)
	if m.res.Jump == nil || m.res.Read || m.pub {
		t.Fatalf("no Now: %+v, committed %v", m.res, m.pub)
	}
	mustNow(t, m.c)
	m.set(0, s0+6*hourMS)
	if m.res.Jump == nil || !m.res.Read || m.pub {
		t.Fatalf("one Now: %+v, committed %v", m.res, m.pub)
	}
	// The Check cleared the mark.
	m.set(0, s0+8*hourMS)
	if m.res.Jump == nil || m.res.Read {
		t.Fatalf("after a read: %+v", m.res)
	}
	m.hold = true
	m.set(0, s0+10*hourMS)
	if m.res.Read || !m.res.Write {
		t.Fatalf("held jump: %+v", m.res)
	}
	if got := mustNow(t, m.c); got != s0+8*hourMS {
		t.Fatalf("Now %d during the hold", got)
	}
	if !m.c.Committed() {
		t.Fatal("Committed lost a read between the Check and the publish")
	}
	m.hold = false
	m.set(0, s0+12*hourMS)
	if m.res.Jump == nil || !m.res.Read {
		t.Fatalf("Committed cleared the mark: %+v", m.res)
	}
	m.set(0, s0+14*hourMS)
	if m.res.Jump == nil || m.res.Read {
		t.Fatalf("read counted three times: %+v", m.res)
	}
	// A publish with no jump does not clear the mark or report it.
	k := graceSim(t)
	mustNow(t, k.c)
	k.hold = true
	k.set(0, s0+30*60000)
	if k.res.Jump != nil || !k.res.Write || k.c.Committed() {
		t.Fatalf("move without jump: %+v", k.res)
	}
	k.hold = false
	k.set(0, s0+91*60000)
	if k.res.Jump == nil || !k.res.Read {
		t.Fatalf("read lost: %+v", k.res)
	}
}

// Now marks the read before it reads the boot clock, so also before the load
// of the base. The test looks at the mark inside the boot clock read.
func TestTU30_NowMarksBeforeLoad(t *testing.T) {
	f := newFake(s0, time.Hour, goodID)
	src := f.source()
	var c *Clock
	marked := false
	inner := src.BootClock
	src.BootClock = func() (time.Duration, error) {
		if c != nil {
			marked = c.read.Load()
		}
		return inner()
	}
	c, _, err := Start(src, StartInput{Stored: stored(s0, goodID, time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	mustNow(t, c)
	if !marked {
		t.Fatal("Now had not marked the read at its boot clock read")
	}
}

// A move that needs a key write is not seen by Now until Committed. With no
// Committed, Now keeps the old S. This holds for a jump, for W over 10 min,
// and for a catch-up gain over 10 min. W of exactly 10 min needs no write.
func TestTU30_MoveWaitsForCommit(t *testing.T) {
	// A jump. Snapshot and Check work from the newest S.
	m := graceSim(t)
	m.hold = true
	m.set(0, s0+2*hourMS)
	if !m.res.Write || m.res.Jump == nil {
		t.Fatalf("jump: %+v", m.res)
	}
	if got := mustNow(t, m.c); got != s0 {
		t.Fatalf("Now %d before Committed", got)
	}
	if snap, err := m.c.Snapshot(); err != nil || snap.S != s0+2*hourMS {
		t.Fatalf("snapshot %+v, %v", snap, err)
	}
	// No Committed: after 1 h of boot clock, Now has the old S only.
	m.f.boot.Add(int64(time.Hour))
	if got := mustNow(t, m.c); got != s0+hourMS {
		t.Fatalf("Now %d with no Committed", got)
	}
	m.c.Committed()
	if got := mustNow(t, m.c); got != s0+2*hourMS+hourMS {
		t.Fatalf("Now %d after Committed", got)
	}

	// W over 10 min. Moves of 5 min twice make 10 min: no write. 1 ms more.
	w := graceSim(t)
	w.hold = true
	for i := int64(1); i <= 2; i++ {
		w.set(0, s0+i*5*60000)
		if w.res.Write || mustNow(t, w.c) != s0+i*5*60000 {
			t.Fatalf("move %d: %+v", i, w.res)
		}
	}
	w.set(0, s0+10*60000+1)
	if !w.res.Write || w.res.Jump != nil || mustNow(t, w.c) != s0+10*60000 {
		t.Fatalf("move over 10 min: %+v", w.res)
	}
	w.c.Committed()
	if mustNow(t, w.c) != s0+10*60000+1 {
		t.Fatal("Now has the old S after Committed")
	}
	// Committed sets W to 0: the next move of 7 min needs no write.
	w.set(0, s0+17*60000+1)
	if w.res.Write {
		t.Fatalf("W not reset: %+v", w.res)
	}

	// A catch-up gain of 10 min needs no write. A gain of 12 min does.
	k := catchClock(t, 3*dayMS, 0)
	k.hold = true
	k.tick(150 * time.Second)
	if k.res.Write || k.res.State.CatchUp != 10*60000 {
		t.Fatalf("catch-up of 10 min: %+v", k.res)
	}
	k = catchClock(t, 3*dayMS, 0)
	k.hold = true
	k.tick(3 * minute)
	if !k.res.Write || k.res.Jump != nil || k.res.State.S != s0+15*60000 {
		t.Fatalf("catch-up of 12 min: %+v", k.res)
	}
	if got := mustNow(t, k.c); got != s0+3*60000 {
		t.Fatalf("Now %d before Committed", got)
	}
	k.c.Committed()
	if got := mustNow(t, k.c); got != s0+15*60000 {
		t.Fatalf("Now %d after Committed", got)
	}
}

// Committed with no pending base only sets W to 0.
func TestTU30_CommittedWithNothingPending(t *testing.T) {
	m := graceSim(t)
	m.set(0, s0+6*60000)
	if m.res.Write || m.c.Committed() {
		t.Fatalf("result %+v", m.res)
	}
	// W is 0, so a move of 6 min needs no write.
	m.set(0, s0+12*60000)
	if m.res.Write {
		t.Fatalf("result %+v", m.res)
	}
}

// Grace moves of 7 min each, then a stop before a write. A start from the
// last written state gives S at most 10 min below the largest S of a Now.
// The last written state is the last State that Committed followed.
// It is not the last State that Check gave.
func TestTU30_StopBeforeWriteLosesAtMost10Min(t *testing.T) {
	m := newSim(t, s0, 0, goodID, nil)
	written := m.res.State // the start writes its key
	m.c.Committed()
	largest, worst := mustNow(t, m.c), int64(0)
	for i := 0; i < 40; i++ {
		m.hold = true
		r := m.set(minute, m.res.State.S+7*60000+60000)
		if r.Write {
			written = r.State
			m.c.Committed()
		}
		largest = max(largest, mustNow(t, m.c))
		// A start on the same host boot, from the written state.
		c, _, err := Start(m.f.source(), StartInput{Stored: &written})
		if err != nil {
			t.Fatal(err)
		}
		got := mustNow(t, c)
		lost := largest - got
		if lost < 0 || lost > 10*60000 {
			t.Fatalf("check %d: S %d, largest %d", i, got, largest)
		}
		worst = max(worst, lost)
	}
	if worst < 7*60000 {
		t.Fatalf("the test lost at most %d ms: it does not test the stop", worst)
	}
}

// A start gives Write, and it publishes its base at once.
func TestTU30_StartWritesTheKey(t *testing.T) {
	m := newSim(t, s0, 0, goodID, nil)
	if !m.res.Write || m.res.Read || mustNow(t, m.c) != s0 {
		t.Fatalf("start with no state: %+v", m.res)
	}
	k := graceSim(t)
	if !k.res.Write || mustNow(t, k.c) != s0 {
		t.Fatalf("start on the same host boot: %+v", k.res)
	}
}

// A boot clock that goes down in Check does not lower the last boot clock.
// Else the time between the low value and the last value counts again.
func TestTU30_BootClockDownThenUpNoReplay(t *testing.T) {
	m := catchClock(t, 3*dayMS, 0)
	m.set(-30*minute, s0+3*dayMS)
	m.wantS(s0)
	if m.res.State.CatchUp != 0 {
		t.Fatalf("catch-up %d with a lower boot clock", m.res.State.CatchUp)
	}
	// 1 min above the start: 4 min of catch-up. Not 31 min of boot clock.
	m.set(31*minute, s0+3*dayMS)
	m.wantS(s0 + 5*60000)
	if m.res.State.CatchUp != 4*60000 {
		t.Fatalf("catch-up %d", m.res.State.CatchUp)
	}
}

// A start that the last check of the state refuses writes no log line. The
// new jump id is 9223372036854 + 1.
func TestTU30_RefusedStartWritesNoJumpLine(t *testing.T) {
	rec := &recorder{}
	f := newFake(s0+2*hourMS, 3*time.Hour, otherID)
	_, _, err := Start(f.source(), StartInput{Stored: stored(s0, goodID, time.Hour),
		KnownJumpID: boundMS, Log: slog.New(rec)})
	if err != ErrState || len(rec.lines) != 0 {
		t.Fatalf("err %v, lines %d", err, len(rec.lines))
	}
}

// At exactly 6 h of boot clock, the catch-up runs. It starts when the boot
// clock is not below 6 h.
func TestTU30_CatchUpAtExactlyGraceBoot(t *testing.T) {
	st := stored(s0, goodID, 5*time.Hour+50*minute)
	m := newSim(t, s0+3*dayMS, 5*time.Hour+50*minute, goodID, st)
	m.set(10*minute, s0+3*dayMS)
	if m.f.boot.Load() != int64(graceBoot) {
		t.Fatal("the boot clock is not 6 h")
	}
	// 10 min of boot clock and 40 min of catch-up.
	m.wantS(s0 + 50*60000)
	if m.res.State.CatchUp != st.CatchUp+40*60000 || m.res.Jump != nil {
		t.Fatalf("state %+v", m.res.State)
	}
}

// The gain is catchUpRate times the whole ms of the boot clock time. A time
// under 1 ms gains 0. The next ms of time gains its own 4.
func TestTU30_CatchUpGainCutsToMilliseconds(t *testing.T) {
	m := catchClock(t, 3*dayMS, 0)
	m.set(900*time.Microsecond, s0+3*dayMS)
	m.wantS(s0)
	if m.res.State.CatchUp != 0 {
		t.Fatalf("catch-up %d for 0.9 ms", m.res.State.CatchUp)
	}
	k := catchClock(t, 3*dayMS, 0)
	k.set(1500*time.Microsecond, s0+3*dayMS)
	// S moved 1 ms with the boot clock. The gain is 4, not 6.
	k.wantS(s0 + 1 + 4)
	if k.res.State.CatchUp != 4 {
		t.Fatalf("catch-up %d for 1.5 ms", k.res.State.CatchUp)
	}
}

// Check in the grace reads the wall clock one time.
func TestTU30_GraceCheckReadsWallOnce(t *testing.T) {
	for _, off := range []int64{-hourMS, 0, 2 * hourMS} {
		f, c := graceClock(t, s0, time.Hour)
		f.wall.Store(s0 + off)
		calls := f.wallCalls.Load()
		if _, err := c.Check(); err != nil {
			t.Fatal(err)
		}
		if got := f.wallCalls.Load() - calls; got != 1 {
			t.Fatalf("wall offset %d: %d reads", off, got)
		}
	}
}

// gate holds one Now between its mark and its load. The Now waits in its
// boot clock read.
type gate struct {
	c       *Clock
	armed   atomic.Bool
	in, out chan struct{}
	got     chan int64
}

// gatedSim is a graceSim with a gate. The simulated writer is stopped: a test
// calls Committed itself.
func gatedSim(t *testing.T) (*sim, *gate) {
	t.Helper()
	g := &gate{in: make(chan struct{}), out: make(chan struct{}),
		got: make(chan int64, 1)}
	f := newFake(s0, time.Hour, goodID)
	src := f.source()
	inner := src.BootClock
	src.BootClock = func() (time.Duration, error) {
		if g.armed.CompareAndSwap(true, false) {
			g.in <- struct{}{}
			<-g.out
		}
		return inner()
	}
	m := &sim{t: t, f: f, rec: &recorder{}, hold: true}
	c, r, err := Start(src, StartInput{Stored: stored(s0, goodID, time.Hour),
		Log: slog.New(m.rec)})
	if err != nil {
		t.Fatal(err)
	}
	m.c, m.res, g.c = c, r, c
	return m, g
}

// start runs a Now and waits until it sits between its mark and its load.
func (g *gate) start() {
	g.armed.Store(true)
	go func() {
		s, err := g.c.Now()
		if err != nil {
			s = -1
		}
		g.got <- s
	}()
	<-g.in
}

// release lets the held Now load its base and gives the S of that Now.
func (g *gate) release(t *testing.T) int64 {
	t.Helper()
	g.out <- struct{}{}
	s := <-g.got
	if s < 0 {
		t.Fatal("the held Now gave an error")
	}
	return s
}

// A Now marks and is held before the Check of jump k. The Check reports the
// read, and the mark stays. The Now loads the new S after Committed. The Check
// of jump k+1 reports the read again.
func TestTU30_ReadInFlightAtJumpIsNotLost(t *testing.T) {
	m, g := gatedSim(t)
	g.start()
	m.set(0, s0+2*hourMS)
	if m.res.Jump == nil || !m.res.Read {
		t.Fatalf("jump k: %+v", m.res)
	}
	m.c.Committed()
	if got := g.release(t); got != s0+2*hourMS {
		t.Fatalf("held Now %d, want the new S", got)
	}
	m.set(0, s0+4*hourMS)
	if m.res.Jump == nil || !m.res.Read {
		t.Fatalf("read lost at jump k+1: %+v", m.res)
	}
}

// A Now marks after the Check of jump k and is held. Committed reports the
// read and does not clear the mark. The Now loads the new S. The Check of jump
// k+1 reports the read.
func TestTU30_ReadMarkedAfterCheckIsNotLost(t *testing.T) {
	m, g := gatedSim(t)
	m.set(0, s0+2*hourMS)
	if m.res.Jump == nil || m.res.Read {
		t.Fatalf("jump k: %+v", m.res)
	}
	g.start()
	if !m.c.Committed() {
		t.Fatal("Committed did not report the read of the held Now")
	}
	if got := g.release(t); got != s0+2*hourMS {
		t.Fatalf("held Now %d, want the new S", got)
	}
	m.set(0, s0+4*hourMS)
	if m.res.Jump == nil || !m.res.Read {
		t.Fatalf("read lost at jump k+1: %+v", m.res)
	}
}

// A Now marks after the Check of jump k and loads the old S, before
// Committed. Committed reports it.
func TestTU30_ReadOfOldSInCommitted(t *testing.T) {
	m := graceSim(t)
	m.hold = true
	m.set(0, s0+2*hourMS)
	if got := mustNow(t, m.c); got != s0 {
		t.Fatalf("Now %d before Committed", got)
	}
	if !m.c.Committed() {
		t.Fatal("Committed did not report the read")
	}
}

// With no Now, the Read and the Committed of each jump are false.
func TestTU30_NoNowNoRead(t *testing.T) {
	m := graceSim(t)
	m.hold = true
	for i := int64(1); i <= 4; i++ {
		m.set(0, s0+2*i*hourMS)
		if m.res.Jump == nil || m.res.Read || m.c.Committed() {
			t.Fatalf("jump %d: %+v", i, m.res)
		}
	}
}

// A jump of a small move: U is 59 min and the move is 2 min. So W is 2 min.
// Only the jump needs the write. Now keeps the old S until Committed.
func TestTU30_JumpOfSmallMoveWaitsForCommit(t *testing.T) {
	m := graceSim(t)
	m.set(0, s0+59*60000)
	if m.res.Jump != nil || m.res.State.GraceSum != 59*60000 {
		t.Fatalf("setup: %+v", m.res)
	}
	m.hold = true
	m.set(0, s0+61*60000)
	if m.res.Jump == nil || m.res.Jump.Size != 61*60000 || !m.res.Write {
		t.Fatalf("small jump: %+v", m.res)
	}
	if got := mustNow(t, m.c); got != s0+59*60000 {
		t.Fatalf("Now %d before Committed", got)
	}
	m.c.Committed()
	if got := mustNow(t, m.c); got != s0+61*60000 {
		t.Fatalf("Now %d after Committed", got)
	}
}

// A Check while a move waits gives ErrPending. It reads no clock and changes
// nothing. The fields, Snapshot, Now, the log and the next Committed are as
// with no second Check.
func TestTU30_CheckRefusesWhileMoveWaits(t *testing.T) {
	type outcome struct {
		snap          State
		before, after int64
		pub           bool
		lines         int
	}
	run := func(refuse bool) outcome {
		m := graceSim(t)
		m.hold = true
		m.set(0, s0+2*hourMS)
		if !m.res.Write || m.res.Jump == nil {
			t.Fatalf("jump: %+v", m.res)
		}
		if refuse {
			c := m.c
			st, lastBoot, lastWall, w := c.st, c.lastBoot, c.lastWall, c.w
			lastID, pending, pj, mark := c.lastID, c.pending, c.pendingJump,
				c.read.Load()
			m.f.boot.Add(int64(minute))
			m.f.wall.Store(s0 + 30*dayMS)
			calls := m.f.wallCalls.Load()
			r, err := c.Check()
			if err != ErrPending || r.Jump != nil || r.Write || r.Read ||
				r.State != (State{}) {
				t.Fatalf("second Check: %+v, %v", r, err)
			}
			if m.f.wallCalls.Load() != calls {
				t.Fatal("the refused Check read the wall clock")
			}
			if c.st != st || c.lastBoot != lastBoot || c.lastWall != lastWall ||
				c.w != w || c.lastID != lastID || c.pending != pending ||
				c.pendingJump != pj || c.read.Load() != mark {
				t.Fatal("the refused Check changed a field")
			}
			m.f.boot.Add(-int64(minute))
		}
		var o outcome
		var err error
		if o.snap, err = m.c.Snapshot(); err != nil {
			t.Fatal(err)
		}
		o.before = mustNow(t, m.c)
		o.pub = m.c.Committed()
		o.after = mustNow(t, m.c)
		o.lines = len(m.rec.lines)
		return o
	}
	got, want := run(true), run(false)
	if got != want {
		t.Fatalf("with a refused Check %+v, without %+v", got, want)
	}
	if got.before != s0 || got.after != s0+2*hourMS || !got.pub {
		t.Fatalf("outcome %+v", got)
	}
}

// Check A (wall 2 h ahead, Write), then Check B (wall 30 d ahead): ErrPending.
// After Committed, a start from key A gives S at most 10 min below the largest
// S of a Now.
func TestTU30_RefusedCheckKeepsStopLossSmall(t *testing.T) {
	m := graceSim(t)
	m.hold = true
	a := m.set(0, s0+2*hourMS)
	if !a.Write {
		t.Fatalf("check A: %+v", a)
	}
	m.f.wall.Store(s0 + 30*dayMS)
	if _, err := m.c.Check(); err != ErrPending {
		t.Fatalf("check B: %v", err)
	}
	m.c.Committed()
	m.f.boot.Add(int64(minute))
	largest := mustNow(t, m.c)
	c, _, err := Start(m.f.source(), StartInput{Stored: &a.State})
	if err != nil {
		t.Fatal(err)
	}
	if lost := largest - mustNow(t, c); lost < 0 || lost > 10*60000 {
		t.Fatalf("largest %d, start S lost %d ms", largest, lost)
	}
}

// After Committed, Check works again.
func TestTU30_CheckWorksAfterCommitted(t *testing.T) {
	m := graceSim(t)
	m.hold = true
	m.set(0, s0+2*hourMS)
	m.f.wall.Store(s0 + 4*hourMS)
	if _, err := m.c.Check(); err != ErrPending {
		t.Fatalf("while the move waits: %v", err)
	}
	m.c.Committed()
	m.hold = false
	r := m.set(0, s0+4*hourMS)
	if r.Jump == nil || r.Jump.Size != 2*hourMS || r.State.S != s0+4*hourMS {
		t.Fatalf("Check after Committed: %+v", r)
	}
}

// A Snapshot while a move waits holds the S of the move. The next Committed
// gives that S to Now.
func TestTU30_SnapshotWhileMoveWaitsThenCommitted(t *testing.T) {
	m := graceSim(t)
	m.hold = true
	m.set(0, s0+2*hourMS)
	m.f.boot.Add(int64(minute))
	snap, err := m.c.Snapshot()
	if err != nil || snap.S != s0+2*hourMS+60000 {
		t.Fatalf("snapshot %+v, %v", snap, err)
	}
	if got := mustNow(t, m.c); got != s0+60000 {
		t.Fatalf("Now %d before Committed", got)
	}
	m.c.Committed()
	if got := mustNow(t, m.c); got != snap.S {
		t.Fatalf("Now %d after Committed, want %d", got, snap.S)
	}
}

// A jump is committed. Then a held move that is no jump is committed. Its
// Committed gives false, and the mark stays for the next jump.
func TestTU30_CommittedOfNonJumpMoveIsFalse(t *testing.T) {
	m := graceSim(t)
	m.set(0, s0+2*hourMS)
	mustNow(t, m.c)
	m.hold = true
	m.set(0, s0+2*hourMS+12*60000)
	if !m.res.Write || m.res.Jump != nil {
		t.Fatalf("move: %+v", m.res)
	}
	if m.c.Committed() {
		t.Fatal("Committed of a move with no jump gave true")
	}
	m.set(0, s0+4*hourMS)
	if m.res.Jump == nil || !m.res.Read {
		t.Fatalf("mark lost: %+v", m.res)
	}
}

// Now makes no allocation.
func TestTU30_NowAllocatesNothing(t *testing.T) {
	m := graceSim(t)
	if n := testing.AllocsPerRun(100, func() { mustNow(t, m.c) }); n != 0 {
		t.Fatalf("%v allocations for each Now", n)
	}
}

// A Check that needs a new jump id above 9223372036854 gives ErrState and
// changes nothing, also lastBoot. The state still encodes.
func TestTU30_NoRoomForJumpID(t *testing.T) {
	for _, known := range []bool{false, true} {
		st := stored(s0, goodID, time.Hour)
		in := StartInput{Stored: st}
		if known {
			in.KnownJumpID = boundMS
		} else {
			st.Jump.ID = boundMS
		}
		rec := &recorder{}
		in.Log = slog.New(rec)
		f := newFake(s0, time.Hour, goodID)
		c, _ := mustStart(t, f, in)
		before, err := c.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		f.wall.Store(s0 + 2*hourMS)
		r, err := c.Check()
		if err != ErrState || r.Jump != nil || r.Write {
			t.Fatalf("known %v: %+v, %v", known, r, err)
		}
		if got := mustNow(t, c); got != s0 {
			t.Fatalf("known %v: Now %d", known, got)
		}
		after, err := c.Snapshot()
		if err != nil || after != before || len(rec.lines) != 0 {
			t.Fatalf("known %v: state changed, %+v, %v", known, after, err)
		}
		if _, err := after.Encode(); err != nil {
			t.Fatalf("known %v: %v", known, err)
		}
		// A move that is no jump still works.
		f.wall.Store(s0 + 30*60000)
		if r, err := c.Check(); err != nil || r.State.GraceSum != 30*60000 {
			t.Fatalf("known %v: small move %+v, %v", known, r, err)
		}
		// The refusal does not change lastBoot. At 6 h of boot clock, the
		// catch-up counts 10 min of boot clock time since the start, not 9.
		st5 := stored(s0, goodID, 5*time.Hour+50*minute)
		in5 := StartInput{Stored: st5}
		if known {
			in5.KnownJumpID = boundMS
		} else {
			st5.Jump.ID = boundMS
		}
		f5 := newFake(s0, 5*time.Hour+50*minute, goodID)
		c5, _ := mustStart(t, f5, in5)
		f5.boot.Add(int64(minute))
		f5.wall.Store(s0 + 2*hourMS)
		if _, err := c5.Check(); err != ErrState {
			t.Fatalf("known %v: refusal %v", known, err)
		}
		f5.boot.Add(int64(9 * minute))
		f5.wall.Store(s0 + 3*dayMS)
		r5, err := c5.Check()
		if err != nil || r5.State.CatchUp != st5.CatchUp+40*60000 {
			t.Fatalf("known %v: catch-up %+v, %v", known, r5.State, err)
		}
	}
}

// T-U-30 (read mark order): reader goroutines call Now in a loop. The writer
// makes jumps of 1 h and 1 ms, each a Check and then Committed. The boot clock
// is fixed, so a value of Now names the base that it loaded. A Now that
// loaded the base of jump k-1 must be in the Read of jump k. It can also be
// in the Committed of jump k. The test counts the reads that are in none. It
// stops after 2 000 000 jumps or after 1.5 s. Fewer than 10 000 jumps fail it.
func TestTU30_ReadMarkStressNoLostRead(t *testing.T) {
	const (
		readers   = 4
		maxJumps  = 2000000
		minJumps  = 10000
		timeLimit = 1500 * time.Millisecond
	)
	step := hourMS + 1
	f, c := graceClock(t, s0, time.Hour)
	var stop atomic.Bool
	seen := make([][]bool, readers)
	var wg sync.WaitGroup
	for i := range seen {
		seen[i] = make([]bool, maxJumps+1)
		wg.Add(1)
		go func(seen []bool) {
			defer wg.Done()
			for !stop.Load() {
				v, err := c.Now()
				if err != nil {
					return
				}
				k := (v - s0) / step
				if (v-s0)%step == 0 && k >= 0 && k <= maxJumps {
					seen[k] = true
				}
			}
		}(seen[i])
	}
	reported := make([]bool, maxJumps+1)
	deadline := time.Now().Add(timeLimit)
	s, n := s0, 0
	for n < maxJumps && (n%256 != 0 || time.Now().Before(deadline)) {
		s += step
		f.wall.Store(s)
		r, err := c.Check()
		if err != nil || r.Jump == nil || !r.Write {
			stop.Store(true)
			wg.Wait()
			t.Fatalf("jump %d: %+v, %v", n+1, r, err)
		}
		n++
		reported[n] = c.Committed() || r.Read
	}
	stop.Store(true)
	wg.Wait()
	if n < minJumps {
		t.Fatalf("%d jumps in %v, want at least %d", n, timeLimit, minJumps)
	}
	lost := 0
	for k := 1; k <= n; k++ {
		for i := range seen {
			if seen[i][k-1] && !reported[k] {
				lost++
				break
			}
		}
	}
	if lost > 0 {
		t.Fatalf("%d of %d jumps lost a read", lost, n)
	}
}
