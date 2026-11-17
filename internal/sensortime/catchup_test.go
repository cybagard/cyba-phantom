package sensortime

import (
	"context"
	"log/slog"
	"math/rand/v2"
	"testing"
	"time"
)

// The texts of the log lines are written out here. A change of the text in
// the code shows as a failure.
const (
	txtJump      = "sensortime: forward jump of S"
	txtStepBack  = "sensortime: wall clock step back"
	txtDiffers   = "sensortime: wall clock differs from S"
	txtExhausted = "sensortime: catch-up budget used"
)

const (
	minute  = time.Minute
	thirdID = "11111111-2222-4333-8444-555555555555"
)

// line is one log line that a test caught.
type line struct {
	msg   string
	level slog.Level
	attrs map[string]slog.Value
}

// recorder is a slog handler that keeps each line.
type recorder struct{ lines []line }

func (r *recorder) Enabled(context.Context, slog.Level) bool { return true }

func (r *recorder) Handle(_ context.Context, rec slog.Record) error {
	l := line{msg: rec.Message, level: rec.Level, attrs: map[string]slog.Value{}}
	rec.Attrs(func(a slog.Attr) bool {
		l.attrs[a.Key] = a.Value
		return true
	})
	r.lines = append(r.lines, l)
	return nil
}

func (r *recorder) WithAttrs([]slog.Attr) slog.Handler { return r }
func (r *recorder) WithGroup(string) slog.Handler      { return r }

// lc is the count of each log line.
type lc struct{ jump, back, differs, budget int }

// counts counts the lines. It fails on an unknown text or a level other
// than Warn. It fails on an attribute that is not an integer. The attribute
// kind of a jump is the only text.
func (r *recorder) counts(t *testing.T) lc {
	t.Helper()
	var n lc
	for _, l := range r.lines {
		switch l.msg {
		case txtJump:
			n.jump++
		case txtStepBack:
			n.back++
		case txtDiffers:
			n.differs++
		case txtExhausted:
			n.budget++
		default:
			t.Fatalf("unknown log text %q", l.msg)
		}
		if l.level != slog.LevelWarn {
			t.Fatalf("%q: level %v, want WARN", l.msg, l.level)
		}
		for k, v := range l.attrs {
			if v.Kind() == slog.KindInt64 {
				continue
			}
			if l.msg != txtJump || k != "kind" || v.Kind() != slog.KindString {
				t.Fatalf("%q: attribute %s is not an integer", l.msg, k)
			}
		}
	}
	return n
}

// sim is a clock under a fake source, with its log and its jumps.
type sim struct {
	t     *testing.T
	f     *fake
	c     *Clock
	rec   *recorder
	jumps []JumpResult
	res   Result
}

func newSim(t *testing.T, wall int64, boot time.Duration, id string,
	st *State) *sim {
	return startSim(t, newFake(wall, boot, id), st)
}

func startSim(t *testing.T, f *fake, st *State) *sim {
	t.Helper()
	m := &sim{t: t, f: f, rec: &recorder{}}
	c, r := mustStart(t, f, StartInput{Stored: st, NextEvent: 8000,
		NextSession: 950, Log: slog.New(m.rec)})
	m.c, m.res = c, r
	if r.Jump != nil {
		m.jumps = append(m.jumps, *r.Jump)
	}
	return m
}

// set moves the boot clock by d, sets the wall clock, and runs a Check.
func (m *sim) set(d time.Duration, wall int64) Result {
	m.t.Helper()
	m.f.boot.Add(int64(d))
	m.f.wall.Store(wall)
	r, err := m.c.Check()
	if err != nil {
		m.t.Fatal(err)
	}
	if r.Jump != nil {
		m.jumps = append(m.jumps, *r.Jump)
	}
	m.res = r
	return r
}

// tick moves both clocks by d and runs a Check.
func (m *sim) tick(d time.Duration) Result {
	m.t.Helper()
	return m.set(d, m.f.wall.Load()+d.Milliseconds())
}

// run does n ticks of d.
func (m *sim) run(n int, d time.Duration) {
	m.t.Helper()
	for range n {
		m.tick(d)
	}
}

// wantLines checks the count of each line. It checks that each jump has a
// line with the attributes kind, id and size.
func (m *sim) wantLines(want lc) {
	m.t.Helper()
	if got := m.rec.counts(m.t); got != want {
		m.t.Fatalf("lines %+v, want %+v", got, want)
	}
	if want.jump != len(m.jumps) {
		m.t.Fatalf("%d jumps, want %d", len(m.jumps), want.jump)
	}
	i := 0
	for _, l := range m.rec.lines {
		if l.msg != txtJump {
			continue
		}
		j := m.jumps[i]
		i++
		if l.attrs["kind"].String() != j.Kind || l.attrs["id"].Int64() != j.ID ||
			l.attrs["size_ms"].Int64() != j.Size || len(l.attrs) != 3 {
			m.t.Fatalf("jump line %v, jump %+v", l.attrs, j)
		}
	}
}

func (m *sim) wantS(s int64) {
	m.t.Helper()
	if got := mustNow(m.t, m.c); got != s || m.res.State.S != s {
		m.t.Fatalf("S %d, state S %d, want %d", got, m.res.State.S, s)
	}
}

// catchClock starts a clock on the same host boot at boot clock 7 h. S is
// s0, with the catch-up used. The wall clock is S plus off.
func catchClock(t *testing.T, off, used int64) *sim {
	st := stored(s0, goodID, 7*time.Hour)
	st.CatchUp = used
	return newSim(t, s0+off, 7*time.Hour, goodID, st)
}

// restart passes the state of the clock through Encode and Decode, as the
// store does. It then starts a new process on the same host boot.
func restart(t *testing.T, m *sim) *sim {
	t.Helper()
	snap, err := m.c.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	enc, err := snap.Encode()
	if err != nil {
		t.Fatal(err)
	}
	dec, err := Decode(enc)
	if err != nil || dec != snap {
		t.Fatalf("decode %+v, %v; want %+v", dec, err, snap)
	}
	n := startSim(t, m.f, &dec)
	if n.res.State.CatchUp != snap.CatchUp || n.res.State.S != snap.S {
		t.Fatalf("restart state %+v, want S and catch-up of %+v", n.res.State, snap)
	}
	return n
}

// T-U-30: after 6 h, S gains 4 min for each boot-clock minute. It gains at
// most 24 h for one host boot. A restart keeps the amount used.
func TestTU30_CatchUpRateAndBudget(t *testing.T) {
	m := catchClock(t, 3*dayMS, 0)
	for i := int64(1); i <= 200; i++ {
		m.tick(minute)
		// S gains 1 min of boot clock and 4 min of catch-up.
		m.wantS(s0 + i*5*60000)
		if m.res.State.CatchUp != i*4*60000 || m.res.Jump != nil {
			t.Fatalf("check %d: state %+v, jump %v", i, m.res.State, m.res.Jump)
		}
	}
	m = restart(t, m)
	for i := int64(201); i <= 360; i++ {
		m.tick(minute)
		m.wantS(s0 + i*5*60000)
		if m.res.State.CatchUp != i*4*60000 {
			t.Fatalf("check %d: catch-up %d", i, m.res.State.CatchUp)
		}
	}
	// 360 checks: 24 h of catch-up used and 6 h of boot clock.
	if m.res.State.CatchUp != catchUpMaxMS {
		t.Fatalf("catch-up %d, want 24 h", m.res.State.CatchUp)
	}
	for i := int64(1); i <= 40; i++ {
		m.tick(minute)
		m.wantS(s0 + 360*5*60000 + i*60000)
	}
	if m.res.State.CatchUp != catchUpMaxMS {
		t.Fatalf("catch-up %d after the budget", m.res.State.CatchUp)
	}
	m.wantLines(lc{budget: 1, differs: 160 + 40})
}

// A start on the same host boot with 24 h used gives no more catch-up and no
// budget line. A start after a reboot gives the budget again.
func TestTU30_CatchUpUsedSurvivesRestart(t *testing.T) {
	m := catchClock(t, 3*dayMS, catchUpMaxMS-4*60000)
	m.tick(minute)
	m.wantS(s0 + 5*60000)
	m.wantLines(lc{differs: 1, budget: 1})
	n := restart(t, m)
	n.run(30, minute)
	n.wantS(s0 + 5*60000 + 30*60000)
	n.wantLines(lc{differs: 30})
	// A new host boot starts with an empty budget.
	snap, _ := n.c.Snapshot()
	n.f.id = otherID
	k := startSim(t, n.f, &snap)
	if k.res.State.CatchUp != 0 {
		t.Fatalf("catch-up %d after a reboot", k.res.State.CatchUp)
	}
}

// The gain is 4 times the boot clock time since the last Check. For the
// first Check, it is since the start.
func TestTU30_CatchUpGainFromLastCheck(t *testing.T) {
	m := catchClock(t, 3*dayMS, 0)
	m.tick(10 * minute) // 10 min of boot clock since the start
	m.wantS(s0 + 10*60000 + 40*60000)
	m.tick(10 * minute) // 10 min since the last Check, not 20
	m.wantS(s0 + 20*60000 + 80*60000)
	m.tick(0) // no boot clock time, no gain
	m.wantS(s0 + 20*60000 + 80*60000)
	m.tick(time.Millisecond)
	m.wantS(s0 + 20*60000 + 80*60000 + 1 + 4)
	if m.res.State.CatchUp != 80*60000+4 {
		t.Fatalf("catch-up %d", m.res.State.CatchUp)
	}
}

// S stops 1 h below the wall. A gap of 1 h or less gives no gain.
func TestTU30_CatchUpStopsOneHourBelowWall(t *testing.T) {
	for _, c := range []struct {
		name string
		d    int64 // wall minus S at the Check
		gain int64
	}{
		{"1 h", hourMS, 0},
		{"1 h and 1 ms", hourMS + 1, 1},
		{"1 h and 30 min", hourMS + 30*60000, 30 * 60000},
		{"1 h and 40 min, rate cap", hourMS + 40*60000, 40 * 60000},
		{"1 h and 50 min, rate cap", hourMS + 50*60000, 40 * 60000},
		{"wall behind", -3 * hourMS, 0},
	} {
		m := catchClock(t, 0, 0)
		m.set(10*minute, s0+10*60000+c.d)
		want := s0 + 10*60000 + c.gain
		m.wantS(want)
		if m.res.State.CatchUp != c.gain || m.res.Jump != nil {
			t.Errorf("%s: state %+v, jump %v", c.name, m.res.State, m.res.Jump)
		}
		if c.gain > 0 && c.gain < 40*60000 && m.f.wall.Load()-want != hourMS {
			t.Errorf("%s: S is not 1 h below the wall", c.name)
		}
	}
}

// The catch-up never passes 24 h for one host boot.
func TestTU30_CatchUpBudgetCap(t *testing.T) {
	m := catchClock(t, 3*dayMS, catchUpMaxMS-60000)
	m.tick(10 * minute)
	m.wantS(s0 + 10*60000 + 60000)
	if m.res.State.CatchUp != catchUpMaxMS {
		t.Fatalf("catch-up %d", m.res.State.CatchUp)
	}
	m.tick(10 * minute)
	m.wantS(s0 + 20*60000 + 60000)
}

// A catch-up of more than 1 h in one Check makes no jump and no jump line.
func TestTU30_CatchUpMakesNoJump(t *testing.T) {
	m := catchClock(t, 3*dayMS, 0)
	m.tick(3 * time.Hour)
	// 3 h of boot clock and 12 h of catch-up.
	m.wantS(s0 + 15*hourMS)
	if m.res.Jump != nil || m.res.State.Jump != stored(s0, goodID, 0).Jump {
		t.Fatalf("jump %v, record %+v", m.res.Jump, m.res.State.Jump)
	}
	m.wantLines(lc{differs: 1})
}

// The grace follows the wall and does not add a catch-up on top of it.
func TestTU30_GraceHasNoCatchUp(t *testing.T) {
	st := stored(s0, goodID, time.Hour)
	st.CatchUp = 0
	m := newSim(t, s0, time.Hour, goodID, st)
	m.set(time.Hour, s0+hourMS+2*dayMS)
	m.wantS(s0 + hourMS + 2*dayMS)
	if m.res.State.CatchUp != 0 || m.res.Jump == nil {
		t.Fatalf("state %+v, jump %v", m.res.State, m.res.Jump)
	}
	// S before the token epoch is a grace case after 6 h too.
	st = stored(epochMS-5*dayMS, goodID, 8*time.Hour)
	st.CatchUp = 0
	k := newSim(t, epochMS+dayMS, 8*time.Hour, goodID, st)
	k.set(time.Hour, epochMS+dayMS+hourMS)
	k.wantS(epochMS + dayMS + hourMS)
	if k.res.State.CatchUp != 0 {
		t.Fatalf("catch-up %d in the grace", k.res.State.CatchUp)
	}
}

// The catch-up moves S only at a Check. After 10 min with no Check, Now is
// S plus 10 min of boot clock and no gain.
func TestTU30_CatchUpMovesOnlyAtCheck(t *testing.T) {
	m := catchClock(t, 2*dayMS, 0)
	calls := m.f.wallCalls.Load()
	m.f.boot.Add(int64(10 * minute))
	m.f.wall.Add(10 * 60000)
	if got := mustNow(t, m.c); got != s0+10*60000 {
		t.Fatalf("Now %d, want S + 10 min", got)
	}
	if m.f.wallCalls.Load() != calls || m.c.st.CatchUp != 0 {
		t.Fatal("Now read the wall clock or moved the catch-up")
	}
	r := m.set(0, m.f.wall.Load())
	// The Check adds 4 times the 10 min.
	m.wantS(s0 + 50*60000)
	if r.State.CatchUp != 40*60000 || mustNow(t, m.c) != r.State.S {
		t.Fatalf("state %+v", r.State)
	}
}

// Check reads the wall clock one time.
func TestTU30_CheckReadsWallOnce(t *testing.T) {
	for _, off := range []int64{0, 2 * hourMS, 3 * dayMS} {
		m := catchClock(t, off, 0)
		calls := m.f.wallCalls.Load()
		m.tick(minute)
		if got := m.f.wallCalls.Load() - calls; got != 1 {
			t.Fatalf("wall offset %d: %d reads", off, got)
		}
	}
}

// T-U-30: S never moves back, for any wall clock sequence. The steps are
// random. They are a Check, a clean restart on the same host boot, and a
// host reboot. A reboot has a new boot id, a small boot clock and a random
// wall clock. Each restart and reboot starts from the last Snapshot, through
// Encode and Decode. No S that Start, Check or Now returns is below the
// highest S seen before. A crash that loses a Snapshot is not covered. The
// generator is seeded: a failure prints the seed.
func TestTU30_SNeverMovesBackProperty(t *testing.T) {
	pick := func(r *rand.Rand, v ...int64) int64 { return v[r.IntN(len(v))] }
	for seed := uint64(1); seed <= 300; seed++ {
		r := rand.New(rand.NewPCG(seed, 0x5eed))
		boot := time.Duration(r.IntN(600)) * minute
		wall := pick(r, 0, epochMS-1, s0, s0+r.Int64N(40*dayMS))
		var st *State
		if r.IntN(2) == 0 {
			id := pick2(r, goodID, otherID)
			st = stored(pick(r, 5*dayMS, epochMS-1, s0),
				id, time.Duration(r.Int64N(int64(boot)+1)))
			st.CatchUp = r.Int64N(catchUpMaxMS + 1)
		}
		f := newFake(wall, boot, goodID)
		c, r0, err := Start(f.source(), StartInput{Stored: st})
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		last, _ := c.Now()
		lastBoot, used := boot, r0.State.CatchUp
		for step := 0; step < 300; step++ {
			if k := r.IntN(10); k < 2 {
				snap, err := c.Snapshot()
				if err != nil {
					t.Fatalf("seed %d step %d: %v", seed, step, err)
				}
				enc, err := snap.Encode()
				if err != nil {
					t.Fatalf("seed %d step %d: %v", seed, step, err)
				}
				dec, err := Decode(enc)
				if err != nil {
					t.Fatalf("seed %d step %d: %v", seed, step, err)
				}
				if k == 1 {
					// Host reboot: new boot id, small boot clock, random wall.
					for f.id == dec.BootID {
						f.id = []string{goodID, otherID, thirdID}[r.IntN(3)]
					}
					boot = time.Duration(r.IntN(180)) * minute
					f.boot.Store(int64(boot))
					f.wall.Store(pick(r, 0, epochMS-1, s0, s0+r.Int64N(40*dayMS),
						max(f.wall.Load()-r.Int64N(40*dayMS), 0)))
				}
				c2, r2, err := Start(f.source(), StartInput{Stored: &dec})
				if err != nil {
					t.Fatalf("seed %d step %d: start: %v", seed, step, err)
				}
				now, _ := c2.Now()
				if r2.State.S < last || now < last {
					t.Fatalf("seed %d step %d: start S %d, Now %d, highest %d, "+
						"reboot %v", seed, step, r2.State.S, now, last, k == 1)
				}
				c, last, lastBoot, used = c2, now, boot, r2.State.CatchUp
				continue
			}
			d := time.Duration(pick(r, 0, 1e6, 6e10, 6e11, 18e12, 108e12))
			boot += d
			f.boot.Store(int64(boot))
			w := f.wall.Load()
			switch r.IntN(4) {
			case 0:
				w += d.Milliseconds()
			case 1:
				w = max(w-r.Int64N(40*dayMS), 0)
			case 2:
				w += r.Int64N(40 * dayMS)
			default:
				w = pick(r, 0, epochMS-1, s0)
			}
			f.wall.Store(w)
			before, _ := c.Now()
			res, err := c.Check()
			after, _ := c.Now()
			if err != nil || res.State.S != after || after < before ||
				before < last {
				t.Fatalf("seed %d step %d: S %d -> %d (last %d), %v",
					seed, step, before, after, last, err)
			}
			if res.State.CatchUp < used || res.State.CatchUp > catchUpMaxMS {
				t.Fatalf("seed %d step %d: catch-up %d, was %d",
					seed, step, res.State.CatchUp, used)
			}
			e := (boot - lastBoot).Milliseconds()
			if boot >= graceBoot && before >= epochMS {
				// The catch-up case: at most 4 e, never above wall - 1 h.
				if after-before > 4*e || after != before &&
					after > w-hourMS || after-before != res.State.CatchUp-used {
					t.Fatalf("seed %d step %d: gain %d, e %d, wall %d, S %d",
						seed, step, after-before, e, w, before)
				}
			} else if res.State.CatchUp != used {
				t.Fatalf("seed %d step %d: catch-up in the grace", seed, step)
			}
			last, lastBoot, used = after, boot, res.State.CatchUp
		}
	}
}

func pick2(r *rand.Rand, a, b string) string {
	if r.IntN(2) == 0 {
		return a
	}
	return b
}

// pauseSeq is the model sequence of a VM pause with no reboot. The clocks
// start at S0 with boot clock 0, and a check runs each boot-clock minute.
// At 7 h the wall moves forward by the pause and the boot clock does not.
func pauseSeq(t *testing.T, pause int64) {
	m := newSim(t, s0, 0, goodID, nil)
	m.run(420, minute)
	m.wantS(s0 + 7*hourMS)
	m.wantLines(lc{})
	m.f.wall.Add(pause)
	for i := int64(1); i <= 480; i++ {
		m.tick(minute)
		if i <= 360 {
			// Each minute: 1 min of boot clock and 4 min of catch-up.
			m.wantS(s0 + 7*hourMS + i*5*60000)
		}
		if i == 360 {
			// S = W0 + 7 h + 6 h + 24 h.
			m.wantS(s0 + 13*hourMS + 24*hourMS)
			if m.res.State.CatchUp != catchUpMaxMS {
				t.Fatalf("catch-up %d at 6 h", m.res.State.CatchUp)
			}
		}
		if i >= 360 && m.f.wall.Load()-m.res.State.S != pause-24*hourMS {
			t.Fatalf("check %d: offset %d, want %d", i,
				m.f.wall.Load()-m.res.State.S, pause-24*hourMS)
		}
	}
	m.wantLines(lc{differs: 480, budget: 1})
}

// T-U-30, bound table row "VM pause of 20 d, no reboot". This test uses the
// same row with a pause of 3 d. The wall moves +3 d at 7 h. After 6 h of
// checks S = W0 + 7 h + 6 h + 24 h. The offset is wall - S = 3 d - 24 h =
// 48 h, and it stays so.
func TestTU30_BoundVMPause3Days(t *testing.T) { pauseSeq(t, 3*dayMS) }

// T-U-30, bound table row "VM pause of 20 d, no reboot": as the 3 d pause.
// The offset is 20 d - 24 h = 19 d at the end.
func TestTU30_BoundVMPause20Days(t *testing.T) { pauseSeq(t, 20*dayMS) }

// rtcLessReboot starts a new host boot with the wall at 1970 and the stored
// S0 of another boot. It checks each minute with the wall at the boot clock.
func rtcLessReboot(t *testing.T) *sim {
	m := newSim(t, 0, 0, otherID, stored(s0, goodID, 5*time.Hour))
	m.wantS(s0)
	m.wantLines(lc{})
	return m
}

// T-U-30, bound table row "no real-time clock, time sync before 6 h". The
// reboot starts with S = S0 and no jump. The sync at 1 h sets the wall to
// S0 + 48 h + 1 h. S is S0 + 1 h then. So the grace jump is 48 h.
func TestTU30_BoundRTCLessSyncBefore6h(t *testing.T) {
	m := rtcLessReboot(t)
	for i := int64(1); i <= 59; i++ {
		m.tick(minute)
		m.wantS(s0 + i*60000)
	}
	m.set(minute, s0+49*hourMS)
	m.wantS(s0 + 49*hourMS)
	// The stored state has jump id 3, so the new id is 4.
	if len(m.jumps) != 1 || m.jumps[0] != (JumpResult{4, 48 * hourMS, KindGrace}) {
		t.Fatalf("jumps %+v", m.jumps)
	}
	m.run(10, minute)
	m.wantS(s0 + 49*hourMS + 10*60000)
	if m.res.State.CatchUp != 0 {
		t.Fatalf("catch-up %d", m.res.State.CatchUp)
	}
	// The 59 checks before the sync have a wall 1970 against S near S0.
	m.wantLines(lc{jump: 1, differs: 59})
}

// T-U-30, bound table row "no real-time clock, time sync after 6 h". The
// sync at 7 h sets the wall to S0 + 48 h + 7 h, with no jump. The checks
// 420 to 779 gain 4 min each. So 360 checks use 24 h. The offset is
// 48 h - 24 h = 24 h. S = S0 + 779 min + 24 h.
func TestTU30_BoundRTCLessSyncAfter6h(t *testing.T) {
	m := rtcLessReboot(t)
	m.run(419, minute)
	m.wantS(s0 + 419*60000)
	m.set(minute, s0+55*hourMS)
	// One catch-up of 4 min on S0 + 7 h.
	m.wantS(s0 + 7*hourMS + 4*60000)
	for i := 1; i < 360; i++ {
		m.tick(minute)
	}
	m.wantS(s0 + 779*60000 + 24*hourMS)
	if m.res.State.CatchUp != catchUpMaxMS ||
		m.f.wall.Load()-m.res.State.S != 24*hourMS {
		t.Fatalf("state %+v, offset %d", m.res.State,
			m.f.wall.Load()-m.res.State.S)
	}
	m.run(10, minute)
	if m.f.wall.Load()-m.res.State.S != 24*hourMS {
		t.Fatal("offset changed after the budget")
	}
	// 419 checks before the sync, 360 with catch-up, 10 after.
	m.wantLines(lc{differs: 419 + 360 + 10, budget: 1})
}

// T-U-30, bound table row "first install at 1970, time sync before 6 h".
// Here the sync is at 7 h, and it still belongs to this row. S is before
// the token epoch, so the grace applies after 6 h. S = 0 and the wall is 0.
// The sync sets the wall to W0. S is 7 h then. The grace jump is W0 - 7 h
// and the catch-up is 0.
func TestTU30_BoundFirstInstallAt1970(t *testing.T) {
	m := newSim(t, 0, 0, goodID, nil)
	m.wantS(0)
	m.run(419, minute)
	m.wantS(419 * 60000)
	m.set(minute, s0)
	m.wantS(s0)
	want := JumpResult{1, s0 - 7*hourMS, KindGrace}
	if len(m.jumps) != 1 || m.jumps[0] != want {
		t.Fatalf("jumps %+v, want %+v", m.jumps, want)
	}
	m.run(10, minute)
	m.wantS(s0 + 10*60000)
	if m.res.State.CatchUp != 0 {
		t.Fatalf("catch-up %d", m.res.State.CatchUp)
	}
	m.wantLines(lc{jump: 1})
}

// T-U-30, bound table row "forward step that stays". Start at W0, then the
// wall is +10 d at 7 h and stays for 10 d. After 360 checks S = true time
// + 24 h, and it stays. With the wall back to the true time, S stays. A
// restart keeps the 24 h used. A reboot with the right wall takes the
// stored S, 24 h ahead.
func TestTU30_BoundForwardStepHeld(t *testing.T) {
	m := newSim(t, s0, 0, goodID, nil)
	m.run(420, minute)
	m.f.wall.Add(10 * dayMS)
	trueTime := func() int64 { return s0 + m.f.boot.Load()/1e6 }
	for i := 1; i <= 14400; i++ {
		m.tick(minute)
		if i >= 360 && m.res.State.S != trueTime()+24*hourMS {
			t.Fatalf("check %d: S %d, true time %d", i, m.res.State.S, trueTime())
		}
	}
	// 7 h + 360 min of boot clock = 13 h, and 24 h of catch-up.
	m.wantLines(lc{differs: 14400, budget: 1})
	before := m.res.State.S
	m.set(minute, trueTime()+60000)
	if m.res.State.S != before+60000 || m.res.State.S != trueTime()+24*hourMS {
		t.Fatalf("S %d after the wall went back, was %d", m.res.State.S, before)
	}
	m.wantLines(lc{differs: 14401, back: 1, budget: 1})

	// A restart on the same host boot gives no more gain, with the wall ahead.
	n := restart(t, m)
	n.f.wall.Add(10 * dayMS)
	n.run(100, minute)
	if n.res.State.CatchUp != catchUpMaxMS ||
		n.res.State.S != before+60000+100*60000 {
		t.Fatalf("restart: state %+v", n.res.State)
	}
	n.wantLines(lc{differs: 100})

	// A host reboot with the right wall clock keeps the stored S, no jump.
	snap, _ := n.c.Snapshot()
	n.f.wall.Store(trueTime())
	n.f.id = otherID
	k := startSim(t, n.f, &snap)
	if k.res.State.S != snap.S || k.res.State.S-trueTime() != 24*hourMS ||
		k.res.State.CatchUp != 0 {
		t.Fatalf("reboot: state %+v, true time %d", k.res.State, trueTime())
	}
	k.wantLines(lc{})
}

// T-U-30: each log line shows for its own case. A jump of the start gives
// one line, with the kind start.
func TestTU30_LogJumpStart(t *testing.T) {
	m := newSim(t, s0+2*hourMS, 3*time.Hour, otherID,
		stored(s0, goodID, 10*time.Hour))
	m.wantLines(lc{jump: 1, differs: 0})
	if m.jumps[0].Kind != KindStart || m.jumps[0].Size != 2*hourMS {
		t.Fatalf("jump %+v", m.jumps[0])
	}
	// A move of 1 h is no jump and no line.
	k := newSim(t, s0+hourMS, 3*time.Hour, otherID,
		stored(s0, goodID, 10*time.Hour))
	k.wantLines(lc{})
}

// A jump of the grace gives one line, with the kind grace.
func TestTU30_LogJumpGrace(t *testing.T) {
	st := stored(s0, goodID, time.Hour)
	m := newSim(t, s0, time.Hour, goodID, st)
	m.set(0, s0+2*hourMS)
	m.wantLines(lc{jump: 1})
	if m.jumps[0].Kind != KindGrace || m.jumps[0].Size != 2*hourMS {
		t.Fatalf("jump %+v", m.jumps[0])
	}
	// A move of 1 h is no jump and no line.
	m.set(0, s0+3*hourMS)
	m.wantLines(lc{jump: 1})
}

// A wall time before the wall time of the last Check gives one line. The
// first Check gives none, and an equal wall time is no step.
func TestTU30_LogStepBack(t *testing.T) {
	m := catchClock(t, 0, 0)
	// The first Check, 1 h behind S: it differs by exactly 1 h, no line.
	m.set(0, s0-hourMS)
	m.wantLines(lc{})
	m.set(0, s0-hourMS)
	m.wantLines(lc{})
	m.set(0, s0-hourMS-1)
	m.wantLines(lc{back: 1, differs: 1})
	// A third and later step back gives a line for each.
	m.set(0, s0-hourMS-2)
	m.wantLines(lc{back: 2, differs: 2})
	// A wall that goes up again is no step.
	m.set(0, s0-hourMS)
	m.wantLines(lc{back: 2, differs: 2})
	m.set(0, s0-hourMS-1)
	m.wantLines(lc{back: 3, differs: 3})

	// The first Check with a wall far behind gives only a differs line.
	k := catchClock(t, -5*hourMS, 0)
	k.set(0, s0-5*hourMS)
	k.wantLines(lc{differs: 1})
	// A step back that keeps the wall near S gives no differs line.
	j := catchClock(t, 0, 0)
	j.set(0, s0+1000)
	j.set(0, s0)
	j.wantLines(lc{back: 1})
}

// A Check with |wall - S| over 1 h, after its move, gives one line. At exactly
// 1 h, in each direction, it gives none.
func TestTU30_LogWallDiffers(t *testing.T) {
	for _, c := range []struct {
		name string
		off  int64
		want lc
	}{
		{"equal", 0, lc{}},
		{"+1 h", hourMS, lc{}},
		{"-1 h", -hourMS, lc{}},
		{"+1 h and 1 ms", hourMS + 1, lc{differs: 1}},
		{"-1 h and 1 ms", -hourMS - 1, lc{differs: 1}},
		{"+3 d", 3 * dayMS, lc{differs: 1}},
		{"-3 d", -3 * dayMS, lc{differs: 1}},
	} {
		m := catchClock(t, c.off, 0)
		m.tick(0)
		if got := m.rec.counts(t); got != c.want {
			t.Errorf("%s: lines %+v, want %+v", c.name, got, c.want)
		}
	}
	// The check tests S after the move. Here S was 1 h 30 min below the wall,
	// and the catch-up moves it to 1 h below.
	m := catchClock(t, 0, 0)
	m.set(10*minute, s0+10*60000+90*60000)
	m.wantS(s0 + 40*60000)
	m.wantLines(lc{})
	// Also in the other direction: S moved by the grace is equal to the wall.
	k := newSim(t, s0, time.Hour, goodID, stored(s0, goodID, time.Hour))
	k.set(0, s0+5*hourMS)
	k.wantLines(lc{jump: 1})
}

// The budget line shows at the Check where the used amount reaches 24 h, and
// not at a later one. A start with 24 h used gives none.
func TestTU30_LogBudgetExhausted(t *testing.T) {
	m := catchClock(t, 3*dayMS, catchUpMaxMS-10*60000)
	m.tick(minute)
	m.wantLines(lc{differs: 1})
	// 10 min are left: the gains are 4 min, 4 min, then 2 min.
	m.tick(minute)
	m.wantLines(lc{differs: 2})
	m.tick(minute)
	if m.res.State.CatchUp != catchUpMaxMS {
		t.Fatalf("catch-up %d", m.res.State.CatchUp)
	}
	m.wantLines(lc{differs: 3, budget: 1})
	for range 5 {
		m.tick(minute)
	}
	m.wantLines(lc{differs: 8, budget: 1})
	// The line has its fixed text and an integer.
	for _, l := range m.rec.lines {
		if l.msg == txtExhausted && (len(l.attrs) != 1 ||
			l.attrs["used_ms"].Int64() != catchUpMaxMS) {
			t.Fatalf("line %+v", l)
		}
	}

	k := catchClock(t, 3*dayMS, catchUpMaxMS)
	k.run(5, minute)
	k.wantLines(lc{differs: 5})
}
