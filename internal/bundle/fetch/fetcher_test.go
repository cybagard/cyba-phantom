package fetch

import (
	"context"
	"log/slog"
	"math"
	"slices"
	"sync/atomic"
	"testing"
	"time"
)

// almostOne is the largest jitter value below 1.
var almostOne = math.Nextafter(1, 0)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

// sim drives a Fetcher with a fake clock and a fake jitter source. A wait
// moves the clock and does not sleep. It records each wait and each start.
type sim struct {
	t        *testing.T
	clk      *clock
	jit      float64
	f        *Fetcher
	results  []bool // what the fake fetches give, in order
	maxWaits int    // when above 0, Run ends at this number of waits
	waits    []time.Duration
	starts   []time.Time
	frozen   []bool // Frozen at each start
	cancel   context.CancelFunc
}

func newSim(t *testing.T, jit float64) *sim {
	return &sim{t: t, jit: jit, clk: &clock{t: time.Unix(1_700_000_000, 0)}}
}

// fake gives the fetcher a fake fetch. It gives each result in turn, and Run
// ends when none is left.
func (s *sim) fake(interval time.Duration, results ...bool) *sim {
	c, err := newClient("https://example.com/x.cbnd", nil, slog.New(slog.DiscardHandler), settings{now: s.clk.now})
	if err != nil {
		s.t.Fatal(err)
	}
	s.results = results
	s.attach(NewFetcher(c, nil, interval))
	s.f.try = func(context.Context) bool {
		if len(s.results) == 0 {
			s.cancel()
			return false
		}
		good := s.results[0]
		s.results = s.results[1:]
		s.starts = append(s.starts, s.clk.t)
		s.frozen = append(s.frozen, s.f.Frozen())
		if good {
			s.f.c.Good()
		}
		return good
	}
	return s
}

// attach sets the fake jitter and the fake wait of f.
func (s *sim) attach(f *Fetcher) {
	s.f = f
	f.jitter = func() float64 { return s.jit }
	f.wait = func(ctx context.Context, d time.Duration) bool {
		s.waits = append(s.waits, d)
		s.clk.t = s.clk.t.Add(d)
		if s.maxWaits > 0 && len(s.waits) >= s.maxWaits {
			s.cancel()
		}
		return ctx.Err() == nil
	}
}

func (s *sim) run() {
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	defer cancel()
	s.f.Run(ctx)
}

// near checks a duration to 1 µs, which covers the float rounding.
func near(t *testing.T, what string, got, want time.Duration) {
	t.Helper()
	if d := got - want; d < -time.Microsecond || d > time.Microsecond {
		t.Errorf("%s = %v, want %v", what, got, want)
	}
}

func secs(n ...float64) []time.Duration {
	out := make([]time.Duration, len(n))
	for i, v := range n {
		out[i] = time.Duration(v * float64(time.Second))
	}
	return out
}

// checkWaits checks the waits after the first one.
func checkWaits(t *testing.T, got, want []time.Duration) {
	t.Helper()
	if len(got) != len(want)+1 {
		t.Fatalf("%d waits, want %d", len(got), len(want)+1)
	}
	for i, w := range want {
		near(t, "wait", got[i+1], w)
	}
}

func TestTU23FirstFetch(t *testing.T) {
	for _, tc := range []struct {
		jit  float64
		want time.Duration
	}{{0, 0}, {0.5, 30 * time.Second}, {almostOne, 60 * time.Second}} {
		s := newSim(t, tc.jit).fake(time.Hour, true)
		begin := s.clk.t
		s.run()
		near(t, "first wait", s.waits[0], tc.want)
		if s.waits[0] >= 60*time.Second || !s.starts[0].Equal(begin.Add(s.waits[0])) {
			t.Errorf("jitter %v: wait %v, start at %v", tc.jit, s.waits[0], s.starts[0].Sub(begin))
		}
	}
}

func TestTU23GoodInterval(t *testing.T) {
	for _, tc := range []struct {
		jit  float64
		want time.Duration
	}{{0, 54 * time.Minute}, {0.5, time.Hour}, {almostOne, 66 * time.Minute}} {
		s := newSim(t, tc.jit).fake(time.Hour, true, true)
		s.run()
		checkWaits(t, s.waits, []time.Duration{tc.want, tc.want})
	}
}

func TestTU23BackoffAfterFailures(t *testing.T) {
	five := secs(60, 120, 240, 480, 960)
	for _, tc := range []struct {
		name     string
		interval time.Duration
		jit      float64
		fails    int
		want     []time.Duration
	}{
		{"no jitter", 24 * time.Hour, 0.5, 5, five},
		{"-20 %, with the floor", 24 * time.Hour, 0, 5, secs(60, 96, 192, 384, 768)},
		{"+20 %", 24 * time.Hour, almostOne, 5, secs(72, 144, 288, 576, 1152)},
		{"cap of 1 h", 24 * time.Hour, 0.5, 9, secs(60, 120, 240, 480, 960, 1920, 3600, 3600, 3600)},
		{"cap of 1 h with +20 %", 24 * time.Hour, almostOne, 9, secs(72, 144, 288, 576, 1152, 2304, 4320, 4320, 4320)},
		{"cap of the interval", 10 * time.Minute, 0.5, 6, secs(60, 120, 240, 480, 600, 600)},
	} {
		s := newSim(t, tc.jit).fake(tc.interval, slices.Repeat([]bool{false}, tc.fails)...)
		s.run()
		t.Log(tc.name)
		checkWaits(t, s.waits, tc.want)
	}
}

func TestTU23ResetAfterGoodFetch(t *testing.T) {
	s := newSim(t, 0.5).fake(time.Hour, false, false, false, true, false, false)
	s.run()
	checkWaits(t, s.waits, secs(60, 120, 240, 3600, 60, 120))
}

func TestTU23NoTwoFetchesWithin60s(t *testing.T) {
	for _, interval := range []time.Duration{30 * time.Second, time.Hour} {
		s := newSim(t, 0).fake(interval, false, false, true, true, false, false)
		s.run()
		for i := 1; i < len(s.starts); i++ {
			if gap := s.starts[i].Sub(s.starts[i-1]); gap < 60*time.Second {
				t.Errorf("interval %v: fetches %d and %d are %v apart", interval, i-1, i, gap)
			}
		}
		// The -20 % jitter of the first step gives 48 s. The floor gives 60 s.
		if s.waits[1] != 60*time.Second {
			t.Errorf("interval %v: wait after the first failure = %v", interval, s.waits[1])
		}
	}
}

func TestTU23Freeze(t *testing.T) {
	for _, tc := range []struct {
		interval, freeze time.Duration
	}{{time.Hour, 24 * time.Hour}, {2 * time.Hour, 24 * time.Hour}, {12 * time.Hour, 48 * time.Hour}} {
		results := append(slices.Repeat([]bool{false}, 70), true, false, false)
		s := newSim(t, 0.5).fake(tc.interval, results...)
		begin := s.clk.t
		s.run()
		ref, sawFrozen, sawClear := begin, false, false
		for i, at := range s.starts {
			if want := at.Sub(ref) >= tc.freeze; s.frozen[i] != want {
				t.Errorf("interval %v: frozen = %v at %v since the reference", tc.interval, s.frozen[i], at.Sub(ref))
			}
			sawFrozen = sawFrozen || s.frozen[i]
			sawClear = sawClear || i > 70 && !s.frozen[i]
			if i == 70 { // the good fetch
				ref = at
			}
		}
		if !sawFrozen || !sawClear {
			t.Errorf("interval %v: frozen seen %v, cleared after a good fetch %v", tc.interval, sawFrozen, sawClear)
		}
	}
}

func TestTU23FreezeEdge(t *testing.T) {
	s := newSim(t, 0.5).fake(time.Hour)
	if s.f.Frozen() {
		t.Error("frozen before Run")
	}
	s.f.began.Store(s.clk.t.UnixNano())
	s.clk.t = s.clk.t.Add(24*time.Hour - 1)
	if s.f.Frozen() {
		t.Error("frozen 1 ns before the freeze time")
	}
	s.clk.t = s.clk.t.Add(1)
	if !s.f.Frozen() {
		t.Error("not frozen at the freeze time")
	}
	s.f.c.Good()
	if s.f.Frozen() {
		t.Error("frozen after a good fetch")
	}
}

func TestTU23StopWhileWaiting(t *testing.T) {
	s := newSim(t, 0.5).fake(time.Hour)
	s.f.wait = sleep // the real wait ends through the context
	s.f.try = func(context.Context) bool { t.Error("a fetch started after the stop"); return false }
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s.f.Run(ctx)
}

// The wait cancels the context and then gives true, as a timer and a stop can
// do together. No fetch may start.
func TestTU23StopWhenWaitAndStopMeet(t *testing.T) {
	s := newSim(t, 0.5).fake(time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	stopped, stop := context.WithCancel(context.Background())
	stop()
	if s.f.wait(stopped, 0) { // the fake wait of the rig ends with its context
		t.Error("the fake wait ignored a done context")
	}
	s.f.wait = func(context.Context, time.Duration) bool { cancel(); return true }
	s.f.try = func(context.Context) bool { t.Error("a fetch started after the stop"); return false }
	s.f.Run(ctx)
}

func TestTU23StopDuringFetch(t *testing.T) {
	s := newSim(t, 0).fake(time.Hour)
	entered := make(chan struct{})
	var ended atomic.Bool
	var tries int
	s.f.try = func(ctx context.Context) bool {
		tries++
		close(entered)
		<-ctx.Done() // the fetch ends through the context of Run
		ended.Store(true)
		return false
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.f.Run(ctx); close(done) }()
	<-entered
	cancel()
	<-done
	if !ended.Load() || tries != 1 {
		t.Errorf("fetch ended %v, %d fetches", ended.Load(), tries)
	}
}
