package bundle

import (
	"bytes"
	"fmt"
	"html/template"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// spinLimit is the number of clock reads that no sound test loader reaches.
const spinLimit = 1_000_000

// noGap makes the swap gap of the loader pass at once. A test that is not about
// the gap uses it. That test then does not wait.
//
// A lock loop that does not end would hang the test run. So the clock and the
// wait panic when a loader spins. The run then fails at once.
func noGap(l *Loader) {
	now, reads := l.now, new(atomic.Int64)
	l.now = func() time.Time {
		if reads.Add(1) > spinLimit {
			panic("the lock loop does not end")
		}
		return now()
	}
	l.sleep = func(d time.Duration) {
		if d <= 0 {
			panic("a load waits for a gap that has passed")
		}
		l.swapMu.Lock()
		l.swapAt = time.Time{}
		l.swapMu.Unlock()
	}
}

// fakeClock is a clock that only a test moves.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// atLeast moves the clock to t. It never moves the clock back.
func (c *fakeClock) atLeast(t time.Time) {
	c.mu.Lock()
	c.t = later(c.t, t)
	c.mu.Unlock()
}

func later(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

// fakeTimers keeps the timers of a loader until a test fires them.
type fakeTimers struct {
	mu     sync.Mutex
	delays []time.Duration
	fns    []func()
}

func (f *fakeTimers) afterFunc(d time.Duration, fn func()) {
	f.mu.Lock()
	f.delays = append(f.delays, d)
	f.fns = append(f.fns, fn)
	f.mu.Unlock()
}

func (f *fakeTimers) fire() {
	f.mu.Lock()
	fns := f.fns
	f.fns = nil
	f.mu.Unlock()
	for _, fn := range fns {
		fn()
	}
}

// gapRig is a loader with a fake clock. It records each wait and the time at
// which each load starts. A wait moves the clock, so no test sleeps. A wait
// must not hold loadMu.
type gapRig struct {
	t      *testing.T
	e      *env
	clk    *fakeClock
	base   time.Time
	dead   atomic.Bool // set when a load did not return in time
	mu     sync.Mutex
	sleeps []time.Duration
	starts []time.Time
}

// gapBound is the real time that a load of a gap test has to return. The fake
// clock needs no real sleep. A load that does not return has a loop that does
// not end. The test then fails and does not hang.
const gapBound = 5 * time.Second

// newBareGapRig gives a rig for an env whose loader has not swapped yet.
func newBareGapRig(t *testing.T, e *env) *gapRig {
	t.Helper()
	g := &gapRig{t: t, e: e, clk: &fakeClock{t: testNow}}
	l := e.l
	l.now = g.clk.now
	l.sleep = func(d time.Duration) {
		g.checkFree()
		g.mu.Lock()
		if g.dead.Load() || len(g.sleeps) >= 1000 {
			// A load that waits so often has a loop that does not end.
			// Stop the loop here. The test fails when gapBound has passed.
			g.mu.Unlock()
			select {}
		}
		g.sleeps = append(g.sleeps, d)
		g.mu.Unlock()
		g.clk.advance(d)
	}
	l.afterRead = func() {
		g.mu.Lock()
		g.starts = append(g.starts, g.clk.now())
		g.mu.Unlock()
	}
	return g
}

// newGapRig gives a rig whose loader swapped last at the time base.
func newGapRig(t *testing.T, src Source) *gapRig {
	t.Helper()
	e := newEnv(t)
	e.install("bundle/current", mf(ver(2)))
	g := newBareGapRig(t, e)
	// A start load swaps at testNow, so the next load waits.
	_, err := g.load(SourceStart)
	must(t, err)
	_, err = g.load(src)
	must(t, err)
	g.reset()
	g.base = g.clk.now()
	return g
}

// within runs fn and fails the test, with exit code 1, if fn does not return
// in gapBound.
func (g *gapRig) within(fn func()) {
	g.t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
	case <-time.After(gapBound):
		g.dead.Store(true)
		g.t.Fatalf("no return in %v: the lock loop does not end", gapBound)
	}
}

// load runs LoadFrom within gapBound.
func (g *gapRig) load(src Source) (b *Bundle, err error) {
	g.t.Helper()
	g.within(func() { b, err = g.e.l.LoadFrom(src) })
	return b, err
}

// checkFree fails the test if a load waits while it holds loadMu.
func (g *gapRig) checkFree() {
	if !loadMu.TryLock() {
		if !g.dead.Load() {
			g.t.Error("a load waits for the swap gap while it holds loadMu")
		}
		return
	}
	loadMu.Unlock()
}

func (g *gapRig) reset() {
	g.mu.Lock()
	g.sleeps, g.starts = nil, nil
	g.mu.Unlock()
}

// T-U-23: with a test clock, a load 1 s after a swap starts 30 s after the
// swap. The wait is 29 s and holds no loadMu. A load after the gap does not
// wait.
func TestTU23SwapGap(t *testing.T) {
	for _, src := range []Source{SourceSignal, SourceReload, SourceFetch} {
		t.Run(src.String(), func(t *testing.T) {
			g := newGapRig(t, src)
			g.clk.advance(time.Second)
			_, err := g.load(src)
			must(t, err)
			if want := []time.Duration{29 * time.Second}; !slices.Equal(g.sleeps, want) {
				t.Errorf("waits %v, want %v", g.sleeps, want)
			}
			if want := []time.Time{g.base.Add(30 * time.Second)}; !slices.Equal(g.starts, want) {
				t.Errorf("load starts at %v, want %v", g.starts, want)
			}
			g.reset()
			g.clk.advance(swapGap)
			_, err = g.load(src)
			must(t, err)
			if len(g.sleeps) != 0 {
				t.Errorf("a load after the gap waited %v", g.sleeps)
			}
		})
	}
}

// T-U-23: a load of a source other than start starts at once when no swap
// has happened. It does not wait.
func TestTU23NoSwapNoWait(t *testing.T) {
	e := newEnv(t)
	e.install("bundle/current", mf(ver(2)))
	g := newBareGapRig(t, e)
	_, err := g.load(SourceReload)
	must(t, err)
	if len(g.sleeps) != 0 || len(g.starts) != 1 {
		t.Errorf("waits %v, %d starts", g.sleeps, len(g.starts))
	}
}

// T-U-23: a load exactly 30 s after a swap starts at once and does not wait.
func TestTU23GapEdgeNoWait(t *testing.T) {
	g := newGapRig(t, SourceReload)
	g.clk.advance(swapGap)
	_, err := g.load(SourceReload)
	must(t, err)
	if len(g.sleeps) != 0 || len(g.starts) != 1 {
		t.Errorf("waits %v, %d starts", g.sleeps, len(g.starts))
	}
}

// T-U-23: a start load does not wait.
func TestTU23StartNoWait(t *testing.T) {
	g := newGapRig(t, SourceStart)
	g.clk.advance(time.Second)
	for _, load := range []func() (*Bundle, error){
		func() (*Bundle, error) { return g.e.l.LoadFrom(SourceStart) },
		func() (*Bundle, error) { return g.e.l.Load(true) },
	} {
		var err error
		g.within(func() { _, err = load() })
		must(t, err)
	}
	if len(g.sleeps) != 0 || len(g.starts) != 2 {
		t.Errorf("waits %v, %d starts", g.sleeps, len(g.starts))
	}
}

// T-U-23: a rejection starts no wait. Only a swap sets the time of the last
// swap, so the load after a rejection starts at once.
func TestTU23RejectionNoWait(t *testing.T) {
	g := newGapRig(t, SourceReload)
	l := g.e.l
	g.clk.advance(swapGap + time.Second)
	l.template = stubParse
	if _, err := g.load(SourceReload); err != ErrTemplateParse {
		t.Fatalf("got %v", err)
	}
	l.template = parseTemplates
	_, err := g.load(SourceReload)
	must(t, err)
	if len(g.sleeps) != 0 || len(g.starts) != 2 {
		t.Errorf("waits %v, %d starts", g.sleeps, len(g.starts))
	}
}

// T-U-23: two loads that wait together do not both start inside the gap. The
// second load checks the gap again after it takes loadMu.
func TestTU23GapCheckedUnderLock(t *testing.T) {
	g := newGapRig(t, SourceReload)
	l, plain := g.e.l, g.e.l.sleep
	var arrive, done sync.WaitGroup
	var calls atomic.Int32
	release := make(chan struct{})
	arrive.Add(2)
	l.sleep = func(d time.Duration) {
		target := g.clk.now().Add(d)
		if calls.Add(1) <= 2 {
			g.checkFree()
			arrive.Done()
			<-release
			g.clk.atLeast(target)
			return
		}
		plain(d)
	}
	g.clk.advance(time.Second)
	for range 2 {
		done.Add(1)
		go func() {
			defer done.Done()
			if _, err := l.LoadFrom(SourceReload); err != nil && !g.dead.Load() {
				t.Error(err)
			}
		}()
	}
	g.within(arrive.Wait)
	close(release)
	g.within(done.Wait)
	if len(g.starts) != 2 {
		t.Fatalf("%d loads started", len(g.starts))
	}
	if gap := g.starts[1].Sub(g.starts[0]); gap < swapGap {
		t.Errorf("the second load starts %v after the first swap", gap)
	}
}

// T-U-23: the seed of a replaced bundle is unchanged until the timer fires
// 30 s after the swap. Then it is zero. A reader of the old seed during the
// swap gives no race report. It never reads a changed seed.
func TestTU23SeedDelay(t *testing.T) {
	e, l, in, key := seeded(t, keyTwo)
	old, timers := l.Current(), &fakeTimers{}
	l.afterFunc = timers.afterFunc
	var changed atomic.Bool
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
				if !bytes.Equal(*old.seed.p, seedA) {
					changed.Store(true)
				}
				runtime.Gosched()
			}
		}
	}()
	e.putSeeded(key, ver(3), e.good(in, key, ver(3), seedB))
	var err error
	(&gapRig{t: t}).within(func() { _, err = l.Load(false) })
	close(stop)
	<-done
	must(t, err)
	if changed.Load() || !bytes.Equal(*old.seed.p, seedA) {
		t.Error("the old seed changed before the timer")
	}
	if want := []time.Duration{30 * time.Second}; !slices.Equal(timers.delays, want) {
		t.Errorf("timer delays %v, want %v", timers.delays, want)
	}
	timers.fire()
	if !bytes.Equal(*old.seed.p, zeros(seedSize)) || !bytes.Equal(*l.Current().seed.p, seedB) {
		t.Error("after the timer the old seed is not zero or the new seed changed")
	}
}

const (
	tp10Env     = "PHANTOM_TP10_CASE"
	tp10Marker  = "PHANTOM_TP10_CHILD" // only the parent sets it
	tp10HWMMax  = 160_000_000
	tp10Limit   = 256 << 20
	tp10Fetched = 8 << 20 // the fetched bytes that the child holds
	tp10Traps   = 64      // trap ids, so a template can use 64 of them
	tp10Files   = 2
	// tp10Fill is the size of the random files of an archive. With the
	// templates, the traps and the headers, the decoded bytes fill the cap.
	tp10Fill = (MaxDecodedBytes - ts25BundleBytes - 32<<10) / tp10Files
	tp10Tmpl = ts25BundleBytes / ts25TmplBytes
)

// tp10Case is one case of T-P-10. The load of the second bundle gives err.
type tp10Case struct {
	name string
	err  error
	// text gives the text of a template with size bytes and the fill byte.
	text func(size int, fill byte) string
}

var tp10Cases = []tp10Case{
	// The only actions are the ones that checkExec accepts.
	{"accepted", nil, func(size int, fill byte) string {
		var sb strings.Builder
		for i := range tp10Traps {
			fmt.Fprintf(&sb, `{{index .Trap "t%02d"}}`, i)
		}
		return sb.String() + strings.Repeat(string(fill), size-sb.Len())
	}},
	// The parentheses shape of T-S-25. checkExec refuses it after the parse.
	{"parens", ErrTemplateParse, func(size int, _ byte) string { return ts25ParensFill(size) }},
}

// tp10Ents gives the files of a bundle at the caps of SEC-29 and of the
// archive. The templates hold ts25BundleBytes with the instruction templates of
// the traps. The random files bring the archive file near its cap.
func tp10Ents(c tp10Case, seed uint8, fill byte) []ent {
	var ents []ent
	for i := range tp10Tmpl {
		size := ts25TmplBytes
		if i == tp10Tmpl-1 {
			size -= tp10Traps // one byte for each instruction template
		}
		ents = append(ents, tf(fmt.Sprintf("vhosts/h.example/%d.tmpl", i), c.text(size, fill)))
	}
	for i := range tp10Files {
		b := make([]byte, tp10Fill)
		rand.NewChaCha8([32]byte{seed, byte(i)}).Read(b)
		ents = append(ents, ent{name: fmt.Sprintf("vhosts/h.example/fill%d.bin", i), data: b})
	}
	ids := make([]string, tp10Traps)
	for i := range ids {
		ids[i] = tj(fmt.Sprintf("t%02d", i), "x")
	}
	return append(withRoutes(ents), tf(trapsName, arr(ids...)), plainEnt(pattern(seedSize, seed, 1)))
}

// tp10Reset sets the peak resident set size to the current size (Linux 4.0).
func tp10Reset(t *testing.T) {
	t.Helper()
	if err := os.WriteFile("/proc/self/clear_refs", []byte("5"), 0); err != nil {
		t.Fatalf("cannot reset VmHWM: %v", err)
	}
}

// TestTP10ReloadMemory is T-P-10. It starts one child process for each case.
// The child loads a bundle at the caps and holds the fetched bytes. Then it
// loads a second bundle while it holds the first.
func TestTP10ReloadMemory(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the child reads /proc/self/status")
	}
	for _, c := range tp10Cases {
		t.Run(c.name, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestTP10Child$", "-test.timeout=120s")
			cmd.Env = append(os.Environ(), tp10Env+"="+c.name, tp10Marker+"=1", "GOMEMLIMIT="+strconv.Itoa(tp10Limit))
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			if err := cmd.Run(); err != nil {
				t.Fatalf("child: %v\n%.1024s", err, stderr.String()+stdout.String())
			}
			var base, afterA, afterB, sizeA, sizeB, nsA, nsB, limit int64
			var ok bool
			var parsed int
			found := false
			for _, line := range strings.Split(stdout.String(), "\n") {
				if strings.HasPrefix(line, "TP10 ") {
					found = true
					if _, err := fmt.Sscanf(line, "TP10 base=%d a=%d b=%d sizea=%d sizeb=%d nsa=%d nsb=%d limit=%d ok=%t parsed=%d",
						&base, &afterA, &afterB, &sizeA, &sizeB, &nsA, &nsB, &limit, &ok, &parsed); err != nil {
						t.Fatalf("result line %q: %v", line, err)
					}
				}
			}
			if !found {
				t.Fatalf("no result line in the child output\n%.1024s", stdout.String())
			}
			diff := afterB - base
			t.Logf("case %s: VmHWM base %.1f MB, after A %.1f MB, after B %.1f MB, difference %.1f MB; archives %d and %d bytes; loads %v and %v",
				c.name, float64(base)/1e6, float64(afterA)/1e6, float64(afterB)/1e6, float64(diff)/1e6,
				sizeA, sizeB, time.Duration(nsA), time.Duration(nsB))
			// A case that does not reach the caps is a test bug, not a pass.
			if sizeA < 7<<20 || sizeB < 7<<20 || sizeA > MaxBundleBytes || sizeB > MaxBundleBytes {
				t.Errorf("archive files of %d and %d bytes; want between %d and %d", sizeA, sizeB, 7<<20, MaxBundleBytes)
			}
			if limit != tp10Limit || ok != (c.err == nil) || parsed != tp10Tmpl {
				t.Errorf("memory limit %d, B accepted %v, %d templates parsed; want %d, %v, %d",
					limit, ok, parsed, tp10Limit, c.err == nil, tp10Tmpl)
			}
			if ts25Race {
				return
			}
			if diff > tp10HWMMax {
				t.Errorf("VmHWM rose by %d bytes; want at most %d", diff, tp10HWMMax)
			}
		})
	}
}

// TestTP10Child is the child process of one case. It skips if
// PHANTOM_TP10_CASE or the marker is not set. Only the parent sets them.
func TestTP10Child(t *testing.T) {
	name := os.Getenv(tp10Env)
	if name == "" || os.Getenv(tp10Marker) == "" {
		t.Skip("child process of TestTP10ReloadMemory")
	}
	var c tp10Case
	for _, k := range tp10Cases {
		if k.name == name {
			c = k
		}
	}
	if c.name == "" {
		t.Fatalf("no case %q", name)
	}
	e := newEnv(t)
	l, key := e.seedLoader(nil), keyTwo(e)
	// Both bundles are on disk before the base is read. A load moves one in.
	stage := t.TempDir()
	sizes := map[string]int64{}
	for _, b := range []struct {
		name string
		c    tp10Case
		n    int
	}{{"a", tp10Cases[0], 2}, {"b", c, 3}} {
		e.putSeeded(key, ver(b.n), tp10Ents(b.c, uint8(b.n), 'a'+byte(b.n))...)
		for _, ext := range []string{".cbnd", ".sig"} {
			must(t, os.Rename(filepath.Join(e.state, "bundle/current"+ext), filepath.Join(stage, b.name+ext)))
		}
		fi, err := os.Stat(filepath.Join(stage, b.name+".cbnd"))
		must(t, err)
		sizes[b.name] = fi.Size()
	}
	load := func() (*Bundle, int64, error) {
		start := time.Now()
		b, err := l.Load(false)
		return b, time.Since(start).Nanoseconds(), err
	}
	use := func(name string) {
		for _, ext := range []string{".cbnd", ".sig"} {
			must(t, os.Rename(filepath.Join(stage, name+ext), filepath.Join(e.state, "bundle/current"+ext)))
		}
	}
	parsed := 0
	step := l.template
	l.template = func(a *Archive) (map[string]*template.Template, error) {
		set, err := step(a)
		parsed = len(set)
		return set, err
	}
	runtime.GC()
	debug.FreeOSMemory()
	tp10Reset(t)
	base := ts25VmHWM(t)
	use("a")
	runA, nsA, err := load()
	must(t, err)
	afterA := ts25VmHWM(t)
	fetched := bytes.Repeat([]byte("f"), tp10Fetched)
	use("b")
	runB, nsB, err := load()
	if err != c.err {
		t.Fatalf("load of B gives %v; want %v", err, c.err)
	}
	afterB := ts25VmHWM(t)
	fmt.Printf("TP10 base=%d a=%d b=%d sizea=%d sizeb=%d nsa=%d nsb=%d limit=%d ok=%t parsed=%d\n",
		base, afterA, afterB, sizes["a"], sizes["b"], nsA, nsB, debug.SetMemoryLimit(-1), err == nil, parsed)
	// A request holds the bundle that ran before the load, so A stays.
	runtime.KeepAlive(runA)
	runtime.KeepAlive(runB)
	runtime.KeepAlive(fetched)
}
