package bundle

import (
	"bytes"
	"context"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// hookCall is one call of the ops-alert hook.
type hookCall struct {
	reason string
	on     bool
}

// watched is an expiry watch with a test clock and a test wait. The wait gives
// a channel that the test fires, and it reports each wait on waits. The watch
// calls the wait after each check, so a read of waits means that a check ended.
type watched struct {
	t      *testing.T
	e      *env
	w      *ExpiryWatch
	now    atomic.Pointer[time.Time]
	freeze atomic.Bool
	tick   chan time.Time
	waits  chan time.Duration
	buf    *bytes.Buffer
	cancel context.CancelFunc
	done   chan struct{}

	mu    sync.Mutex
	calls []hookCall
}

// newWatched gives a watch for the loader of e. The clock is at now. extra runs
// in the hook after it records the call.
func newWatched(e *env, now time.Time, extra func()) *watched {
	x := &watched{t: e.t, e: e, tick: make(chan time.Time), waits: make(chan time.Duration, 256), buf: new(bytes.Buffer)}
	x.setNow(now)
	// The load of the env left a request for a check. A test counts checks.
	select {
	case <-e.l.expiryKick:
	default:
	}
	hook := func(reason string, on bool) {
		x.mu.Lock()
		x.calls = append(x.calls, hookCall{reason, on})
		x.mu.Unlock()
		if extra != nil {
			extra()
		}
	}
	x.use(NewExpiryWatch(e.l, x.freeze.Load, hook, slog.New(slog.NewTextHandler(x.buf, nil))))
	return x
}

// use sets the watch of x, with the test clock and the test wait.
func (x *watched) use(w *ExpiryWatch) {
	x.w = w
	w.now = func() time.Time { return *x.now.Load() }
	w.after = func(d time.Duration) <-chan time.Time {
		select {
		case x.waits <- d:
		default:
		}
		return x.tick
	}
}

// setNow sets the clock of the watch.
func (x *watched) setNow(t time.Time) { x.now.Store(&t) }

// start runs the watch in a goroutine and waits for its first check. It gives
// the wait that follows that check.
func (x *watched) start() time.Duration {
	x.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	x.cancel, x.done = cancel, make(chan struct{})
	go func() { defer close(x.done); x.w.Run(ctx) }()
	x.t.Cleanup(x.stop)
	return x.await()
}

// stop ends the watch and waits for Run to return.
func (x *watched) stop() {
	x.cancel()
	select {
	case <-x.done:
	case <-time.After(5 * time.Second):
		x.t.Error("Run did not return")
	}
}

// await waits for the end of one check and gives the wait that follows it.
func (x *watched) await() time.Duration {
	x.t.Helper()
	select {
	case d := <-x.waits:
		return d
	case <-time.After(5 * time.Second):
		x.t.Fatal("no check")
		return 0
	}
}

// step fires the wait and waits for the check that follows.
func (x *watched) step() {
	x.t.Helper()
	select {
	case x.tick <- time.Time{}:
	case <-time.After(5 * time.Second):
		x.t.Fatal("the watch does not wait")
	}
	x.await()
}

func (x *watched) hooked() []hookCall {
	x.mu.Lock()
	defer x.mu.Unlock()
	return slices.Clone(x.calls)
}

func (x *watched) wantReasons(want ...string) {
	x.t.Helper()
	if got := x.w.Reasons(); !slices.Equal(got, want) {
		x.t.Errorf("reasons %v; want %v", got, want)
	}
}

func (x *watched) wantCalls(want ...hookCall) {
	x.t.Helper()
	if got := x.hooked(); !slices.Equal(got, want) {
		x.t.Errorf("hook calls %v; want %v", got, want)
	}
}

// expiryOf gives the expiry time of the running bundle.
func expiryOf(e *env) time.Time { return e.l.Current().Manifest().Expires }

// laterExpires is the manifest text of a bundle that expires after the one of
// mf.
var laterExpires = []string{"2027-09-19T00:00:00Z", "2027-09-20T00:00:00Z"}

// T-S-06: the watch checks the running bundle with the wall clock. At expires
// and after it, "expired" is on. The running bundle, its template and its trap
// stay in service.
func TestTS06ExpiryBoundary(t *testing.T) {
	const act = `{{comment (index .Trap "a")}}`
	for _, c := range []struct {
		name string
		off  time.Duration
		want []string
	}{
		{"1 s before", -time.Second, nil},
		{"at expires", 0, []string{ReasonExpired}},
		{"1 s after", time.Second, []string{ReasonExpired}},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := running(t)
			arch := build(append([]ent{{name: "manifest.json", data: []byte(mf(ver(3)))}},
				append(withRoutes([]ent{tf(vhostFile, act)}), tf(trapsName, arr(tj("a", "x"))))...)...)
			e.write("bundle/current.cbnd", arch)
			e.write("bundle/current.sig", e.sign(arch))
			b, err := e.l.Load(false)
			must(t, err)
			if got := e.l.CheckRunning(expiryOf(e).Add(c.off)); got != (c.want != nil) {
				t.Errorf("CheckRunning gave %v", got)
			}
			x := newWatched(e, expiryOf(e).Add(c.off), nil)
			x.start()
			x.wantReasons(c.want...)
			x.step()
			x.wantReasons(c.want...)
			var sb strings.Builder
			if e.l.Current() != b || b.Execute(&sb, vhostFile, Page{Trap: map[string]string{"a": "ok"}}) != nil || sb.String() != "<!-- ok -->" {
				t.Errorf("the bundle does not serve: %q", sb.String())
			}
			if len(b.Traps()) != 1 {
				t.Error("the trap is gone")
			}
		})
	}
}

// T-S-06: with no running bundle, CheckRunning is false.
func TestTS06NoRunningBundle(t *testing.T) {
	e := newEnv(t)
	if e.l.CheckRunning(time.Date(3000, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Error("expired with no bundle")
	}
}

// T-S-06: the watch waits 60 s between two checks.
func TestTS06WaitIs60s(t *testing.T) {
	x := newWatched(running(t), testNow, nil)
	if d := x.start(); d != 60*time.Second {
		t.Errorf("first wait %v", d)
	}
	x.freeze.Store(true)
	x.tick <- time.Time{}
	if d := x.await(); d != 60*time.Second {
		t.Errorf("wait after a tick %v", d)
	}
}

// T-U-23: a new accepted bundle that is not expired clears "expired" at once,
// with no tick of the wait.
func TestTU23NewBundleClearsExpired(t *testing.T) {
	e := running(t)
	x := newWatched(e, expiryOf(e).Add(time.Hour), nil)
	x.start()
	x.wantReasons(ReasonExpired)
	e.install("bundle/current", mf(ver(3), laterExpires...))
	_, err := e.l.Load(false)
	must(t, err)
	x.await()
	x.wantReasons()
	x.wantCalls(hookCall{ReasonExpired, true}, hookCall{ReasonExpired, false})
}

// T-U-23: a start load of an expired bundle sets "expired" at the first check.
func TestTU23StartLoadExpired(t *testing.T) {
	e := running(t)
	late := testNow.AddDate(2, 0, 0)
	e.l.now = func() time.Time { return late }
	b, err := e.l.Load(true)
	if err != nil || !b.Expired() {
		t.Fatalf("start: %v, %v", b, err)
	}
	x := newWatched(e, late, nil)
	x.start()
	x.wantReasons(ReasonExpired)
	x.wantCalls(hookCall{ReasonExpired, true})
}

// T-U-23: the freeze input sets and clears "freeze". Each reason is on or off
// by itself.
func TestTU23FreezeReason(t *testing.T) {
	e := running(t)
	x := newWatched(e, testNow, nil)
	x.start()
	x.wantReasons()
	x.freeze.Store(true)
	x.step()
	x.wantReasons(ReasonFreeze)
	x.setNow(expiryOf(e))
	x.step()
	x.wantReasons(ReasonExpired, ReasonFreeze)
	x.freeze.Store(false)
	x.step()
	x.wantReasons(ReasonExpired)
	x.setNow(testNow)
	x.step()
	x.wantReasons()
	x.wantCalls(
		hookCall{ReasonFreeze, true}, hookCall{ReasonExpired, true},
		hookCall{ReasonFreeze, false}, hookCall{ReasonExpired, false})
}

// T-U-23: the two reasons are the fixed strings "expired" and "freeze".
func TestTU23ReasonStrings(t *testing.T) {
	e := running(t)
	x := newWatched(e, expiryOf(e), nil)
	x.freeze.Store(true)
	x.start()
	if got := x.w.Reasons(); !slices.Equal(got, []string{"expired", "freeze"}) {
		t.Errorf("reasons %q", got)
	}
	x.wantCalls(hookCall{"expired", true}, hookCall{"freeze", true})
	x.stop()
	if got := logLines(t, x.buf.String()); len(got) != 2 || got[0]["reason"] != "expired" || got[1]["reason"] != "freeze" {
		t.Errorf("log %v", got)
	}
}

// T-U-23: one hook call and one log line for each change, none for a check
// with no change. The line has no version, path or time of the bundle.
func TestTU23HookAndLogPerChange(t *testing.T) {
	e := running(t)
	x := newWatched(e, testNow, nil)
	x.start()
	x.step()
	x.wantCalls()
	x.freeze.Store(true)
	x.step()
	x.step()
	x.wantCalls(hookCall{ReasonFreeze, true})
	x.freeze.Store(false)
	x.step()
	x.step()
	x.wantCalls(hookCall{ReasonFreeze, true}, hookCall{ReasonFreeze, false})
	x.stop()
	lines := logLines(t, x.buf.String())
	if len(lines) != 2 {
		t.Fatalf("%d log lines: %q", len(lines), x.buf.String())
	}
	for i, on := range []string{"true", "false"} {
		want := map[string]string{"level": "WARN", "msg": "bundle degraded state changed", "reason": "freeze", "on": on}
		if !maps.Equal(lines[i], want) {
			t.Errorf("line %d: %v; want %v", i, lines[i], want)
		}
	}
	for _, bad := range []string{ver(2), "bundle/", "current", "2027", "k1"} {
		if strings.Contains(x.buf.String(), bad) {
			t.Errorf("the log holds %q", bad)
		}
	}
}

// T-S-06: the watch sends no event and does not change the running bundle.
func TestTS06WatchSendsNoEvent(t *testing.T) {
	e := running(t)
	p := e.observe(e.l)
	b := e.l.Current()
	x := newWatched(e, expiryOf(e), nil)
	x.start()
	x.freeze.Store(true)
	x.step()
	x.freeze.Store(false)
	x.step()
	x.stop()
	if _, ok := p.q.TryTake(); ok || e.l.Current() != b {
		t.Error("an event or a change of the running bundle")
	}
	if p.buf.Len() != 0 {
		t.Errorf("the loader log has %q", p.buf.String())
	}
}

// T-U-23: a hook that calls Reasons sees the new state. It does not wait for a
// lock that the check holds. The first check waits at most 5 s.
func TestTU23HookSeesNewState(t *testing.T) {
	e := running(t)
	seen := make(chan []string, 4)
	var x *watched
	x = newWatched(e, expiryOf(e).Add(time.Hour), func() { seen <- x.w.Reasons() })
	x.start()
	select {
	case got := <-seen:
		if !slices.Equal(got, []string{ReasonExpired}) {
			t.Errorf("the hook saw %v; want [expired]", got)
		}
	default:
		t.Fatal("the hook did not run")
	}
}

// T-U-23: a watch with no freeze input, no hook and no log works. It reports an
// expired bundle and the clear after a swap, and it does not panic.
func TestTU23WatchWithNilInputs(t *testing.T) {
	e := running(t)
	x := newWatched(e, expiryOf(e).Add(time.Hour), nil)
	x.use(NewExpiryWatch(e.l, nil, nil, nil))
	x.start()
	x.wantReasons(ReasonExpired)
	e.install("bundle/current", mf(ver(3), laterExpires...))
	_, err := e.l.Load(false)
	must(t, err)
	x.await()
	x.wantReasons()
}

// T-U-23: a hook can call a method that takes the load lock.
func TestTU23HookCallsHealthy(t *testing.T) {
	e := running(t)
	var healthy atomic.Bool
	x := newWatched(e, expiryOf(e), func() { healthy.Store(e.l.Healthy()) })
	x.start()
	x.freeze.Store(true)
	x.step()
	if !healthy.Load() || len(x.hooked()) != 2 {
		t.Errorf("hook calls %v, healthy %v", x.hooked(), healthy.Load())
	}
}

// T-U-23: after Run returns, no hook call and no log line come. This holds when
// the freeze input changes or a load swaps.
func TestTU23NoHookAfterRun(t *testing.T) {
	e := running(t)
	x := newWatched(e, testNow, nil)
	x.start()
	x.stop()
	x.freeze.Store(true)
	x.setNow(expiryOf(e))
	e.install("bundle/current", mf(ver(3)))
	_, err := e.l.Load(false)
	must(t, err)
	select {
	case x.tick <- time.Time{}:
		t.Error("the watch still waits")
	case <-time.After(50 * time.Millisecond):
	}
	x.wantCalls()
	if x.buf.Len() != 0 {
		t.Errorf("log %q", x.buf.String())
	}
	// A done context also gives no check.
	y := newWatched(e, expiryOf(e), nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	y.w.Run(ctx)
	y.wantCalls()
}

// T-U-23: the watch goroutine and loads run together. go test -race checks it.
func TestTU23WatchAndLoadTogether(t *testing.T) {
	e := running(t)
	x := newWatched(e, expiryOf(e).Add(time.Hour), func() { e.l.Healthy() })
	x.start()
	loaded := make(chan struct{})
	go func() {
		defer close(loaded)
		for n := 3; n < 8; n++ {
			e.install("bundle/current", mf(ver(n), laterExpires...))
			if _, err := e.l.Load(false); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	for i := 0; i < 100; i++ {
		x.freeze.Store(i%2 == 0)
		select {
		case x.tick <- time.Time{}:
		default:
		}
		x.w.Reasons()
	}
	<-loaded
	// Loads and ticks give extra checks, so wait until the state settles.
	x.freeze.Store(false)
	for end := time.Now().Add(5 * time.Second); len(x.w.Reasons()) > 0; {
		if time.Now().After(end) {
			t.Fatalf("reasons %v", x.w.Reasons())
		}
		select {
		case x.tick <- time.Time{}:
		case <-time.After(10 * time.Millisecond):
		}
	}
}
