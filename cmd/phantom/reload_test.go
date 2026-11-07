package main

import (
	"bytes"
	"context"
	"crypto/hpke"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/cybagard/cyba-phantom/internal/bundle"
	"github.com/cybagard/cyba-phantom/internal/listener"
)

// reloadClock is the clock of the loader in the reload tests. A gap wait of a
// load (30 s after a swap) does not wait for 30 s. It counts, blocks until
// release, and then moves the clock on.
type reloadClock struct {
	base    time.Time
	offset  atomic.Int64
	gaps    atomic.Int32  // the gap waits that began
	entered chan struct{} // a gap wait began (buffer 1)
	hold    chan struct{}
	once    sync.Once
}

func (c *reloadClock) now() time.Time { return c.base.Add(time.Duration(c.offset.Load())) }

func (c *reloadClock) sleep(d time.Duration) {
	c.gaps.Add(1)
	select {
	case c.entered <- struct{}{}:
	default:
	}
	<-c.hold
	c.offset.Add(int64(d))
}

func (c *reloadClock) release() { c.once.Do(func() { close(c.hold) }) }

// wait blocks until n gap waits began. A load that is not a start load
// waits for the gap after a swap. So the count shows that such a load began.
func (c *reloadClock) wait(t *testing.T, n int32) {
	t.Helper()
	for c.gaps.Load() < n {
		select {
		case <-c.entered:
		case <-time.After(sigtermWait):
			t.Fatalf("%d gap waits began, want %d", c.gaps.Load(), n)
		}
	}
}

// reloadRig is the real serve function with a valid bundle, the test trust
// set and the test clock. The test process has its own SIGHUP handler, so a
// SIGHUP never ends it.
type reloadRig struct {
	*mixed
	t     *testing.T
	clock *reloadClock
	mine  chan os.Signal
	l     atomic.Pointer[bundle.Loader]
}

// bundleOf makes a valid reference bundle with the version v.
func bundleOf(t testing.TB, v string) []byte {
	fs := referenceFiles()
	fs[0].data = bytes.Replace(fs[0].data, []byte(bundleVersion), []byte(v), 1)
	return archiveOf(t, fs...)
}

// startReload starts the rig. With hold, a gap wait blocks until the clock
// release. during is "setup" or "loader" for a SIGHUP in the serveSetup seam
// or in the loader seam. It is "" for none.
func startReload(t *testing.T, hold bool, during string) *reloadRig {
	t.Helper()
	g := &reloadRig{t: t, mine: make(chan os.Signal, 1),
		clock: &reloadClock{base: time.Now(), entered: make(chan struct{}, 1), hold: make(chan struct{})}}
	signal.Notify(g.mine, syscall.SIGHUP)
	t.Cleanup(func() { signal.Stop(g.mine) })
	if !hold {
		g.clock.release()
	}
	oldTrust, oldNew := bundleTrust, newLoader
	t.Cleanup(func() { bundleTrust, newLoader = oldTrust, oldNew })
	bundleTrust = testTrust
	newLoader = func(s *os.Root, path string, ts bundle.TrustSet, k hpke.PrivateKey) *bundle.Loader {
		l := oldNew(s, path, ts, k)
		l.SetClock(g.clock.now, g.clock.sleep)
		g.l.Store(l)
		if during == "loader" {
			g.hup()
		}
		return l
	}
	o := mixOpt{remove: true, viaServe: true, prep: func(t *testing.T, p startParams) {
		putBundle(t, p.Root, p.BundlePath, bundleOf(t, "2026.11.01-1"), seedKey(goodSeed))
	}}
	if during == "setup" {
		o.setup = g.hup
	}
	g.mixed = startMixed(t, o)
	return g
}

// hup sends one SIGHUP to the process. It returns when the handler of the test
// got it, so the signal is not pending in the kernel.
func (g *reloadRig) hup() {
	if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
		g.t.Error(err)
		return
	}
	select {
	case <-g.mine:
	case <-time.After(sigtermWait):
		g.t.Error("the test did not get SIGHUP")
	}
}

// stop ends serve, frees the gap waits, and returns the bundle events.
func (g *reloadRig) stop() []bundleRow {
	g.r.cancel()
	g.clock.release()
	<-g.r.done
	if g.r.code != 0 {
		g.t.Errorf("exit %d, want 0; stderr %q", g.r.code, g.r.err.String())
	}
	return (&bundleRun{p: g.p}).rows(g.t)
}

// count gives the rows of the kind with the source src.
func count(rows []bundleRow, kind, src string) (n int) {
	for _, r := range rows {
		if r.kind == kind && strings.Contains(r.detail, `"source":"`+src+`"`) {
			n++
		}
	}
	return n
}

// TestTU23_SighupDuringStart sends a SIGHUP in the serveSetup seam. Then it
// sends one in the loader seam, which runs in the start. Each gives one load
// with the source signal after the start load (FR-14).
func TestTU23_SighupDuringStart(t *testing.T) {
	for _, during := range []string{"setup", "loader"} {
		t.Run(during, func(t *testing.T) {
			g := startReload(t, false, during)
			g.clock.wait(t, 1)
			rows := g.stop()
			if len(rows) != 2 || count(rows, "bundle_load", "start") != 1 || count(rows, "bundle_load", "signal") != 1 {
				t.Errorf("rows %v; want one load with source start and one with source signal", rows)
			}
		})
	}
}

// TestTU23_SignalsDuringLoad sends one SIGHUP and holds its load in the gap
// wait. Then it sends 1 000 more. The signals give one more load, and no
// other (SEC-34). The channel has a buffer of 1.
func TestTU23_SignalsDuringLoad(t *testing.T) {
	hup := notifyReload()
	signal.Stop(hup)
	if cap(hup) != 1 {
		t.Errorf("buffer of the signal channel %d, want 1", cap(hup))
	}
	g := startReload(t, true, "")
	g.hup()
	g.clock.wait(t, 1)
	for range 1000 {
		g.hup()
	}
	g.clock.release()
	g.clock.wait(t, 2)
	if rows := g.stop(); count(rows, "bundle_load", "signal") != 2 || len(rows) != 3 {
		t.Errorf("rows %v; want the start load and two loads with source signal", rows)
	}
}

// TestTU23_SignalLoad sends a SIGHUP with a new valid bundle and one with a
// bundle that the trust set refuses. The valid bundle swaps and gives one
// bundle_load. The other keeps the running bundle and gives one
// bundle_rejected. Both have the source signal.
func TestTU23_SignalLoad(t *testing.T) {
	for _, c := range []struct {
		name, kind string
		seed       byte
		swap       bool
	}{{"valid", "bundle_load", goodSeed, true}, {"rejected", "bundle_rejected", wrongSeed, false}} {
		t.Run(c.name, func(t *testing.T) {
			g := startReload(t, false, "")
			before := g.l.Load().Current()
			putBundle(t, g.p.Root, g.p.BundlePath, bundleOf(t, "2026.11.01-2"), seedKey(c.seed))
			g.hup()
			g.clock.wait(t, 1)
			rows := g.stop()
			if after := g.l.Load().Current(); before == nil || (after != before) != c.swap {
				t.Errorf("swap %v, want %v", after != before, c.swap)
			}
			if len(rows) != 2 || count(rows, c.kind, "signal") != 1 {
				t.Errorf("rows %v; want the start load and one %s with source signal", rows, c.kind)
			}
		})
	}
}

// TestTU23_ReloadWithoutLoader calls Reload with no loader. It writes one fixed
// line and loads nothing.
func TestTU23_ReloadWithoutLoader(t *testing.T) {
	var buf bytes.Buffer
	b := &bundlePart{lg: slog.New(slog.NewTextHandler(&buf, nil))}
	b.Reload(bundle.SourceSignal)
	if got := buf.String(); strings.Count(got, "\n") != 1 || !strings.Contains(got, ` level=ERROR msg="bundle does not reload: no bundle loader"`+"\n") {
		t.Errorf("log %q; want the one fixed line", got)
	}
}

// TestTU23_StopWaitsForLoad holds a load of a SIGHUP in the gap wait. It sends
// a second SIGHUP. Then it stops serve. The stop waits for the load. The event
// of the load is in the store, so the load ended before the queue closed.
// The second SIGHUP gives no load, because the stop began. The test frees
// the load when serve has not returned after a short time. A serve that does
// not wait for the load returns in much less time. Then the event is lost.
func TestTU23_StopWaitsForLoad(t *testing.T) {
	oldServed := served
	t.Cleanup(func() { served = oldServed })
	both := make(chan struct{}, 2)
	served = func() { both <- struct{}{} }
	g := startReload(t, true, "")
	g.hup()
	g.clock.wait(t, 1)
	g.hup()
	g.r.cancel()
	for range 2 {
		select {
		case <-both:
		case <-time.After(sigtermWait):
			t.Fatal("a serve call did not return after the stop")
		}
	}
	// The wait only bounds this check. A correct serve cannot fail by it.
	select {
	case <-g.r.done:
		t.Error("serve returned while a load was in progress")
	case <-time.After(200 * time.Millisecond):
	}
	if rows := g.stop(); count(rows, "bundle_load", "signal") != 1 || len(rows) != 2 {
		t.Errorf("rows %v; want the start load and one load with source signal", rows)
	}
}

// TestTU23_NoLoadAfterStop calls reloadOnSignal 1 000 times with an ended ctx
// and one signal on hup. With no loader, each Reload call writes one line.
// The select may take the signal or the end, so the check after it must
// stop each time. No line is written.
func TestTU23_NoLoadAfterStop(t *testing.T) {
	var buf bytes.Buffer
	b := &bundlePart{lg: slog.New(slog.NewTextHandler(&buf, nil))}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	hup := make(chan os.Signal, 1)
	for range 1000 {
		select {
		case <-hup:
		default:
		}
		hup <- syscall.SIGHUP
		b.reloadOnSignal(ctx, hup)
	}
	if buf.Len() != 0 {
		t.Errorf("%d bytes of log: a load began after the end of ctx", buf.Len())
	}
}

// holdWriter blocks the first WriteHeader of a response until wait returns.
// The handler has read the running bundle by then.
type holdWriter struct {
	http.ResponseWriter
	wait func()
}

func (w holdWriter) WriteHeader(code int) {
	w.wait()
	w.ResponseWriter.WriteHeader(code)
}

// TestTI12_SighupUnderLoad sends 250 decoy requests to the static name, one
// each 5 ms (at most 200 each second, 1.25 s). A goroutine of its own sends
// them, so the pace holds during a swap. The run must take 1 s to 3 s. The
// test sends 5 SIGHUPs with new bundles, spread over the run. Each gives one
// swap and one bundle_load. The load waits in the swap gap until a request
// that is not held begins. Before each swap, one request stops inside the
// handler, after it read the running bundle. It ends after the swap. Each
// response must have the status and the
// body of the first one. A running bundle gives the fixed 404 page of the
// bait handler. The hello page serves with no bundle only. The bundles have
// no pages, so this is not the run with bait pages.
func TestTI12_SighupUnderLoad(t *testing.T) {
	const total, swaps = 250, 5
	inside, gate := make(chan struct{}), make(chan struct{})
	oldServer := newServer
	t.Cleanup(func() { newServer = oldServer })
	newServer = func(c listener.Config, h http.Handler) (*listener.Server, error) {
		return oldServer(c, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("X-Hold") != "" {
				w = holdWriter{w, func() { inside <- struct{}{}; <-gate }}
			}
			h.ServeHTTP(w, r)
		}))
	}
	g := startReload(t, true, "")
	tr := &http.Transport{TLSClientConfig: &tls.Config{ServerName: staticName, InsecureSkipVerify: true}}
	t.Cleanup(tr.CloseIdleConnections)
	cl := &http.Client{Transport: tr, Timeout: netWait}
	get := func(hold bool) (code int, body string, err error) {
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+g.https+"/", nil)
		req.Host = staticName
		if hold {
			req.Header.Set("X-Hold", "1")
		}
		resp, err := cl.Do(req)
		if err != nil {
			return 0, "", err
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b), err
	}
	wantCode, wantBody, err := get(false)
	if err != nil || wantCode != http.StatusNotFound {
		t.Fatalf("first response %d, %v; want the 404 page", wantCode, err)
	}
	var sent, failed, overlapped atomic.Int64
	check := func(hold bool) {
		code, body, err := get(hold)
		if err != nil || code != wantCode || body != wantBody {
			failed.Add(1)
		}
		sent.Add(1)
		if hold {
			overlapped.Add(1)
		}
	}
	until := func(what string, cond func() bool) {
		t.Helper()
		for deadline := time.Now().Add(netWait); !cond(); time.Sleep(time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatalf("no %s", what)
			}
		}
	}
	var wg sync.WaitGroup
	var started atomic.Int64 // the requests that are not held and began
	// swap holds the load in its gap wait. Then it waits for a request that
	// is not held to begin. Then it lets the load swap.
	swap := func(i int) {
		before := g.l.Load().Current()
		putBundle(t, g.p.Root, g.p.BundlePath, bundleOf(t, fmt.Sprintf("2026.11.01-%d", i+1)), seedKey(goodSeed))
		wg.Go(func() { check(true) })
		<-inside
		g.hup()
		g.clock.wait(t, int32(i))
		in := started.Load()
		until("request inside the swap window", func() bool { return started.Load() > in })
		g.clock.hold <- struct{}{}
		until("swap", func() bool { return g.l.Load().Current() != before })
		gate <- struct{}{}
	}
	begin, genDone := time.Now(), make(chan struct{})
	go func() {
		defer close(genDone)
		tick := time.NewTicker(5 * time.Millisecond)
		defer tick.Stop()
		for range total {
			<-tick.C
			started.Add(1)
			wg.Go(func() { check(false) })
		}
	}()
	step := total / (swaps + 1)
	for i := 1; i <= swaps; i++ {
		until("request count for the swap", func() bool { return started.Load() >= int64(i*step) })
		swap(i)
	}
	<-genDone
	wg.Wait()
	rows := g.stop()
	took := time.Since(begin)
	if failed.Load() != 0 || sent.Load() < 200 || took < time.Second || took > 3*time.Second || overlapped.Load() != swaps ||
		count(rows, "bundle_load", "signal") != swaps || len(rows) != swaps+1 {
		t.Errorf("%d of %d requests failed, %d overlapped a swap, %v; rows %v; want 0 of 200 or more in 1 s to 3 s, 5 overlaps, 5 signal loads",
			failed.Load(), sent.Load(), overlapped.Load(), took, rows)
	}
}
