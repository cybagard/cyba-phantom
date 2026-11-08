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
// release, and then moves the clock on. The stop of the loader also ends it,
// and then the clock does not move. A loader gets the stop of serve, and the
// test gives the clock the same channel. Before that, stop is nil.
type reloadClock struct {
	base    time.Time
	offset  atomic.Int64
	gaps    atomic.Int32  // the gap waits that began
	entered chan struct{} // a gap wait began (buffer 1)
	hold    chan struct{}
	stop    atomic.Pointer[<-chan struct{}]
	seen    atomic.Pointer[chan struct{}]
	once    sync.Once
}

func (c *reloadClock) now() time.Time {
	if p := c.seen.Swap(nil); p != nil {
		close(*p)
	}
	return c.base.Add(time.Duration(c.offset.Load()))
}

// firstRead gives a channel that the first read of the clock after this call
// closes. A load reads the clock when it checks the bundle, so the close shows
// that a load began.
func (c *reloadClock) firstRead() <-chan struct{} {
	ch := make(chan struct{})
	c.seen.Store(&ch)
	return ch
}

func (c *reloadClock) sleep(d time.Duration) {
	c.gaps.Add(1)
	select {
	case c.entered <- struct{}{}:
	default:
	}
	var stop <-chan struct{}
	if p := c.stop.Load(); p != nil {
		stop = *p
	}
	select {
	case <-c.hold:
		c.offset.Add(int64(d))
	case <-stop:
	}
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
	return startReloadWith(t, hold, during, bundleOf(t, "2026.11.01-1"))
}

// startReloadWith is startReload with the archive of the bundle at the start.
// A nil first puts no bundle file.
func startReloadWith(t *testing.T, hold bool, during string, first []byte) *reloadRig {
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
		if first != nil {
			putBundle(t, p.Root, p.BundlePath, first, seedKey(goodSeed))
		}
	}}
	if during == "setup" {
		o.setup = g.hup
	}
	g.mixed = startMixed(t, o)
	// The stop of serve is the context that WarnExpiry got. The loader has
	// the same channel.
	done := g.ctx.Done()
	g.clock.stop.Store(&done)
	return g
}

// pass ends the held gap wait number n. Then it sends one more SIGHUP. That
// load begins its gap wait only after load n returned, so the event of load n
// is queued. The new load stays in its wait. The stop ends it.
func (g *reloadRig) pass(n int32) {
	g.t.Helper()
	g.free(n)
	g.hup()
	g.clock.wait(g.t, n+1)
}

// free ends the held gap wait number n.
func (g *reloadRig) free(n int32) {
	g.t.Helper()
	select {
	case g.clock.hold <- struct{}{}:
	case <-time.After(sigtermWait):
		g.t.Fatalf("no held gap wait %d", n)
	}
}

// until polls cond each millisecond until it is true. It fails the test after
// netWait.
func until(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(netWait); !cond(); time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("no %s", what)
		}
	}
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

// stop ends serve and returns the bundle events. The stop ends each gap wait
// that began after startReloadWith set the clock stop, and its load does not
// start. Serve must return within the wait of the test.
func (g *reloadRig) stop() []bundleRow {
	g.r.cancel()
	select {
	case <-g.r.done:
	case <-time.After(sigtermWait):
		g.t.Fatal("serve did not return after the stop")
	}
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
// with the source signal after the start load (FR-14). The test ends the gap
// wait of that load. A second SIGHUP then starts a load that the stop ends
// in its gap wait.
func TestTU23_SighupDuringStart(t *testing.T) {
	for _, during := range []string{"setup", "loader"} {
		t.Run(during, func(t *testing.T) {
			g := startReload(t, true, during)
			g.clock.wait(t, 1)
			g.pass(1)
			rows := g.stop()
			if len(rows) != 2 || count(rows, "bundle_load", "start") != 1 || count(rows, "bundle_load", "signal") != 1 {
				t.Errorf("rows %v; want one load with source start and one with source signal", rows)
			}
		})
	}
}

// TestTU23_SignalsDuringLoad sends one SIGHUP and holds its load in the gap
// wait. Then it sends 1 000 more (SEC-34). The check of the buffer shows that
// the channel keeps one signal of them. The test ends the gap wait of each of
// the two loads that ran. A last SIGHUP starts a load that the stop ends in
// its gap wait. The stop ends each load that is left, so the rows cannot show
// an extra load. Only the check of the buffer bounds the loads.
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
	g.pass(1)
	g.pass(2)
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
			g := startReload(t, true, "")
			before := g.l.Load().Current()
			putBundle(t, g.p.Root, g.p.BundlePath, bundleOf(t, "2026.11.01-2"), seedKey(c.seed))
			g.hup()
			g.clock.wait(t, 1)
			if c.swap {
				// The swap sets the gap, so the wait of a second load shows
				// that the first load ended.
				g.pass(1)
			} else {
				// A rejection sets no gap, and the file of a second load
				// would change the first load. No wait shows its end. So the
				// log line of the loader is the only signal. The test polls.
				g.free(1)
				line := `msg="bundle rejected" source=signal`
				until(t, "log line of the signal load", func() bool { return strings.Contains(g.r.err.String(), line) })
			}
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

// TestTU23_StopEndsGapWait holds a load of a SIGHUP in the gap wait. Then it
// stops serve. The test clock never ends the wait by itself. The stop ends
// it, as the clock has the stop of serve by then. So serve returns within the
// wait of the test. The load does not start: the rows hold the start load
// only (FR-14).
func TestTU23_StopEndsGapWait(t *testing.T) {
	g := startReload(t, true, "")
	g.hup()
	g.clock.wait(t, 1)
	g.r.cancel()
	select {
	case <-g.r.done:
	case <-time.After(sigtermWait):
		t.Fatal("serve did not return after the stop")
	}
	if g.r.code != 0 {
		t.Errorf("exit %d, want 0; stderr %q", g.r.code, g.r.err.String())
	}
	if rows := (&bundleRun{p: g.p}).rows(t); count(rows, "bundle_load", "start") != 1 || len(rows) != 1 {
		t.Errorf("rows %v; want the start load only", rows)
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

// TestTI12_SighupUnderLoad sends decoy requests to the static name, one each
// 5 ms (at most 200 each second). A goroutine of its own sends them, so the
// pace holds during a swap. It sends at least 250 and runs until the last
// swap ended, so the load is continuous in every swap. The test has no upper
// bound on the run time, as that measures the speed of the machine. The test
// sends 5 SIGHUPs with new bundles, spread over the run. Each gives one
// swap and one bundle_load. The load waits in the swap gap until a request
// that the swap sends is inside the handler. Before each swap, one request
// stops inside the handler, after it read the running bundle. It ends after
// the swap. Each response must have the status and the
// body of the first one. A running bundle gives the fixed 404 page of the
// bait handler. The hello page serves with no bundle only. The bundles have
// no pages, so this is not the run with bait pages.
func TestTI12_SighupUnderLoad(t *testing.T) { sighupUnderLoad(t, false) }

// TestTI12_SighupBaitPages is TestTI12_SighupUnderLoad with bundles that have
// a bait page, each with its own text. Each response must have status 200 and
// the page of one of the bundles. After swap i, a request that begins gets
// the page of bundle i. The request that read the bundle before swap i gets
// the page of bundle i-1.
func TestTI12_SighupBaitPages(t *testing.T) { sighupUnderLoad(t, true) }

// pageText is the heading of the bait page of bundle i.
func pageText(i int) string { return fmt.Sprintf("<h1>bait page of bundle %d</h1>", i) }

// pageBundle makes a bundle with the version number i+1 and the bait page of
// baitFiles for the static name. The page has its own text.
func pageBundle(t testing.TB, i int) []byte {
	fs := baitFiles()
	for k := range fs {
		fs[k].name = strings.ReplaceAll(fs[k].name, decoyName, staticName)
		fs[k].data = bytes.ReplaceAll(fs[k].data, []byte(decoyName), []byte(staticName))
		fs[k].data = bytes.ReplaceAll(fs[k].data, []byte("<h1>page</h1>"), []byte(pageText(i)))
	}
	fs[0].data = bytes.Replace(fs[0].data, []byte(bundleVersion), []byte(fmt.Sprintf("2026.11.01-%d", i+1)), 1)
	return archiveOf(t, fs...)
}

// getter gives two functions. The first makes a GET for path at the static
// name and returns what it got. The second closes the idle connections of the
// client. A request of the kind "hold" stops inside the handler. One of the
// kind "probe" tells the test that it is inside.
func (g *reloadRig) getter(path string) (get func(kind string) (int, string, error), closeIdle func()) {
	tr := &http.Transport{TLSClientConfig: &tls.Config{ServerName: staticName, InsecureSkipVerify: true}}
	g.t.Cleanup(tr.CloseIdleConnections)
	cl := &http.Client{Transport: tr, Timeout: netWait}
	return func(kind string) (code int, body string, err error) {
		req, _ := http.NewRequestWithContext(g.t.Context(), http.MethodGet, "https://"+g.https+path, nil)
		req.Host = staticName
		if kind != "" {
			req.Header.Set("X-Kind", kind)
		}
		resp, err := cl.Do(req)
		if err != nil {
			return 0, "", err
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b), err
	}, tr.CloseIdleConnections
}

// sighupUnderLoad is the run of the two TestTI12 tests above.
func sighupUnderLoad(t *testing.T, pages bool) {
	const total, swaps = 250, 5
	inside, gate, probe := make(chan struct{}), make(chan struct{}), make(chan struct{}, 1)
	oldServer := newServer
	t.Cleanup(func() { newServer = oldServer })
	newServer = func(c listener.Config, h http.Handler) (*listener.Server, error) {
		return oldServer(c, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Header.Get("X-Kind") {
			case "hold":
				w = holdWriter{w, func() { inside <- struct{}{}; <-gate }}
			case "probe":
				probe <- struct{}{}
			}
			h.ServeHTTP(w, r)
		}))
	}
	path, first := "/", bundleOf(t, "2026.11.01-1")
	if pages {
		path, first = "/page", pageBundle(t, 0)
	}
	g := startReloadWith(t, true, "", first)
	get, closeIdle := g.getter(path)
	wantCode, wantBody, err := get("")
	if err != nil || (!pages && wantCode != http.StatusNotFound) || (pages && !strings.Contains(wantBody, pageText(0))) {
		t.Fatalf("first response %d, %q, %v; want the 404 page or the page of bundle 0", wantCode, wantBody, err)
	}
	var sent, failed, overlapped atomic.Int64
	// check makes one request. With pages and a want, the body must have the
	// text of that page. With pages and no want, it must be a page of any
	// bundle. With no pages, it must equal the first response.
	check := func(kind, want string) {
		code, body, err := get(kind)
		switch {
		case err != nil, !pages && (code != wantCode || body != wantBody):
			failed.Add(1)
		case pages && (code != http.StatusOK || !strings.Contains(body, "<h1>bait page of bundle ")):
			failed.Add(1)
		case !strings.Contains(body, want):
			failed.Add(1)
		}
		sent.Add(1)
		if kind == "hold" {
			overlapped.Add(1)
		}
	}
	var wg sync.WaitGroup
	var started atomic.Int64 // the requests of the generator that began
	var swapsDone atomic.Bool
	// swap holds the load in its gap wait. Then it sends a request of its own
	// that is not held, and waits until the handler has it. This does not
	// depend on the generator. Then it lets the load swap. With pages, a
	// request after the swap gets the page of bundle i. The held request ends
	// after that and gets the page of bundle i-1.
	swap := func(i int) {
		before := g.l.Load().Current()
		next, held, now := bundleOf(t, fmt.Sprintf("2026.11.01-%d", i+1)), "", ""
		if pages {
			next, held, now = pageBundle(t, i), pageText(i-1), pageText(i)
		}
		putBundle(t, g.p.Root, g.p.BundlePath, next, seedKey(goodSeed))
		wg.Go(func() { check("hold", held) })
		<-inside
		g.hup()
		g.clock.wait(t, int32(i))
		wg.Go(func() { check("probe", "") })
		select {
		case <-probe:
		case <-time.After(netWait):
			t.Fatal("no request inside the swap window")
		}
		g.free(int32(i))
		until(t, "swap", func() bool { return g.l.Load().Current() != before })
		if pages {
			check("", now)
		}
		gate <- struct{}{}
	}
	begin, genDone := time.Now(), make(chan struct{})
	go func() {
		defer close(genDone)
		tick := time.NewTicker(5 * time.Millisecond)
		defer tick.Stop()
		for n := 0; n < total || !swapsDone.Load(); n++ {
			select {
			case <-tick.C:
			case <-t.Context().Done():
				return
			}
			started.Add(1)
			wg.Go(func() { check("", "") })
		}
	}()
	step := total / (swaps + 1)
	for i := 1; i <= swaps; i++ {
		until(t, "request count for the swap", func() bool { return started.Load() >= int64(i*step) })
		swap(i)
	}
	swapsDone.Store(true)
	<-genDone
	wg.Wait()
	took := time.Since(begin)
	// A connection that the client dialed and did not use keeps the shutdown
	// of the server waiting. So the client closes its idle connections.
	closeIdle()
	stopAt := time.Now()
	rows := g.stop()
	stopTook := time.Since(stopAt)
	minTook := time.Duration(started.Load()-1) * 5 * time.Millisecond
	if failed.Load() != 0 || sent.Load() < 200 || took < minTook || overlapped.Load() != swaps ||
		count(rows, "bundle_load", "signal") != swaps || len(rows) != swaps+1 || stopTook >= shutdownTime {
		t.Errorf("%d of %d requests failed, %d overlapped a swap, %v (at least %v), stop %v; rows %v; want 0 of 200 or more, at most 200 each second, 5 overlaps, 5 signal loads, stop before %v",
			failed.Load(), sent.Load(), overlapped.Load(), took, minTook, stopTook, rows, shutdownTime)
	}
}

// TestTI12_NoBundleThenSwap starts serve with no bundle file. The loader
// exists and has no bundle, so the start line says "bundle not healthy" and
// the hello page serves. A bait bundle and a SIGHUP then swap, and the next
// request gets the bait page of that bundle.
func TestTI12_NoBundleThenSwap(t *testing.T) {
	g := startReloadWith(t, true, "", nil)
	if l := g.l.Load(); l == nil || l.Current() != nil {
		t.Fatalf("loader %v; want a loader with no bundle", l)
	}
	if line := g.r.out.String(); !strings.Contains(line, "bundle not healthy") {
		t.Errorf("start line %q; want \"bundle not healthy\"", line)
	}
	get, _ := g.getter("/page")
	if code, body, err := get(""); err != nil || code != http.StatusOK || body != "hello\n" {
		t.Fatalf("before the swap: %d, %q, %v; want the hello page", code, body, err)
	}
	putBundle(t, g.p.Root, g.p.BundlePath, pageBundle(t, 1), seedKey(goodSeed))
	// The second signal comes after the first load began, so the channel of
	// the signals holds it. The second load waits for the swap gap only after
	// the first load swapped. So its wait shows the swap. The stop ends it.
	began := g.clock.firstRead()
	g.hup()
	select {
	case <-began:
	case <-time.After(sigtermWait):
		t.Fatal("the first load did not begin")
	}
	g.hup()
	g.clock.wait(t, 1)
	if g.l.Load().Current() == nil {
		t.Fatal("the load did not swap")
	}
	if code, body, err := get(""); err != nil || code != http.StatusOK || !strings.Contains(body, pageText(1)) {
		t.Errorf("after the swap: %d, %q, %v; want the bait page of the bundle", code, body, err)
	}
	if rows := g.stop(); count(rows, "bundle_load", "signal") != 1 {
		t.Errorf("rows %v; want one load with source signal", rows)
	}
}
