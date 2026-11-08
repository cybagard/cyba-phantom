package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cybagard/cyba-phantom/internal/bundle"
	"github.com/cybagard/cyba-phantom/internal/config"
	"github.com/cybagard/cyba-phantom/internal/event"
	"github.com/cybagard/cyba-phantom/internal/listener"
)

const fetchSection = "bundle:\n  fetch_url: \"https://bundle.example/b.cbnd\"\n  fetch_interval: 20m\n  fetch_private: [10.0.0.0/8]\n"

// realNewFetcher is the production seam value, kept before a test replaces it.
var realNewFetcher = newFetcher

// fakeFetch replaces the newFetcher seam until the test ends. It records the
// values of the call. Its run function waits for the stop and then for linger.
// It notes if the queue was closed when it returned.
type fakeFetch struct {
	mu      sync.Mutex
	calls   int
	url     string
	private []netip.Prefix
	every   time.Duration
	lg      *slog.Logger // the logger argument of the call
	logOut  io.Writer    // the writer of the std log at the call
	errLog  io.Writer    // the error log writer of the server that serve made
	loaded  bool         // the loader held a running bundle when run began
	q       *event.Queue
	err     error
	frozen  func() bool
	linger  time.Duration
	begun   chan struct{}
	ended   chan bool // the queue state at the return of run
}

func newFakeFetch(t *testing.T) *fakeFetch {
	f := &fakeFetch{begun: make(chan struct{}, 1), ended: make(chan bool, 1)}
	old, oldServer, oldLog := newFetcher, newServer, log.Writer()
	t.Cleanup(func() { newFetcher, newServer = old, oldServer; log.SetOutput(oldLog) })
	newServer = func(c listener.Config, h http.Handler) (*listener.Server, error) {
		srv, err := oldServer(c, h)
		f.mu.Lock()
		f.q = c.Queue
		if srv != nil {
			f.errLog = srv.ErrLog()
		}
		f.mu.Unlock()
		return srv, err
	}
	newFetcher = func(url string, private []netip.Prefix, every time.Duration, l *bundle.Loader, lg *slog.Logger) (func(context.Context), func() bool, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.calls++
		f.url, f.private, f.every = url, private, every
		f.lg, f.logOut = lg, log.Writer()
		if f.err != nil {
			return nil, nil, f.err
		}
		return func(ctx context.Context) {
			f.mu.Lock()
			f.loaded = l.Current() != nil
			f.mu.Unlock()
			f.begun <- struct{}{}
			<-ctx.Done()
			time.Sleep(f.linger)
			f.mu.Lock()
			closed := f.q != nil && f.q.Closed()
			f.mu.Unlock()
			f.ended <- closed
		}, f.frozen, nil
	}
	return f
}

func (f *fakeFetch) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// startFetchRun starts serveWith with a valid bundle and the test trust set.
// section is the bundle section of the config.
func startFetchRun(t *testing.T, section string) *mixed {
	t.Helper()
	oldTrust := bundleTrust
	t.Cleanup(func() { bundleTrust = oldTrust })
	bundleTrust = testTrust
	return startMixed(t, mixOpt{remove: true, bundle: section, prep: func(t *testing.T, p startParams) {
		putBundle(t, p.Root, p.BundlePath, bundleOf(t, "2026.11.01-1"), seedKey(goodSeed))
	}})
}

func awaitDone(t *testing.T, r *running) {
	t.Helper()
	r.cancel()
	select {
	case <-r.done:
	case <-time.After(sigtermWait):
		t.Fatal("serve did not return after the stop")
	}
}

// TestTU23_FetcherStart checks that serve starts one fetcher after the start
// load. It gets the URL, the interval and the private list of the config. It
// gets the logger of the bundle part. It starts after the std log went to the
// error log writer of the server.
func TestTU23_FetcherStart(t *testing.T) {
	f := newFakeFetch(t)
	g := startFetchRun(t, fetchSection)
	select {
	case <-f.begun:
	case <-time.After(netWait):
		t.Fatal("the fetcher did not run")
	}
	awaitDone(t, g.r)
	want := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.lg == nil {
		t.Error("the fetcher got a nil logger")
	} else {
		f.lg.Error("test: fetcher logger")
		if !strings.Contains(g.r.err.String(), `msg="test: fetcher logger"`) {
			t.Errorf("the fetcher logger does not write to the log of the process: %q", g.r.err.String())
		}
	}
	if f.errLog == nil || f.logOut != f.errLog {
		t.Errorf("std log writer %v at the fetcher start, want the error log writer %v of the server", f.logOut, f.errLog)
	}
	if f.calls != 1 || f.url != "https://bundle.example/b.cbnd" || f.every != 20*time.Minute || !slices.Equal(f.private, want) || !f.loaded {
		t.Errorf("%d fetchers with url %q, interval %v, private %v, loaded %v; want 1, the config values, loaded true", f.calls, f.url, f.every, f.private, f.loaded)
	}
}

// TestTU23_RealNewFetcher calls the production seam value. A valid URL gives
// a run function and a freeze input that is false before run. A URL that the
// client refuses gives an error and no functions.
func TestTU23_RealNewFetcher(t *testing.T) {
	_, b, stop := startBoth(t, archiveOf(t, referenceFiles()...))
	defer stop()
	private := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	lg := slog.New(slog.NewTextHandler(io.Discard, nil))
	run, frozen, err := realNewFetcher("https://bundle.example/b.cbnd", private, 20*time.Minute, b.l, lg)
	if err != nil || run == nil || frozen == nil {
		t.Fatalf("valid URL: error %v, run nil %v, frozen nil %v; want no error and both set", err, run == nil, frozen == nil)
	}
	if frozen() {
		t.Error("frozen is true before run")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	done := make(chan struct{})
	go func() { run(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(netWait):
		t.Error("run did not return with a canceled context")
	}
	run, frozen, err = realNewFetcher("http://bundle.example/b.cbnd", private, 20*time.Minute, b.l, lg)
	if err == nil || run != nil || frozen != nil {
		t.Errorf("http URL: error %v, run nil %v, frozen nil %v; want an error and both nil", err, run == nil, frozen == nil)
	}
}

// TestTU23_NoFetcherWithEmptyURL checks that serve starts no fetcher with an
// empty bundle.fetch_url.
func TestTU23_NoFetcherWithEmptyURL(t *testing.T) {
	f := newFakeFetch(t)
	g := startFetchRun(t, "")
	awaitDone(t, g.r)
	if n := f.callCount(); n != 0 {
		t.Errorf("%d fetchers started, want 0", n)
	}
}

func fetchCfg(t *testing.T) *config.Config {
	t.Helper()
	cfg, err := config.Load(writeFile(t, validBody(t)+fetchSection), []string{"CKPT_TOKEN=" + strings.Repeat("t", 32)})
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// TestTU23_NoFetcherWithoutLoader checks that a bundle part with no loader
// starts no fetcher and no watch.
func TestTU23_NoFetcherWithoutLoader(t *testing.T) {
	f := newFakeFetch(t)
	b := &bundlePart{lg: slog.New(slog.NewTextHandler(io.Discard, nil))}
	var wg sync.WaitGroup
	b.startFetchAndWatch(t.Context(), &wg, fetchCfg(t))
	wg.Wait()
	if n := f.callCount(); n != 0 || b.watch.Load() != nil || b.Degraded() != nil {
		t.Errorf("%d fetchers, watch %v, reasons %v; want none", n, b.watch.Load(), b.Degraded())
	}
}

// TestTU23_FetcherNewError checks that a fetcher that does not start gives one
// fixed line with no URL. The watch starts, with no freeze input.
func TestTU23_FetcherNewError(t *testing.T) {
	f := newFakeFetch(t)
	f.err = errors.New("test: no client")
	_, b, stop := startBoth(t, archiveOf(t, referenceFiles()...))
	defer stop()
	var buf bytes.Buffer
	b.lg = slog.New(slog.NewTextHandler(&buf, nil))
	ctx, cancel := context.WithCancel(t.Context())
	var wg sync.WaitGroup
	b.startFetchAndWatch(ctx, &wg, fetchCfg(t))
	cancel()
	wg.Wait()
	if got := buf.String(); strings.Count(got, "\n") != 1 || !strings.HasSuffix(got, ` level=ERROR msg="bundle fetcher does not start"`+"\n") {
		t.Errorf("log %q; want the one fixed line", got)
	}
	if f.callCount() != 1 || b.watch.Load() == nil {
		t.Errorf("%d fetcher calls, watch %v; want 1 and a watch", f.callCount(), b.watch.Load())
	}
}

// TestTU23_WatchDegraded checks that the watch gets the freeze input of the
// fetcher. Degraded then gives the reason while the watch runs. The watch gets
// the logger of the bundle part and writes its line for the change.
func TestTU23_WatchDegraded(t *testing.T) {
	f := newFakeFetch(t)
	f.frozen = func() bool { return true }
	_, b, stop := startBoth(t, archiveOf(t, referenceFiles()...))
	defer stop()
	if b.Degraded() != nil {
		t.Errorf("reasons %v before the start, want nil", b.Degraded())
	}
	var buf syncBuf // the watch writes from its goroutine
	b.lg = slog.New(slog.NewTextHandler(&buf, nil))
	ctx, cancel := context.WithCancel(t.Context())
	var wg sync.WaitGroup
	b.startFetchAndWatch(ctx, &wg, fetchCfg(t))
	defer wg.Wait()
	defer cancel()
	// The watch sets the reason before it writes the line.
	const line = `msg="bundle degraded state changed" reason=freeze on=true`
	for deadline := time.Now().Add(netWait); !slices.Equal(b.Degraded(), []string{bundle.ReasonFreeze}) || !strings.Contains(buf.String(), line); time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("reasons %v, log %q; want [freeze] and the line %q", b.Degraded(), buf.String(), line)
		}
	}
}

// TestTU23_StopOrder checks that the fetcher returns before the queue closes,
// and that the stop starts no second fetcher.
func TestTU23_StopOrder(t *testing.T) {
	f := newFakeFetch(t)
	// A serve that does not wait for the fetcher closes the queue in this time.
	f.linger = 200 * time.Millisecond
	g := startFetchRun(t, fetchSection)
	select {
	case <-f.begun:
	case <-time.After(netWait):
		t.Fatal("the fetcher did not run")
	}
	awaitDone(t, g.r)
	select {
	case closed := <-f.ended:
		if closed {
			t.Error("the queue was closed when the fetcher returned")
		}
	default:
		t.Error("serve returned before the fetcher")
	}
	if n := f.callCount(); n != 1 {
		t.Errorf("%d fetchers started, want 1", n)
	}
}

// TestTU23_StopWaitsForWatch holds the freeze input of the watch. The stop
// must wait for the watch, so serve does not return before it.
func TestTU23_StopWaitsForWatch(t *testing.T) {
	f := newFakeFetch(t)
	gate := make(chan struct{})
	release := sync.OnceFunc(func() { close(gate) })
	t.Cleanup(release)
	inside := make(chan struct{}, 1)
	f.frozen = func() bool {
		select {
		case inside <- struct{}{}:
		default:
		}
		<-gate
		return false
	}
	g := startFetchRun(t, fetchSection)
	select {
	case <-inside:
	case <-time.After(netWait):
		t.Fatal("the watch did not read the freeze input")
	}
	g.r.cancel()
	select {
	case <-g.r.done:
		t.Fatal("serve returned while the watch ran")
	case <-time.After(300 * time.Millisecond):
	}
	release()
	select {
	case <-g.r.done:
	case <-time.After(sigtermWait):
		t.Fatal("serve did not return after the watch returned")
	}
}
