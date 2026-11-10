package main

import (
	"context"
	"database/sql"
	"log/slog"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cybagard/cyba-phantom/internal/event"
	"github.com/cybagard/cyba-phantom/internal/session"
	"github.com/cybagard/cyba-phantom/internal/store"
	"github.com/cybagard/cyba-phantom/internal/tlog"
)

const closeLine = "phantom: close did not end in 1.5s\n"

// boundTime is the close bound of ADR-041. The tests keep their own value.
// TestTU18_CloseTimeIsBound checks that closeTime is equal to it.
const boundTime = 1500 * time.Millisecond

// closeMargin is the scheduling margin that a test allows on top of boundTime.
const closeMargin = 100 * time.Millisecond

// closeRun is a serve call with a seam in startDeps for its close.
type closeRun struct {
	r *running
	p startParams

	mu           sync.Mutex
	lastServed   time.Time // the time of the last serve call to return
	stderrServed string    // the stderr when that serve call returned
}

// launchClose runs serve with the real parts, except that the checkpointer
// runs the function run. run gets the context, the checkpointer and the queue.
// The served seam runs when a serve call returns, before wg.Wait in serve
// returns. It first sleeps for slow, so the first phase of the stop takes
// at least that time. The test uses the time of the last call as the start
// of the close wait.
func launchClose(t *testing.T, slow time.Duration, run func(context.Context, *tlog.Checkpointer, *event.Queue)) *closeRun {
	t.Helper()
	oldServed := served
	t.Cleanup(func() { served = oldServed })
	c := &closeRun{}
	served = func() {
		time.Sleep(slow)
		now := time.Now()
		c.mu.Lock()
		defer c.mu.Unlock()
		if now.After(c.lastServed) {
			c.lastServed, c.stderrServed = now, c.r.err.String()
		}
	}
	https, plain, caAddr := openListeners(t)
	cfg := serveCfg(t, https.Addr().String(), plain.Addr().String(), caAddr)
	c.p = tempState(t, cfg)
	ca, _ := cfg.Get("acme.ca")
	seedCache(t, c.p, ca.Str)
	d := realDeps
	var q *event.Queue
	d.newWriter = func(db *sql.DB, qq *event.Queue, b bool, lg *slog.Logger, rec store.Recovery, dk *session.DayKey) *store.Writer {
		q = qq // start calls newWriter before it starts the checkpointer
		return realDeps.newWriter(db, qq, b, lg, rec, dk)
	}
	d.runCheckpointer = func(ctx context.Context, cp *tlog.Checkpointer) { run(ctx, cp, q) }
	c.r = launchServe(t, cfg, c.p, d)
	c.r.waitStarted(t)
	return c
}

// storeStopName is the name of the function that the blocked close goroutine
// runs. It comes from the method, so a rename of the method breaks the build.
var storeStopName = runtime.FuncForPC(reflect.ValueOf((*storePart).Stop).Pointer()).Name()

// closeInStop tells if a goroutine is in storePart.Stop. It reads the stack
// dump of all goroutines, and doubles the buffer until the dump fits.
// It scans all goroutines of the test binary, so it is correct only while
// no test of the package runs in parallel.
func closeInStop() bool {
	buf := make([]byte, 1<<16)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			return strings.Contains(string(buf[:n]), storeStopName)
		}
		buf = make([]byte, 2*len(buf))
	}
}

// waitCloseEnd waits until no goroutine is in storePart.Stop. A close that was
// blocked has then ended, and no file of the state directory is open.
func waitCloseEnd(t *testing.T) {
	t.Helper()
	for end := time.Now().Add(netWait); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		if !closeInStop() {
			return
		}
	}
	t.Error("the close goroutine did not end after the release")
}

// waitServeEnd waits until serve returns. It fails the test after the time
// that the stop and the close bound allow, plus closeMargin.
func (c *closeRun) waitServeEnd(t *testing.T) {
	t.Helper()
	limit := shutdownTime + boundTime + closeMargin
	select {
	case <-c.r.done:
	case <-time.After(limit):
		t.Fatalf("serve did not return in %v after the stop", limit)
	}
}

// TestTU18_CloseTimeIsBound checks that closeTime is equal to the bound of the
// tests. A change of the constant fails this test.
func TestTU18_CloseTimeIsBound(t *testing.T) {
	if closeTime != boundTime {
		t.Errorf("closeTime is %v, want %v", closeTime, boundTime)
	}
}

// TestTU18_CloseBound blocks the checkpointer, so the store close does not end
// at the cancel. Serve must return after boundTime, with exit 1 and one fixed
// line. The wait runs from the return of the last serve call, which is before
// the timer of serve starts. The upper limit is boundTime plus closeMargin.
// The d check, not the guard of waitServeEnd, proves the bound. Before the
// end, the test checks that the close goroutine is still in storePart.Stop.
// Then it releases the checkpointer and waits for that goroutine, so no file
// stays open.
func TestTU18_CloseBound(t *testing.T) {
	release, entered := make(chan struct{}), make(chan struct{})
	c := launchClose(t, 0, func(ctx context.Context, _ *tlog.Checkpointer, _ *event.Queue) {
		close(entered)
		<-ctx.Done()
		<-release
	})
	t.Cleanup(func() {
		if !closeInStop() {
			t.Errorf("no goroutine is in %s before the release", storeStopName)
		}
		close(release)
		waitCloseEnd(t)
	})
	select {
	case <-entered:
	case <-time.After(netWait):
		t.Fatal("the checkpointer did not start")
	}
	c.r.cancel()
	c.waitServeEnd(t)
	end := time.Now()
	c.mu.Lock()
	begin, stderrBefore := c.lastServed, c.stderrServed
	c.mu.Unlock()
	if begin.IsZero() {
		t.Fatal("serve did not reach the close")
	}
	if d := end.Sub(begin); d < boundTime || d > boundTime+closeMargin {
		t.Errorf("serve returned %v after the last serve call, want from %v to %v", d, boundTime, boundTime+closeMargin)
	}
	if c.r.code != 1 {
		t.Errorf("exit %d, want 1", c.r.code)
	}
	if got := strings.TrimPrefix(c.r.err.String(), stderrBefore); got != closeLine {
		t.Errorf("stderr after the serve calls %q, want %q", got, closeLine)
	}
}

// TestTU18_CloseWithinBound slows the first phase of the stop by boundTime and
// the close by boundTime/3. Serve must wait for the close, write nothing after
// the last serve call, and give exit 0. The slow first phase fails a timer
// that starts before srv.Shutdown.
func TestTU18_CloseWithinBound(t *testing.T) {
	c := launchClose(t, boundTime, func(ctx context.Context, cp *tlog.Checkpointer, _ *event.Queue) {
		cp.Run(ctx)
		time.Sleep(boundTime / 3)
	})
	c.r.cancel()
	c.waitServeEnd(t)
	if c.r.code != 0 {
		t.Errorf("exit %d, want 0; stderr %q", c.r.code, c.r.err.String())
	}
	c.mu.Lock()
	stderrBefore := c.stderrServed
	c.mu.Unlock()
	if got := strings.TrimPrefix(c.r.err.String(), stderrBefore); got != "" {
		t.Errorf("stderr after the serve calls %q, want none", got)
	}
}

// TestTU18_StopWritesCounts adds drop counts to the overflow counter at the
// cancel of the checkpointer, inside the store close. The test checks the
// outcome only. A normal stop gives exit 0. The database has the ip_counter
// row with those drops.
func TestTU18_StopWritesCounts(t *testing.T) {
	const drops = 3
	c := launchClose(t, 0, func(ctx context.Context, cp *tlog.Checkpointer, q *event.Queue) {
		cp.Run(ctx)
		for range drops {
			q.Counters().DropNoAddr()
		}
	})
	c.r.cancel()
	c.waitServeEnd(t)
	if c.r.code != 0 {
		t.Fatalf("exit %d, want 0; stderr %q", c.r.code, c.r.err.String())
	}
	db, err := sql.Open("sqlite", filepath.Join(c.p.Root, filepath.FromSlash(c.p.StorePath)))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var rows, dropped int
	if err := db.QueryRow("SELECT count(*), COALESCE(sum(dropped), 0) FROM ip_counter").Scan(&rows, &dropped); err != nil {
		t.Fatal(err)
	}
	if rows != 1 || dropped != drops {
		t.Errorf("ip_counter has %d rows and %d drops, want 1 row and %d drops", rows, dropped, drops)
	}
}
