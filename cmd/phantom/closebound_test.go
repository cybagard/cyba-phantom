package main

import (
	"context"
	"database/sql"
	"log/slog"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cybagard/cyba-phantom/internal/event"
	"github.com/cybagard/cyba-phantom/internal/listener"
	"github.com/cybagard/cyba-phantom/internal/session"
	"github.com/cybagard/cyba-phantom/internal/store"
	"github.com/cybagard/cyba-phantom/internal/tlog"
)

const closeLine = "phantom: close did not end in 1.5s\n"

// boundTime is the close bound of ADR-041. The tests do not use closeTime, so
// a change of that constant fails them.
const boundTime = 1500 * time.Millisecond

// closeMargin is the scheduling margin that a test allows on top of boundTime.
const closeMargin = time.Second

// closeRun is a serve call with a seam in startDeps for its close.
type closeRun struct {
	r      *running
	p      startParams
	atWait chan time.Time // the time of the first close step
	before chan string    // the stderr at the first close step
}

// launchClose runs serve with the real parts, except that the checkpointer
// runs the function run. run gets the context and the checkpointer.
// The first close step is the stopACME call. So the test sees where it begins.
func launchClose(t *testing.T, run func(context.Context, *tlog.Checkpointer, *event.Queue)) *closeRun {
	t.Helper()
	oldStop := stopACME
	t.Cleanup(func() { stopACME = oldStop })
	c := &closeRun{atWait: make(chan time.Time, 1), before: make(chan string, 1)}
	stopACME = func(a *listener.ACME) {
		c.before <- c.r.err.String()
		c.atWait <- time.Now()
		oldStop(a)
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

// waitCloseEnd waits until no goroutine is in storePart.Stop. A close that was
// blocked has then ended, and no file of the state directory is open.
func waitCloseEnd(t *testing.T) {
	t.Helper()
	buf := make([]byte, 1<<20)
	for end := time.Now().Add(netWait); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		if !strings.Contains(string(buf[:runtime.Stack(buf, true)]), "(*storePart).Stop") {
			return
		}
	}
	t.Error("the close goroutine did not end after the release")
}

// TestTU18_CloseBound blocks the checkpointer, so the store close does not end
// at the cancel. Serve must return after boundTime, with exit 1 and one fixed
// line. The wait is measured from the first close step, which is the end of the
// serve calls. The upper limit is boundTime plus closeMargin. The test does not
// use a longer timeout to pass. At the end, the test releases the checkpointer
// and waits for the close goroutine, so no file stays open.
func TestTU18_CloseBound(t *testing.T) {
	release, entered := make(chan struct{}), make(chan struct{})
	var once sync.Once
	free := func() { once.Do(func() { close(release) }) }
	c := launchClose(t, func(ctx context.Context, _ *tlog.Checkpointer, _ *event.Queue) {
		close(entered)
		<-ctx.Done()
		<-release
	})
	t.Cleanup(func() { free(); waitCloseEnd(t) })
	select {
	case <-entered:
	case <-time.After(netWait):
		t.Fatal("the checkpointer did not start")
	}
	c.r.cancel()
	select {
	case <-c.r.done:
	case <-time.After(shutdownTime + boundTime + closeMargin):
		t.Fatalf("serve did not return in %v after the stop", shutdownTime+boundTime+closeMargin)
	}
	end := time.Now()
	var begin time.Time
	var before string
	select {
	case begin = <-c.atWait:
		before = <-c.before
	default:
		t.Fatal("serve did not reach the close")
	}
	if d := end.Sub(begin); d < boundTime || d > boundTime+closeMargin {
		t.Errorf("serve returned %v after the close began, want from %v to %v", d, boundTime, boundTime+closeMargin)
	}
	if c.r.code != 1 {
		t.Errorf("exit %d, want 1", c.r.code)
	}
	if got := strings.TrimPrefix(c.r.err.String(), before); got != closeLine {
		t.Errorf("stderr after the close began %q, want %q", got, closeLine)
	}
}

// TestTU18_CloseWithinBound slows the close by boundTime/3 and then lets it
// end. Serve must wait for it, write no close line, and give exit 0.
func TestTU18_CloseWithinBound(t *testing.T) {
	c := launchClose(t, func(ctx context.Context, cp *tlog.Checkpointer, _ *event.Queue) {
		cp.Run(ctx)
		time.Sleep(boundTime / 3)
	})
	c.r.cancel()
	select {
	case <-c.r.done:
	case <-time.After(shutdownTime + boundTime + closeMargin):
		t.Fatal("serve did not return after the stop")
	}
	if c.r.code != 0 {
		t.Errorf("exit %d, want 0; stderr %q", c.r.code, c.r.err.String())
	}
	if strings.Contains(c.r.err.String(), "close did not end") {
		t.Errorf("stderr %q has the close line", c.r.err.String())
	}
}

// TestTU18_StopWritesCounts adds drop counts to the overflow counter at the
// cancel of the checkpointer, inside the store close. A normal stop gives exit
// 0, and the writer writes the ip_counter row of those counts.
func TestTU18_StopWritesCounts(t *testing.T) {
	const drops = 3
	c := launchClose(t, func(ctx context.Context, cp *tlog.Checkpointer, q *event.Queue) {
		cp.Run(ctx)
		for range drops {
			q.Counters().DropNoAddr()
		}
	})
	c.r.cancel()
	select {
	case <-c.r.done:
	case <-time.After(shutdownTime + boundTime + closeMargin):
		t.Fatal("serve did not return after the stop")
	}
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
