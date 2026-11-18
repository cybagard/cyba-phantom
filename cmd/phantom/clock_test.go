package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cybagard/cyba-phantom/internal/event"
	"github.com/cybagard/cyba-phantom/internal/sensortime"
	"github.com/cybagard/cyba-phantom/internal/store"
	"github.com/cybagard/cyba-phantom/internal/testutil"
	"github.com/cybagard/cyba-phantom/internal/tlog"
)

const clockLine = "phantom: sensor time does not start\n"

// acceptWatch counts the Accept calls of a listener.
type acceptWatch struct {
	net.Listener
	n *atomic.Int64
}

func (a acceptWatch) Accept() (net.Conn, error) { a.n.Add(1); return a.Listener.Accept() }

// storedKey returns the sensor_time key of the store of p.
func storedKey(t *testing.T, p startParams) (v string) {
	t.Helper()
	withState(t, p, p.StorePath, func(db *sql.DB) {
		mustOK(t, db.QueryRow("SELECT value FROM meta WHERE key = 'sensor_time'").Scan(&v))
	})
	return v
}

// startAndStop runs the real start and then the stop of the store part. The
// clock writes its key at the start.
func startAndStop(t *testing.T, p startParams) {
	t.Helper()
	q, err := event.NewQueue(8, event.NewCounters())
	mustOK(t, err)
	start(p, q, realDeps, slog.New(slog.DiscardHandler)).Stop()
}

// dumpRows gives the rows of each table of the store, the meta rows too.
func dumpRows(t *testing.T, db *sql.DB) string {
	t.Helper()
	var names []string
	rows, err := db.Query("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
	mustOK(t, err)
	for rows.Next() {
		var n string
		mustOK(t, rows.Scan(&n))
		names = append(names, n)
	}
	mustOK(t, rows.Err())
	rows.Close()
	var b strings.Builder
	for _, n := range names {
		rows, err := db.Query(`SELECT * FROM "` + n + `"`)
		mustOK(t, err)
		cols, _ := rows.Columns()
		for rows.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			mustOK(t, rows.Scan(ptrs...))
			fmt.Fprintln(&b, n, vals)
		}
		mustOK(t, rows.Err())
		rows.Close()
	}
	return b.String()
}

// TestTU30_ServeStartsTheClockBeforeAnyAccept checks that serve writes the
// sensor_time key before a listener accepts a connection (T-U-30).
func TestTU30_ServeStartsTheClockBeforeAnyAccept(t *testing.T) {
	https, plain, ca := openListeners(t)
	var accepts, atClock atomic.Int64
	atClock.Store(-1)
	old := listen
	t.Cleanup(func() { listen = old })
	listen = func(network, addr string) (net.Listener, error) {
		l, err := old(network, addr)
		if err != nil {
			return nil, err
		}
		return acceptWatch{l, &accepts}, nil
	}
	cfg := serveCfg(t, https.Addr().String(), plain.Addr().String(), ca)
	p := tempState(t, cfg)
	d := realDeps
	// The real clock has written its key when the call returns.
	d.startClock = func(w *store.Writer) error {
		err := realDeps.startClock(w)
		atClock.Store(accepts.Load())
		return err
	}
	r := launchServe(t, cfg, p, d)
	r.waitStarted(t)
	if n := atClock.Load(); n != 0 {
		t.Errorf("%d Accept calls when the clock start returned, want 0", n)
	}
	testutil.WaitFor(t, func() bool { return accepts.Load() > 0 }, 10*time.Second)
	r.cancel()
	<-r.done
	if storedKey(t, p) == "" {
		t.Error("no sensor_time key after the start")
	}
}

// TestTU30_ClockStartsBeforeTheWriterAndTheSchedule checks the order inside
// start. At the clock call, the queue still holds the event of the test.
// A writer that ran would have taken it. The schedule is made after the clock.
func TestTU30_ClockStartsBeforeTheWriterAndTheSchedule(t *testing.T) {
	q, err := event.NewQueue(8, event.NewCounters())
	mustOK(t, err)
	put(t, q, event.KindRequest, 1)
	var taken bool
	var order []string
	d := realDeps
	d.startClock = func(w *store.Writer) error {
		order = append(order, "clock")
		// A writer that runs takes the event at once. This wait gives it time.
		time.Sleep(100 * time.Millisecond)
		_, taken = q.TryTake()
		return realDeps.startClock(w)
	}
	d.schedule = func(w *store.Writer, p startParams, lg *slog.Logger) (func(context.Context), error) {
		order = append(order, "schedule")
		return realDeps.schedule(w, p, lg)
	}
	p := testParams(t, "events.db")
	s := start(p, q, d, slog.New(slog.DiscardHandler))
	mustOK(t, s.clockErr)
	s.Stop()
	if !taken {
		t.Error("the writer took the event before the clock started")
	}
	if want := []string{"clock", "schedule"}; !slices.Equal(order, want) {
		t.Errorf("call order %v, want %v", order, want)
	}
}

// TestTU30_ClockRefusalStopsTheStart checks a stored sensor_time value that
// does not decode. serve ends with exit 1 and one fixed line. It closes both
// listeners, starts no checkpointer, and changes no row (T-U-30).
func TestTU30_ClockRefusalStopsTheStart(t *testing.T) {
	https, plain, ca := openListeners(t)
	cfg := serveCfg(t, https.Addr().String(), plain.Addr().String(), ca)
	p := tempState(t, cfg)
	var before string
	withState(t, p, p.StorePath, func(db *sql.DB) {
		mustExec(t, db, "INSERT OR REPLACE INTO meta (key, value) VALUES ('sensor_time', 'bad')")
		before = dumpRows(t, db)
	})
	ctx, cancel := context.WithTimeout(t.Context(), netWait)
	defer cancel()
	var stderr syncBuf
	code := serveWith(ctx, cancel, nil, cfg, content{}, p, realDeps, io.Discard, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), clockLine) || strings.Contains(stderr.String(), "retention cap") {
		t.Errorf("exit %d, stderr %q; want exit 1 and the clock line", code, stderr.String())
	}
	for _, name := range []string{"keys/checkpoint.key", tlog.VKeyName} {
		if _, err := os.Lstat(filepath.Join(p.Root, name)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s after the refusal: Lstat gave %v, want a missing file", name, err)
		}
	}
	for name, ln := range map[string]*trackedListener{"https": https, "plain": plain} {
		ln.Listener.(*net.TCPListener).SetDeadline(time.Now().Add(50 * time.Millisecond))
		if _, err := ln.Accept(); !errors.Is(err, net.ErrClosed) {
			t.Errorf("%s listener after the refusal: Accept gave %v, want a closed listener", name, err)
		}
	}
	withState(t, p, p.StorePath, func(db *sql.DB) {
		if after := dumpRows(t, db); after != before {
			t.Errorf("rows changed by the refusal:\nbefore %s\nafter  %s", before, after)
		}
	})
}

// TestTU30_StopMarkerKeepsServing checks a start with writer.stop and a stored
// key. serve does not refuse. The sensor serves on, not healthy, and the key
// stays as it is (T-U-30).
func TestTU30_StopMarkerKeepsServing(t *testing.T) {
	https, plain, ca := openListeners(t)
	cfg := serveCfg(t, https.Addr().String(), plain.Addr().String(), ca)
	p := tempState(t, cfg)
	startAndStop(t, p)
	key := storedKey(t, p)
	mustOK(t, os.WriteFile(filepath.Join(p.Root, "writer.stop"), nil, 0o600))
	r := launchServe(t, cfg, p, realDeps)
	r.waitStarted(t)
	select {
	case <-r.done:
		t.Fatalf("serve ended with exit %d, stderr %q; want it to serve on", r.code, r.err.String())
	default:
	}
	if !https.isBound() || !plain.isBound() {
		t.Error("a listener is not bound")
	}
	r.cancel()
	<-r.done
	if strings.Contains(r.err.String(), clockLine) {
		t.Errorf("stderr %q has the clock refusal line", r.err.String())
	}
	if got := storedKey(t, p); got != key {
		t.Errorf("key %q after the start with the marker, want %q", got, key)
	}
}

// TestTU30_StartClockWithStopMarker checks that StartClock with the stop marker
// returns store.ErrStopMarker and leaves the stored key as it is (T-U-30).
func TestTU30_StartClockWithStopMarker(t *testing.T) {
	p := testParams(t, "events.db")
	startAndStop(t, p)
	key := storedKey(t, p)
	mustOK(t, os.WriteFile(filepath.Join(p.Root, "writer.stop"), nil, 0o600))
	root, err := os.OpenRoot(p.Root)
	mustOK(t, err)
	defer root.Close()
	q, err := event.NewQueue(8, event.NewCounters())
	mustOK(t, err)
	withState(t, p, p.StorePath, func(db *sql.DB) {
		w := store.NewWriter(db, q, false, slog.New(slog.DiscardHandler), store.Recovery{State: root, Origin: p.Origin})
		if err := w.StartClock(sensortime.DefaultSource()); !errors.Is(err, store.ErrStopMarker) {
			t.Errorf("StartClock gave %v, want store.ErrStopMarker", err)
		}
	})
	if got := storedKey(t, p); got != key {
		t.Errorf("key %q after the refusal, want %q", got, key)
	}
}
