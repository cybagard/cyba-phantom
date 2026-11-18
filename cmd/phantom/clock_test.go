package main

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cybagard/cyba-phantom/internal/event"
	"github.com/cybagard/cyba-phantom/internal/sensortime"
	"github.com/cybagard/cyba-phantom/internal/store"
	"github.com/cybagard/cyba-phantom/internal/tlog"
)

// TestTU30_ClockRefusalStopsTheStart has two cases. In the first, the stored
// sensor_time value is not valid, and the real start of the clock refuses it.
// In the second, the start of the clock returns an error. serve must end with
// exit 1 and one fixed line. It must close the listeners and run no schedule.
// A refusal that is only logged leaves the sensor running with no clock
// (T-U-30).
func TestTU30_ClockRefusalStopsTheStart(t *testing.T) {
	cases := []struct {
		name string
		seam func(*store.Writer) error // nil means the real start of the clock
		bad  bool                      // bad sensor_time in the store
	}{
		{"bad stored value", nil, true},
		{"start error", func(*store.Writer) error { return errors.New("no clock") }, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			https, plain, ca := openListeners(t)
			cfg := serveCfg(t, https.Addr().String(), plain.Addr().String(), ca)
			p := tempState(t, cfg)
			if c.bad {
				withState(t, p, "events.db", func(db *sql.DB) {
					mustExec(t, db, "INSERT OR REPLACE INTO meta (key, value) VALUES ('sensor_time', 'bad')")
				})
			}
			d := realDeps
			if c.seam != nil {
				d.startClock = c.seam
			}
			ctx, cancel := context.WithTimeout(t.Context(), netWait)
			defer cancel()
			var stderr strings.Builder
			code := serveWith(ctx, cancel, nil, cfg, content{}, p, d, io.Discard, &stderr)
			if code != 1 || !strings.Contains(stderr.String(), "phantom: sensor time does not start\n") {
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
			withState(t, p, "events.db", func(db *sql.DB) {
				if n := countOf(t, db, "SELECT count(*) FROM meta WHERE key = 'retention_last'"); n != 0 {
					t.Errorf("%d retention marks: the schedule ran after the refusal", n)
				}
			})
		})
	}
}

// TestTU30_ClockStartsBeforeTheWriterRuns checks the order of the start. At the
// call of the clock, the queue still holds the event that the test put in. A
// writer that already ran would have taken it. After the start, the writer has
// a clock: the key is stored.
func TestTU30_ClockStartsBeforeTheWriterRuns(t *testing.T) {
	q, err := event.NewQueue(8, event.NewCounters())
	if err != nil {
		t.Fatal(err)
	}
	e, err := event.NewEvent(time.Now, event.Input{Kind: event.KindRequest})
	if err != nil || !q.Enqueue(e) {
		t.Fatalf("enqueue: %v", err)
	}
	var taken bool
	d := realDeps
	d.schedule = nil
	d.startClock = func(w *store.Writer) error {
		// A writer that runs takes the event at once. This wait gives it time.
		time.Sleep(100 * time.Millisecond)
		_, taken = q.TryTake()
		return w.StartClock(sensortime.DefaultSource())
	}
	p := testParams(t, "events.db")
	s := start(p, q, d, slog.New(slog.DiscardHandler))
	if s.clockErr != nil {
		t.Fatal(s.clockErr)
	}
	s.Stop()
	if !taken {
		t.Error("the writer took the event before the clock started")
	}
	withState(t, p, "events.db", func(db *sql.DB) {
		if n := countOf(t, db, "SELECT count(*) FROM meta WHERE key = 'sensor_time'"); n != 1 {
			t.Errorf("%d sensor_time keys after the start, want 1", n)
		}
	})
}
