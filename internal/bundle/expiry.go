package bundle

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// The reasons of the degraded state. Each is on or off by itself.
const (
	// ReasonExpired is on when the running bundle has reached its expiry time.
	ReasonExpired = "expired"
	// ReasonFreeze is on when the freeze input says that no fetch succeeds.
	ReasonFreeze = "freeze"
)

// expiryInterval is the time between two checks of the watch (ADR-037).
const expiryInterval = 60 * time.Second

// CheckRunning is true when the running bundle expires at now or before. It is
// false with no running bundle. It uses the wall clock, as the expiry time has
// no monotonic reading. It changes nothing.
func (l *Loader) CheckRunning(now time.Time) bool {
	b := l.cur.Load()
	return b != nil && b.manifest.CheckExpiry(now) != nil
}

// kickExpiry asks the expiry watch for one check at once. It never blocks. A
// check that is already asked for covers this one.
func (l *Loader) kickExpiry() {
	select {
	case l.expiryKick <- struct{}{}:
	default:
	}
}

// ExpiryWatch keeps the reasons of the degraded state of one loader. It never
// sends an event and never changes the running bundle (C3, T-S-06).
type ExpiryWatch struct {
	l      *Loader
	frozen func() bool
	hook   func(reason string, on bool)
	log    *slog.Logger

	// now and after are seams for tests. after gives a channel that fires once
	// when the wait ends.
	now   func() time.Time
	after func(time.Duration) <-chan time.Time

	mu      sync.Mutex
	expired bool
	freeze  bool
}

// NewExpiryWatch gives a watch for l. frozen tells if the fetch is frozen, and
// nil means never. hook gets the reason and the new state at each change, and
// it can be nil. A nil log writes no line. The hook and the log line run on the
// goroutine of Run, never while a load holds its lock. A loader has one watch.
func NewExpiryWatch(l *Loader, frozen func() bool, hook func(reason string, on bool), log *slog.Logger) *ExpiryWatch {
	return &ExpiryWatch{l: l, frozen: frozen, hook: hook, log: log, now: time.Now, after: time.After}
}

// Run checks at once. Then it checks each 60 s, and also after each swap of the
// loader. It returns after ctx is done. No hook call and no log line follow.
func (w *ExpiryWatch) Run(ctx context.Context) {
	for ctx.Err() == nil {
		w.check()
		select {
		case <-ctx.Done():
		case <-w.after(expiryInterval):
		case <-w.l.expiryKick:
		}
	}
}

// Reasons gives the active reasons, "expired" first. It is safe for concurrent
// use.
func (w *ExpiryWatch) Reasons() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	var out []string
	if w.expired {
		out = append(out, ReasonExpired)
	}
	if w.freeze {
		out = append(out, ReasonFreeze)
	}
	return out
}

// check reads both inputs and reports each change. The state changes before the
// hook runs, so a hook that calls Reasons sees the new state.
func (w *ExpiryWatch) check() {
	expired := w.l.CheckRunning(w.now())
	freeze := w.frozen != nil && w.frozen()
	w.mu.Lock()
	changeExpired, changeFreeze := expired != w.expired, freeze != w.freeze
	w.expired, w.freeze = expired, freeze
	w.mu.Unlock()
	if changeExpired {
		w.report(ReasonExpired, expired)
	}
	if changeFreeze {
		w.report(ReasonFreeze, freeze)
	}
}

// report writes the fixed log line and calls the hook for one change.
func (w *ExpiryWatch) report(reason string, on bool) {
	if w.log != nil {
		w.log.Warn("bundle degraded state changed", "reason", reason, "on", on)
	}
	if w.hook != nil {
		w.hook(reason, on)
	}
}
