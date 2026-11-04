package fetch

import (
	"bytes"
	"context"
	"errors"
	"math/rand/v2"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/cybagard/cyba-phantom/internal/bundle"
)

// The schedule of the fetch (SEC-34).
const (
	firstSpan    = 60 * time.Second // the first fetch is 0 to 60 s after start
	backoffStart = 60 * time.Second
	backoffCap   = time.Hour
	minWait      = 60 * time.Second // the least time between two fetch starts
	goodJitter   = 0.1
	failJitter   = 0.2
	freezeFloor  = 24 * time.Hour
	freezeTimes  = 4 // intervals of the freeze time, if more than freezeFloor
)

// Fetcher runs the schedule of the fetch. Run is the only goroutine. It starts
// one fetch at a time, so the memory bound of one fetch holds.
type Fetcher struct {
	c        *Client
	loader   *bundle.Loader
	interval time.Duration // bundle.fetch_interval
	began    atomic.Int64  // the start of Run; 0 before it
	faults   atomic.Uint64 // the loads that failed to write their files
	// The four fields below are the test seam. New values replace them only in
	// tests of this package.
	jitter   func() float64 // in [0, 1)
	wait     func(ctx context.Context, d time.Duration) bool
	try      func(ctx context.Context) bool
	pairRead func() // a fetch calls it after the second signature read
}

// NewFetcher makes the fetcher of c. A good fetch loads into loader. interval
// is bundle.fetch_interval. The waits use timers. Frozen and the start time
// use the clock of c.
func NewFetcher(c *Client, loader *bundle.Loader, interval time.Duration) *Fetcher {
	f := &Fetcher{c: c, loader: loader, interval: interval, jitter: rand.Float64, wait: sleep}
	f.try = f.fetch
	return f
}

// sleep waits for d. It gives false when ctx ends first.
func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// Run does the fetches until ctx ends. The requests of a fetch end through ctx.
// A load in progress runs to its end, and Run returns after it. The caller
// starts Run after the start load.
func (f *Fetcher) Run(ctx context.Context) {
	f.began.Store(f.c.now().UnixNano())
	d := time.Duration(f.jitter() * float64(firstSpan))
	var step time.Duration // the last backoff step; 0 after a good fetch
	for f.wait(ctx, d) && ctx.Err() == nil {
		good := f.try(ctx)
		if ctx.Err() != nil {
			return
		}
		d, step = f.next(good, step)
	}
}

// next gives the wait before the next fetch and the new backoff step.
func (f *Fetcher) next(good bool, step time.Duration) (time.Duration, time.Duration) {
	if good {
		return max(f.spread(f.interval, goodJitter), minWait), 0
	}
	limit := min(f.interval, backoffCap)
	step = min(max(2*step, backoffStart), limit)
	return max(f.spread(step, failJitter), minWait), step
}

// spread gives d changed by a random part of at most frac of d, up or down.
func (f *Fetcher) spread(d time.Duration, frac float64) time.Duration {
	return time.Duration(float64(d) * (1 + frac*(2*f.jitter()-1)))
}

// fetch does one fetch. It gives true for a good fetch. The client records its
// own failures. Only changed and rejected are recorded here.
func (f *Fetcher) fetch(ctx context.Context) bool {
	first, err := f.c.Signature(ctx)
	if err != nil {
		return false
	}
	if run := f.loader.Current(); run != nil && bytes.Equal(first, run.Signature()) {
		f.c.Good()
		return true
	}
	archive, err := f.c.Archive(ctx)
	if err != nil {
		return false
	}
	second, err := f.c.Signature(ctx)
	if err != nil {
		return false
	}
	if !bytes.Equal(first, second) {
		f.c.Record(ClassChanged, http.StatusOK)
		return false
	}
	if f.pairRead != nil {
		f.pairRead()
	}
	if ctx.Err() != nil { // no load starts after the stop
		return false
	}
	if _, err := f.loader.LoadFetched(archive, first); err != nil {
		if errors.Is(err, bundle.ErrInstallFault) {
			// LoadFetched wrote the one log line. This is no rejection.
			f.faults.Add(1)
			return false
		}
		f.c.Record(ClassRejected, http.StatusOK)
		return false
	}
	f.c.Good()
	return true
}

// InstallFaults gives the number of loads that passed each check and then
// failed to write their files. It is safe for concurrent use.
func (f *Fetcher) InstallFaults() uint64 { return f.faults.Load() }

// Frozen tells if there was no good fetch for max(24 h, 4 intervals). Before
// the first good fetch, the time counts from the start of Run. It is false
// before Run starts. It is safe for concurrent use.
func (f *Fetcher) Frozen() bool {
	ref := f.c.LastGood()
	if ref.IsZero() {
		n := f.began.Load()
		if n == 0 {
			return false
		}
		ref = time.Unix(0, n)
	}
	return f.c.now().Sub(ref) >= max(freezeFloor, freezeTimes*f.interval)
}
