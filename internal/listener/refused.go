package listener

import (
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cybagard/cyba-phantom/internal/event"
)

// The caps of the refused events (SEC-22). They are constants, not config
// keys.
const (
	// refusedWindow is the time in which one client key makes one event.
	refusedWindow = 60 * time.Second
	// refusedInterval is the time for one token of the total bucket to come
	// back. It gives 5 events each second in the long run.
	refusedInterval = time.Second / 5
	// refusedBurst is the size of the total bucket.
	refusedBurst = 5
)

// refusedEmitter makes the refused events of one Server. The window of each
// client key and the total bucket both read the clock mono. It is separate
// from the event clock, so a step of the wall clock changes neither. One lock
// covers the window map and the bucket. The map has no String or Format
// method, and no code prints it.
type refusedEmitter struct {
	q *event.Queue
	c *event.Counters
	// mono gives the time since the start, on the monotonic clock.
	mono func() time.Duration
	// ts is the clock of the event time. Nil is the wall clock.
	ts event.Clock
	// errs counts the emits for which NewEvent returned an error.
	errs atomic.Uint64

	mu sync.Mutex
	// last holds the time of the last event of each key.
	last map[netip.Addr]time.Duration
	// tat is the time at which the bucket is full again.
	tat time.Duration
}

// newRefusedEmitter returns an emitter that reads mono for the caps.
func newRefusedEmitter(q *event.Queue, c *event.Counters, mono func() time.Duration) *refusedEmitter {
	return &refusedEmitter{q: q, c: c, mono: mono, last: make(map[netip.Addr]time.Duration)}
}

// monotonicSince returns a clock that gives the time since now. time.Since
// reads the monotonic clock.
func monotonicSince() func() time.Duration {
	start := time.Now()
	return func() time.Duration { return time.Since(start) }
}

// emit makes one refused event for the peer and puts it on the queue. It takes
// the reason and the address of the connection, and no request value. A peer
// that is not a valid *net.TCPAddr gets no event and adds one to the overflow
// bucket. An emit over a cap adds one to the counter of its key, and no event
// and no queue drop. The call never waits.
func (r *refusedEmitter) emit(reason event.RefusedReason, peer net.Addr) {
	t, ok := peer.(*net.TCPAddr)
	if !ok {
		r.c.DropNoAddr()
		return
	}
	// AddrPort of a nil *net.TCPAddr gives an invalid address.
	ip := t.AddrPort().Addr().Unmap().WithZone("")
	key, ok := event.CounterKey(ip)
	if !ok {
		r.c.DropNoAddr()
		return
	}
	if !r.allow(key, r.mono()) {
		r.c.Drop(ip)
		return
	}
	e, err := event.NewEvent(r.ts, event.Input{Kind: event.KindRefused, Reason: reason, ClientIP: ip.String()})
	if err != nil {
		r.errs.Add(1)
		return
	}
	r.q.Enqueue(e)
}

// allow tells if key may make an event at now. It checks the window of the key,
// then the bucket. Only an event that passes both takes a token and writes the
// entry of the key. When it writes an entry, it removes the entries that are
// not in the window.
func (r *refusedEmitter) allow(key netip.Addr, now time.Duration) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if at, found := r.last[key]; found && now-at < refusedWindow {
		return false
	}
	if r.tat-now > (refusedBurst-1)*refusedInterval {
		return false
	}
	r.tat = max(r.tat, now) + refusedInterval
	for k, at := range r.last {
		if now-at >= refusedWindow {
			delete(r.last, k)
		}
	}
	r.last[key] = now
	return true
}

// keys is the number of client keys in the window map.
func (r *refusedEmitter) keys() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.last)
}
