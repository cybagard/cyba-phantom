package bait

import (
	"net/netip"
	"slices"
	"sync"
	"time"
)

// The caps of the callback events (SEC-37, ADR-039 decision 9). They are
// constants, not config keys.
const (
	// capTokenWindow is the time in which one token makes one event.
	capTokenWindow = 600 * time.Second
	// capKeyWindow is the sliding window of one client key, and capKeyMax is
	// the number of events that it holds.
	capKeyWindow = 60 * time.Second
	capKeyMax    = 10
	// capInterval is the time for one slot of the total bucket to come
	// back. It gives 1 event each second in the long run. capBurst is the
	// number of slots in the bucket.
	capInterval = time.Second
	capBurst    = 60
)

// callbackCap is the admission cap of the callback events. It holds the window
// of each token, the sliding window of each client key and the total bucket.
// One lock covers all three. The maps hold admitted entries only. So they
// hold at most 660 tokens and 120 client keys. That is the burst plus the
// events of one window. The maps have no String or Format
// method, and no code prints them.
type callbackCap struct {
	mu sync.Mutex
	// tokens holds the time of the last admitted event of each token id.
	tokens map[string]time.Duration
	// keys holds the times of the admitted events of each client key.
	keys map[netip.Addr][]time.Duration
	// tat is the time at which the bucket is full again.
	tat time.Duration
}

func newCallbackCap() *callbackCap {
	return &callbackCap{tokens: make(map[string]time.Duration), keys: make(map[netip.Addr][]time.Duration)}
}

// monotonicSince returns a clock that gives the time since start. time.Since
// reads the monotonic clock if start has a monotonic reading.
func monotonicSince(start time.Time) func() time.Duration {
	return func() time.Duration { return time.Since(start) }
}

// allow tells if the token id may make an event for the client key at now. It
// checks the window of the token, the window of the key, then the bucket. Only
// an event that passes all three takes a bucket slot and writes the entries.
// When it writes, it removes the entries that are not in their window.
func (c *callbackCap) allow(id string, key netip.Addr, now time.Duration) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if at, found := c.tokens[id]; found && now-at < capTokenWindow {
		return false
	}
	recent := 0
	for _, at := range c.keys[key] {
		if now-at < capKeyWindow {
			recent++
		}
	}
	if recent >= capKeyMax {
		return false
	}
	if c.tat-now > (capBurst-1)*capInterval {
		return false
	}
	c.tat = max(c.tat, now) + capInterval
	for k, at := range c.tokens {
		if now-at >= capTokenWindow {
			delete(c.tokens, k)
		}
	}
	for k, times := range c.keys {
		times = slices.DeleteFunc(times, func(at time.Duration) bool { return now-at >= capKeyWindow })
		if len(times) == 0 {
			delete(c.keys, k)
		} else {
			c.keys[k] = times
		}
	}
	c.tokens[id] = now
	c.keys[key] = append(c.keys[key], now)
	return true
}

// sizes gives the number of tokens and of client keys in the maps.
func (c *callbackCap) sizes() (tokens, keys int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.tokens), len(c.keys)
}

// keyEntries gives the number of entries in all key slices, and the most
// entries that one key holds.
func (c *callbackCap) keyEntries() (total, most int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, times := range c.keys {
		total += len(times)
		most = max(most, len(times))
	}
	return total, most
}
