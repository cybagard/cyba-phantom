package event

import (
	"net/netip"
	"sync"
)

// maxCounterKeys is the largest number of keys that a Counters value holds
// between two snapshots. The value is fixed (ADR-015). It is not a config
// value.
const maxCounterKeys = 4096

// ipv6PrefixBits is the length of the prefix that keys an IPv6 address.
const ipv6PrefixBits = 64

// Counters counts the events that the queue drops, for each client key
// (SEC-15). A key is an IPv4 address, or the /64 prefix of an IPv6 address.
// The map holds at most maxCounterKeys keys. When it is full, an increment for
// a new key goes to one shared overflow bucket. A key that is in the map
// always increments its own counter. The map never evicts a key between two
// snapshots.
//
// The package never logs a key. Counters has no String, GoString, or Format
// method. Only Snapshot gives the keys to its caller. All methods are safe for
// concurrent use. The zero value is not ready for use: call NewCounters.
type Counters struct {
	mu     sync.Mutex
	counts map[netip.Addr]uint64
	other  uint64
}

// NewCounters returns an empty Counters value.
func NewCounters() *Counters {
	return &Counters{counts: make(map[netip.Addr]uint64)}
}

// counterKey returns the key for a. It maps an IPv4-mapped IPv6 address to
// IPv4, removes the zone, and masks an IPv6 address to its /64 prefix. The
// second result is false for an invalid address: that address has no key.
func counterKey(a netip.Addr) (netip.Addr, bool) {
	a = a.Unmap().WithZone("")
	if !a.IsValid() {
		return netip.Addr{}, false
	}
	if a.Is6() {
		return netip.PrefixFrom(a, ipv6PrefixBits).Masked().Addr(), true
	}
	return a, true
}

// Drop counts one dropped event for the client address a. An invalid address
// goes to the overflow bucket.
func (c *Counters) Drop(a netip.Addr) {
	k, ok := counterKey(a)
	c.mu.Lock()
	defer c.mu.Unlock()
	if !ok {
		c.other++
		return
	}
	if _, found := c.counts[k]; found || len(c.counts) < maxCounterKeys {
		c.counts[k]++
		return
	}
	c.other++
}

// DropNoAddr counts one dropped event that has no client address, for example
// a system event. It goes to the overflow bucket.
func (c *Counters) DropNoAddr() {
	c.mu.Lock()
	c.other++
	c.mu.Unlock()
}

// Snapshot swaps in an empty map and a zero overflow bucket. It returns the
// old map and the old bucket count. The caller owns the returned map. Each
// increment is in the snapshot before it or in the snapshot after it, one
// time.
func (c *Counters) Snapshot() (counts map[netip.Addr]uint64, other uint64) {
	c.mu.Lock()
	counts, other = c.counts, c.other
	c.counts, c.other = make(map[netip.Addr]uint64), 0
	c.mu.Unlock()
	return counts, other
}
