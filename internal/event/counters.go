package event

import (
	"fmt"
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
// The default fmt output of the map would print every key. A key is a client
// address (C8). Counters therefore implements fmt.Formatter. For the verbs
// that call it, Format prints only the key count and the overflow bucket count.
// The verbs %T and %p do not call Format. They print the type and the address
// of the pointer, and they print no key.
//
// A Counters value holds a pointer to a stateRef. The stateRef holds the
// pointer to the state. The state holds the lock, the map, and the bucket.
// When fmt reaches a Counters value by reflection, fmt stops at the second
// pointer and prints no key. This holds for a Counters value in an unexported
// field, in an unexported any field, in a nested struct, in an array, and in
// a map. It also holds for a *Counters in an unexported field.
//
// Only Snapshot gives the keys to its caller. All methods are safe for
// concurrent use. The zero value is not ready for use: call NewCounters.
type Counters struct {
	h *stateRef
}

// stateRef holds the pointer to the state. It is the second pointer between
// a Counters value and the map.
type stateRef struct {
	s *counterState
}

// counterState holds the lock, the map, and the overflow bucket.
type counterState struct {
	mu       sync.Mutex
	counts   map[netip.Addr]uint64
	overflow uint64
}

// NewCounters returns an empty Counters value.
func NewCounters() *Counters {
	st := &counterState{counts: make(map[netip.Addr]uint64)}
	return &Counters{h: &stateRef{s: st}}
}

// Format implements fmt.Formatter. It prints the key count and the overflow
// bucket count for every verb and flag, and never prints a key. The zero value
// prints zero for both counts.
func (c Counters) Format(f fmt.State, _ rune) {
	var keys int
	var overflow uint64
	if c.h != nil {
		s := c.h.s
		s.mu.Lock()
		keys, overflow = len(s.counts), s.overflow
		s.mu.Unlock()
	}
	fmt.Fprintf(f, "event.Counters{keys:%d overflow:%d}", keys, overflow)
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
	s := c.h.s
	s.mu.Lock()
	defer s.mu.Unlock()
	if !ok {
		s.overflow++
		return
	}
	if _, found := s.counts[k]; found || len(s.counts) < maxCounterKeys {
		s.counts[k]++
		return
	}
	s.overflow++
}

// DropNoAddr counts one dropped event that has no client address, for example
// a system event. It goes to the overflow bucket.
func (c *Counters) DropNoAddr() {
	s := c.h.s
	s.mu.Lock()
	s.overflow++
	s.mu.Unlock()
}

// Snapshot swaps in an empty map and a zero overflow bucket. It returns the
// old map and the old bucket count. The caller owns the returned map. Each
// increment is in exactly one snapshot.
func (c *Counters) Snapshot() (counts map[netip.Addr]uint64, overflow uint64) {
	s := c.h.s
	s.mu.Lock()
	counts, overflow = s.counts, s.overflow
	s.counts, s.overflow = make(map[netip.Addr]uint64), 0
	s.mu.Unlock()
	return counts, overflow
}
