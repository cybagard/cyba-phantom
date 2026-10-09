package event

import (
	"math/rand/v2"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
)

func mustAddr(t testing.TB, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// total adds the counts of a snapshot and its overflow bucket.
func total(m map[netip.Addr]uint64, other uint64) uint64 {
	n := other
	for _, v := range m {
		n += v
	}
	return n
}

// T-U-17: the key of an address is IPv4 as is, IPv4-mapped IPv6 as IPv4, no
// zone, and the /64 prefix for IPv6.
func TestTU17_KeyNormalization(t *testing.T) {
	key := func(s string) netip.Addr {
		t.Helper()
		k, ok := counterKey(mustAddr(t, s))
		if !ok {
			t.Fatalf("no key for %s", s)
		}
		return k
	}
	if got, want := key("192.0.2.1"), mustAddr(t, "192.0.2.1"); got != want {
		t.Errorf("IPv4 key changed: got %v, want %v", got, want)
	}
	if key("::ffff:192.0.2.1") != key("192.0.2.1") {
		t.Error("IPv4-mapped IPv6 and IPv4 have different keys")
	}
	if k := key("fe80::1%eth0"); k.Zone() != "" || k != key("fe80::1") {
		t.Errorf("zone not removed: %v", k)
	}
	if k := key("2001:db8:1:2:aaaa:bbbb:cccc:dddd"); k != mustAddr(t, "2001:db8:1:2::") {
		t.Errorf("IPv6 not masked to /64: %v", k)
	}
	if key("2001:db8:1:2::1") != key("2001:db8:1:2:ffff::9") {
		t.Error("two addresses in one /64 have different keys")
	}
	if key("2001:db8:1:2::1") == key("2001:db8:1:3::1") {
		t.Error("addresses in different /64 prefixes share a key")
	}
	if _, ok := counterKey(netip.Addr{}); ok {
		t.Error("invalid address has a key")
	}
}

// T-U-17: the counters count by key, and an invalid address or an event with
// no address goes to the overflow bucket.
func TestTU17_DropCounts(t *testing.T) {
	c := NewCounters()
	c.Drop(mustAddr(t, "192.0.2.1"))
	c.Drop(mustAddr(t, "::ffff:192.0.2.1"))
	c.Drop(mustAddr(t, "fe80::1%eth0"))
	c.Drop(netip.Addr{})
	c.DropNoAddr()
	m, other := c.Snapshot()
	if len(m) != 2 || m[mustAddr(t, "192.0.2.1")] != 2 || m[mustAddr(t, "fe80::")] != 1 {
		t.Errorf("unexpected counts: %v", m)
	}
	if other != 2 {
		t.Errorf("bucket = %d, want 2", other)
	}
}

func checkBound(t *testing.T, gen func(r *rand.Rand) netip.Addr) {
	const n = 1_000_000
	r := rand.New(rand.NewPCG(1, 2))
	c := NewCounters()
	for range n {
		c.Drop(gen(r))
	}
	m, other := c.Snapshot()
	if len(m) > maxCounterKeys {
		t.Errorf("%d keys, want at most %d", len(m), maxCounterKeys)
	}
	if got := total(m, other); got != n {
		t.Errorf("sum = %d, want %d", got, n)
	}
	if other == 0 {
		t.Error("overflow bucket is empty")
	}
}

// T-U-17: 10^6 distinct random IPv6 addresses keep the map at 4096 keys or
// fewer, and no count is lost.
func TestTU17_BoundRandomIPv6(t *testing.T) {
	checkBound(t, func(r *rand.Rand) netip.Addr {
		var b [16]byte
		for i := range b {
			b[i] = byte(r.Uint32())
		}
		return netip.AddrFrom16(b)
	})
}

// T-U-17: 10^6 distinct IPv6 addresses inside one /48 keep the map at 4096
// keys or fewer, and no count is lost.
func TestTU17_BoundOneSlash48(t *testing.T) {
	checkBound(t, func(r *rand.Rand) netip.Addr {
		b := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01}
		for i := 6; i < len(b); i++ {
			b[i] = byte(r.Uint32())
		}
		return netip.AddrFrom16(b)
	})
}

// T-U-17: a full map evicts no key. New keys go to the bucket, and a key in
// the map still increments its own counter.
func TestTU17_NoEviction(t *testing.T) {
	c := NewCounters()
	key := func(i int) netip.Addr {
		return netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
	}
	for i := range maxCounterKeys {
		c.Drop(key(i))
	}
	for i := maxCounterKeys; i < maxCounterKeys+10; i++ {
		c.Drop(key(i))
	}
	c.Drop(key(0))
	c.Drop(key(maxCounterKeys - 1))
	m, other := c.Snapshot()
	if len(m) != maxCounterKeys {
		t.Fatalf("%d keys, want %d", len(m), maxCounterKeys)
	}
	if other != 10 {
		t.Errorf("bucket = %d, want 10", other)
	}
	if m[key(0)] != 2 || m[key(maxCounterKeys-1)] != 2 || m[key(1)] != 1 {
		t.Error("a key in the map did not keep its own counter")
	}
	if _, ok := m[key(maxCounterKeys)]; ok {
		t.Error("a new key entered a full map")
	}
}

// T-U-17: Snapshot runs while goroutines increment. The sum over all
// snapshots equals the number of increments. Run with -race.
func TestTU17_ConcurrentSnapshot(t *testing.T) {
	const workers, per = 8, 50_000
	c := NewCounters()
	var done atomic.Bool
	var sum uint64
	var snapWG sync.WaitGroup
	snapWG.Add(1)
	go func() {
		defer snapWG.Done()
		for !done.Load() {
			sum += total(c.Snapshot())
		}
	}()
	var wg sync.WaitGroup
	for w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range per {
				if i%10 == 0 {
					c.DropNoAddr()
					continue
				}
				c.Drop(netip.AddrFrom4([4]byte{192, 0, byte(w), byte(i)}))
			}
		}()
	}
	wg.Wait()
	done.Store(true)
	snapWG.Wait()
	sum += total(c.Snapshot())
	if want := uint64(workers * per); sum != want {
		t.Errorf("sum = %d, want %d", sum, want)
	}
}

// T-U-17: a snapshot resets the counters. The next snapshot is empty when
// there was no increment.
func TestTU17_SnapshotReset(t *testing.T) {
	c := NewCounters()
	c.Drop(mustAddr(t, "192.0.2.1"))
	c.DropNoAddr()
	if m, other := c.Snapshot(); len(m) != 1 || other != 1 {
		t.Fatalf("first snapshot = %v, %d", m, other)
	}
	if m, other := c.Snapshot(); len(m) != 0 || other != 0 {
		t.Errorf("second snapshot = %v, %d, want empty", m, other)
	}
}
