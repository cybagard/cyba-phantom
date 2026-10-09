package event

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/netip"
	"strings"
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

// markerForms returns every text form of the client address s that a leak
// could show: the address, its key, the IPv4-mapped forms, and the decimal and
// hex forms of the two 64-bit words of the key. All forms are lower case.
func markerForms(t *testing.T, s string) []string {
	t.Helper()
	a := mustAddr(t, s)
	k, ok := counterKey(a)
	if !ok {
		t.Fatalf("no key for %s", s)
	}
	forms := []string{a.String(), k.String(), k.StringExpanded(), a.Unmap().String()}
	if k.Is4() {
		m := netip.AddrFrom16(k.As16())
		forms = append(forms, "::ffff:"+k.String(), m.String(), m.StringExpanded())
	}
	b := k.As16()
	for _, w := range []uint64{binary.BigEndian.Uint64(b[:8]), binary.BigEndian.Uint64(b[8:])} {
		if w < 1<<16 {
			continue // too short to be a marker: it would match a count
		}
		forms = append(forms, fmt.Sprintf("%d", w), fmt.Sprintf("%x", w))
	}
	for i, f := range forms {
		forms[i] = strings.ToLower(f)
	}
	return forms
}

// markerAddrs are a known IPv4 address, an IPv4-mapped IPv6 address, and an
// IPv6 address.
var markerAddrs = []string{
	"203.0.113.7",
	"::ffff:198.51.100.9",
	"2001:db8:1:2:aaaa:bbbb:cccc:dddd",
}

// markedCounters returns a Counters value with one key for each marker and
// two events in the overflow bucket.
func markedCounters() *Counters {
	c := NewCounters()
	for _, s := range markerAddrs {
		c.Drop(netip.MustParseAddr(s))
	}
	c.Drop(netip.Addr{})
	c.DropNoAddr()
	return c
}

// checkNoMarker fails when out holds a form of a marker, or does not hold the
// key count and the bucket count.
func checkNoMarker(t *testing.T, out string) {
	t.Helper()
	low := strings.ToLower(out)
	for _, s := range markerAddrs {
		for _, f := range markerForms(t, s) {
			if strings.Contains(low, f) {
				t.Errorf("output holds %q (a form of %s): %s", f, s, out)
			}
		}
	}
	if !strings.Contains(out, "keys:3") || !strings.Contains(out, "overflow:2") {
		t.Errorf("output lacks the key count or the bucket count: %s", out)
	}
}

// T-U-17: the marker forms hold the known words: 203.0.113.7 as a netip word
// is 281474087547143 (0xffffcb007107). The leak checks below are not vacuous.
func TestTU17_MarkerFormsCoverNetipWords(t *testing.T) {
	forms := strings.Join(markerForms(t, "203.0.113.7"), " ")
	for _, want := range []string{"203.0.113.7", "::ffff:203.0.113.7", "281474087547143", "ffffcb007107"} {
		if !strings.Contains(forms, want) {
			t.Errorf("forms lack %q: %s", want, forms)
		}
	}
}

// T-U-17: fmt of a *Counters and of a Counters value, with each verb, prints
// no key in any form, and prints the key count.
func TestTU17_FormatHoldsNoKey(t *testing.T) {
	c := markedCounters()
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%d", "%x", "%q"} {
		for _, form := range []struct {
			name string
			arg  any
		}{{"pointer", c}, {"value", *c}} {
			t.Run(verb+"/"+form.name, func(t *testing.T) {
				checkNoMarker(t, fmt.Sprintf(verb, form.arg))
			})
		}
	}
}

// T-U-17: a Counters inside an error text and inside a slog record holds no
// key, for the pointer and for the value.
func TestTU17_FormatInErrorAndLog(t *testing.T) {
	c := markedCounters()
	for _, form := range []struct {
		name string
		arg  any
	}{{"pointer", c}, {"value", *c}} {
		t.Run("error/"+form.name, func(t *testing.T) {
			checkNoMarker(t, fmt.Errorf("drops: %v", form.arg).Error())
		})
		t.Run("slog/"+form.name, func(t *testing.T) {
			var buf bytes.Buffer
			slog.New(slog.NewTextHandler(&buf, nil)).Info("dropped", slog.Any("c", form.arg))
			checkNoMarker(t, buf.String())
		})
	}
}

// T-U-17: Format does not change the counts (a snapshot after a format still
// returns the keys), and a zero value formats without a panic.
func TestTU17_FormatKeepsCounts(t *testing.T) {
	c := markedCounters()
	_ = fmt.Sprintf("%v %+v %#v %s", c, c, *c, *c)
	m, other := c.Snapshot()
	if len(m) != 3 || other != 2 {
		t.Errorf("snapshot after format = %d keys, %d in the bucket, want 3 and 2", len(m), other)
	}
	if got := fmt.Sprintf("%v", Counters{}); !strings.Contains(got, "keys:0") {
		t.Errorf("zero value formats as %q", got)
	}
}
