package listener

import (
	"crypto/tls"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cybagard/cyba-phantom/internal/event"
)

// The caps of SEC-22, written again here so that a changed constant in the code
// fails a test.
const (
	testWindow   = 60 * time.Second
	testInterval = 200 * time.Millisecond
)

// The emit takes a reason and a net.Addr, and no request value.
var _ func(*refusedEmitter, event.RefusedReason, net.Addr) = (*refusedEmitter).emit

// testSinks returns a queue of the given depth and the counters of that queue.
func testSinks(t testing.TB, depth int) (*event.Queue, *event.Counters) {
	t.Helper()
	c := event.NewCounters()
	q, err := event.NewQueue(depth, c)
	if err != nil {
		t.Fatal(err)
	}
	return q, c
}

// refusedRig is an emitter with a fake monotonic clock that the test sets.
type refusedRig struct {
	r   *refusedEmitter
	q   *event.Queue
	c   *event.Counters
	now time.Duration
}

func newRefusedRig(t testing.TB, depth int) *refusedRig {
	q, c := testSinks(t, depth)
	g := &refusedRig{q: q, c: c}
	g.r = newRefusedEmitter(q, c, func() time.Duration { return g.now })
	return g
}

func tcpAddr(s string) *net.TCPAddr {
	return net.TCPAddrFromAddrPort(netip.AddrPortFrom(netip.MustParseAddr(s), 443))
}

// emit sets the clock to at and emits a bad_hello for the address s.
func (g *refusedRig) emit(at time.Duration, s string) {
	g.now = at
	g.r.emit(event.ReasonBadHello, tcpAddr(s))
}

// want takes the events and the counts since the last call, and compares them
// with the expected values. The queue must count no drop.
func (g *refusedRig) want(t *testing.T, events int, drops map[string]uint64, overflow uint64) {
	t.Helper()
	if n := len(g.q.Drain()); n != events {
		t.Errorf("%d events, want %d", n, events)
	}
	counts, ov := g.c.Snapshot()
	got := map[string]uint64{}
	for k, n := range counts {
		got[k.String()] = n
	}
	if !maps.Equal(got, drops) || ov != overflow {
		t.Errorf("counts %v and overflow %d, want %v and %d", got, ov, drops, overflow)
	}
	if d := g.q.Dropped(); d != (event.Dropped{}) {
		t.Errorf("the queue counts drops %+v, want none", d)
	}
}

// T-S-22: one event for each client key in 60 s. A second emit makes no event
// and adds one to the counter of its key. The window ends at 60 s, and the key
// of an IPv6 address is its /64 prefix.
func TestTS22PerKeyWindow(t *testing.T) {
	g := newRefusedRig(t, 1024)
	g.emit(0, "192.0.2.1")
	g.want(t, 1, nil, 0)
	g.emit(testWindow-1, "192.0.2.1")
	g.want(t, 0, map[string]uint64{"192.0.2.1": 1}, 0)
	g.emit(testWindow-1, "::ffff:192.0.2.1") // the same key as 192.0.2.1
	g.want(t, 0, map[string]uint64{"192.0.2.1": 1}, 0)
	g.emit(testWindow, "192.0.2.1")
	g.want(t, 1, nil, 0)

	g.emit(2*testWindow, "2001:db8:0:1::1")
	g.emit(2*testWindow, "2001:db8:0:2::1")
	g.emit(2*testWindow+time.Second, "2001:db8:0:1::2") // same /64 as ::1
	g.want(t, 2, map[string]uint64{"2001:db8:0:1::": 1}, 0)
	// An entry of age 60 s is out of the window and is removed.
	g.emit(3*testWindow, "2001:db8:0:1::3")
	g.want(t, 1, nil, 0)
	if n := g.r.keys(); n != 1 {
		t.Errorf("the map holds %d keys, want 1", n)
	}
}

// T-S-22: the total bucket is 5 each second with burst 5. An emit over it, or
// over both caps, adds exactly one to the counter of its key.
func TestTS22TotalBucket(t *testing.T) {
	g := newRefusedRig(t, 1024)
	for i := 1; i <= 5; i++ {
		g.emit(0, fmt.Sprintf("192.0.2.%d", i))
	}
	g.want(t, 5, nil, 0)
	g.emit(0, "192.0.2.6")
	g.want(t, 0, map[string]uint64{"192.0.2.6": 1}, 0)
	g.emit(testInterval-1, "192.0.2.7")
	g.want(t, 0, map[string]uint64{"192.0.2.7": 1}, 0)
	g.emit(testInterval, "192.0.2.8")
	g.want(t, 1, nil, 0)
	g.emit(testInterval, "192.0.2.9")
	g.want(t, 0, map[string]uint64{"192.0.2.9": 1}, 0)
	// Key 1 is in its window, and the bucket is empty.
	g.emit(testInterval, "192.0.2.1")
	g.want(t, 0, map[string]uint64{"192.0.2.1": 1}, 0)
}

// T-S-22: after an idle hour the bucket holds 5 tokens, not more. The clock
// jumps, then 1000 emits of new keys give 5 events and 995 counted drops.
func TestTS22BucketAfterIdle(t *testing.T) {
	g := newRefusedRig(t, 1024)
	for i := 1; i <= 5; i++ {
		g.emit(0, fmt.Sprintf("192.0.2.%d", i))
	}
	g.want(t, 5, nil, 0)
	drops := map[string]uint64{}
	for i := range 1000 {
		s := fmt.Sprintf("10.0.%d.%d", i>>8, i&255)
		g.emit(time.Hour, s)
		if i >= 5 {
			drops[s] = 1
		}
	}
	g.want(t, 5, drops, 0)
}

// T-S-22: a key that fails its window takes no token.
func TestTS22WindowFailTakesNoToken(t *testing.T) {
	g := newRefusedRig(t, 1024)
	for range 10 {
		g.emit(0, "192.0.2.1")
	}
	g.want(t, 1, map[string]uint64{"192.0.2.1": 9}, 0)
	for i := 2; i <= 5; i++ {
		g.emit(0, fmt.Sprintf("192.0.2.%d", i))
	}
	g.want(t, 4, nil, 0)
	g.emit(0, "192.0.2.6")
	g.want(t, 0, map[string]uint64{"192.0.2.6": 1}, 0)
}

// T-S-22: over T seconds at most 5 + 5*T emits pass. A new key makes each emit,
// one every 10 ms for 10 s, so the window never limits.
func TestTS22BucketRate(t *testing.T) {
	g := newRefusedRig(t, 1024)
	for i := 0; i <= 1000; i++ {
		g.now = time.Duration(i) * 10 * time.Millisecond
		g.r.emit(event.ReasonBadHello, &net.TCPAddr{IP: net.IPv4(10, 0, byte(i>>8), byte(i)), Port: 443})
	}
	passed := len(g.q.Drain())
	if passed != 5+5*10 {
		t.Errorf("%d emits passed in 10 s, want %d", passed, 5+5*10)
	}
	counts, _ := g.c.Snapshot()
	var drops uint64
	for _, n := range counts {
		drops += n
	}
	if drops != uint64(1001-passed) {
		t.Errorf("%d drops counted, want %d", drops, 1001-passed)
	}
	if d := g.q.Dropped(); d != (event.Dropped{}) {
		t.Errorf("the queue counts drops %+v, want none", d)
	}
}

// T-S-22, T-U-17: take 10^6 IPv6 /64 keys in 120 s at more than the full rate
// of the bucket. The run crosses the edge of the window, so old entries leave.
// The window map holds at most 305 entries. The counters hold at most 4096 keys
// plus the overflow bucket.
func TestTS22MapBound(t *testing.T) {
	const n = 1_000_000
	g := newRefusedRig(t, 1024)
	maxKeys := 0
	for i := range n {
		g.now = 2 * testWindow / n * time.Duration(i)
		ip := [16]byte{0x20, 0x01, 0x0d, 0xb8, byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i), 0, 0, 0, 0, 0, 0, 0, 1}
		g.r.emit(event.ReasonBadHello, &net.TCPAddr{IP: ip[:], Port: 443})
		maxKeys = max(maxKeys, g.r.keys())
	}
	passed := len(g.q.Drain())
	if passed < 600 || passed > 605 || maxKeys < 300 || maxKeys > 305 {
		t.Errorf("%d events passed and the map held %d entries at most, want 600 to 605 and 300 to 305", passed, maxKeys)
	}
	counts, overflow := g.c.Snapshot()
	var drops uint64
	for _, c := range counts {
		drops += c
	}
	if len(counts) != 4096 || overflow == 0 || drops+overflow != uint64(n-passed) {
		t.Errorf("%d counter keys, overflow %d, %d counted; want 4096 keys, an overflow, %d in all", len(counts), overflow, drops, n-passed)
	}
	if d := g.q.Dropped(); d != (event.Dropped{}) {
		t.Errorf("the queue counts drops %+v, want none", d)
	}
	g.emit(4*testWindow, "192.0.2.1")
	if k := g.r.keys(); k != 1 {
		t.Errorf("the map holds %d entries after a quiet 60 s, want 1", k)
	}
}

// T-S-22: two emits at the same time for one key give one event.
func TestTS22SameKeyAtOnce(t *testing.T) {
	const callers = 64
	g := newRefusedRig(t, 1024)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			g.r.emit(event.ReasonBadHello, tcpAddr("192.0.2.1"))
		}()
	}
	close(start)
	wg.Wait()
	g.want(t, 1, map[string]uint64{"192.0.2.1": callers - 1}, 0)
}

// T-S-22: a step of the event clock does not reset a window. The window reads
// the monotonic seam.
func TestTS22EventClockStep(t *testing.T) {
	g := newRefusedRig(t, 1024)
	wall := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	g.r.ts = func() time.Time { return wall }
	g.emit(0, "192.0.2.1")
	wall = wall.Add(-time.Hour)
	g.emit(time.Second, "192.0.2.1")
	wall = wall.Add(2 * time.Hour)
	g.emit(2*time.Second, "192.0.2.1")
	evs := g.q.Drain()
	if len(evs) != 1 || evs[0].Record().TS != time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC).UnixMilli() {
		t.Errorf("%d events, want 1 with the time of the event clock", len(evs))
	}
	g.want(t, 0, map[string]uint64{"192.0.2.1": 2}, 0)
}

// T-S-22: the event has the reason and the address of the peer, with no zone
// and no mapping. It has no status, vhost, method, path or session.
func TestTS22EventValues(t *testing.T) {
	g := newRefusedRig(t, 1024)
	peers := []struct {
		peer *net.TCPAddr
		ip   string
	}{
		{&net.TCPAddr{IP: net.ParseIP("fe80::1"), Port: 443, Zone: "eth0"}, "fe80::1"},
		{&net.TCPAddr{IP: net.ParseIP("::ffff:192.0.2.9"), Port: 443}, "192.0.2.9"},
		{tcpAddr("2001:db8:5:6:7:8:9:a"), "2001:db8:5:6:7:8:9:a"},
	}
	for _, p := range peers {
		g.r.emit(event.ReasonClientAbort, p.peer)
	}
	evs := g.q.Drain()
	if len(evs) != len(peers) {
		t.Fatalf("%d events, want %d", len(evs), len(peers))
	}
	for i, e := range evs {
		r := e.Record()
		if e.Kind() != event.KindRefused || e.IP() != peers[i].ip {
			t.Errorf("peer %d: kind %v, ip %q; want refused and %q", i, e.Kind(), e.IP(), peers[i].ip)
		}
		if j, err := r.Detail.JSON(); err != nil || string(j) != `{"reason":"client_abort"}` {
			t.Errorf("peer %d: detail %s, %v; want the reason client_abort", i, j, err)
		}
		if r.Status != nil || r.Vhost != nil || r.Method != nil || r.Path != nil || r.Session != nil {
			t.Errorf("peer %d: the record has a request field", i)
		}
	}
}

// T-S-22: with a full bulk lane, and after Queue.Close, the emit returns. The
// queue counts the drop.
func TestTS22FullLaneAndClosedQueue(t *testing.T) {
	g := newRefusedRig(t, 1)
	g.emit(0, "192.0.2.1")
	g.emit(0, "192.0.2.2") // the lane holds one event
	if d := g.q.Dropped(); d.Bulk != 1 {
		t.Errorf("full lane: the queue counts %+v, want one bulk drop", d)
	}
	g.q.Drain()
	g.q.Close()
	g.emit(0, "192.0.2.3")
	if d := g.q.Dropped(); d.Bulk != 2 {
		t.Errorf("closed queue: the queue counts %+v, want two bulk drops", d)
	}
	counts, _ := g.c.Snapshot()
	want := map[netip.Addr]uint64{netip.MustParseAddr("192.0.2.2"): 1, netip.MustParseAddr("192.0.2.3"): 1}
	if !maps.Equal(counts, want) {
		t.Errorf("counters %v, want %v", counts, want)
	}
}

// T-S-22: a peer with no valid address makes no event and adds one to the
// overflow bucket.
func TestTS22NoValidPeerAddress(t *testing.T) {
	g := newRefusedRig(t, 1024)
	var nilTCP *net.TCPAddr
	peers := []net.Addr{nil, nilTCP, &net.TCPAddr{}, &net.UDPAddr{IP: net.ParseIP("192.0.2.1")}, &net.UnixAddr{Name: "x", Net: "unix"}}
	for i, p := range peers {
		g.now = 0
		g.r.emit(event.ReasonBadHello, p)
		g.want(t, 0, nil, 1)
		if k := g.r.keys(); k != 0 {
			t.Errorf("peer %d: the map holds %d entries, want 0", i, k)
		}
	}
}

// T-S-22: an event that NewEvent refuses adds one to the error count, makes no
// event and no drop.
func TestTS22NewEventErrorCount(t *testing.T) {
	g := newRefusedRig(t, 1024)
	g.r.emit(0, tcpAddr("192.0.2.1")) // the zero value is not a reason
	if n := g.r.errs.Load(); n != 1 {
		t.Errorf("error count %d, want 1", n)
	}
	g.want(t, 0, nil, 0)
}

// T-S-22: New refuses a nil queue and nil counters. It gives the emitter the
// queue and the counters of its config.
func TestTS22NewWiresQueueAndCounters(t *testing.T) {
	cert, _ := testCert(t)
	q, c := testSinks(t, 1024)
	cfg := Config{TLS: &tls.Config{Certificates: []tls.Certificate{cert}}, MaxConns: 1, HeaderBytes: testHeaderBytes, Queue: q, Counters: c}
	for name, mod := range map[string]func(*Config){
		"no queue":    func(c *Config) { c.Queue = nil },
		"no counters": func(c *Config) { c.Counters = nil },
	} {
		bad := cfg
		mod(&bad)
		if _, err := New(bad, okHandler); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	s, err := New(cfg, okHandler)
	if err != nil {
		t.Fatal(err)
	}
	s.refused.emit(event.ReasonBadHello, tcpAddr("192.0.2.1"))
	s.refused.emit(event.ReasonBadHello, tcpAddr("192.0.2.1"))
	if evs := q.Drain(); len(evs) != 1 {
		t.Errorf("the queue holds %d events, want 1", len(evs))
	}
	if counts, _ := c.Snapshot(); counts[netip.MustParseAddr("192.0.2.1")] != 1 {
		t.Errorf("counters %v, want one drop for 192.0.2.1", counts)
	}
	s.refused.emit(0, tcpAddr("192.0.2.2")) // the zero value is not a reason
	if n := s.RefusedEventErrors(); n != 1 {
		t.Errorf("RefusedEventErrors %d, want 1", n)
	}
}

// T-S-22: the caps of a server read a clock that runs from the start of the
// server. The test moves the start back one hour and reads the clock. The
// clock must be 1 h or more. It must not exceed 1 h plus the time since an
// earlier read of the wall clock.
func TestTS22ServerClockRuns(t *testing.T) {
	before := time.Now()
	d := monotonicSince(time.Now().Add(-time.Hour))()
	if limit := time.Hour + time.Since(before); d < time.Hour || d > limit {
		t.Errorf("monotonicSince gives %v for a start one hour back, want 1h to %v", d, limit)
	}
	old := serverStart
	t.Cleanup(func() { serverStart = old })
	serverStart = func() time.Time { return time.Now().Add(-time.Hour) }
	cert, _ := testCert(t)
	q, c := testSinks(t, 16)
	cfg := Config{TLS: &tls.Config{Certificates: []tls.Certificate{cert}}, MaxConns: 1, HeaderBytes: testHeaderBytes, Queue: q, Counters: c}
	before = time.Now()
	s, err := New(cfg, okHandler)
	if err != nil {
		t.Fatal(err)
	}
	d = s.refused.mono()
	if limit := time.Hour + time.Since(before); d < time.Hour || d > limit {
		t.Errorf("the clock of the server gives %v, want 1h to %v", d, limit)
	}
}

// T-S-22: in production, the clock starts when New makes the server. The
// test does not replace the start. The clock of a new server starts near zero.
func TestTS22ProductionStart(t *testing.T) {
	if d := time.Since(serverStart()); d < 0 || d > time.Minute {
		t.Errorf("time since the production start is %v, want 0 to 1m", d)
	}
	cert, _ := testCert(t)
	q, c := testSinks(t, 16)
	cfg := Config{TLS: &tls.Config{Certificates: []tls.Certificate{cert}}, MaxConns: 1, HeaderBytes: testHeaderBytes, Queue: q, Counters: c}
	t0 := time.Now()
	s, err := New(cfg, okHandler)
	if err != nil {
		t.Fatal(err)
	}
	d := s.refused.mono()
	if limit := time.Since(t0); d < 0 || d > limit {
		t.Errorf("the clock of a new server gives %v, want 0 to %v", d, limit)
	}
}

// T-S-22: the production start has a monotonic reading, so a step of the wall
// clock does not move the caps. Such a time prints " m=" in its string form.
func TestTS22ProductionStartMonotonic(t *testing.T) {
	if s := serverStart().String(); !strings.Contains(s, " m=") {
		t.Errorf("the production start %q has no monotonic reading", s)
	}
}

// BenchmarkRefusedEmit measures an emit that passes both caps and an emit over
// the window of its key.
func BenchmarkRefusedEmit(b *testing.B) {
	peer := tcpAddr("192.0.2.1")
	for _, c := range []struct {
		name string
		step time.Duration
	}{{"pass", testWindow}, {"capped", 0}} {
		b.Run(c.name, func(b *testing.B) {
			g := newRefusedRig(b, 1024)
			g.r.emit(event.ReasonBadHello, peer)
			b.ReportAllocs()
			for b.Loop() {
				g.now += c.step
				g.r.emit(event.ReasonBadHello, peer)
				g.q.TryTake()
			}
		})
	}
}
