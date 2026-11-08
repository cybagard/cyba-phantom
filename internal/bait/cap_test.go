package bait

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/cybagard/cyba-phantom/internal/event"
	"github.com/cybagard/cyba-phantom/internal/token"
)

// The numbers of SEC-37 as literals, not the constants of the code, so a
// changed constant fails a test.
const (
	wantTokenWindow = 600 * time.Second
	wantKeyWindow   = 60 * time.Second
	wantKeyMax      = 10
	wantBurst       = 60
	wantInterval    = time.Second
)

// capEnv is a callback handler with a clock that the test steps.
type capEnv struct {
	*cbEnv
	clock time.Duration
}

func newCapEnv(t testing.TB) *capEnv {
	c := &capEnv{cbEnv: newCBEnv(t)}
	c.h.mono = func() time.Duration { return c.clock }
	return c
}

// addr4 gives the remote address of client number i. Each i is its own key.
func addr4(i int) string { return fmt.Sprintf("10.%d.%d.%d:1000", i>>16&255, i>>8&255, i&255) }

// hit serves a GET with tok at the query position from the remote address
// from. It gives the response, the request record and the number of callback
// events.
func (c *capEnv) hit(t testing.TB, from, tok string) (*httptest.ResponseRecorder, event.Record, int) {
	t.Helper()
	r := cbReq(http.MethodGet, cbRoutePath, posQuery, tok)
	r.RemoteAddr = from
	w := serve(t, c.h, r)
	reqs, cbs := take(c.q)
	if len(reqs) != 1 {
		t.Fatalf("%d request events, want 1", len(reqs))
	}
	return w, reqs[0], len(cbs)
}

// fresh gives a token that no request has used.
func (c *capEnv) fresh(t testing.TB) string { return c.mint(t, time.Now()) }

// TestTS32CapToken checks the cap of one token: one event in 600 s. A replay
// of the token 1 000 times in 599 s gives one event. The last request at the
// boundary is capped, and the first request after it passes.
func TestTS32CapToken(t *testing.T) {
	c := newCapEnv(t)
	tok := c.fresh(t)
	got := 0
	for i := range 1000 {
		c.clock = time.Duration(i) * (wantTokenWindow - time.Second) / 1000
		_, _, n := c.hit(t, addr4(0), tok)
		got += n
	}
	if got != 1 {
		t.Fatalf("%d events for 1 000 replays, want 1", got)
	}
	for _, s := range []struct {
		at   time.Duration
		want int
	}{
		{wantTokenWindow - 1, 0}, {wantTokenWindow, 1},
		{2*wantTokenWindow - 1, 0}, {2 * wantTokenWindow, 1},
	} {
		c.clock = s.at
		if _, _, n := c.hit(t, addr4(0), tok); n != s.want {
			t.Errorf("at %v: %d events, want %d", s.at, n, s.want)
		}
	}
	if capped := c.h.capped.Load(); capped != 1001 {
		t.Errorf("%d capped tokens, want 1 001", capped)
	}
}

// TestTS32CapKey checks the cap of one client key: 10 events in any 60 s. The
// window slides. The 11th token passes when the first leaves the window, and
// the 12th passes only when the second leaves it.
func TestTS32CapKey(t *testing.T) {
	c := newCapEnv(t)
	from := addr4(7)
	for i := range wantKeyMax {
		c.clock = time.Duration(i) * time.Second
		if _, _, n := c.hit(t, from, c.fresh(t)); n != 1 {
			t.Fatalf("token %d: %d events, want 1", i, n)
		}
	}
	t11, t12 := c.fresh(t), c.fresh(t)
	for _, s := range []struct {
		at   time.Duration
		tok  string
		want int
	}{
		{wantKeyWindow - 1, t11, 0}, {wantKeyWindow, t11, 1},
		{wantKeyWindow, t12, 0}, {wantKeyWindow + time.Second - 1, t12, 0}, {wantKeyWindow + time.Second, t12, 1},
	} {
		c.clock = s.at
		if _, _, n := c.hit(t, from, s.tok); n != s.want {
			t.Errorf("at %v: %d events, want %d", s.at, n, s.want)
		}
	}
	// Another key is not in the window of the first.
	if _, _, n := c.hit(t, addr4(8), c.fresh(t)); n != 1 {
		t.Errorf("other key: %d events, want 1", n)
	}
}

// TestTS32CapKeyPrefix checks that the key is event.CounterKey of the client
// address: 11 hosts of one IPv6 /64 are one key.
func TestTS32CapKeyPrefix(t *testing.T) {
	c := newCapEnv(t)
	got := 0
	for i := range wantKeyMax + 1 {
		_, _, n := c.hit(t, fmt.Sprintf("[2001:db8:0:1::%x]:1000", i+1), c.fresh(t))
		got += n
	}
	if got != wantKeyMax {
		t.Errorf("%d events from one /64, want %d", got, wantKeyMax)
	}
	if _, _, n := c.hit(t, "[2001:db8:0:2::1]:1000", c.fresh(t)); n != 1 {
		t.Errorf("other /64: %d events, want 1", n)
	}
}

// TestTS32CapTotal checks the total bucket: 100 keys in 1 s give 60 events.
// Then each second gives 1 event, and the request just before it gives none.
func TestTS32CapTotal(t *testing.T) {
	c := newCapEnv(t)
	got := 0
	for i := range 100 {
		_, _, n := c.hit(t, addr4(i), c.fresh(t))
		got += n
	}
	if got != wantBurst {
		t.Fatalf("%d events in the burst, want %d", got, wantBurst)
	}
	for s := 1; s <= 5; s++ {
		for i, step := range []struct {
			at   time.Duration
			want int
		}{{time.Duration(s)*wantInterval - 1, 0}, {time.Duration(s) * wantInterval, 1}, {time.Duration(s) * wantInterval, 0}} {
			c.clock = step.at
			if _, _, n := c.hit(t, addr4(100*s+i), c.fresh(t)); n != step.want {
				t.Errorf("second %d step %d: %d events, want %d", s, i, n, step.want)
			}
		}
	}
}

// TestTS32CapRefusedToken checks a token that a cap refuses. The request has
// no callback event. The request event has the trap id, the token id and the
// surface of the first refused token. The counter adds one for each refused
// token. The response equals the response to an admitted token. A request
// with no refused token has none of the three fields.
func TestTS32CapRefusedToken(t *testing.T) {
	c := newCapEnv(t)
	tok := c.fresh(t)
	wa, ra, n := c.hit(t, addr4(1), tok)
	if n != 1 || ra.TrapID != nil || ra.TokenID != nil || ra.Surface != nil || c.h.capped.Load() != 0 {
		t.Fatalf("admitted: %d events, request %+v, %d capped", n, ra, c.h.capped.Load())
	}
	wc, rc, n := c.hit(t, addr4(1), tok)
	parsed, _ := token.Parse(tok)
	if n != 0 || rc.TrapID == nil || *rc.TrapID != "a" || rc.TokenID == nil || *rc.TokenID != token.ID(parsed) ||
		rc.Surface == nil || *rc.Surface != event.SurfaceQuery || c.h.capped.Load() != 1 {
		t.Errorf("capped: %d events, request %+v, %d capped", n, rc, c.h.capped.Load())
	}
	if dump(wa) != dump(wc) {
		t.Errorf("response differs:\n%s\n%s", dump(wa), dump(wc))
	}
	// A fresh path token passes. The query and header tokens are used.
	// The query token comes first, so it is in the request event.
	q, h := c.fresh(t), c.fresh(t)
	for _, tk := range []string{q, h} {
		c.hit(t, addr4(2), tk)
	}
	before := c.h.capped.Load()
	r := cbReqN(http.MethodGet, cbRoutePath, [4]string{c.fresh(t), q, h, ""})
	serve(t, c.h, r)
	reqs, cbs := take(c.q)
	qp, _ := token.Parse(q)
	if len(cbs) != 1 || len(reqs) != 1 || reqs[0].TokenID == nil || *reqs[0].TokenID != token.ID(qp) ||
		reqs[0].Surface == nil || *reqs[0].Surface != event.SurfaceQuery || c.h.capped.Load() != before+2 {
		t.Errorf("two capped: %d callbacks, request %+v, %d new capped", len(cbs), reqs, c.h.capped.Load()-before)
	}
}

// TestTS32CapNoClientKey checks that a token with no valid client key gets no
// callback event.
func TestTS32CapNoClientKey(t *testing.T) {
	c := newCapEnv(t)
	r := cbReq(http.MethodGet, cbRoutePath, posQuery, c.fresh(t))
	r.RemoteAddr = "bogus"
	serve(t, c.h, r)
	if _, cbs := take(c.q); len(cbs) != 0 || c.h.capped.Load() != 0 {
		t.Errorf("%d events and %d capped for a client with no key", len(cbs), c.h.capped.Load())
	}
}

// The bounds of the maps: the burst and the events of one window.
const (
	boundTokens = wantBurst + int(wantTokenWindow/wantInterval)
	boundKeys   = wantBurst + int(wantKeyWindow/wantInterval)
)

// TestTP12CapBounds checks the size of the maps after 10^6 tries with distinct
// tokens and keys. The tries come 1 000 each second, so the clock runs for
// 1 000 s and the windows slide. The maps hold at most 660 tokens and 120 keys.
func TestTP12CapBounds(t *testing.T) {
	c := newCallbackCap()
	const tries = 1_000_000
	maxTokens, maxKeys, admitted := 0, 0, 0
	for i := range tries {
		key, _ := event.CounterKey(addr(i))
		if c.allow(strconv.Itoa(i), key, time.Duration(i)*time.Millisecond) {
			admitted++
		}
		tk, ks := c.sizes()
		maxTokens, maxKeys = max(maxTokens, tk), max(maxKeys, ks)
	}
	if maxTokens > boundTokens || maxKeys > boundKeys {
		t.Errorf("maps reached %d tokens and %d keys, bounds %d and %d", maxTokens, maxKeys, boundTokens, boundKeys)
	}
	t.Logf("%d admitted of %d tries; at most %d tokens and %d keys", admitted, tries, maxTokens, maxKeys)
}

// addr gives a distinct IPv4 address for each i.
func addr(i int) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)})
}

// floodSeconds is the length of the simulated flood of T-P-12.
const floodSeconds = 60

// TestTP12CapFlood runs the flood of T-P-12 at the cap. It has 3 000 requests
// each second with valid, distinct tokens from 1 000 client keys. It runs for
// 60 simulated seconds. The test steps the clock. Each callback event is one
// tlog leaf. It logs the count for each second. The first second gives the
// burst. Each later second gives 1. Request i uses the key (i + i/3000) mod
// 1000. So the first request of each second is not always the same key.
func TestTP12CapFlood(t *testing.T) {
	c := newCapEnv(t)
	const rate, keys = 3000, 1000
	perSecond := make([]int, floodSeconds)
	// One request value serves all tries: the loop sets its query and address.
	r := cbReq(http.MethodGet, cbRoutePath, posQuery, "")
	w := &discard{h: http.Header{}}
	for i := range rate * floodSeconds {
		s := i / rate
		c.clock = time.Duration(s)*time.Second + time.Duration(i%rate)*(time.Second/rate)
		r.URL.RawQuery, r.RemoteAddr = "ref="+c.mint(t, time.Now()), addr4((i+s)%keys)
		clear(w.h)
		c.h.ServeHTTP(w, r)
		for _, ev := range c.q.Drain() {
			if ev.Record().Kind == event.KindCallback {
				perSecond[s]++
			}
		}
	}
	total := 0
	for s, n := range perSecond {
		want := 1
		if s == 0 {
			want = wantBurst
		}
		if n != want {
			t.Errorf("second %d: %d events, want %d", s, n, want)
		}
		total += n
	}
	if want := wantBurst + floodSeconds - 1; total != want {
		t.Errorf("%d events in %d s, want %d", total, floodSeconds, want)
	}
	t.Logf("callback events for each second: %v", perSecond)
	if tk, ks := c.h.admit.sizes(); tk > boundTokens || ks > boundKeys {
		t.Errorf("maps hold %d tokens and %d keys", tk, ks)
	}
}

// settle waits until the writer has taken each event off the queue.
func settle(t *testing.T, q *event.Queue) {
	t.Helper()
	for end := time.Now().Add(5 * time.Second); q.Bytes() != (event.Bytes{}); {
		if time.Now().After(end) {
			t.Fatal("the writer did not take the events")
		}
		time.Sleep(time.Millisecond)
	}
}

// TestTP12CapLeaves runs a smaller flood through a real writer and tlog. It
// has 100 requests each second from 50 client keys for 5 seconds. The tlog
// leaves equal the admitted callback events. No event is dropped.
func TestTP12CapLeaves(t *testing.T) {
	rig := newStoreRig(t)
	e := newCBEnv(t)
	h := NewWithDayKey(e.h.src, &fallbackFn{}, rig.q, rig.dk)
	h.SetRing(e.h.ring)
	var clock time.Duration
	h.mono = func() time.Duration { return clock }
	done := make(chan error, 1)
	go func() { done <- rig.w.Run(context.Background()) }()
	const rate, keys, seconds = 100, 50, 5
	admitted := 0
	for i := range rate * seconds {
		s := i / rate
		clock = time.Duration(s)*time.Second + time.Duration(i%rate)*(time.Second/rate)
		r := cbReq(http.MethodGet, cbRoutePath, posQuery, e.mint(t, time.Now()))
		r.RemoteAddr = addr4((i + s) % keys)
		before := h.capped.Load()
		serve(t, h, r)
		admitted += int(1 - (h.capped.Load() - before))
		settle(t, rig.q)
	}
	rig.q.Close()
	if err := <-done; err != nil || !rig.w.Healthy() {
		t.Fatalf("the writer stopped: %v %v", err, rig.w.Err())
	}
	if d := rig.q.Dropped(); d != (event.Dropped{}) {
		t.Errorf("dropped events %+v", d)
	}
	leaves := countOf(t, rig.db, "SELECT count(*) FROM event WHERE kind = 'callback' AND leaf_index IS NOT NULL")
	rows := countOf(t, rig.db, "SELECT count(*) FROM event WHERE kind = 'callback'")
	if want := wantBurst + seconds - 1; admitted != want || leaves != admitted || rows != admitted {
		t.Errorf("admitted %d (want %d), callback rows %d, leaves %d", admitted, want, rows, leaves)
	}
}
