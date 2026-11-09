package bait

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
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
	_, ra, n := c.hit(t, addr4(1), tok)
	if n != 1 || ra.TrapID != nil || ra.TokenID != nil || ra.Surface != nil || c.h.capped.Load() != 0 {
		t.Fatalf("admitted: %d events, request %+v, %d capped", n, ra, c.h.capped.Load())
	}
	_, rc, n := c.hit(t, addr4(1), tok)
	parsed, _ := token.Parse(tok)
	if n != 0 || rc.TrapID == nil || *rc.TrapID != "a" || rc.TokenID == nil || *rc.TokenID != token.ID(parsed) ||
		rc.Surface == nil || *rc.Surface != event.SurfaceQuery || c.h.capped.Load() != 1 {
		t.Errorf("capped: %d events, request %+v, %d capped", n, rc, c.h.capped.Load())
	}
	// At each position, the first request is admitted and the second is
	// capped. The two responses are equal.
	for pos, surface := range surfaces {
		tk, from := c.fresh(t), addr4(20+pos)
		var got [2]*httptest.ResponseRecorder
		before := c.h.capped.Load()
		for i := range got {
			r := cbReq(methodOf(pos), cbRoutePath, pos, tk)
			r.RemoteAddr = from
			got[i] = serve(t, c.h, r)
			if _, cbs := take(c.q); len(cbs) != 1-i {
				t.Errorf("%s: request %d made %d callback events, want %d", surface, i, len(cbs), 1-i)
			}
		}
		if n := c.h.capped.Load() - before; n != 1 {
			t.Errorf("%s: %d capped tokens for the two requests, want 1", surface, n)
		}
		if dump(got[0]) != dump(got[1]) || len(got[1].Result().Header.Values("Set-Cookie")) != 0 {
			t.Errorf("%s: response differs or sets a cookie:\n%s\n%s", surface, dump(got[0]), dump(got[1]))
		}
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

// TestTS32CapNoClientKey checks a token with no valid client key. It gets no
// callback event, no capped count and no entry in the maps. The empty address
// is valid for the request event, so only the cap code can refuse it.
func TestTS32CapNoClientKey(t *testing.T) {
	c := newCapEnv(t)
	r := cbReq(http.MethodGet, cbRoutePath, posQuery, c.fresh(t))
	r.RemoteAddr = ""
	serve(t, c.h, r)
	reqs, cbs := take(c.q)
	tk, ks := c.h.admit.sizes()
	if len(reqs) != 1 || len(cbs) != 0 || c.h.capped.Load() != 0 || tk != 0 || ks != 0 {
		t.Errorf("%d request and %d callback events, %d capped, maps %d and %d", len(reqs), len(cbs), c.h.capped.Load(), tk, ks)
	}
}

// TestTS32CapKeySliceBound reuses one client key over many windows. The
// entries of the key stay at 10 or fewer. All key slices hold 120 or fewer.
func TestTS32CapKeySliceBound(t *testing.T) {
	c := newCallbackCap()
	key, _ := event.CounterKey(addr(1))
	for i := range 2000 {
		now := time.Duration(i) * 6 * time.Second
		c.allow(strconv.Itoa(i), key, now)
		if total, most := c.keyEntries(); most > wantKeyMax || total > boundKeys {
			t.Fatalf("try %d: %d entries for one key, %d in all, want %d and %d at most", i, most, total, wantKeyMax, boundKeys)
		}
	}
	if total, _ := c.keyEntries(); total != wantKeyMax {
		t.Errorf("%d entries at the end, want %d", total, wantKeyMax)
	}
}

// TestTS32CapIdleBurst checks the bucket after a long idle time. The test
// admits some events and then pauses longer than the refill time. Then many
// distinct tokens and keys at one instant give exactly the burst.
func TestTS32CapIdleBurst(t *testing.T) {
	c := newCallbackCap()
	for i := range 10 {
		key, _ := event.CounterKey(addr(i))
		c.allow("early"+strconv.Itoa(i), key, time.Duration(i)*time.Second)
	}
	idle := 2000 * time.Second
	got := 0
	for i := range 2000 {
		key, _ := event.CounterKey(addr(100 + i))
		if c.allow("late"+strconv.Itoa(i), key, idle) {
			got++
		}
	}
	if got != wantBurst {
		t.Errorf("%d events at one instant after the idle time, want %d", got, wantBurst)
	}
}

// TestTS32CapClockRuns checks the clock of a handler that New makes. The
// test moves the start back by a time that is not a whole second. The clock
// must give that time or more. It must give at most that time plus the time
// since an earlier read. The clock also advances: after 10 ms of sleep, a
// second read is at least 10 ms later.
func TestTS32CapClockRuns(t *testing.T) {
	const offset = time.Hour + 1234567891*time.Nanosecond
	old := capStart
	t.Cleanup(func() { capStart = old })
	capStart = func() time.Time { return time.Now().Add(-offset) }
	before := time.Now()
	h := New(&swap{}, &fallbackFn{}, testQueue(t))
	d, limit := h.mono(), offset+time.Since(before)
	if d < offset || d > limit {
		t.Errorf("the clock gives %v, want %v to %v", d, offset, limit)
	}
	time.Sleep(10 * time.Millisecond)
	if d2 := h.mono(); d2-d < 10*time.Millisecond {
		t.Errorf("the clock advanced %v in 10 ms of sleep, want 10 ms or more", d2-d)
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
		// Each key holds one entry here, so the entries equal the keys.
		if total, most := c.keyEntries(); total != ks || total > boundKeys || most > 1 {
			t.Fatalf("try %d: %d entries in %d keys, %d for one key", i, total, ks, most)
		}
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
func settle(t testing.TB, q *event.Queue) {
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
// leaves equal the admitted callback events. No event is dropped. The test
// also checks the tlog leaves for each second: 60 in second 0, then 1 each
// second.
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
	const leafQuery = "SELECT count(*) FROM event WHERE kind = 'callback' AND leaf_index IS NOT NULL"
	admitted, stored := 0, 0
	perSecond := make([]int, seconds)
	for i := range rate * seconds {
		s := i / rate
		clock = time.Duration(s)*time.Second + time.Duration(i%rate)*(time.Second/rate)
		r := cbReq(http.MethodGet, cbRoutePath, posQuery, e.mint(t, time.Now()))
		r.RemoteAddr = addr4((i + s) % keys)
		before := h.capped.Load()
		serve(t, h, r)
		admitted += int(1 - (h.capped.Load() - before))
		settle(t, rig.q)
		if i%rate != rate-1 {
			continue
		}
		// The end of the second: wait for the leaves of the admitted events.
		leaves := 0
		for end := time.Now().Add(5 * time.Second); ; time.Sleep(time.Millisecond) {
			if leaves = countOf(t, rig.db, leafQuery); leaves >= admitted || time.Now().After(end) {
				break
			}
		}
		perSecond[s], stored = leaves-stored, leaves
	}
	for s, n := range perSecond {
		want := 1
		if s == 0 {
			want = wantBurst
		}
		if n != want {
			t.Errorf("second %d: %d leaves, want %d", s, n, want)
		}
	}
	t.Logf("tlog leaves for each second: %v", perSecond)
	rig.q.Close()
	if err := <-done; err != nil || !rig.w.Healthy() {
		t.Fatalf("the writer stopped: %v %v", err, rig.w.Err())
	}
	if d := rig.q.Dropped(); d != (event.Dropped{}) {
		t.Errorf("dropped events %+v", d)
	}
	leaves := countOf(t, rig.db, leafQuery)
	rows := countOf(t, rig.db, "SELECT count(*) FROM event WHERE kind = 'callback'")
	if want := wantBurst + seconds - 1; admitted != want || leaves != admitted || rows != admitted {
		t.Errorf("admitted %d (want %d), callback rows %d, leaves %d", admitted, want, rows, leaves)
	}
}

// tableBytes gives the page bytes of each table (dbstat). The bytes of the
// indexes of a table are in its value.
func tableBytes(t testing.TB, db *sql.DB) map[string]float64 {
	t.Helper()
	rows, err := db.Query("SELECT m.tbl_name, SUM(d.pgsize) FROM dbstat d JOIN sqlite_master m ON m.name = d.name GROUP BY m.tbl_name")
	mustOK(t, err)
	defer rows.Close()
	out := map[string]float64{}
	for rows.Next() {
		var name string
		var n float64
		mustOK(t, rows.Scan(&name, &n))
		out[name] = n
	}
	mustOK(t, rows.Err())
	return out
}

// dirBytes gives the sum of the sizes of the files below dir.
func dirBytes(t testing.TB, dir string) (n int64) {
	t.Helper()
	mustOK(t, filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		fi, err := d.Info()
		n += fi.Size()
		return err
	}))
	return n
}

// BenchmarkCallbackRows renders 4 000 pages that each carry a token. Then it
// serves the 4 000 callbacks of these tokens through a real writer and tlog.
// For each callback it reports the bytes that the event table and the token
// table gain (dbstat). It reports the bytes that the tlog files gain for each
// leaf, and the callback rows and token rows. The event gain includes the
// request row of the callback. The event bytes for each render are the request
// row of a render page. One page is 4 096 bytes. A token row takes about 130
// bytes. At this count one page changes the token value by 0.8 %. The
// benchmark does its work one time and ignores b.N.
func BenchmarkCallbackRows(b *testing.B) {
	const n = 4000
	rig := newStoreRig(b)
	e := newCBEnvFiles(b, map[string]string{
		"traps/traps.json":          `[{"id":"a","slot":"hidden-p","surface":"path","visibility":"human-visible","instruction_template":"x {{.Token}}"}]`,
		"vhosts/example.com/t.tmpl": `<p>{{index .Trap "a"}}</p>`,
	})
	h := NewWithDayKey(e.h.src, &fallbackFn{}, rig.q, rig.dk)
	h.SetRing(e.h.ring)
	var clock time.Duration
	h.mono = func() time.Duration { return clock }
	done := make(chan error, 1)
	go func() { done <- rig.w.Run(context.Background()) }()
	texts := make([]string, n)
	for i := range n {
		r := get("/t", "example.com")
		r.RemoteAddr = addr4(i)
		texts[i] = tokenRE.FindString(serve(b, h, r).Body.String())
		settle(b, rig.q)
	}
	for end := time.Now().Add(10 * time.Second); countOf(b, rig.db, "SELECT count(*) FROM mint") < n; time.Sleep(time.Millisecond) {
		if time.Now().After(end) {
			b.Fatal("the writer did not store the mint rows")
		}
	}
	before, logBefore := tableBytes(b, rig.db), dirBytes(b, rig.log)
	for i, tok := range texts {
		// The cap lets one callback through each second after its burst.
		clock = time.Duration(i) * wantInterval
		r := cbReq(http.MethodGet, cbRoutePath, posQuery, tok)
		r.RemoteAddr = addr4(i)
		serve(b, h, r)
		settle(b, rig.q)
	}
	rig.q.Close()
	if err := <-done; err != nil || !rig.w.Healthy() {
		b.Fatalf("the writer stopped: %v %v", err, rig.w.Err())
	}
	const leafQuery = "SELECT count(*) FROM event WHERE kind = 'callback' AND leaf_index IS NOT NULL"
	leaves := countOf(b, rig.db, leafQuery)
	cbs := countOf(b, rig.db, "SELECT count(*) FROM event WHERE kind = 'callback'")
	toks := countOf(b, rig.db, "SELECT count(*) FROM token")
	if cbs != n || leaves != n || h.capped.Load() != 0 {
		b.Fatalf("%d callback rows and %d leaves, want %d; %d capped", cbs, leaves, n, h.capped.Load())
	}
	after := tableBytes(b, rig.db)
	b.ReportMetric(before["event"]/n, "event-B/render")
	b.ReportMetric((after["event"]-before["event"])/n, "event-B/callback")
	b.ReportMetric((after["token"]-before["token"])/n, "token-B/callback")
	b.ReportMetric(float64(dirBytes(b, rig.log)-logBefore)/float64(leaves), "tlog-B/leaf")
	b.ReportMetric(float64(cbs)/n, "callback-rows/callback")
	b.ReportMetric(float64(toks)/n, "token-rows/callback")
}

// TestTS32CapPruneKeepsWindow checks that a write removes only the entries
// outside their window. A token that is admitted late stays capped after two
// more writes.
func TestTS32CapPruneKeepsWindow(t *testing.T) {
	c := newCallbackCap()
	const late = 1000 * time.Second
	ka, _ := event.CounterKey(addr(1))
	kb, _ := event.CounterKey(addr(2))
	if !c.allow("a", ka, late) || !c.allow("b", kb, late+time.Second) {
		t.Fatal("a fresh token was capped")
	}
	if c.allow("a", ka, late+2*time.Second) {
		t.Error("a token in its window passed after another write")
	}
}

// TestTS32CapPruneBoundary checks the edge of each window. An entry that is
// exactly one window old leaves the map at the next write. The token map does
// this after 600 s. The key map does this after 60 s.
func TestTS32CapPruneBoundary(t *testing.T) {
	ka, _ := event.CounterKey(addr(1))
	kb, _ := event.CounterKey(addr(2))
	for _, tc := range []struct {
		name   string
		window time.Duration
		sizes  func(c *callbackCap) int
	}{
		{"token", wantTokenWindow, func(c *callbackCap) int { n, _ := c.sizes(); return n }},
		{"key", wantKeyWindow, func(c *callbackCap) int { _, n := c.sizes(); return n }},
	} {
		c := newCallbackCap()
		const start = 100 * time.Second
		if !c.allow("a", ka, start) || !c.allow("b", kb, start+tc.window-1) {
			t.Fatalf("%s: a fresh token was capped", tc.name)
		}
		if n := tc.sizes(c); n != 2 {
			t.Errorf("%s: %d entries just before the boundary, want 2", tc.name, n)
		}
		c = newCallbackCap()
		if !c.allow("a", ka, start) || !c.allow("b", kb, start+tc.window) {
			t.Fatalf("%s: a fresh token was capped", tc.name)
		}
		if n := tc.sizes(c); n != 1 {
			t.Errorf("%s: %d entries at the boundary, want 1", tc.name, n)
		}
	}
}
