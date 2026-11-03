package token

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// clock is a clock that a test sets.
type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

// unitTime gives the start of time unit u since the epoch.
func unitTime(u int64) time.Time {
	return epoch.Add(time.Duration(u) * unitSeconds * time.Second)
}

// keys makes n key sets with other keys, and one token from each.
func keys(t testing.TB, n int) ([]*KeySet, [][Size]byte) {
	t.Helper()
	sets, toks := make([]*KeySet, n), make([][Size]byte, n)
	for i := range sets {
		key := []byte(fmt.Sprintf("ring-key-%07d", i))
		sets[i] = newSet(t, key, 2)
		toks[i], _ = sets[i].Mint(1, unitTime(100))
	}
	return sets, toks
}

// T-U-22: the class of a token for each age, at each side of each boundary.
// The clock is near the wrap at 2^20, and before the epoch. No age gives a
// refusal. The counter counts each future token and no other.
func TestTU22_Window(t *testing.T) {
	nows := map[string]time.Time{
		"2026":             unitTime(5000),
		"just after wrap":  unitTime(1<<20 + 3),
		"just before wrap": unitTime(1<<20 - 3),
		"at the epoch":     epoch,
		"before the epoch": epoch.Add(-48 * time.Hour),
	}
	ages := []struct {
		age           int64
		stale, future bool
	}{
		{-1 << 19, true, true}, // the smallest 20-bit age
		{-7, true, true},
		{-6, false, false},
		{0, false, false},
		{150, false, false},
		{151, true, false},
		{1<<19 - 1, true, false}, // the largest 20-bit age
	}
	for name, now := range nows {
		for _, a := range ages {
			t.Run(name+"/"+strconv.FormatInt(a.age, 10), func(t *testing.T) {
				k := newSet(t, testKey, 2)
				r := NewRing(func() time.Time { return now })
				r.Swap(k)
				tok, _ := k.Mint(1, now.Add(-time.Duration(a.age)*unitSeconds*time.Second))
				got := r.Verify(tok)
				if !got.OK || got.Set != First || got.Stale != a.stale || got.Future != a.future {
					t.Fatalf("Verify = %+v, want stale %v, future %v", got, a.stale, a.future)
				}
				want := uint64(0)
				if a.future {
					want = 1
				}
				if r.Futures() != want {
					t.Errorf("Futures = %d, want %d", r.Futures(), want)
				}
			})
		}
	}
}

// T-U-22: the replaced key set stays for one swap and for 25 h. Each row has
// the swaps. A swap is a position in sets, or -1 for a bundle with no key set.
// It has the wait after the last swap. It has the position that each token
// gets, and the number of key sets in the ring. A key set that is not in the
// ring gives no token.
func TestTU22_RingSwap(t *testing.T) {
	const none = -1
	tests := []struct {
		name   string
		swaps  []int
		wait   time.Duration
		want   [4]int
		length int
	}{
		{"empty ring", nil, 0, [4]int{none, none, none, none}, 0},
		{"one key set", []int{0}, 0, [4]int{First, none, none, none}, 1},
		{"one swap", []int{0, 1}, 0, [4]int{Second, First, none, none}, 2},
		{"second swap", []int{0, 1, 2}, 0, [4]int{none, Second, First, none}, 2},
		{"swap back", []int{0, 1, 0}, 0, [4]int{First, Second, none, none}, 2},
		{"just before 25 h", []int{0, 1}, replacedFor - time.Nanosecond, [4]int{Second, First, none, none}, 2},
		{"25 h", []int{0, 1}, replacedFor, [4]int{none, First, none, none}, 1},
		{"a long time", []int{0, 1}, 1000 * time.Hour, [4]int{none, First, none, none}, 1},
		{"no key set", []int{0, none}, 0, [4]int{Second, none, none, none}, 1},
		{"no key set twice", []int{0, none, none}, 0, [4]int{none, none, none, none}, 0},
		{"key set after none", []int{0, none, 1}, 0, [4]int{none, First, none, none}, 1},
		{"no key set first", []int{none, 0}, 0, [4]int{First, none, none, none}, 1},
	}
	sets, toks := keys(t, 4)
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := &clock{unitTime(110)}
			r := NewRing(c.now)
			for _, s := range tc.swaps {
				var k *KeySet
				if s != none {
					k = sets[s]
				}
				r.Swap(k)
			}
			c.t = c.t.Add(tc.wait)
			for i, tok := range toks {
				got := r.Verify(tok)
				if got.OK != (tc.want[i] != none) || got.OK && got.Set != tc.want[i] {
					t.Errorf("token %d: Verify = %+v, want position %d", i, got, tc.want[i])
				}
			}
			if r.Len() != tc.length {
				t.Errorf("Len = %d, want %d", r.Len(), tc.length)
			}
		})
	}
}

// T-U-22: a token with no match gets no class and no count. The clock is
// before the epoch, where the unit of a zero token is a future unit. The two
// tokens are the zero token and a token of a key set that is not in the ring.
func TestTU22_NoMatchNoClass(t *testing.T) {
	sets, toks := keys(t, 2)
	r := NewRing(func() time.Time { return epoch.Add(-48 * time.Hour) })
	r.Swap(sets[0])
	for name, tok := range map[string][Size]byte{"zero token": {}, "other key set": toks[1]} {
		if got := r.Verify(tok); got != (Result{}) || r.Futures() != 0 {
			t.Errorf("%s: Verify = %+v, Futures = %d", name, got, r.Futures())
		}
	}
}

// T-U-22: the 25 h end is wall time. The clock has a monotonic reading, as
// time.Now has. The stored end has none. The replaced key set verifies at 25 h
// minus 1 ns, and it gives no token at 25 h.
func TestTU22_RingEndWallTime(t *testing.T) {
	sets, toks := keys(t, 2)
	base := time.Now()
	var d time.Duration
	r := NewRing(func() time.Time { return base.Add(d) })
	r.Swap(sets[0])
	r.Swap(sets[1])
	if until := r.cur.Load().until; until != until.Round(0) {
		t.Errorf("the end %v has a monotonic reading", until)
	}
	for _, tc := range []struct {
		d  time.Duration
		ok bool
	}{{replacedFor - time.Nanosecond, true}, {replacedFor, false}} {
		d = tc.d
		if got := r.Verify(toks[0]); got.OK != tc.ok {
			t.Errorf("at %v: Verify = %+v", tc.d, got)
		}
	}
}

// T-U-22: after 100 swaps the ring holds 2 key sets, the last two. A new ring
// is a restart: it holds the key set of the first load, and no older one.
func TestTU22_RingHundredSwaps(t *testing.T) {
	sets, toks := keys(t, 100)
	r := NewRing(nil)
	for _, k := range sets {
		r.Swap(k)
	}
	if r.Len() != 2 {
		t.Errorf("Len = %d, want 2", r.Len())
	}
	for i, tok := range toks {
		want := map[int]bool{98: true, 99: true}[i]
		if got := r.Verify(tok); got.OK != want {
			t.Errorf("token %d: Verify = %+v", i, got)
		}
	}
	restart := NewRing(nil)
	if restart.Len() != 0 || restart.Verify(toks[99]).OK {
		t.Error("a new ring is not empty")
	}
	restart.Swap(sets[99])
	if got := restart.Verify(toks[99]); restart.Len() != 1 || !got.OK || got.Set != First {
		t.Errorf("a restart: Len = %d, Verify = %+v", restart.Len(), got)
	}
	if restart.Verify(toks[98]).OK {
		t.Error("a restart keeps the replaced key set")
	}
}

// T-U-22: swaps and verifies run at the same time (run it with -race). A
// token of a key set that the swaps keep in the ring always verifies.
func TestTU22_RingConcurrent(t *testing.T) {
	sets, toks := keys(t, 2)
	r := NewRing(func() time.Time { return unitTime(110) })
	r.Swap(sets[0])
	r.Swap(sets[1])
	var wg sync.WaitGroup
	wg.Go(func() {
		for i := range 2000 {
			r.Swap(sets[i%2])
		}
	})
	for range 2000 {
		for _, tok := range toks {
			if !r.Verify(tok).OK {
				t.Fatal("a token of a key set in the ring gives no token")
			}
		}
	}
	wg.Wait()
}

// T-C-06: a step of the clock. The token is fresh at the unit boundary. A
// step of 1 h in either direction keeps it fresh. A step of 2 d makes it
// stale, and a step back of 2 d makes it future. It is never refused.
func TestTC06_ClockSteps(t *testing.T) {
	tests := []struct {
		step          time.Duration
		stale, future bool
	}{
		{0, false, false},
		{time.Hour, false, false},
		{-time.Hour, false, false},
		{25 * time.Hour, false, false},
		{25*time.Hour + 10*time.Minute, true, false},
		{-time.Hour - 10*time.Minute, true, true},
		{48 * time.Hour, true, false},
		{-48 * time.Hour, true, true},
	}
	k := newSet(t, testKey, 2)
	for _, tc := range tests {
		t.Run(tc.step.String(), func(t *testing.T) {
			c := &clock{unitTime(5000)}
			r := NewRing(c.now)
			r.Swap(k)
			tok, _ := k.Mint(1, c.t)
			c.t = c.t.Add(tc.step)
			got := r.Verify(tok)
			if !got.OK || got.Trap != "trap-1" || got.Stale != tc.stale || got.Future != tc.future {
				t.Errorf("Verify = %+v, want stale %v, future %v", got, tc.stale, tc.future)
			}
		})
	}
	// The default clock is time.Now. A token of now is fresh.
	r := NewRing(nil)
	r.Swap(k)
	tok, _ := k.Mint(0, time.Now())
	if got := r.Verify(tok); !got.OK || got.Stale || got.Future {
		t.Errorf("default clock: Verify = %+v", got)
	}
}

// T-S-29: no print of a ring shows a trap id or a counter. Every verb gives
// one fixed text, also in a struct field that fmt can reach.
func TestTS29_RingFormat(t *testing.T) {
	k := newSet(t, testKey, 3)
	k.counter.Store(4886718345)
	r := NewRing(nil)
	r.Swap(k)
	r.futures.Store(987654321)
	type wrap struct{ R *Ring }
	// fmt does not call Format for a field that is not exported.
	type hidden struct{ r *Ring }
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d"} {
		for _, arg := range []any{r, wrap{r}, &wrap{r}, hidden{r}, &hidden{r}} {
			got := fmt.Sprintf(verb, arg)
			_, isHidden := arg.(hidden)
			_, isHiddenPtr := arg.(*hidden)
			if !strings.Contains(got, "token.Ring") && !isHidden && !isHiddenPtr {
				t.Errorf("%s of %T gives %q", verb, arg, got)
			}
			// 4886718345 is 0x123456789 and 987654321 is 0x3ADE68B1.
			for _, m := range []string{"trap-", "987654321", "4886718345", "123456789", "3ade68b1", "3ADE68B1"} {
				if strings.Contains(got, m) {
					t.Errorf("%s of %T holds %q: %q", verb, arg, m, got)
				}
			}
		}
	}
}

// T-U-22: a verify through the ring does not allocate in steady state.
func TestTU22_RingNoAllocs(t *testing.T) {
	sets, toks := keys(t, 2)
	r := NewRing(func() time.Time { return unitTime(110) })
	r.Swap(sets[0])
	r.Swap(sets[1])
	if n := testing.AllocsPerRun(1000, func() { _ = r.Verify(toks[0]) }); n != 0 {
		t.Errorf("Ring.Verify allocates %v times", n)
	}
}

func BenchmarkRingVerify(b *testing.B) {
	sets, toks := keys(b, 2)
	r := NewRing(func() time.Time { return unitTime(110) })
	r.Swap(sets[0])
	r.Swap(sets[1])
	b.ReportAllocs()
	for b.Loop() {
		_ = r.Verify(toks[0])
	}
}
