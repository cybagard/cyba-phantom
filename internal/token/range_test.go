package token

import (
	"errors"
	"slices"
	"sync"
	"testing"
	"time"
)

// cycle gives n indexes that cycle over the trap list of size traps.
func cycle(n, traps int) []int {
	idx := make([]int, n)
	for i := range idx {
		idx[i] = i % traps
	}
	return idx
}

func TestTU01_RangeParallel(t *testing.T) {
	const workers, calls, traps = 8, 1000, 5
	const n = MaxRange
	k := newSet(t, testKey, traps)
	at := epoch.Add(3 * time.Hour)
	start := k.counter.Load()
	var spans [workers][]uint64
	var toks [workers][][Size]byte
	var wg sync.WaitGroup
	for w := range spans {
		wg.Add(1)
		go func() {
			defer wg.Done()
			idx := cycle(n, traps)
			toks[w] = make([][Size]byte, calls*n)
			for c := range calls {
				first, err := k.MintRange(idx, at, toks[w][c*n:(c+1)*n])
				if err != nil {
					t.Error(err)
					return
				}
				spans[w] = append(spans[w], first)
			}
		}()
	}
	wg.Wait()
	if t.Failed() {
		return
	}
	var offs []uint64
	for _, s := range spans {
		for _, first := range s {
			offs = append(offs, (first-start-1)&counterMask)
		}
	}
	slices.Sort(offs)
	for i, o := range offs {
		if o != uint64(i*n) {
			t.Fatalf("range %d starts at offset %d, want %d", i, o, i*n)
		}
	}
	if got := k.counter.Load() - start; got != workers*calls*n {
		t.Fatalf("counter moved by %d, want %d", got, workers*calls*n)
	}
	for w := range toks {
		for i, tok := range toks[w] {
			first := spans[w][i/n]
			want := Result{
				OK: true, Trap: "trap-" + string(rune('0'+(i%n)%traps)),
				Unit: uint32(unitOf(at)), Counter: (first + uint64(i%n)) & counterMask,
			}
			if got := Verify([]*KeySet{k}, tok); got != want {
				t.Fatalf("token %d of worker %d: Verify = %+v, want %+v", i, w, got, want)
			}
		}
	}
}

func TestTU01_RangeCounter(t *testing.T) {
	k := newSet(t, testKey, 3)
	for _, n := range []int{1, 2, MaxRange} {
		before := k.counter.Load()
		out := make([][Size]byte, n)
		first, err := k.MintRange(cycle(n, 3), epoch, out)
		if err != nil {
			t.Fatal(err)
		}
		if got := k.counter.Load() - before; got != uint64(n) {
			t.Errorf("range of %d moves the counter by %d", n, got)
		}
		if first != (before+1)&counterMask {
			t.Errorf("range of %d: first = %d, want %d", n, first, (before+1)&counterMask)
		}
		for i, tok := range out {
			if idx, _, c := open(k, tok); idx != uint64(i%3) || c != (first+uint64(i))&counterMask {
				t.Fatalf("range of %d, token %d: index %d, counter %d", n, i, idx, c)
			}
		}
	}
	// A range of one uses the counter that Mint would use.
	k.counter.Store(100)
	out := make([][Size]byte, 1)
	if _, err := k.MintRange([]int{2}, epoch, out); err != nil {
		t.Fatal(err)
	}
	k.counter.Store(100)
	tok, _ := k.Mint(2, epoch)
	if out[0] != tok {
		t.Error("a range of one and Mint give different tokens")
	}
	if _, _, c := open(k, tok); c != 101 {
		t.Errorf("counter = %d, want 101", c)
	}
}

func TestTU01_RangeWrap(t *testing.T) {
	k := newSet(t, testKey, 2)
	k.counter.Store(counterMask - 2)
	out := make([][Size]byte, 8)
	first, err := k.MintRange(cycle(8, 2), epoch, out)
	if err != nil {
		t.Fatal(err)
	}
	if first != counterMask-1 {
		t.Errorf("first = %d, want %d", first, uint64(counterMask-1))
	}
	want := []uint64{counterMask - 1, counterMask, 0, 1, 2, 3, 4, 5}
	for i, tok := range out {
		// A carry out of the counter would change the unit or the index.
		w := Result{OK: true, Trap: traps(2)[i%2], Counter: want[i]}
		if got := Verify([]*KeySet{k}, tok); got != w {
			t.Errorf("token %d: Verify = %+v, want %+v", i, got, w)
		}
	}
	// The raw counter can be at its top or past 2^42, as after a real wrap.
	for _, tc := range []struct {
		name  string
		raw   uint64
		n     int
		first uint64
	}{
		{"raw counter at the top", counterMask, 3, 0},
		{"raw counter past 2^42", 1<<42 + 5, 2, 6},
	} {
		k.counter.Store(tc.raw)
		out := make([][Size]byte, tc.n)
		first, err := k.MintRange(cycle(tc.n, 2), epoch, out)
		if err != nil {
			t.Fatal(err)
		}
		if first != tc.first {
			t.Errorf("%s: first = %d, want %d", tc.name, first, tc.first)
		}
		for i, tok := range out {
			w := Result{OK: true, Trap: traps(2)[i%2], Counter: tc.first + uint64(i)}
			if got := Verify([]*KeySet{k}, tok); got != w {
				t.Errorf("%s, token %d: Verify = %+v, want %+v", tc.name, i, got, w)
			}
		}
	}
}

func TestTU01_ScratchIsCleared(t *testing.T) {
	k := newSet(t, testKey, 2)
	tok, _ := k.Mint(1, epoch)
	calls := []struct {
		name string
		call func()
	}{
		{"MintRange", func() {
			_, _ = k.MintRange(cycle(MaxRange, 2), epoch, make([][Size]byte, MaxRange))
		}},
		{"Mint", func() { _, _ = k.Mint(1, epoch) }},
		{"Verify", func() { Verify([]*KeySet{k}, tok) }},
	}
	for _, c := range calls {
		for range 100 {
			c.call()
			b := scratch.Get().(*[2 * Size]byte)
			if *b != [2 * Size]byte{} {
				t.Fatalf("%s: the scratch buffer is not zero", c.name)
			}
			scratch.Put(b)
		}
	}
}

func TestTU01_RangeRefusals(t *testing.T) {
	k := newSet(t, testKey, 3)
	var none *KeySet
	tests := []struct {
		name string
		k    *KeySet
		idx  []int
		out  int
		want error
	}{
		{"nil key set", none, []int{0}, 1, ErrNoKeySet},
		{"empty key set", &KeySet{}, []int{0}, 1, ErrNoKeySet},
		{"length 69", k, cycle(69, 3), 69, ErrRange},
		{"length 0", k, nil, 0, ErrRange},
		{"out one short", k, cycle(4, 3), 3, ErrRange},
		{"out one long", k, cycle(4, 3), 5, ErrRange},
		{"index -1", k, []int{0, -1}, 2, ErrIndex},
		{"index at trap count, last", k, []int{0, 1, 2, 3}, 4, ErrIndex},
		{"index at trap count, last of 68", k, append(cycle(MaxRange-1, 3), 3), MaxRange, ErrIndex},
	}
	for _, tc := range tests {
		out := make([][Size]byte, tc.out)
		before := uint64(0)
		if tc.k == k {
			before = k.counter.Load()
		}
		if _, err := tc.k.MintRange(tc.idx, epoch, out); !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, want %v", tc.name, err, tc.want)
		}
		if tc.k == k && k.counter.Load() != before {
			t.Errorf("%s: the counter moved", tc.name)
		}
		if !slices.Equal(out, make([][Size]byte, tc.out)) {
			t.Errorf("%s: out was written", tc.name)
		}
	}
	// The largest list is allowed.
	if _, err := k.MintRange(cycle(68, 3), epoch, make([][Size]byte, 68)); err != nil {
		t.Errorf("length 68: err = %v", err)
	}
	if MaxRange != 68 {
		t.Errorf("MaxRange = %d, want 68", MaxRange)
	}
}

func TestTU01_VerifyCounter(t *testing.T) {
	a, b := newSet(t, testKey, 2), newSet(t, otherKey, 2)
	tok, _ := a.Mint(1, epoch)
	_, _, want := open(a, tok)
	if got := Verify([]*KeySet{a}, tok); !got.OK || got.Counter != want {
		t.Errorf("Verify = %+v, want counter %d", got, want)
	}
	bad := tok
	bad[0] ^= 1
	if got := Verify([]*KeySet{a, b}, bad); got != (Result{}) {
		t.Errorf("bad token: Verify = %+v", got)
	}
	// Only b matches. The last decrypt gives another counter.
	tb, _ := b.Mint(0, epoch)
	_, _, want = open(b, tb)
	if got := Verify([]*KeySet{b, a, a}, tb); got.Set != First || got.Counter != want {
		t.Errorf("first match: Verify = %+v, want counter %d", got, want)
	}
	if got := Verify([]*KeySet{a, b, a}, tb); got.Set != 1 || got.Counter != want {
		t.Errorf("middle match: Verify = %+v, want counter %d", got, want)
	}
}
