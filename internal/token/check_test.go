package token

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"strings"
	"sync"
	"testing"
	"time"
)

// sumKeySet makes a key set from a seed and a bundle SHA-256.
func sumKeySet(t testing.TB, seed string, sum [32]byte) *KeySet {
	t.Helper()
	k, err := NewKeySet([]byte(seed), sum, traps(2), false)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// allMatch is a cipher that decrypts every block to a valid future token.
type allMatch struct{ cipher.Block }

func (allMatch) Decrypt(dst, _ []byte) { pack(dst, 1, 200, 5) }

func fixedRing(sets ...*KeySet) *Ring {
	r := NewRing(func() time.Time { return unitTime(110) })
	for _, k := range sets {
		r.Swap(k)
	}
	return r
}

// T-S-32: the set id is the first 8 bytes of the bundle SHA-256, for each
// ring order. A non-match gives a zero set id.
func TestTS32_SetID(t *testing.T) {
	sumA, sumB := sha256.Sum256([]byte("a")), sha256.Sum256([]byte("b"))
	a, b := sumKeySet(t, "seed", sumA), sumKeySet(t, "seed", sumB)
	tok, _ := a.Mint(1, unitTime(100))
	var want, other [8]byte
	copy(want[:], sumA[:8])
	copy(other[:], sumB[:8])
	if want == other {
		t.Fatal("test sums share a set id")
	}
	if got, _ := b.Mint(0, unitTime(100)); Verify([]*KeySet{a}, got).OK {
		t.Fatal("token of B matches A")
	}
	for name, ring := range map[string][]*KeySet{"A,B": {a, b}, "B,A": {b, a}} {
		res := Verify(ring, tok)
		if !res.OK || res.SetID != want {
			t.Errorf("%s: Verify = %+v, want set id %x", name, res, want)
		}
		r := fixedRing(ring[1], ring[0])
		if res := r.Check([4]string{"", Text(tok)})[1]; !res.OK || res.SetID != want {
			t.Errorf("%s: Check = %+v, want set id %x", name, res, want)
		}
	}
	bTok, _ := b.Mint(0, unitTime(100))
	if res := Verify([]*KeySet{a, b}, bTok); res.SetID != other {
		t.Errorf("token of B: set id %x, want %x", res.SetID, other)
	}
	if res := Verify([]*KeySet{b}, tok); res != (Result{}) {
		t.Errorf("non-match = %+v", res)
	}
	r := fixedRing(a, b)
	if n := testing.AllocsPerRun(1000, func() { _ = Verify([]*KeySet{a, b}, tok) }); n != 0 {
		t.Errorf("Verify allocates %v times", n)
	}
	if n := testing.AllocsPerRun(1000, func() { _ = r.Verify(tok) }); n != 0 {
		t.Errorf("Ring.Verify allocates %v times", n)
	}
}

// T-S-32: each Check call does 4 decrypts for each key set, for each input.
func TestTS32_CheckDecrypts(t *testing.T) {
	c1 := &countingBlock{Block: must(aes.NewCipher(testKey))}
	c2 := &countingBlock{Block: must(aes.NewCipher(otherKey))}
	k1, _ := newKeySetBlock(c1, traps(2))
	k2, _ := newKeySetBlock(c2, traps(2))
	good, _ := k1.Mint(1, unitTime(100))
	bad := Text([Size]byte{1, 2, 3})
	gt := Text(good)
	refused := []string{strings.ToUpper(gt), gt[:25], gt + "a", strings.Repeat("-", 26)}
	cases := map[string][4]string{
		"good":    {gt, gt, gt, gt},
		"bad":     {bad, bad, bad, bad},
		"absent":  {},
		"refused": {refused[0], refused[1], refused[2], refused[3]},
		"mix":     {gt, bad, "", refused[0]},
	}
	for name, texts := range cases {
		for ringLen, ring := range map[int]*Ring{1: fixedRing(k1), 2: fixedRing(k1, k2)} {
			c1.decrypts.Store(0)
			c2.decrypts.Store(0)
			ring.Check(texts)
			want2 := int32(4)
			if ringLen == 1 {
				want2 = 0
			}
			if c1.decrypts.Load() != 4 || c2.decrypts.Load() != want2 {
				t.Errorf("%s, ring of %d: decrypts %d and %d", name, ringLen, c1.decrypts.Load(), c2.decrypts.Load())
			}
		}
	}
}

// swapBlock swaps a key set into the ring at its first Decrypt.
type swapBlock struct {
	cipher.Block
	once sync.Once
	swap func()
}

func (s *swapBlock) Decrypt(dst, src []byte) {
	s.once.Do(s.swap)
	s.Block.Decrypt(dst, src)
}

// T-S-32: one Check reads the clock one time and loads the ring one time. A
// Swap in the middle of the call does not change the key sets of the call.
func TestTS32_CheckOneLoad(t *testing.T) {
	calls := 0
	r := NewRing(func() time.Time { calls++; return unitTime(110) })
	next := &countingBlock{Block: must(aes.NewCipher(otherKey))}
	sb := &swapBlock{Block: must(aes.NewCipher(testKey))}
	k1, _ := newKeySetBlock(sb, traps(2))
	k2, _ := newKeySetBlock(next, traps(2))
	sb.swap = func() { r.Swap(k2) }
	r.Swap(k1)
	calls = 0
	r.Check([4]string{Text([Size]byte{1}), "", "", ""})
	if next.decrypts.Load() != 0 {
		t.Errorf("new key set decrypted %d times in the call", next.decrypts.Load())
	}
	if calls != 2 { // one in Check, one in the Swap of the test hook
		t.Errorf("clock read %d times, want 2", calls)
	}
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

// T-S-32: a position gives the Result of Ring.Verify. A bad, absent or
// refused position gives the zero Result and no future count.
func TestTS32_CheckResults(t *testing.T) {
	sets, toks := keys(t, 2)
	r := fixedRing(sets[0], sets[1])
	future, _ := sets[1].Mint(0, unitTime(200))
	stale, _ := sets[0].Mint(1, unitTime(1<<20-100))
	texts := [4]string{Text(toks[0]), Text(future), Text(stale), Text(toks[1])}
	f0 := r.Futures()
	got := r.Check(texts)
	if d := r.Futures() - f0; d != 1 {
		t.Errorf("Futures grew by %d, want 1", d)
	}
	for i, tok := range [4][Size]byte{toks[0], future, stale, toks[1]} {
		if want := r.Verify(tok); got[i] != want || !got[i].OK {
			t.Errorf("position %d = %+v, want %+v", i, got[i], want)
		}
	}
	if !got[1].Future || !got[2].Stale || got[2].Future || got[0].Stale {
		t.Errorf("window classes: %+v", got)
	}
	f0 = r.Futures()
	none := r.Check([4]string{Text([Size]byte{9}), "", strings.ToUpper(texts[1]), texts[1][1:]})
	if none != ([4]Result{}) || r.Futures() != f0 {
		t.Errorf("bad, absent and refused: %+v, futures +%d", none, r.Futures()-f0)
	}
}

// T-S-32: a refused or absent text gives the zero Result and no future
// count. This holds also if the zero block would verify.
func TestTS32_CheckRefusedNeverMatches(t *testing.T) {
	b, _ := aes.NewCipher(testKey)
	k, _ := newKeySetBlock(allMatch{b}, traps(2))
	r := fixedRing(k)
	valid := Text([Size]byte{7})
	got := r.Check([4]string{"", strings.ToUpper(valid), valid, valid[:25]})
	if got[0] != (Result{}) || got[1] != (Result{}) || got[3] != (Result{}) {
		t.Errorf("refused or absent position matched: %+v", got)
	}
	if !got[2].OK || !got[2].Future || r.Futures() != 1 {
		t.Errorf("valid position = %+v, futures %d", got[2], r.Futures())
	}
}

// T-S-32: Check does not allocate.
func TestTS32_CheckNoAllocs(t *testing.T) {
	sets, toks := keys(t, 2)
	r := fixedRing(sets[0], sets[1])
	gt := Text(toks[0])
	for name, in := range checkInputs(gt) {
		if n := testing.AllocsPerRun(1000, func() { _ = r.Check(in) }); n != 0 {
			t.Errorf("%s: Check allocates %v times", name, n)
		}
	}
}

func checkInputs(gt string) map[string][4]string {
	bad := Text([Size]byte{1})
	return map[string][4]string{"good": {gt, gt, gt, gt}, "bad": {bad, bad, bad, bad}, "absent": {}}
}

func BenchmarkRingCheck(b *testing.B) {
	sets, toks := keys(b, 2)
	r := fixedRing(sets[0], sets[1])
	for name, in := range checkInputs(Text(toks[0])) {
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				_ = r.Check(in)
			}
		})
	}
}
