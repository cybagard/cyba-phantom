package token

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var (
	testKey  = []byte("0123456789abcdef")
	otherKey = []byte("fedcba9876543210")
	epoch    = time.Unix(epochUnix, 0)
)

func traps(n int) []string {
	ids := make([]string, n)
	for i := range ids {
		ids[i] = "trap-" + strconv.Itoa(i)
	}
	return ids
}

func newSet(t testing.TB, key []byte, n int) *KeySet {
	t.Helper()
	k, err := newKeySet(key, traps(n))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// seal encrypts a plaintext block under the key set, as a forger who holds
// the key would.
func seal(k *KeySet, plain [Size]byte) [Size]byte {
	var out [Size]byte
	k.block.Encrypt(out[:], plain[:])
	return out
}

// open decrypts a token and gives the fields of the plaintext.
func open(k *KeySet, tok [Size]byte) (index, unit, counter uint64) {
	var out [Size]byte
	k.block.Decrypt(out[:], tok[:])
	return unpack(out[:])
}

// countingBlock counts the Decrypt calls of a cipher.
type countingBlock struct {
	cipher.Block
	decrypts atomic.Int32
}

func (c *countingBlock) Decrypt(dst, src []byte) {
	c.decrypts.Add(1)
	c.Block.Decrypt(dst, src)
}

func TestTU01_Layout(t *testing.T) {
	tests := []struct {
		name                 string
		index, unit, counter uint64
		want                 string
	}{
		{"all small", 1, 2, 3, "00400008000000000300000000000000"},
		{"max index", 1023, 0, 0, "ffc00000000000000000000000000000"},
		{"max unit", 0, 1<<20 - 1, 0, "003ffffc000000000000000000000000"},
		{"max counter", 0, 0, 1<<42 - 1, "00000003ffffffffff00000000000000"},
		{"all max", 1023, 1<<20 - 1, 1<<42 - 1, "ffffffffffffffffff00000000000000"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var b [Size]byte
			pack(b[:], tc.index, tc.unit, tc.counter)
			if got := hex.EncodeToString(b[:]); got != tc.want {
				t.Fatalf("pack = %s, want %s", got, tc.want)
			}
			i, u, c := unpack(b[:])
			if i != tc.index || u != tc.unit || c != tc.counter {
				t.Fatalf("unpack = %d %d %d", i, u, c)
			}
		})
	}
}

func TestTU01_Unit(t *testing.T) {
	tests := []struct {
		name string
		at   time.Time
		want uint64
	}{
		{"epoch", epoch, 0},
		{"last second of unit 0", epoch.Add(599 * time.Second), 0},
		{"unit 1", epoch.Add(600 * time.Second), 1},
		{"max unit", epoch.Add((1<<20 - 1) * 600 * time.Second), 1<<20 - 1},
		{"wrap", epoch.Add(1 << 20 * 600 * time.Second), 0},
		{"one second before", epoch.Add(-time.Second), 1<<20 - 1},
		{"600 s before", epoch.Add(-600 * time.Second), 1<<20 - 1},
		{"601 s before", epoch.Add(-601 * time.Second), 1<<20 - 2},
		{"zero time", time.Time{}, unitOf(time.Time{})},
	}
	for _, tc := range tests {
		if got := unitOf(tc.at); got != tc.want || got > unitMask {
			t.Errorf("%s: unit = %d, want %d", tc.name, got, tc.want)
		}
	}
}

func TestTU01_RoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		count   int
		index   int
		at      time.Time
		counter uint64 // counter value that the mint uses
		unit    uint32
	}{
		{"zeros", 1, 0, epoch, 0, 0},
		{"max index", 1024, 1023, epoch, 5, 0},
		{"max unit", 3, 2, epoch.Add((1<<20 - 1) * 600 * time.Second), 5, 1<<20 - 1},
		{"max counter", 3, 1, epoch, 1<<42 - 1, 0},
		{"all max", 1024, 1023, epoch.Add((1<<20 - 1) * 600 * time.Second), 1<<42 - 1, 1<<20 - 1},
		{"before epoch", 4, 3, epoch.Add(-time.Hour), 77, 1<<20 - 6},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			k := newSet(t, testKey, tc.count)
			k.counter.Store((tc.counter - 1) & counterMask)
			tok, err := k.Mint(tc.index, tc.at)
			if err != nil {
				t.Fatal(err)
			}
			if i, u, c := open(k, tok); i != uint64(tc.index) || u != uint64(tc.unit) || c != tc.counter {
				t.Fatalf("fields = %d %d %d", i, u, c)
			}
			// A second key set from the same key has no shared state.
			other := newSet(t, testKey, tc.count)
			want := Result{OK: true, Trap: traps(tc.count)[tc.index], Unit: tc.unit, Set: First}
			if got := Verify([]*KeySet{other}, tok); got != want {
				t.Fatalf("Verify = %+v, want %+v", got, want)
			}
		})
	}
}

// TestTU14_TrapFromTokenAlone checks that Verify gives the trap id from the
// token and the key set. It uses no store and no session.
func TestTU14_TrapFromTokenAlone(t *testing.T) {
	mint := newSet(t, testKey, 8)
	var toks [8][Size]byte
	for i := range toks {
		toks[i], _ = mint.Mint(i, epoch)
	}
	verify := newSet(t, testKey, 8) // other counter, no memory of the mints
	for i, tok := range toks {
		if got := Verify([]*KeySet{verify}, tok); !got.OK || got.Trap != "trap-"+strconv.Itoa(i) {
			t.Errorf("token %d: Verify = %+v", i, got)
		}
	}
}

func TestTU01_Forgeries(t *testing.T) {
	k := newSet(t, testKey, 3)
	plain := func(index, unit, counter uint64, flip int) [Size]byte {
		var b [Size]byte
		pack(b[:], index, unit, counter)
		if flip >= 0 {
			b[fieldBytes+flip/8] |= 1 << (flip % 8)
		}
		return b
	}
	tests := []struct {
		name  string
		block [Size]byte
		want  bool
	}{
		{"last index", plain(2, 9, 9, -1), true},
		{"index equals count", plain(3, 9, 9, -1), false},
		{"index above count", plain(4, 9, 9, -1), false},
		{"max index", plain(1023, 9, 9, -1), false},
		{"first check bit", plain(0, 9, 9, 0), false},
		{"last check bit", plain(0, 9, 9, 55), false},
		{"middle check bit", plain(0, 9, 9, 24), false},
	}
	for _, tc := range tests {
		if got := Verify([]*KeySet{k}, seal(k, tc.block)); got.OK != tc.want {
			t.Errorf("%s: OK = %v, want %v", tc.name, got.OK, tc.want)
		}
	}
}

func TestTU01_BitFlips(t *testing.T) {
	k := newSet(t, testKey, 16)
	for i := 0; i < 16; i++ {
		tok, _ := k.Mint(i, epoch.Add(time.Duration(i)*time.Hour))
		for bit := 0; bit < Size*8; bit++ {
			bad := tok
			bad[bit/8] ^= 1 << (bit % 8)
			if Verify([]*KeySet{k}, bad).OK {
				t.Fatalf("token %d: flip of bit %d accepted", i, bit)
			}
		}
	}
}

func TestTU01_Distinct(t *testing.T) {
	k := newSet(t, testKey, 1)
	seen := make(map[[Size]byte]struct{}, 1_000_000)
	for i := 0; i < 1_000_000; i++ {
		tok, _ := k.Mint(0, epoch)
		if _, dup := seen[tok]; dup {
			t.Fatalf("mint %d repeats a token", i)
		}
		seen[tok] = struct{}{}
	}
}

func TestTU01_Concurrent(t *testing.T) {
	const workers, each = 8, 100_000
	k := newSet(t, testKey, 1)
	var all [workers][][Size]byte
	var wg sync.WaitGroup
	for w := range all {
		wg.Add(1)
		go func() {
			defer wg.Done()
			all[w] = make([][Size]byte, each)
			for i := range all[w] {
				all[w][i], _ = k.Mint(0, epoch)
			}
		}()
	}
	wg.Wait()
	seen := make(map[[Size]byte]struct{}, workers*each)
	for _, toks := range all {
		for _, tok := range toks {
			if _, dup := seen[tok]; dup {
				t.Fatal("two mints give one token")
			}
			seen[tok] = struct{}{}
		}
	}
}

func TestTU01_Counter(t *testing.T) {
	a, b := newSet(t, testKey, 1), newSet(t, testKey, 1)
	if a.counter.Load() == b.counter.Load() {
		t.Error("two key sets have the same counter start")
	}
	if a.counter.Load() > counterMask {
		t.Error("counter start is wider than 42 bits")
	}
	tests := []struct{ set, want uint64 }{
		{counterMask - 1, counterMask},
		{counterMask, 0},
		{0, 1},
	}
	for _, tc := range tests {
		a.counter.Store(tc.set)
		tok, _ := a.Mint(0, epoch)
		if _, _, c := open(a, tok); c != tc.want {
			t.Errorf("counter %d: mint uses %d, want %d", tc.set, c, tc.want)
		}
	}
}

func TestTU01_Ring(t *testing.T) {
	key := [2][]byte{testKey, otherKey}
	tests := []struct {
		name    string
		count   int  // size of the ring
		from    int  // ring position that mints the token, -1 for a stranger
		wantSet int  // position that Verify reports
		wantOK  bool // whether Verify accepts
		calls   int  // Decrypt calls on each key set
	}{
		{"ring of 1", 1, 0, First, true, 1},
		{"first of 2", 2, 0, First, true, 1},
		{"second of 2", 2, 1, Second, true, 1},
		{"stranger", 2, -1, 0, false, 1},
		{"stranger, ring of 1", 1, -1, 0, false, 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ring := make([]*KeySet, tc.count)
			counters := make([]*countingBlock, tc.count)
			for i := range ring {
				b, _ := aes.NewCipher(key[i])
				counters[i] = &countingBlock{Block: b}
				ids := traps(4)
				ids[0] = "set-" + strconv.Itoa(i) // a trap list for each set
				ring[i], _ = newKeySetBlock(counters[i], ids)
			}
			signer := newSet(t, []byte("0000000000000000"), 4)
			if tc.from >= 0 {
				signer = ring[tc.from]
			}
			tok, _ := signer.Mint(0, epoch)
			got := Verify(ring, tok)
			want := Result{}
			if tc.wantOK {
				want = Result{OK: true, Trap: "set-" + strconv.Itoa(tc.wantSet), Set: tc.wantSet}
			}
			if got != want {
				t.Errorf("Verify = %+v, want %+v", got, want)
			}
			for i, c := range counters {
				if n := int(c.decrypts.Load()); n != tc.calls {
					t.Errorf("key set %d: %d Decrypt calls, want %d", i, n, tc.calls)
				}
			}
		})
	}
}

func TestTU01_Refusals(t *testing.T) {
	good := newSet(t, testKey, 2)
	if _, err := newKeySet(testKey[:15], traps(1)); !errors.Is(err, ErrKey) {
		t.Errorf("short key: err = %v", err)
	}
	for _, n := range []int{0, 1025} {
		if _, err := newKeySet(testKey, traps(n)); !errors.Is(err, ErrTraps) {
			t.Errorf("%d traps: err = %v", n, err)
		}
	}
	for _, i := range []int{-1, 2, 1023} {
		if _, err := good.Mint(i, epoch); !errors.Is(err, ErrIndex) {
			t.Errorf("index %d: err = %v", i, err)
		}
	}
	var none *KeySet
	if _, err := none.Mint(0, epoch); !errors.Is(err, ErrNoKeySet) {
		t.Errorf("nil key set: err = %v", err)
	}
	tok, _ := good.Mint(1, epoch)
	for _, ring := range [][]*KeySet{nil, {}, {nil}, {none, nil}, {{}}} {
		if Verify(ring, tok).OK {
			t.Errorf("ring %v accepts a token", ring)
		}
	}
	if got := Verify([]*KeySet{none, good}, tok); !got.OK || got.Set != Second {
		t.Errorf("nil key set first: Verify = %+v", got)
	}
}

func TestTU01_NoAllocs(t *testing.T) {
	ring := []*KeySet{newSet(t, testKey, 4), newSet(t, otherKey, 4)}
	tok, _ := ring[1].Mint(3, epoch)
	if n := testing.AllocsPerRun(1000, func() { _, _ = ring[0].Mint(3, epoch) }); n != 0 {
		t.Errorf("Mint allocates %v times", n)
	}
	if n := testing.AllocsPerRun(1000, func() { _ = Verify(ring, tok) }); n != 0 {
		t.Errorf("Verify allocates %v times", n)
	}
}

func BenchmarkMint(b *testing.B) {
	k := newSet(b, testKey, 4)
	b.ReportAllocs()
	for b.Loop() {
		_, _ = k.Mint(3, epoch)
	}
}

func BenchmarkVerify(b *testing.B) {
	ring := []*KeySet{newSet(b, testKey, 4), newSet(b, otherKey, 4)}
	tok, _ := ring[1].Mint(3, epoch)
	b.ReportAllocs()
	for b.Loop() {
		_ = Verify(ring, tok)
	}
}
