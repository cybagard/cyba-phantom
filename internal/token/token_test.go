package token

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
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
		{"zero time", time.Time{}, 450048},
		// These two cases do not use epochUnix.
		{"literal epoch", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), 0},
		{"literal unit 1", time.Date(2026, 1, 1, 0, 10, 0, 0, time.UTC), 1},
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
		traps   int // number of trap ids in the key set
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
			k := newSet(t, testKey, tc.traps)
			k.counter.Store((tc.counter - 1) & counterMask)
			tok, err := k.Mint(tc.index, tc.at)
			if err != nil {
				t.Fatal(err)
			}
			if i, u, c := open(k, tok); i != uint64(tc.index) || u != uint64(tc.unit) || c != tc.counter {
				t.Fatalf("fields = %d %d %d", i, u, c)
			}
			// A second key set from the same key has no shared state.
			other := newSet(t, testKey, tc.traps)
			want := Result{OK: true, Trap: traps(tc.traps)[tc.index], Unit: tc.unit, Set: First}
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
		size    int  // size of the ring
		from    int  // ring position that mints the token, -1 for a stranger
		wantSet int  // position that Verify reports
		wantOK  bool // whether Verify accepts
	}{
		{"ring of 1", 1, 0, First, true},
		{"first of 2", 2, 0, First, true},
		{"second of 2", 2, 1, Second, true},
		{"stranger", 2, -1, 0, false},
		{"stranger, ring of 1", 1, -1, 0, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ring := make([]*KeySet, tc.size)
			counters := make([]*countingBlock, tc.size)
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
				if n := c.decrypts.Load(); n != 1 {
					t.Errorf("key set %d: %d Decrypt calls, want 1", i, n)
				}
			}
		})
	}
}

// TestTU01_RingBounds checks that each key set has its own index bound.
func TestTU01_RingBounds(t *testing.T) {
	a, b := newSet(t, testKey, 2), newSet(t, otherKey, 8)
	tok, _ := b.Mint(5, epoch)
	want := Result{OK: true, Trap: "trap-5", Set: Second}
	if got := Verify([]*KeySet{a, b}, tok); got != want {
		t.Errorf("index 5 of B: Verify = %+v, want %+v", got, want)
	}
	var plain [Size]byte
	pack(plain[:], 3, 0, 0)
	sealed := seal(a, plain)
	for name, ring := range map[string][]*KeySet{"A, B": {a, b}, "B, A": {b, a}} {
		if Verify(ring, sealed).OK {
			t.Errorf("index 3 under A on ring %s is accepted", name)
		}
	}
}

// TestTU01_Copy checks that a key set keeps its own copy of the trap ids.
func TestTU01_Copy(t *testing.T) {
	ids := traps(3)
	k, err := newKeySet(testKey, ids)
	if err != nil {
		t.Fatal(err)
	}
	tok, _ := k.Mint(1, epoch)
	ids[1] = "changed"
	if got := Verify([]*KeySet{k}, tok); got.Trap != "trap-1" {
		t.Errorf("Verify = %+v after the caller changed the slice", got)
	}
}

// These constants hold the known answer for NewKeySet. OpenSSL computed the
// key, not Go. The seed is the bytes 0x01 to 0x20. The salt is 32 bytes of
// 0xaa.
const (
	katKey   = "f9b515888dac9e08583ee19b3e0aacab"
	katBlock = "87abc4dfb358b2375d71f189ca5458a0" // AES-128 of the zero block
)

func katSeed() []byte {
	s := make([]byte, 32)
	for i := range s {
		s[i] = byte(i + 1)
	}
	return s
}

func sumOf(b byte) [32]byte { return [32]byte(bytes.Repeat([]byte{b}, 32)) }

func newDerived(t testing.TB, seed []byte, sum [32]byte, n int, ref bool) *KeySet {
	t.Helper()
	k, err := NewKeySet(seed, sum, traps(n), ref)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// TestTU01_NewKeySetVector checks the key against the OpenSSL vector. A
// changed label, salt, secret, length or hash gives another block.
func TestTU01_NewKeySetVector(t *testing.T) {
	k := newDerived(t, katSeed(), sumOf(0xaa), 2, false)
	var out [Size]byte
	k.block.Encrypt(out[:], make([]byte, Size))
	if got := hex.EncodeToString(out[:]); got != katBlock {
		t.Errorf("AES of the zero block = %s, want %s", got, katBlock)
	}
	key, _ := hex.DecodeString(katKey)
	if want := newSet(t, key, 2); seal(k, [Size]byte{1}) != seal(want, [Size]byte{1}) {
		t.Error("the key set differs from the set of the vector key")
	}
}

// TestTU01_NewKeySetClearsKey keeps the key slice and checks that it is zero
// after NewKeySet returns. It also checks the refusals.
func TestTU01_NewKeySetClearsKey(t *testing.T) {
	orig := deriveKey
	t.Cleanup(func() { deriveKey = orig })
	var kept []byte
	var seen string
	calls := 0
	deriveKey = func(seed []byte, sum [32]byte) ([]byte, error) {
		calls++
		key, err := orig(seed, sum)
		kept, seen = key, hex.EncodeToString(key)
		return key, err
	}
	newDerived(t, katSeed(), sumOf(0xaa), 1, false)
	if seen != katKey || len(kept) != 16 || !bytes.Equal(kept, make([]byte, 16)) {
		t.Errorf("key seen %s, slice after return %x", seen, kept)
	}
	calls = 0
	for _, seed := range [][]byte{nil, {}} {
		if k, err := NewKeySet(seed, sumOf(0xaa), traps(1), false); k != nil || !errors.Is(err, ErrSeed) {
			t.Errorf("seed %v: %v, %v", seed, k, err)
		}
	}
	if calls != 0 {
		t.Error("an empty seed reached the derivation")
	}
	deriveKey = func([]byte, [32]byte) ([]byte, error) { return nil, errors.New("stub") }
	if k, err := NewKeySet(katSeed(), sumOf(0xaa), traps(1), false); k != nil || !errors.Is(err, ErrKey) {
		t.Errorf("derivation error: %v, %v", k, err)
	}
	short := bytes.Repeat([]byte{7}, 5)
	deriveKey = func([]byte, [32]byte) ([]byte, error) { return short, nil }
	if k, err := NewKeySet(katSeed(), sumOf(0xaa), traps(1), false); k != nil || !errors.Is(err, ErrKey) {
		t.Errorf("short key: %v, %v", k, err)
	}
	if !bytes.Equal(short, make([]byte, 5)) {
		t.Errorf("short key after the cipher error: %x", short)
	}
	// A bad trap list refuses the call before any key exists.
	calls, kept = 0, nil
	deriveKey = func(seed []byte, sum [32]byte) ([]byte, error) {
		calls++
		key, err := orig(seed, sum)
		kept = key
		return key, err
	}
	for _, n := range []int{0, 1025} {
		if k, err := NewKeySet(katSeed(), sumOf(0xaa), traps(n), false); k != nil || !errors.Is(err, ErrTraps) {
			t.Errorf("%d traps: %v, %v", n, k, err)
		}
	}
	if calls != 0 || !bytes.Equal(kept, make([]byte, len(kept))) {
		t.Errorf("a bad trap list derived %d keys, last %x", calls, kept)
	}
}

// TestTU01_NewKeySetSum checks that the salt is part of the key. The counter
// start is random, so the test checks Verify, not the token bytes.
func TestTU01_NewKeySetSum(t *testing.T) {
	a := newDerived(t, katSeed(), sumOf(1), 3, false)
	same := newDerived(t, katSeed(), sumOf(1), 3, false)
	other := newDerived(t, katSeed(), sumOf(2), 3, false)
	ta, _ := a.Mint(1, epoch)
	ts, _ := same.Mint(2, epoch)
	to, _ := other.Mint(1, epoch)
	if got := Verify([]*KeySet{same}, ta); !got.OK || got.Trap != "trap-1" {
		t.Errorf("same sum, a to same: %+v", got)
	}
	if got := Verify([]*KeySet{a}, ts); !got.OK || got.Trap != "trap-2" {
		t.Errorf("same sum, same to a: %+v", got)
	}
	if Verify([]*KeySet{a}, to).OK || Verify([]*KeySet{other}, ta).OK {
		t.Error("a token verifies under the key set of another sum")
	}
}

// TestTU01_Reference checks that Verify gives the flag of the matching key
// set, not the flag of ring[0].
func TestTU01_Reference(t *testing.T) {
	prop := newDerived(t, katSeed(), sumOf(1), 2, false)
	ref := newDerived(t, katSeed(), sumOf(2), 2, true)
	tp, _ := prop.Mint(0, epoch)
	tr, _ := ref.Mint(0, epoch)
	ring := []*KeySet{prop, ref}
	if got := Verify(ring, tr); !got.OK || !got.Reference || got.Set != 1 {
		t.Errorf("reference token: %+v", got)
	}
	if got := Verify(ring, tp); !got.OK || got.Reference || got.Set != 0 {
		t.Errorf("proprietary token: %+v", got)
	}
	if got := Verify([]*KeySet{ref, prop}, tp); got.Reference || got.Set != 1 {
		t.Errorf("proprietary token, reversed ring: %+v", got)
	}
}

// markers lists the forms of b that no print may hold. They are the raw bytes
// and the hex text. They are also each uint32 word, in both byte orders, in
// decimal and in hex. An AES key schedule prints as such words.
func markers(b []byte) []string {
	m := []string{string(b), hex.EncodeToString(b)}
	for _, o := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		for i := 0; i+4 <= len(b); i += 4 {
			w := uint64(o.Uint32(b[i:]))
			m = append(m, strconv.FormatUint(w, 10), strconv.FormatUint(w, 16))
		}
	}
	return m
}

// TestTS29_Format checks that no print of a key set shows the key, the seed or
// a trap id. The prints are fmt (direct and in a struct), json and slog.
func TestTS29_Format(t *testing.T) {
	ids := traps(3)
	k, err := NewKeySet(katSeed(), sumOf(0xaa), ids, false)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := hex.DecodeString(katKey)
	bad := append(append(markers(key), markers(katSeed())...), ids...)
	type wrap struct{ ks *KeySet }
	w := wrap{k}
	var outs []string
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d"} {
		got := fmt.Sprintf(verb, k)
		if got != "token.KeySet" {
			t.Errorf("%s: got %q, want token.KeySet", verb, got)
		}
		outs = append(outs, got)
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d"} {
		outs = append(outs, fmt.Sprintf(verb, w), fmt.Sprintf(verb, &w))
	}
	jk, err1 := json.Marshal(k)
	jw, err2 := json.Marshal(w)
	if err1 != nil || err2 != nil {
		t.Fatal(err1, err2)
	}
	// "{}" is fixed only if key sets of other seeds and traps give it too.
	o := newDerived(t, bytes.Repeat([]byte{9}, 32), sumOf(3), 7, true)
	jo, _ := json.Marshal(o)
	if string(jk) != string(jo) || string(jw) != string(jo) || string(jo) != "{}" {
		t.Errorf("json %s, wrapper %s, other key set %s", jk, jw, jo)
	}
	var text, js bytes.Buffer
	slog.New(slog.NewTextHandler(&text, nil)).Info("m", slog.Any("ks", k))
	slog.New(slog.NewJSONHandler(&js, nil)).Info("m", slog.Any("ks", k))
	if !strings.HasSuffix(text.String(), " msg=m ks=token.KeySet\n") || !strings.HasSuffix(js.String(), `,"ks":{}}`+"\n") {
		t.Errorf("slog: %q, %q", text.String(), js.String())
	}
	outs = append(outs, string(jk), string(jw), text.String(), js.String())
	for _, out := range outs {
		for _, m := range bad {
			if strings.Contains(out, m) {
				t.Errorf("print %q holds %q", out, m)
			}
		}
	}
}

// TestTS29_ErrorsHoldNoSecret checks the errors of the package and of
// NewKeySet. None holds the key, the seed, a trap id or a token.
func TestTS29_ErrorsHoldNoSecret(t *testing.T) {
	key, _ := hex.DecodeString(katKey)
	bad := append(append(markers(key), markers(katSeed())...), "trap-0")
	tok, err := newDerived(t, katSeed(), sumOf(0xaa), 1, false).Mint(0, epoch)
	if err != nil {
		t.Fatal(err)
	}
	bad = append(bad, markers(tok[:])...)
	bad = append(bad, Text(tok))
	_, e1 := NewKeySet(nil, sumOf(0xaa), traps(1), false)
	_, e2 := NewKeySet(katSeed(), sumOf(0xaa), nil, false)
	for _, err := range []error{ErrNoKeySet, ErrIndex, ErrTraps, ErrKey, ErrSeed, e1, e2} {
		if err == nil {
			t.Error("a call gave no error")
			continue
		}
		for _, m := range bad {
			if strings.Contains(err.Error(), m) {
				t.Errorf("error %v holds %q", err, m)
			}
		}
	}
}

func TestTU01_Refusals(t *testing.T) {
	good := newSet(t, testKey, 2)
	if _, err := newKeySet(testKey[:15], traps(1)); !errors.Is(err, ErrKey) {
		t.Errorf("short key: err = %v", err)
	}
	for _, n := range []int{24, 32} { // AES-128 only
		if _, err := newKeySet(make([]byte, n), traps(1)); !errors.Is(err, ErrKey) {
			t.Errorf("%d-byte key: err = %v", n, err)
		}
	}
	if _, err := (&KeySet{}).Mint(0, epoch); !errors.Is(err, ErrNoKeySet) {
		t.Errorf("empty key set: err = %v", err)
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
