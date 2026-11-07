package token

import (
	"math"
	"math/bits"
	"math/rand/v2"
	"strings"
	"testing"
)

const (
	randTokens  = 10000 // tokens for each randomness test
	blockSize   = 128   // block length M of the block frequency test, in bits
	minP        = 0.01  // a p-value below this fails a NIST test
	sessionBits = 8 * Size
	zBand       = 2.5758 // two-sided 99 % point of the normal distribution
	tiny        = 1e-300
	eps         = 1e-15
)

// bitsOf gives the bits of b, the most significant bit of each byte first.
func bitsOf(b []byte) []uint8 {
	out := make([]uint8, 0, 8*len(b))
	for _, v := range b {
		for i := 7; i >= 0; i-- {
			out = append(out, v>>uint(i)&1)
		}
	}
	return out
}

func bitsOfString(s string) []uint8 {
	out := make([]uint8, len(s))
	for i := range s {
		out[i] = s[i] - '0'
	}
	return out
}

// igamc is the regularized upper incomplete gamma function Q(a, x).
func igamc(a, x float64) float64 {
	if x <= 0 {
		return 1
	}
	lg, _ := math.Lgamma(a)
	pre := math.Exp(-x + a*math.Log(x) - lg)
	if x < a+1 {
		ap, del := a, 1/a
		sum := del
		for range 1000000 {
			ap++
			del *= x / ap
			sum += del
			if math.Abs(del) < math.Abs(sum)*eps {
				break
			}
		}
		return 1 - pre*sum
	}
	b := x + 1 - a
	c, d := 1/tiny, 1/b
	h := d
	for i := 1.0; i < 1000000; i++ {
		an := -i * (i - a)
		b += 2
		d = an*d + b
		if math.Abs(d) < tiny {
			d = tiny
		}
		c = b + an/c
		if math.Abs(c) < tiny {
			c = tiny
		}
		d = 1 / d
		del := d * c
		h *= del
		if math.Abs(del-1) < eps {
			break
		}
	}
	return pre * h
}

// frequency is the monobit test (NIST SP 800-22 rev1a, section 2.1).
func frequency(e []uint8) float64 {
	s := 0.0
	for _, b := range e {
		s += float64(2*int(b) - 1)
	}
	n := float64(len(e))
	return math.Erfc(math.Abs(s) / math.Sqrt(n) / math.Sqrt2)
}

// blockFrequency is the test of section 2.2 with blocks of m bits.
func blockFrequency(e []uint8, m int) float64 {
	nb := len(e) / m
	chi := 0.0
	for i := range nb {
		ones := 0
		for _, b := range e[i*m : (i+1)*m] {
			ones += int(b)
		}
		d := float64(ones)/float64(m) - 0.5
		chi += d * d
	}
	chi *= 4 * float64(m)
	return igamc(float64(nb)/2, chi/2)
}

// runs is the runs test of section 2.3. It gives 0 when the frequency
// prerequisite fails.
func runs(e []uint8) float64 {
	n := float64(len(e))
	ones := 0
	for _, b := range e {
		ones += int(b)
	}
	pi := float64(ones) / n
	if math.Abs(pi-0.5) >= 2/math.Sqrt(n) {
		return 0
	}
	v := 1.0
	for k := 1; k < len(e); k++ {
		if e[k] != e[k-1] {
			v++
		}
	}
	pq := pi * (1 - pi)
	return math.Erfc(math.Abs(v-2*n*pq) / (2 * math.Sqrt(2*n) * pq))
}

// mintBits mints n tokens with counters 0 ... n-1 and gives them in order.
func mintBits(t *testing.T, n int) (toks [][Size]byte, k *KeySet) {
	t.Helper()
	k = newSet(t, testKey, 1)
	k.counter.Store(counterMask) // The first Mint then uses counter 0.
	for range n {
		tok, err := k.Mint(0, epoch)
		if err != nil {
			t.Fatal(err)
		}
		toks = append(toks, tok)
	}
	return toks, k
}

func TestTS05_Statistics(t *testing.T) {
	const e100 = "11001001000011111101101010100010001000010110100011" +
		"00001000110100110001001100011001100010100010111000"
	// 80 ones and 20 zeros in 32 runs: the frequency prerequisite fails.
	skew := strings.Repeat("111110", 12) + strings.Repeat("1111100", 4)
	tests := []struct {
		name string
		fn   func([]uint8) float64
		e    string
		want float64
	}{
		{"frequency short", frequency, "1011010101", 0.527089},
		{"frequency 100", frequency, e100, 0.109599},
		{"block frequency short", func(e []uint8) float64 {
			return blockFrequency(e, 3)
		}, "0110011010", 0.801252},
		{"block frequency 100", func(e []uint8) float64 {
			return blockFrequency(e, 10)
		}, e100, 0.706438},
		{"runs short", runs, "1001101011", 0.147232},
		{"runs 100", runs, e100, 0.500798},
		{"runs prerequisite", runs, skew, 0},
	}
	for _, tc := range tests {
		if got := tc.fn(bitsOfString(tc.e)); math.Abs(got-tc.want) > 1e-6 {
			t.Errorf("%s: p = %f, want %f", tc.name, got, tc.want)
		}
	}
}

// Q(1/2, x) = erfc(sqrt(x)) and Q(1, x) = exp(-x). The tail values need the
// continued fraction: a series loses all digits there.
func TestTS05_Igamc(t *testing.T) {
	tests := []struct{ a, x, want float64 }{
		{0.5, 0.1, math.Erfc(math.Sqrt(0.1))},
		{0.5, 40, math.Erfc(math.Sqrt(40))},
		{1, 0.5, math.Exp(-0.5)},
		{1, 40, math.Exp(-40)},
	}
	for _, tc := range tests {
		if got := igamc(tc.a, tc.x); math.Abs(got-tc.want) > 1e-9*tc.want {
			t.Errorf("igamc(%g, %g) = %g, want %g", tc.a, tc.x, got, tc.want)
		}
	}
}

func TestTS05_BitOrder(t *testing.T) {
	got := bitsOf([]byte{0x80, 0x01})
	want := bitsOfString("1000000000000001")
	if string(got) != string(want) {
		t.Errorf("bits = %v, want %v", got, want)
	}
}

// pValues runs the three tests on e and checks them against minP.
func pValues(t *testing.T, e []uint8, wantPass bool) {
	t.Helper()
	if nb := len(e) / blockSize; nb != randTokens {
		t.Fatalf("%d blocks, want %d", nb, randTokens)
	}
	for _, tc := range []struct {
		name string
		p    float64
	}{
		{"frequency", frequency(e)},
		{"block frequency", blockFrequency(e, blockSize)},
		{"runs", runs(e)},
	} {
		t.Logf("%s: p = %f", tc.name, tc.p)
		if (tc.p >= minP) != wantPass {
			t.Errorf("%s: p = %f, pass = %v, want %v",
				tc.name, tc.p, tc.p >= minP, wantPass)
		}
	}
}

func TestTS05_NIST(t *testing.T) {
	toks, k := mintBits(t, randTokens)
	if _, _, c := open(k, toks[0]); c != 0 {
		t.Errorf("first counter = %d, want 0", c)
	}
	if _, _, c := open(k, toks[randTokens-1]); c != randTokens-1 {
		t.Errorf("last counter = %d, want %d", c, randTokens-1)
	}
	var raw []byte
	for _, tok := range toks {
		raw = append(raw, tok[:]...)
	}
	pValues(t, bitsOf(raw), true)
}

// The plaintext blocks have structure. The tests must reject them.
func TestTS05_NISTPlaintext(t *testing.T) {
	var raw []byte
	var b [Size]byte
	for c := range uint64(randTokens) {
		pack(b[:], 0, 0, c)
		raw = append(raw, b[:]...)
	}
	pValues(t, bitsOf(raw), false)
}

// band gives the 99 % band of the sum of n fair coin flips.
func band(n int) (lo, hi int) {
	mean, sd := float64(n)/2, math.Sqrt(float64(n))/2
	return int(math.Ceil(mean - zBand*sd)), int(math.Floor(mean + zBand*sd))
}

func TestTS05_SessionID(t *testing.T) {
	rng := rand.New(rand.NewChaCha8([32]byte{'s', 'e', 's', 's', 'i', 'o', 'n'}))
	k := newSet(t, testKey, 1)
	k.counter.Store(counterMask) // A fixed start: the same count in each run.
	agree, pairs := 0, 0
	for range randTokens {
		var id [Size]byte
		for i := range id {
			id[i] = byte(rng.Uint32())
		}
		tok, err := k.Mint(0, epoch)
		if err != nil {
			t.Fatal(err)
		}
		for i := range id {
			agree += 8 - bits.OnesCount8(tok[i]^id[i])
			pairs += 8
		}
	}
	if want := sessionBits * randTokens; pairs != want {
		t.Fatalf("%d bit pairs, want %d", pairs, want)
	}
	lo, hi := band(pairs)
	t.Logf("agreement %d, band %d ... %d", agree, lo, hi)
	if agree < lo || agree > hi {
		t.Errorf("agreement %d is outside %d ... %d", agree, lo, hi)
	}
	// A token equal to its session id agrees in every bit.
	if pairs >= lo && pairs <= hi {
		t.Errorf("full agreement %d is inside the band", pairs)
	}
}
