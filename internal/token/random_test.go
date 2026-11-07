package token

import (
	"math"
	"math/bits"
	"math/rand/v2"
	"strconv"
	"strings"
	"testing"
)

const (
	randTokens    = 10000 // each randomness test uses this number of tokens
	nistBlockBits = 128   // the block frequency test uses blocks of M bits
	minP          = 0.01  // a NIST test fails below this p-value
	sessionBits   = 8 * Size
	zBand         = 2.5758 // z is the two-sided 99 % point of the normal law
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
	const (
		tiny = 1e-300
		eps  = 1e-15
	)
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

// nistFrequency is the monobit test (NIST SP 800-22 rev1a, section 2.1).
func nistFrequency(e []uint8) float64 {
	s := 0.0
	for _, b := range e {
		s += float64(2*int(b) - 1)
	}
	n := float64(len(e))
	return math.Erfc(math.Abs(s) / math.Sqrt(n) / math.Sqrt2)
}

// nistBlockFrequency is the test of section 2.2 with blocks of m bits.
func nistBlockFrequency(e []uint8, m int) float64 {
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

// nistRuns is the runs test of section 2.3. The test is not run when
// |pi - 1/2| >= 2/sqrt(n). The function then gives 0. The integer form
// d*d >= 16*n of this rule has no rounding error at the edge.
func nistRuns(e []uint8) float64 {
	n := float64(len(e))
	ones := 0
	for _, b := range e {
		ones += int(b)
	}
	d := 2*ones - len(e)
	if d*d >= 16*len(e) {
		return 0
	}
	pi := float64(ones) / n
	v := 1.0
	for k := 1; k < len(e); k++ {
		if e[k] != e[k-1] {
			v++
		}
	}
	pq := pi * (1 - pi)
	return math.Erfc(math.Abs(v-2*n*pq) / (2 * math.Sqrt(2*n) * pq))
}

// mintTokens mints n tokens with counters 0 ... n-1 and gives them in order.
func mintTokens(t *testing.T, n int) (toks [][Size]byte, k *KeySet) {
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
	// 70 ones in 100 bits: d*d = 16*n, so the test is not run.
	edge := strings.Repeat("10", 30) + strings.Repeat("1", 40)
	// These 100 bits have V = 34 runs. n*2pq expects 50 runs.
	few := strings.Repeat("000111", 16) + "0011"
	tests := []struct {
		name string
		fn   func([]uint8) float64
		e    string
		want float64
	}{
		{"frequency short", nistFrequency, "1011010101", 0.527089},
		{"frequency 100", nistFrequency, e100, 0.109599},
		{"block frequency short", func(e []uint8) float64 {
			return nistBlockFrequency(e, 3)
		}, "0110011010", 0.801252},
		{"block frequency 100", func(e []uint8) float64 {
			return nistBlockFrequency(e, 10)
		}, e100, 0.706438},
		{"runs short", nistRuns, "1001101011", 0.147232},
		{"runs 100", nistRuns, e100, 0.500798},
		{"runs prerequisite", nistRuns, skew, 0},
		{"runs prerequisite edge", nistRuns, edge, 0},
		{"runs too few", nistRuns, few, 0.001374},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.fn(bitsOfString(tc.e)); math.Abs(got-tc.want) > 1e-6 {
				t.Errorf("p = %f, want %f", got, tc.want)
			}
		})
	}
}

// Q(1/2, x) = erfc(sqrt(x)) and Q(1, x) = exp(-x). The tail values need the
// continued fraction: a series loses all digits there.
func TestTS05_Igamc(t *testing.T) {
	tests := []struct {
		name       string
		a, x, want float64
	}{
		{"half series", 0.5, 0.1, math.Erfc(math.Sqrt(0.1))},
		{"half tail", 0.5, 40, math.Erfc(math.Sqrt(40))},
		{"one series", 1, 0.5, math.Exp(-0.5)},
		{"one tail", 1, 40, math.Exp(-40)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := igamc(tc.a, tc.x); math.Abs(got-tc.want) > 1e-9*tc.want {
				t.Errorf("igamc(%g, %g) = %g, want %g", tc.a, tc.x, got, tc.want)
			}
		})
	}
}

func TestTS05_BitOrder(t *testing.T) {
	got := bitsOf([]byte{0x80, 0x01})
	want := bitsOfString("1000000000000001")
	if string(got) != string(want) {
		t.Errorf("bits = %v, want %v", got, want)
	}
}

// checkNIST runs the three tests on e. It checks each p-value against minP
// and against the expected result: frequency, block frequency, runs.
func checkNIST(t *testing.T, e []uint8, wantPass [3]bool) {
	t.Helper()
	if nb := len(e) / nistBlockBits; nb != randTokens {
		t.Fatalf("%d blocks, want %d", nb, randTokens)
	}
	for i, tc := range []struct {
		name string
		p    float64
	}{
		{"frequency", nistFrequency(e)},
		{"block frequency", nistBlockFrequency(e, nistBlockBits)},
		{"runs", nistRuns(e)},
	} {
		t.Logf("%s: p = %f", tc.name, tc.p)
		if (tc.p >= minP) != wantPass[i] {
			t.Errorf("%s: p = %f, pass = %v, want %v",
				tc.name, tc.p, tc.p >= minP, wantPass[i])
		}
	}
}

func TestTS05_NIST(t *testing.T) {
	toks, k := mintTokens(t, randTokens)
	var raw []byte
	for i, tok := range toks {
		index, unit, counter := open(k, tok)
		if index != 0 || unit != 0 || counter != uint64(i) {
			t.Fatalf("token %d opens to index %d, unit %d, counter %d",
				i, index, unit, counter)
		}
		raw = append(raw, tok[:]...)
	}
	checkNIST(t, bitsOf(raw), [3]bool{true, true, true})
}

// The plaintext blocks differ only in the counter field. The tests must
// reject them.
func TestTS05_NISTPlaintext(t *testing.T) {
	var raw []byte
	var b [Size]byte
	for c := range uint64(randTokens) {
		pack(b[:], 0, 0, c)
		raw = append(raw, b[:]...)
	}
	checkNIST(t, bitsOf(raw), [3]bool{false, false, false})
}

// The control has as many ones as zeros in each byte, but a fixed pattern.
// Frequency and block frequency pass. Runs reaches its formula and fails.
func TestTS05_NISTBalanced(t *testing.T) {
	raw := make([]byte, randTokens*Size)
	for i := range raw {
		raw[i] = 0x0F
	}
	checkNIST(t, bitsOf(raw), [3]bool{true, true, false})
}

// agreementBand gives the 99 % band of the sum of n fair coin flips.
func agreementBand(n int) (lo, hi int) {
	mean, sd := float64(n)/2, math.Sqrt(float64(n))/2
	return int(math.Ceil(mean - zBand*sd)), int(math.Floor(mean + zBand*sd))
}

func TestTS05_Band(t *testing.T) {
	tests := []struct{ n, lo, hi int }{
		{10000, 4872, 5128},
		{1280000, 638543, 641457},
	}
	for _, tc := range tests {
		t.Run(strconv.Itoa(tc.n), func(t *testing.T) {
			if lo, hi := agreementBand(tc.n); lo != tc.lo || hi != tc.hi {
				t.Errorf("band = %d ... %d, want %d ... %d",
					lo, hi, tc.lo, tc.hi)
			}
		})
	}
}

// agreement counts the bits where tok and id have the same value.
func agreement(tok, id [Size]byte) int {
	agree := 0
	for i := range id {
		agree += 8 - bits.OnesCount8(tok[i]^id[i])
	}
	return agree
}

// This test fails when each token holds a copied session bit, or each holds
// an inverted one. A mix of copied and inverted bits can pass. A copy into
// few tokens can pass too. The test cannot show that a token is not derived
// from a session id. That holds because Mint takes no session id. A keyless
// hash of the id also passes.
func TestTS05_SessionID(t *testing.T) {
	rng := rand.New(rand.NewChaCha8([32]byte{'s', 'e', 's', 's', 'i', 'o', 'n'}))
	toks, _ := mintTokens(t, randTokens)
	agree := 0
	for _, tok := range toks {
		var id [Size]byte
		for i := range id {
			id[i] = byte(rng.Uint32())
		}
		agree += agreement(tok, id)
	}
	lo, hi := agreementBand(sessionBits * randTokens)
	t.Logf("agreement %d, band %d ... %d", agree, lo, hi)
	if agree < lo || agree > hi {
		t.Errorf("agreement %d is outside %d ... %d", agree, lo, hi)
	}
}

// A token equal to its session id, or its complement, is outside the band.
func TestTS05_SessionIDControl(t *testing.T) {
	var tok, inv [Size]byte
	for i := range tok {
		tok[i] = byte(i*37 + 11)
		inv[i] = tok[i] ^ 0xFF
	}
	if got := agreement(tok, tok); got != sessionBits {
		t.Errorf("equal agreement = %d, want %d", got, sessionBits)
	}
	if got := agreement(tok, inv); got != 0 {
		t.Errorf("complement agreement = %d, want 0", got)
	}
	same, opposite := 0, 0
	for range randTokens {
		same += agreement(tok, tok)
		opposite += agreement(tok, inv)
	}
	lo, hi := agreementBand(sessionBits * randTokens)
	for _, tc := range []struct {
		name string
		sum  int
	}{
		{"equal", same},
		{"complement", opposite},
	} {
		if tc.sum >= lo && tc.sum <= hi {
			t.Errorf("%s agreement %d is inside %d ... %d",
				tc.name, tc.sum, lo, hi)
		}
	}
}
