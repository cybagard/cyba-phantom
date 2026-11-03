package token

import (
	"strings"
	"testing"
)

// vectorText and vectorID are for the block with byte i = i*17. A host tool
// computed them: the base32 text, then shasum -a 256 of the text.
const (
	vectorText = "aaisem2ekvthpcezvk54zxpo74"
	vectorID   = "826827bea6c390d55a66b6bf498a15d5"
)

func vectorBlock() (b [Size]byte) {
	for i := range b {
		b[i] = byte(i * 17)
	}
	return b
}

type textCase struct{ name, text string }

// refusedTexts lists texts that Parse must refuse. Each is near vectorText.
func refusedTexts() []textCase {
	v := vectorText
	at := func(i int, c byte) string { return v[:i] + string(c) + v[i+1:] }
	cases := []textCase{
		{"empty", ""},
		{"25 bytes", v[:25]},
		{"27 bytes", v + "a"},
		{"27 bytes with CR inside", v[:10] + "\r" + v[10:]},
		{"27 bytes with LF inside", v[:10] + "\n" + v[10:]},
		{"40 bytes", v + strings.Repeat("a", 14)},
		{"upper case", strings.ToUpper(v)},
		{"one upper-case byte", at(0, 'A')},
		{"CR", at(5, '\r')},
		{"LF", at(5, '\n')},
		{"CR at the end", at(25, '\r')},
		{"equals sign", at(12, '=')},
		{"padded text", v[:24] + "=="},
		{"digit 0", at(3, '0')},
		{"digit 1", at(3, '1')},
		{"NUL", at(3, 0)},
		{"space", at(3, ' ')},
	}
	// The last character holds 2 pad bits. The valid text ends in "4".
	for _, c := range []byte("567") {
		cases = append(cases, textCase{"pad bits, last " + string(c), at(25, c)})
	}
	for _, pos := range []int{0, 12, 25} {
		for c := 0x80; c <= 0xff; c++ {
			name := "byte " + string(rune('0'+pos/10)) + string(rune('0'+pos%10))
			cases = append(cases, textCase{name + " 0x" + hexByte(byte(c)), at(pos, byte(c))})
		}
	}
	return cases
}

func hexByte(b byte) string {
	const digits = "0123456789abcdef"
	return string([]byte{digits[b>>4], digits[b&15]})
}

func TestTS29_ParseRefuses(t *testing.T) {
	for _, tc := range refusedTexts() {
		if got, ok := Parse(tc.text); ok || got != ([Size]byte{}) {
			t.Errorf("%s: Parse(%q) = %x, %v", tc.name, tc.text, got, ok)
		}
	}
}

// TestTS29_Alphabet checks the byte table for all 256 values.
func TestTS29_Alphabet(t *testing.T) {
	for b := 0; b < 256; b++ {
		want := strings.IndexByte(alphabet, byte(b)) >= 0
		if inAlphabet[b] != want {
			t.Errorf("byte 0x%02x: table %v, want %v", b, inAlphabet[b], want)
		}
	}
}

func TestTS29_ParseAccepts(t *testing.T) {
	want := vectorBlock()
	if got, ok := Parse(vectorText); !ok || got != want {
		t.Errorf("Parse(%q) = %x, %v", vectorText, got, ok)
	}
}

func TestTU01_Text(t *testing.T) {
	if got := Text(vectorBlock()); got != vectorText {
		t.Errorf("Text = %q, want %q", got, vectorText)
	}
	k := newSet(t, testKey, 4)
	for i := 0; i < 4; i++ {
		tok, _ := k.Mint(i, epoch)
		s := Text(tok)
		if len(s) != textLen || s != strings.ToLower(s) || strings.Contains(s, "=") {
			t.Fatalf("Text = %q is not canonical", s)
		}
		if got, ok := Parse(s); !ok || got != tok {
			t.Fatalf("Parse(Text(%x)) = %x, %v", tok, got, ok)
		}
	}
}

func TestTU01_TextBitFlips(t *testing.T) {
	k := newSet(t, testKey, 4)
	tok, _ := k.Mint(2, epoch)
	s := Text(tok)
	for bit := 0; bit < textLen*8; bit++ {
		b := []byte(s)
		b[bit/8] ^= 1 << (bit % 8)
		got, ok := Parse(string(b))
		if ok && got == tok {
			t.Fatalf("flip of bit %d gives the same token", bit)
		}
		if ok && Verify([]*KeySet{k}, got).OK {
			t.Fatalf("flip of bit %d gives a token that verifies", bit)
		}
	}
}

func TestTU01_ID(t *testing.T) {
	if got := ID(vectorBlock()); got != vectorID {
		t.Errorf("ID = %q, want %q", got, vectorID)
	}
	k := newSet(t, testKey, 1)
	for i := 0; i < 20; i++ {
		tok, _ := k.Mint(0, epoch)
		id := ID(tok)
		if len(id) != 32 || strings.Trim(id, "0123456789abcdef") != "" {
			t.Fatalf("ID = %q is not 32 lower-case hex characters", id)
		}
	}
}

func TestTS29_ParseNoAllocs(t *testing.T) {
	cases := []string{vectorText, vectorText[:25], strings.ToUpper(vectorText), vectorText[:25] + "5"}
	for _, s := range cases {
		if n := testing.AllocsPerRun(1000, func() { _, _ = Parse(s) }); n != 0 {
			t.Errorf("Parse(%q) allocates %v times", s, n)
		}
	}
}

func BenchmarkParse(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		_, _ = Parse(vectorText)
	}
}
