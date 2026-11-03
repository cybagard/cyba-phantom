package token

import "testing"

// FuzzParseVerify feeds any text to Parse, and a parsed block to Verify
// (T-S-29, SEC-33). A refused text gives the zero block and no Verify call.
func FuzzParseVerify(f *testing.F) {
	ring := []*KeySet{newSet(f, testKey, 4), newSet(f, otherKey, 4)}
	for _, tc := range refusedTexts() {
		f.Add(tc.text)
	}
	f.Add(vectorText)
	for i := range ring {
		tok, _ := ring[i].Mint(3, epoch)
		f.Add(Text(tok))
	}
	f.Fuzz(func(t *testing.T, s string) {
		tok, ok := Parse(s)
		if !ok {
			if tok != ([Size]byte{}) {
				t.Fatalf("Parse(%q) refused with block %x", s, tok)
			}
			return
		}
		if Text(tok) != s {
			t.Fatalf("Parse(%q) accepted, but Text gives %q", s, Text(tok))
		}
		res := Verify(ring, tok)
		if !res.OK && res != (Result{}) {
			t.Fatalf("Verify(%x) = %+v with OK false", tok, res)
		}
		if res.OK && (res.Trap == "" || res.Set < 0 || res.Set >= len(ring)) {
			t.Fatalf("Verify(%x) = %+v", tok, res)
		}
	})
}
