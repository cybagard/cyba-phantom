package token

import "testing"

// FuzzParseVerify feeds any text to Parse, and a parsed block to Verify
// (T-S-29, SEC-33). A refused text gives the zero block and no Verify call.
// Check gets the text at all positions and must agree with Ring.Verify.
func FuzzParseVerify(f *testing.F) {
	ring := []*KeySet{newSet(f, testKey, 4), newSet(f, otherKey, 4)}
	checkRing := fixedRing(ring...)
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
		got := checkRing.Check([Positions]string{s, s, s, s})
		if !ok {
			if tok != ([Size]byte{}) {
				t.Fatalf("Parse(%q) refused with block %x", s, tok)
			}
			if got != ([Positions]Result{}) {
				t.Fatalf("Check(%q) = %+v for a refused text", s, got)
			}
			return
		}
		want := checkRing.Verify(tok)
		for i, res := range got {
			if res != want {
				t.Fatalf("Check(%q)[%d] = %+v, Ring.Verify = %+v", s, i, res, want)
			}
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
