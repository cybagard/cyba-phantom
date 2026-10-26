package tlog

import (
	"crypto/rand"
	"strings"
	"testing"

	"golang.org/x/mod/sumdb/note"
)

// FuzzTU12KeyParse checks that note.NewSigner does not panic on key text of 0
// to 1 024 bytes. The key loader reads at most that much from a key file.
func FuzzTU12KeyParse(f *testing.F) {
	skey, _, err := note.GenerateKey(rand.Reader, testOrigin)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(skey)
	f.Add(skey + strings.Repeat("\n", maxKeySize-len(skey)))
	f.Add(strings.Repeat("A", maxKeySize))
	f.Fuzz(func(t *testing.T, text string) {
		if len(text) > maxKeySize {
			t.Skip()
		}
		_, _ = note.NewSigner(text)
	})
}
