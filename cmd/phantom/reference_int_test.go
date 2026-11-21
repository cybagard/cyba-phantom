package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/cybagard/cyba-phantom/internal/bundle"
)

// The base64 text of a signing seed is 43 characters and "=" (32 bytes). The
// text of a private key is 86 characters and "==" (64 bytes). A private key is
// the seed and then the public key. A longer run of base64 characters that ends
// in such a tail is found too. The scan is by hand and not a regular
// expression. The test reads the build output of the tree. A repeat count of 43
// is slow in regexp.
const (
	seedChars = 43
	privChars = 86
)

func isBase64Char(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/'
}

// seedsIn gives the seeds that the base64 runs of text decode to. A text that
// does not decode to 32 or 64 bytes gives none. For 64 bytes, the seed is the
// first 32.
func seedsIn(text []byte) [][]byte {
	var out [][]byte
	add := func(s string) {
		b, err := base64.StdEncoding.DecodeString(s)
		if err == nil && (len(b) == ed25519.SeedSize || len(b) == 2*ed25519.SeedSize) {
			out = append(out, b[:ed25519.SeedSize])
		}
	}
	run := 0 // base64 characters before text[i], with no "=" between
	for i, c := range text {
		switch {
		case isBase64Char(c):
			run++
			continue
		case c == '=':
			if run >= privChars && i+1 < len(text) && text[i+1] == '=' {
				add(string(text[i-privChars : i+2]))
			}
			if run >= seedChars {
				add(string(text[i-seedChars : i+1]))
			}
		}
		run = 0
	}
	return out
}

// keyFilesIn walks the tree below root. It reads each regular file for base64
// runs that decode to a seed (seedsIn). It gives the path of each file with a
// seed. The public key of the seed must be a key of class reference in the
// trust set. The paths use "/" and are relative to root.
//
// The walk skips each entry named .git, a directory or a file. It holds the
// object store of the version control, and no file of the tree. The walk also
// skips each link and each file that is not regular. It does not follow links,
// and a link has no bytes of its own. It skips no other path. The build
// output, the test data and the untracked files are in the scan. So a key
// cannot hide in a directory that the version control ignores.
//
// The scan takes the trust set as a parameter. So a test can run it with the
// trust set of a release build.
func keyFilesIn(root string, trust bundle.TrustSet) ([]string, error) {
	var keys [][32]byte
	for _, k := range trust {
		if k.Class == bundle.ClassReference {
			keys = append(keys, k.PublicKey)
		}
	}
	var found []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Name() == ".git" {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		text, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		for _, seed := range seedsIn(text) {
			pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
			if slices.Contains(keys, [32]byte(pub)) {
				rel, _ := filepath.Rel(root, p)
				found = append(found, filepath.ToSlash(rel))
				break
			}
		}
		return nil
	})
	return found, err
}

// TestTU29_NoReferenceSigningKeyInModule checks that no file of the module tree
// holds the private signing key of class reference (T-U-29, SEC-42). The scan
// reads each base64 run of 43 characters and "=" that decodes to 32 bytes. It
// derives the public key of the seed. It compares that key with the reference
// key of the trust set under test. This test uses the key of its own run
// (devKey), which is the one key of class reference. A later change can call
// keyFilesIn with releaseTrust(). The public seed of the token in
// bundles/reference/src/secrets/token.seed is raw bytes and not base64, and it
// is no signing key.
func TestTU29_NoReferenceSigningKeyInModule(t *testing.T) {
	root := filepath.Join("..", "..")
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("the module root %s: %v", root, err)
	}
	trust := refTrustOf(devKey(t).Public().(ed25519.PublicKey))
	found, err := keyFilesIn(root, trust)
	mustOK(t, err)
	if len(found) > 0 {
		t.Errorf("files with the base64 seed of the reference key: %q; want none", found)
	}
}

// TestTU29_KeyScanFindsPlantedSeed checks the key scan (T-U-29, SEC-42). A tree
// in a temporary directory holds the base64 text of a seed. The public key of
// the seed is the reference key of the test trust set. The scan finds the seed
// alone and in a longer line. It also finds a 64-byte private key and a seed at
// the end of a longer base64 run. It does not find a seed of another key or a
// file below .git. It does not find raw seed bytes or a run of the wrong
// length.
func TestTU29_KeyScanFindsPlantedSeed(t *testing.T) {
	seed := devKey(t).Seed()
	priv := ed25519.NewKeyFromSeed(seed)
	trust := refTrustOf(priv.Public().(ed25519.PublicKey))
	std := base64.StdEncoding
	other := devKey(t).Seed()
	root := t.TempDir()
	plant := map[string][]byte{
		"seed.txt":          []byte(std.EncodeToString(seed)),
		"notes/line.md":     []byte("signing key: " + std.EncodeToString(seed) + "\nend\n"),
		"private.b64":       []byte(std.EncodeToString(priv)),
		"long/run.txt":      []byte("QUJD" + std.EncodeToString(seed)),
		"other.txt":         []byte(std.EncodeToString(other)),
		".git/config":       []byte(std.EncodeToString(seed)),
		"raw.bin":           seed,
		"short.txt":         []byte(std.EncodeToString(seed[:30])),
		"empty.txt":         nil,
		"sub/.git/inner.md": []byte(std.EncodeToString(seed)),
	}
	for name, data := range plant {
		p := filepath.Join(root, name)
		mustOK(t, os.MkdirAll(filepath.Dir(p), 0o755))
		mustOK(t, os.WriteFile(p, data, 0o644))
	}
	got, err := keyFilesIn(root, trust)
	mustOK(t, err)
	slices.Sort(got)
	want := []string{"long/run.txt", "notes/line.md", "private.b64", "seed.txt"}
	if !slices.Equal(got, want) {
		t.Errorf("files with the seed: %q; want %q", got, want)
	}
	// A trust set with another reference key does not match the seed. A key
	// of the other class does not match it either.
	otherKey := ed25519.NewKeyFromSeed(other).Public().(ed25519.PublicKey)
	if got, err := keyFilesIn(root, refTrustOf(otherKey)); err != nil || !slices.Equal(got, []string{"other.txt"}) {
		t.Errorf("scan with the other key: %q, %v; want only other.txt", got, err)
	}
	proprietary := bundle.TrustSet{{KeyID: "p1", PublicKey: [32]byte(priv.Public().(ed25519.PublicKey)), Class: bundle.ClassProprietary}}
	if got, err := keyFilesIn(root, proprietary); err != nil || len(got) != 0 {
		t.Errorf("scan with a key of class proprietary: %q, %v; want none", got, err)
	}
}
