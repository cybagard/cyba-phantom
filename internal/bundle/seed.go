package bundle

import (
	"crypto/hpke"
	"fmt"
	"slices"
)

// The seed files of a bundle and the size of a seed (SEC-25). A reference
// bundle holds the plain seed. A proprietary bundle holds the sealed seed.
const (
	seedPlainName  = "secrets/token.seed"
	seedSealedName = "secrets/token.key"
	seedSize       = 32
)

// seedText is the one text that a seed prints for each verb and encoding.
const seedText = "[seed]"

// seedBytes is the token seed in memory. Every way to print or encode it gives
// seedText and no byte of the seed.
type seedBytes []byte

func (seedBytes) Format(f fmt.State, _ rune)   { fmt.Fprint(f, seedText) }
func (seedBytes) MarshalJSON() ([]byte, error) { return []byte(`"` + seedText + `"`), nil }
func (seedBytes) MarshalText() ([]byte, error) { return []byte(seedText), nil }

// seedInfo is the HPKE info of a sealed seed. It holds a fixed label, the
// version and the key ID. A zero byte comes before each part after the label.
func seedInfo(version, keyID string) []byte {
	return []byte("phantom-bundle-seed-v1\x00" + version + "\x00" + keyID)
}

// openSeed gives the seed of a bundle of this class. A reference bundle holds
// the plain file, and a proprietary bundle holds the sealed file, never both.
// The seed is a copy, not a part of the archive bytes. Any failure gives
// ErrSeedInvalid, which holds no byte and no error of the HPKE code.
func openSeed(a *Archive, class Class, m *Manifest, install hpke.PrivateKey) (*seedBytes, error) {
	plain, hasPlain := a.File(seedPlainName)
	sealed, hasSealed := a.File(seedSealedName)
	var seed []byte
	switch {
	case hasPlain == hasSealed:
	case class == ClassReference && hasPlain:
		seed = slices.Clone(plain)
	case class == ClassProprietary && hasSealed && install != nil:
		seed, _ = hpke.Open(install, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), seedInfo(m.Version, m.KeyID), sealed)
	}
	if len(seed) != seedSize {
		clear(seed)
		return nil, ErrSeedInvalid
	}
	return (*seedBytes)(&seed), nil
}
