package bundle

import (
	"crypto/hpke"
	"errors"
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

// seedText is the string that most fmt verbs, encoding/json,
// encoding.TextMarshaler and slog give for a seed.
const seedText = "[seed]"

// seedBytes is the token seed in memory. fmt gives seedText for each verb
// except %T, %p and %w. %T gives the type name and %p gives an address. Under
// %w, fmt calls no method and prints the bytes of a seed value and of a seed
// pointer. encoding/json and encoding.TextMarshaler users get seedText.
// encoding/gob gets an error. encoding/binary and a conversion to []byte give
// the raw bytes. fmt cannot call a method of a value in an unexported struct
// field and prints the bytes there. Under %s and the other verbs that are not
// valid for a pointer, fmt also prints the bytes of a pointer in such a field.
type seedBytes []byte

// seedRef holds the *seedBytes of a Bundle. A print of a seedRef or a *seedRef
// gives seedText. In an unexported struct field, fmt cannot call Format. There
// fmt prints p as an address, so it prints no seed byte.
type seedRef struct{ p *seedBytes }

func (seedRef) Format(f fmt.State, _ rune) { fmt.Fprint(f, seedText) }

func (seedBytes) Format(f fmt.State, _ rune)   { fmt.Fprint(f, seedText) }
func (seedBytes) String() string               { return seedText }
func (seedBytes) MarshalJSON() ([]byte, error) { return []byte(`"` + seedText + `"`), nil }
func (seedBytes) MarshalText() ([]byte, error) { return []byte(seedText), nil }
func (seedBytes) GobEncode() ([]byte, error)   { return nil, errors.New("bundle: seed is not encodable") }

// seedInfo is the HPKE info of a sealed seed. It holds a fixed label, the
// version and the key ID. A zero byte comes before each part after the label.
func seedInfo(version, keyID string) []byte {
	return []byte("phantom-bundle-seed-v1\x00" + version + "\x00" + keyID)
}

// openSeed gives the seed of a bundle of this class. A reference bundle holds
// the plain file, and a proprietary bundle holds the sealed file, never both.
// The seed is a copy, not a part of the archive bytes. openSeed zeroes the
// archive entry of a plain seed after the copy. Any failure gives
// ErrSeedInvalid, which holds no byte and no error of the HPKE code.
func openSeed(a *Archive, class Class, m *Manifest, install hpke.PrivateKey) (*seedBytes, error) {
	plain, hasPlain := a.File(seedPlainName)
	sealed, hasSealed := a.File(seedSealedName)
	var seed []byte
	switch {
	case hasPlain == hasSealed:
		// No seed file, or both files: no seed.
	case class == ClassReference && hasPlain:
		seed = slices.Clone(plain)
		// This is the one place that changes an archive entry. The entry is
		// a second copy of the seed. The zero step after a swap does not reach
		// this entry.
		clear(plain)
	case class == ClassProprietary && hasSealed && install != nil:
		seed, _ = hpke.Open(install, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), seedInfo(m.Version, m.KeyID), sealed)
	}
	if len(seed) != seedSize {
		clear(seed)
		return nil, ErrSeedInvalid
	}
	return (*seedBytes)(&seed), nil
}
