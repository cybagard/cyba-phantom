package bundle

import (
	"encoding/hex"
	"errors"
	"slices"
	"strings"
)

// Class is the class of a trust-set key. The zero value is not a class.
type Class uint8

const (
	ClassProprietary Class = iota + 1
	ClassReference
)

// TrustKey is one entry of a trust set: key ID, public key and class.
type TrustKey struct {
	KeyID     string
	PublicKey [32]byte
	Class     Class
}

// TrustSet is the list of the keys that a caller trusts (SEC-24). VerifySig
// takes it as a parameter. This package holds no set.
type TrustSet []TrustKey

// ErrTrustSet is the error of TrustSet.Check. It holds no key bytes.
var ErrTrustSet = errors.New("bundle: trust set is not valid")

// smallOrderY holds the y values of the points of small order on Ed25519. Each
// is 32 bytes in hex with the sign bit clear. They are 0, 1, p-1, c and p-c.
// p is 2^255-19. The last two are the unreduced forms p and p+1 of 0 and 1.
var smallOrderY = [...]string{
	"0000000000000000000000000000000000000000000000000000000000000000",
	"0100000000000000000000000000000000000000000000000000000000000000",
	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
	"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
}

// smallOrder tells if the public key k is a point of small order. Such a key
// lets a fixed signature verify for some archives, so no key may be one. The
// sign bit of the encoding does not change the result.
func smallOrder(k [32]byte) bool {
	k[31] &^= 0x80
	return slices.Contains(smallOrderY[:], hex.EncodeToString(k[:]))
}

// Check gives ErrTrustSet for an entry with a key ID or class that is not
// valid. It also gives it for a repeated key ID and for a key in testKeys. It
// gives it for a key of small order too.
func (t TrustSet) Check(testKeys [][32]byte) error {
	seen := make(map[string]bool, len(t))
	for _, k := range t {
		if !validKeyID(k.KeyID) || seen[k.KeyID] ||
			(k.Class != ClassProprietary && k.Class != ClassReference) ||
			slices.Contains(testKeys, k.PublicKey) || smallOrder(k.PublicKey) {
			return ErrTrustSet
		}
		seen[k.KeyID] = true
	}
	return nil
}

// ParseKeyLine reads a public key line, "<key_id> <base64>" with no newline.
// The base64 text is the canonical form of 32 bytes. A key of small order is
// not valid.
func ParseKeyLine(s string) (id string, key [32]byte, ok bool) {
	id, text, found := strings.Cut(s, " ")
	if !found || !validKeyID(id) {
		return "", key, false
	}
	if key, ok = parseKey(text); !ok || smallOrder(key) {
		return "", key, false
	}
	return id, key, true
}
