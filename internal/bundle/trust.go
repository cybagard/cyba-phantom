package bundle

import (
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

// Check gives ErrTrustSet for an entry with a key ID or class that is not
// valid. It also gives it for a repeated key ID, or for a key in testKeys.
func (t TrustSet) Check(testKeys [][32]byte) error {
	seen := make(map[string]bool, len(t))
	for _, k := range t {
		if !validKeyID(k.KeyID) || seen[k.KeyID] ||
			(k.Class != ClassProprietary && k.Class != ClassReference) ||
			slices.Contains(testKeys, k.PublicKey) {
			return ErrTrustSet
		}
		seen[k.KeyID] = true
	}
	return nil
}

// ParseKeyLine reads a public key line, "<key_id> <base64>" with no newline.
// The base64 text is the canonical form of 32 bytes.
func ParseKeyLine(s string) (id string, key [32]byte, ok bool) {
	id, text, found := strings.Cut(s, " ")
	if !found || !validKeyID(id) {
		return "", key, false
	}
	if key, ok = parseKey(text); !ok {
		return "", key, false
	}
	return id, key, true
}
