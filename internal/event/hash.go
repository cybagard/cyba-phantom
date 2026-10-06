package event

import (
	"crypto/sha256"
)

// Hash returns the sha256 of the canonical bytes. It hashes the exact bytes
// with no encoding step before the hash and no cut of the result. A stranger
// hashes the bytes it receives and gets the same value.
func Hash(canonical []byte) [32]byte {
	return sha256.Sum256(canonical)
}
