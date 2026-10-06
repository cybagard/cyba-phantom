package event

import (
	"crypto/sha256"
)

// Hash returns the sha256 of the canonical bytes. A verifier hashes the bytes
// that it receives and gets the same hash. Hash does not encode the bytes
// before it hashes them, and it does not shorten the result.
func Hash(canonical []byte) [32]byte {
	return sha256.Sum256(canonical)
}
