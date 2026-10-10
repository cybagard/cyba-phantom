// Package verifier holds the checks that a third party runs on a log of the
// sensor (FR-07, SEC-16): the strict parser of a signed checkpoint, the leaf
// hash of an event, and the check of an inclusion proof. The package opens no
// file and no network connection. It imports no net, net/http, or crypto/tls,
// directly or through a dependency. A verifier command must depend on this
// package and not on internal/tlog (SEC-18). The package also holds the note
// body writer (CheckpointBody) and SignCheckpoint, which the log uses.
package verifier

import (
	"crypto/sha256"

	"golang.org/x/mod/sumdb/tlog"
)

const (
	// TileHeight is the height of a tile. A full tile holds 256 hashes.
	TileHeight = 8

	// MaxLevel is the highest tile level. A tree of MaxSize leaves has one
	// hash at this level. x/mod does not return for a size above 2^62, so the
	// bound is much lower.
	MaxLevel = 6
	MaxSize  = 1 << (TileHeight * MaxLevel)
)

// ruleInclusion is the rule in the text of an Error from VerifyInclusion.
const ruleInclusion = "proof does not match the event hash, the index, and the tree head"

// Error names the file that failed and the rule that failed. The name is never
// empty. This package makes errors with fixed words as names. The log package
// (internal/tlog) makes errors of the same type with other names: a tile path,
// the name of the tree head, a directory, or a comma-separated list of tile
// paths.
type Error struct {
	Name string
	Rule string
}

func (e *Error) Error() string { return "tlog: " + e.Name + ": " + e.Rule }

// EventHash is the SHA-256 hash of the canonical bytes of one event. It is the
// record data of a leaf. It is never a hash of the tree.
type EventHash [sha256.Size]byte

// LeafHash returns the leaf hash of an event: SHA-256(0x00 || event hash)
// (RFC 6962, SEC-16). The log, the verifier, and the SDK use this one rule.
func LeafHash(h EventHash) tlog.Hash { return tlog.RecordHash(h[:]) }

// VerifyInclusion checks that the event is the leaf at position index in the
// tree that has size leaves and the root root. It returns nil only if the
// proof, with the leaf hash of the event, gives the root. It never panics for
// any input.
func VerifyInclusion(h EventHash, index, size int64, root tlog.Hash, proof tlog.RecordProof) error {
	if index < 0 || size < 1 || size > MaxSize || index >= size ||
		tlog.CheckRecord(proof, size, root, index, LeafHash(h)) != nil {
		return &Error{"inclusion proof", ruleInclusion}
	}
	return nil
}
