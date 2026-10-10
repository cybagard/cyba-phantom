package tlog

import (
	"github.com/cybagard/cyba-phantom/internal/tlog/verifier"
	"golang.org/x/mod/sumdb/note"
)

// maxNoteSize is the largest signed note that ParseCheckpoint accepts.
const maxNoteSize = verifier.MaxNoteSize

// Checkpoint is the content of a checkpoint note body.
type Checkpoint = verifier.Checkpoint

// SignCheckpoint signs a checkpoint note (FR-09, SEC-16). The origin is the
// name of the signer. The signature is Ed25519 (note signature type 0x01).
func SignCheckpoint(signer note.Signer, size uint64, root [32]byte) ([]byte, error) {
	return verifier.SignCheckpoint(signer, size, root)
}

// ParseCheckpoint is the strict parser for the notes of this package (SEC-16).
// The rules are in internal/tlog/verifier.
func ParseCheckpoint(msg []byte, origin string, v note.Verifier) (Checkpoint, error) {
	return verifier.ParseCheckpoint(msg, origin, v)
}

// canonicalDecimal reports whether s is a canonical decimal.
func canonicalDecimal(s string) bool { return verifier.CanonicalDecimal(s) }
