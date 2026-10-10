package tlog

import (
	"encoding/base64"
	"strconv"

	"github.com/cybagard/cyba-phantom/internal/tlog/verifier"
	"golang.org/x/mod/sumdb/note"
)

// maxNoteSize is the largest signed note that ParseCheckpoint accepts.
const maxNoteSize = verifier.MaxNoteSize

// Checkpoint is the content of a checkpoint note body.
type Checkpoint = verifier.Checkpoint

// checkpointBody writes the note body in the C2SP tlog-checkpoint format. The
// lines are the origin, the tree size in decimal, and the root hash in
// standard base64, each with a newline. There is no extension line. The
// tree-note helpers of x/mod write another first line, so this code does not
// use them.
func checkpointBody(c Checkpoint) string {
	return c.Origin + "\n" +
		strconv.FormatUint(c.Size, 10) + "\n" +
		base64.StdEncoding.EncodeToString(c.Root[:]) + "\n"
}

// SignCheckpoint signs a checkpoint note (FR-09, SEC-16). The origin is the
// name of the signer. The signature is Ed25519 (note signature type 0x01).
func SignCheckpoint(signer note.Signer, size uint64, root [32]byte) ([]byte, error) {
	return note.Sign(&note.Note{Text: checkpointBody(Checkpoint{Origin: signer.Name(), Size: size, Root: root})}, signer)
}

// ParseCheckpoint is the strict parser for the notes of this package (SEC-16).
// The rules are in internal/tlog/verifier.
func ParseCheckpoint(msg []byte, origin string, v note.Verifier) (Checkpoint, error) {
	return verifier.ParseCheckpoint(msg, origin, v)
}

// canonicalDecimal reports whether s is a canonical decimal.
func canonicalDecimal(s string) bool { return verifier.CanonicalDecimal(s) }
