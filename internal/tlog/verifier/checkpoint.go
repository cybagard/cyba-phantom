package verifier

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"

	"golang.org/x/mod/sumdb/note"
)

// MaxNoteSize is the largest signed note that ParseCheckpoint accepts. A
// checkpoint with one signature is far smaller.
const MaxNoteSize = 1024

// Checkpoint is the content of a checkpoint note body.
type Checkpoint struct {
	Origin string
	Size   uint64
	Root   [32]byte
}

// CheckpointBody writes the note body in the C2SP tlog-checkpoint format. The
// lines are the origin, the tree size in decimal, and the root hash in
// standard base64, each with a newline. There is no extension line. The
// tree-note helpers of x/mod write another first line, so this code does not
// use them.
func CheckpointBody(c Checkpoint) string {
	return c.Origin + "\n" +
		strconv.FormatUint(c.Size, 10) + "\n" +
		base64.StdEncoding.EncodeToString(c.Root[:]) + "\n"
}

// SignCheckpoint signs a checkpoint note (FR-09, SEC-16). The origin is the
// name of the signer. The signature is Ed25519 (note signature type 0x01).
func SignCheckpoint(signer note.Signer, size uint64, root [32]byte) ([]byte, error) {
	return note.Sign(&note.Note{Text: CheckpointBody(Checkpoint{signer.Name(), size, root})}, signer)
}

// ParseCheckpoint is the strict parser for the notes of the sensor (SEC-16).
// It returns an error if the note is larger than 1 KiB. It returns an error if
// the signature does not verify with the given note verifier. It returns an error if the
// signature block does not have exactly one line. It returns an error if the
// body is not exactly three canonical lines: the configured origin, a canonical
// decimal size, and a canonical base64 root of 32 bytes.
func ParseCheckpoint(msg []byte, origin string, verifier note.Verifier) (Checkpoint, error) {
	var c Checkpoint
	if len(msg) > MaxNoteSize { // before any parse
		return c, errors.New("checkpoint note is larger than 1 KiB")
	}
	n, err := note.Open(msg, note.VerifierList(verifier))
	if err != nil {
		return c, errors.New("checkpoint note signature does not verify")
	}
	// The sensor's own notes have exactly one signature line. A cosigned note
	// needs another parser. Open drops a repeated line of the same key name and
	// hash before it verifies that line, so the count uses the raw bytes. The
	// signature block is the part after the last blank line. Open succeeded, so
	// that blank line exists.
	if bytes.Count(msg[bytes.LastIndex(msg, []byte("\n\n"))+2:], []byte("\n")) != 1 {
		return c, errors.New("checkpoint note must have exactly one signature")
	}
	lines := strings.Split(n.Text, "\n")
	if len(lines) != 4 || lines[3] != "" {
		return c, errors.New("checkpoint note body must have exactly three lines")
	}
	if lines[0] != origin {
		return c, errors.New("checkpoint note origin is not the configured origin")
	}
	c.Origin = lines[0]
	if !CanonicalDecimal(lines[1]) {
		return c, errors.New("checkpoint note size is not a canonical decimal")
	}
	if c.Size, err = strconv.ParseUint(lines[1], 10, 64); err != nil {
		return c, errors.New("checkpoint note size is too large")
	}
	// Strict rejects non-zero padding bits. The decoder skips CR and LF, so the
	// encoded form must also equal the input.
	raw, err := base64.StdEncoding.Strict().DecodeString(lines[2])
	if err != nil || base64.StdEncoding.EncodeToString(raw) != lines[2] {
		return c, errors.New("checkpoint note root is not canonical base64")
	}
	if len(raw) != len(c.Root) {
		return c, errors.New("checkpoint note root is not 32 bytes")
	}
	copy(c.Root[:], raw)
	return c, nil
}

// CanonicalDecimal reports whether s is digits only, with no leading zero
// (except "0" itself), no sign, and no space.
func CanonicalDecimal(s string) bool {
	if s == "" || (len(s) > 1 && s[0] == '0') {
		return false
	}
	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
