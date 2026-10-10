// Package verify reads and checks the inputs of the open verifier (SEC-18,
// 04 §7): the key, the checkpoint note, the event and the proof file. All of
// them are untrusted, except the key, which the user gives out of band. Each
// input has a size cap that is checked before the parse. The package does not
// check a proof against a root.
//
// Errors are the fixed values below. They hold no input bytes. The package does
// not wrap or pass on an error from another package, because that text can
// hold input bytes. Callers test errors with errors.Is.
package verify

import (
	"errors"
	"io"
	"strings"

	"golang.org/x/mod/sumdb/note"

	"github.com/cybagard/cyba-phantom/internal/event"
	"github.com/cybagard/cyba-phantom/internal/tlog"
)

// The size caps of the inputs, in bytes. The key cap and the note cap are
// small because a key text and a note with one signature are small.
const (
	MaxKeyBytes   = 1 << 10
	MaxNoteBytes  = 1 << 10
	MaxProofBytes = 16 << 10
)

// maxSize is the largest size or index that the verifier accepts: 2^48. It has
// the same value as the bound of internal/tlog, which does not export it.
const maxSize = 1 << 48

// The errors of this package.
var (
	ErrTooLarge   = errors.New("verify: input is larger than its size cap")
	ErrRead       = errors.New("verify: input cannot be read")
	ErrKey        = errors.New("verify: key text is not a valid verifier key")
	ErrCheckpoint = errors.New("verify: checkpoint note is not valid for the key")
	ErrEvent      = errors.New("verify: event is not one canonical JSON object")
	ErrProof      = errors.New("verify: proof file is not valid")
	ErrRange      = errors.New("verify: size or index is outside 0 to 2^48")
)

// readCapped reads at most limit+1 bytes. The caller sees an input past its
// cap and refuses it. Memory stays bounded for any reader.
func readCapped(r io.Reader, limit int) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, int64(limit)+1))
	if err != nil {
		return nil, ErrRead
	}
	return b, nil
}

// ParseKey makes the verifier from the text of a key file. The origin is the
// name of the key. One final newline is allowed, as in keys/checkpoint.vkey.
func ParseKey(b []byte) (note.Verifier, error) {
	if len(b) > MaxKeyBytes {
		return nil, ErrTooLarge
	}
	v, err := note.NewVerifier(strings.TrimSuffix(string(b), "\n"))
	if err != nil {
		return nil, ErrKey
	}
	return v, nil
}

// ReadKey reads a key file with the size cap, then calls ParseKey.
func ReadKey(r io.Reader) (note.Verifier, error) {
	b, err := readCapped(r, MaxKeyBytes)
	if err != nil {
		return nil, err
	}
	return ParseKey(b)
}

// ParseCheckpoint parses a signed note with the strict parser of internal/tlog.
// The origin is the name of the verifier. A note with more than one signature
// line, also from another key, is refused. The size is checked against 2^48.
func ParseCheckpoint(b []byte, v note.Verifier) (tlog.Checkpoint, error) {
	if len(b) > MaxNoteBytes {
		return tlog.Checkpoint{}, ErrTooLarge
	}
	c, err := tlog.ParseCheckpoint(b, v.Name(), v)
	if err != nil {
		return tlog.Checkpoint{}, ErrCheckpoint
	}
	if c.Size > maxSize {
		return tlog.Checkpoint{}, ErrRange
	}
	return c, nil
}

// ReadCheckpoint reads a note with the size cap, then calls ParseCheckpoint.
func ReadCheckpoint(r io.Reader, v note.Verifier) (tlog.Checkpoint, error) {
	b, err := readCapped(r, MaxNoteBytes)
	if err != nil {
		return tlog.Checkpoint{}, err
	}
	return ParseCheckpoint(b, v)
}

// Event holds the received bytes of an event and their hash.
type Event struct {
	Raw  []byte
	Hash tlog.EventHash
}

// ParseEvent accepts b only if it is at most event.MaxRecordBytes and equal to
// its RFC 8785 form. The hash is of the received bytes. It does not decode the
// event into a schema.
func ParseEvent(b []byte) (Event, error) {
	if len(b) > event.MaxRecordBytes {
		return Event{}, ErrTooLarge
	}
	c, err := event.Canonical(b)
	if err != nil || string(c) != string(b) {
		return Event{}, ErrEvent
	}
	return Event{Raw: b, Hash: event.Hash(b)}, nil
}

// ReadEvent reads an event with the size cap, then calls ParseEvent.
func ReadEvent(r io.Reader) (Event, error) {
	b, err := readCapped(r, event.MaxRecordBytes)
	if err != nil {
		return Event{}, err
	}
	return ParseEvent(b)
}
