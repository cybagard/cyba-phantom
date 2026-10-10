// Package verify reads and checks the inputs of the open verifier (SEC-18,
// 04 §7): the key, the checkpoint note, the event and the proof file. The
// package treats the checkpoint note, the event and the proof file as
// untrusted. The user gives the key by a separate channel, and the package
// trusts it. The package checks the size cap of each input before it parses
// the input. The package also checks that an event is in the tree of a
// checkpoint (verify.go).
//
// The errors of this package are the fixed values below. They hold no input
// bytes. The package does not wrap an error from another package and does not
// return one, because the text of that error can hold input bytes. Callers
// test errors with errors.Is.
package verify

import (
	"errors"
	"io"
	"strings"

	"golang.org/x/mod/sumdb/note"

	"github.com/cybagard/cyba-phantom/internal/event"
	"github.com/cybagard/cyba-phantom/internal/tlog/verifier"
)

// The size caps of the inputs, in bytes. The key cap and the note cap are
// small, because a key text and a note with one signature are small.
const (
	MaxKeyBytes   = 1 << 10
	MaxNoteBytes  = 1 << 10
	MaxProofBytes = 16 << 10
)

// maxSize is the largest size or index that the verifier accepts: 2^48. It is
// the bound of the log.
const maxSize = verifier.MaxSize

// The errors of this package. ErrSignature means that the signature does not
// verify with the key (not verified). ErrCheckpoint means that the form of the
// note is bad (an input error).
var (
	ErrTooLarge   = errors.New("verify: input is larger than its size cap")
	ErrRead       = errors.New("verify: input cannot be read")
	ErrKey        = errors.New("verify: key text is not a valid verifier key")
	ErrCheckpoint = errors.New("verify: checkpoint note is not valid for the key")
	ErrSignature  = errors.New("verify: checkpoint signature does not verify with the key")
	ErrEvent      = errors.New("verify: event is not one canonical JSON object")
	ErrProof      = errors.New("verify: proof file is not valid")
	ErrRange      = errors.New("verify: size or index is outside 0 to 2^48")
)

// readCapped reads at most limit+1 bytes. The extra byte lets the caller see
// that the input is larger than its cap and refuse it. The memory use has a
// bound for any reader.
func readCapped(r io.Reader, limit int) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, int64(limit)+1))
	if err != nil {
		return nil, ErrRead
	}
	return b, nil
}

// ParseKey makes the verifier from the text of a key file. The origin is the
// name of the key. The text can end with one newline, as in
// keys/checkpoint.vkey.
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

// ParseCheckpoint parses a signed note with the strict parser of
// internal/tlog/verifier.
// The origin is the name of the verifier. The parser refuses a note with two or
// more signature lines. This rule applies also when a line is from another
// key. The function checks the size against 2^48.
//
// When the strict parser refuses the note, the function opens the note with
// the same key. If that fails, the signature is bad or the key is another key:
// the result is ErrSignature (not verified). If it works, the form of the note
// is bad: a second signature line, a bad body, or a size that is too large. The
// result is ErrCheckpoint (an input error).
func ParseCheckpoint(b []byte, v note.Verifier) (verifier.Checkpoint, error) {
	if len(b) > MaxNoteBytes {
		return verifier.Checkpoint{}, ErrTooLarge
	}
	c, err := verifier.ParseCheckpoint(b, v.Name(), v)
	if err != nil {
		if _, nerr := note.Open(b, note.VerifierList(v)); nerr != nil {
			return verifier.Checkpoint{}, ErrSignature
		}
		return verifier.Checkpoint{}, ErrCheckpoint
	}
	if c.Size > maxSize {
		return verifier.Checkpoint{}, ErrRange
	}
	return c, nil
}

// ReadCheckpoint reads a note with the size cap, then calls ParseCheckpoint.
func ReadCheckpoint(r io.Reader, v note.Verifier) (verifier.Checkpoint, error) {
	b, err := readCapped(r, MaxNoteBytes)
	if err != nil {
		return verifier.Checkpoint{}, err
	}
	return ParseCheckpoint(b, v)
}

// Event holds the received bytes of an event and their hash.
type Event struct {
	Raw  []byte
	Hash verifier.EventHash
}

// ParseEvent accepts b only if b is at most event.MaxRecordBytes long and equal
// to its RFC 8785 form. The hash covers the received bytes. The function does
// not decode the event into a schema. Event.Raw uses the memory of b, so the
// caller must not change b after the call.
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
