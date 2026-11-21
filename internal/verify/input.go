// Package verify reads and checks the inputs of the open verifier (SEC-18,
// 04 §7): the key, the checkpoint note, the event and the proof file. The
// package treats the checkpoint note, the event and the proof file as
// untrusted. The user gives the key by a separate channel, and the package
// trusts it. The package checks the size cap of each input before it parses
// the input. It checks that an event is in the tree of a checkpoint
// (verify.go). It keeps the verifier state (state.go). It makes the state
// directory if it is missing. It writes, renames and removes files in that
// directory.
//
// The errors of this package are the fixed values below. They hold no input
// bytes. The package does not wrap an error from another package and does not
// return one, because the text of that error can hold input bytes. Callers
// test errors with errors.Is.
package verify

import (
	"bytes"
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

// toSize converts a size from a note to a log size. A size above maxSize gives
// ErrRange. ParseCheckpoint refuses this size first. The check stays here so
// that the bound is next to the conversion.
func toSize(u uint64) (int64, error) {
	if u > maxSize {
		return 0, ErrRange
	}
	return int64(u), nil
}

// The errors of this package. ErrSignature means that the signature does not
// verify with the key (not verified). ErrCheckpoint means that the note is not
// valid in form (an input error).
var (
	ErrTooLarge   = errors.New("verify: input is larger than its size cap")
	ErrRead       = errors.New("verify: input cannot be read")
	ErrKey        = errors.New("verify: key text is not a valid verifier key")
	ErrCheckpoint = errors.New("verify: checkpoint note is not valid in form")
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
// The origin is the name of the verifier. A nil verifier gives ErrKey, because
// the trusted key is missing. The function checks this before the size check.
// The parser refuses a note with two or more signature lines. This rule
// applies also when a line is from another key. The function checks the size
// against 2^48.
//
// When the strict parser refuses the note, the function opens the note with
// the same key. If note.Open says that the signature of the key is wrong, the
// result is ErrSignature (not verified). The result is also ErrSignature if
// no signature line is from the key. An example is a note signed by another
// key. Every other result is ErrCheckpoint (an input error). These are text
// that is not a note, a second signature line, and a bad body. A size that is
// not a 64-bit number also gives ErrCheckpoint. A size above 2^48 gives
// ErrRange. The first fault that note.Open finds decides between ErrSignature
// and ErrCheckpoint. A note that is both malformed and badly signed can give
// either.
//
// The value keeps its own copy of the note bytes. A later change of b does not
// change the value. The value also holds the key hash of v.
func ParseCheckpoint(b []byte, v note.Verifier) (Checkpoint, error) {
	if v == nil {
		return Checkpoint{}, ErrKey
	}
	if len(b) > MaxNoteBytes {
		return Checkpoint{}, ErrTooLarge
	}
	c, err := verifier.ParseCheckpoint(b, v.Name(), v)
	if err != nil {
		_, nerr := note.Open(b, note.VerifierList(v))
		var invalid *note.InvalidSignatureError
		var unverified *note.UnverifiedNoteError
		if errors.As(nerr, &invalid) || errors.As(nerr, &unverified) {
			return Checkpoint{}, ErrSignature
		}
		return Checkpoint{}, ErrCheckpoint
	}
	if c.Size > maxSize {
		return Checkpoint{}, ErrRange
	}
	return Checkpoint{
		origin:  c.Origin,
		size:    c.Size,
		root:    c.Root,
		keyHash: v.KeyHash(),
		note:    bytes.Clone(b),
	}, nil
}

// Checkpoint is a checkpoint note that ParseCheckpoint accepted. A value holds
// the origin, the size, the root, the key hash of the verifier and the note
// bytes. Only ParseCheckpoint and ReadCheckpoint make a value that is not
// zero. The fields are not exported, so code outside the package cannot change
// a value.
type Checkpoint struct {
	origin  string
	size    uint64
	root    [32]byte
	keyHash uint32
	note    []byte
}

// Origin returns the origin of the note.
func (c Checkpoint) Origin() string { return c.origin }

// Size returns the tree size of the note.
func (c Checkpoint) Size() uint64 { return c.size }

// Root returns the root hash of the note.
func (c Checkpoint) Root() [32]byte { return c.root }

// Note returns a copy of the note bytes. A change of the copy does not change
// the value.
func (c Checkpoint) Note() []byte { return bytes.Clone(c.note) }

// ReadCheckpoint reads a note with the size cap, then calls ParseCheckpoint.
// The value is the only form of checkpoint that Inclusion accepts. The value
// is the value of ParseCheckpoint, with its own copy of the bytes.
func ReadCheckpoint(r io.Reader, v note.Verifier) (Checkpoint, error) {
	b, err := readCapped(r, MaxNoteBytes)
	if err != nil {
		return Checkpoint{}, err
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
