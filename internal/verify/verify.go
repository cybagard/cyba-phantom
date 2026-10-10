package verify

import (
	"errors"
	"slices"

	"golang.org/x/mod/sumdb/note"
	modtlog "golang.org/x/mod/sumdb/tlog"

	"github.com/cybagard/cyba-phantom/internal/tlog"
)

// The errors of the inclusion check are fixed values like the errors in
// input.go. ErrNotVerified means that the inclusion proof does not give the
// root. ErrTreeSize means that the proof tree size is larger than the
// checkpoint size. Inclusion also returns ErrProof when the proof has a wrong
// shape for its tree size. It returns ErrFork when the consistency proof does
// not verify.
var (
	ErrNotVerified = errors.New("verify: event is not in the tree of the checkpoint")
	ErrTreeSize    = errors.New("verify: proof tree size is larger than the checkpoint size")
)

// Result is what a successful inclusion check shows (04 §7, Output). The proof
// hashes are the hashes that the check used. Consistency holds the consistency
// hashes of a bridged proof. It is nil for a proof at the checkpoint size.
type Result struct {
	Origin      string
	Size        uint64
	Root        [32]byte
	EventHash   tlog.EventHash
	LeafIndex   int64
	Proof       []modtlog.Hash
	Consistency []modtlog.Hash
}

// Inclusion checks that the event is in the tree of a checkpoint (SEC-18,
// FR-16). The key v is the trust anchor. The event e must come from ParseEvent
// or ReadEvent. Inclusion uses e.Hash and does not hash e.Raw again.
//
// The function parses the checkpoint note with ParseCheckpoint. It refuses a
// note with a bad signature, an origin other than the key name, or a size past
// 2^48. A proof size larger than the checkpoint size gives ErrTreeSize.
//
// A proof at the checkpoint size must not have a root or a consistency proof.
// If it has one, the result is ErrProof. A proof at a smaller size m must have
// both. The inclusion proof must give the root at m. The consistency proof from
// m to the checkpoint size must give the checkpoint root. The root at m is
// accepted only through the consistency proof. A bad inclusion proof gives
// ErrNotVerified. A bad consistency proof gives ErrFork. The leaf hash and the
// proof checks come from internal/tlog.
func Inclusion(v note.Verifier, checkpoint []byte, e Event, p InclusionProof) (Result, error) {
	c, err := ParseCheckpoint(checkpoint, v)
	if err != nil {
		return Result{}, err
	}
	size := int64(c.Size) // ParseCheckpoint kept the size inside 0 to 2^48
	root := c.Root
	bridged := p.TreeSize < size
	switch {
	case p.TreeSize > size:
		return Result{}, ErrTreeSize
	case bridged != (p.Root != nil) || bridged != (p.Consistency != nil):
		return Result{}, ErrProof
	case bridged:
		root = *p.Root
	}
	if tlog.VerifyInclusion(e.Hash, p.Index, p.TreeSize, root, modtlog.RecordProof(p.Hashes)) != nil {
		return Result{}, ErrNotVerified
	}
	if bridged {
		if err := consistent(p.TreeSize, size, root, c.Root, p.Consistency); err != nil {
			return Result{}, err
		}
	}
	return Result{
		Origin:      c.Origin,
		Size:        c.Size,
		Root:        c.Root,
		EventHash:   e.Hash,
		LeafIndex:   p.Index,
		Proof:       slices.Clone(p.Hashes),
		Consistency: slices.Clone(p.Consistency),
	}, nil
}
