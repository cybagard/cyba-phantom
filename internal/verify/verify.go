package verify

import (
	"errors"
	"slices"

	"golang.org/x/mod/sumdb/note"
	modtlog "golang.org/x/mod/sumdb/tlog"

	"github.com/cybagard/cyba-phantom/internal/tlog"
)

// The errors of the inclusion check. They are fixed values like the errors in
// input.go. ErrNotVerified means that the inputs are valid but the event is not
// in the checkpoint. The other two errors mean that the proof file does not fit
// the checkpoint.
var (
	ErrNotVerified = errors.New("verify: event is not in the tree of the checkpoint")
	ErrTreeSize    = errors.New("verify: proof tree size is larger than the checkpoint size")
	ErrBridged     = errors.New("verify: proof for a smaller tree is not supported")
)

// Result is what a successful inclusion check shows (04 §7, Output). The
// proof hashes are the hashes that the check used.
type Result struct {
	Origin    string
	Size      uint64
	Root      [32]byte
	EventHash tlog.EventHash
	LeafIndex int64
	Proof     []modtlog.Hash
}

// Inclusion checks that the event is in the tree of a checkpoint (SEC-18,
// FR-16). The key v is the trust anchor. The function parses the checkpoint
// note with ParseCheckpoint, so a note with a bad signature, an origin other
// than the key name, or a size past 2^48 is refused. The tree size of the proof
// must be equal to the checkpoint size. A larger size gives ErrTreeSize. A
// smaller size gives ErrBridged, and so does a proof that has a root or a
// consistency proof: the bridged form is not checked yet. The leaf hash and the
// proof check come from internal/tlog.
func Inclusion(v note.Verifier, checkpoint []byte, e Event, p InclusionProof) (Result, error) {
	c, err := ParseCheckpoint(checkpoint, v)
	if err != nil {
		return Result{}, err
	}
	switch size := int64(c.Size); { // ParseCheckpoint kept the size inside 0 to 2^48
	case p.TreeSize > size:
		return Result{}, ErrTreeSize
	case p.TreeSize < size || p.Root != nil || p.Consistency != nil:
		return Result{}, ErrBridged
	}
	if tlog.VerifyInclusion(e.Hash, p.Index, p.TreeSize, c.Root, modtlog.RecordProof(p.Hashes)) != nil {
		return Result{}, ErrNotVerified
	}
	return Result{
		Origin:    c.Origin,
		Size:      c.Size,
		Root:      c.Root,
		EventHash: e.Hash,
		LeafIndex: p.Index,
		Proof:     slices.Clone(p.Hashes),
	}, nil
}
