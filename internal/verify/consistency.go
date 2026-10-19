package verify

import (
	"errors"

	"golang.org/x/mod/sumdb/note"
	modtlog "golang.org/x/mod/sumdb/tlog"
)

// The errors of the consistency check. ErrFork means that two signed roots
// cannot come from one log, or that the consistency proof is bad. ErrNoProof
// means that the list of proofs has no proof with the needed sizes. The text of
// both is fixed.
var (
	ErrFork    = errors.New("verify: checkpoints are not consistent")
	ErrNoProof = errors.New("verify: no consistency proof has the needed sizes")
)

// Consistency checks that two checkpoints belong to one log (SEC-18, FR-16).
// The key v is the trust anchor for both notes. S is the size of the prior
// note and N is the size of the latest note.
//
// If N is larger than S, a proof from S to N must verify. If N is smaller than
// S, a proof from N to S must verify. If the sizes are equal, the roots must be
// equal. A size of 0 needs no proof, but its root must be the root of the empty
// tree. The sizes do not have to be adjacent. The function does not read or
// write state.
//
// A proof that fails, roots that differ at one size, or a bad empty root give
// ErrFork. A list without the needed proof gives ErrNoProof.
func Consistency(v note.Verifier, prior, latest []byte, proofs []ConsistencyProof) error {
	p, err := ParseCheckpoint(prior, v)
	if err != nil {
		return err
	}
	l, err := ParseCheckpoint(latest, v)
	if err != nil {
		return err
	}
	priorSize, err := toSize(p.Size)
	if err != nil {
		return err
	}
	latestSize, err := toSize(l.Size)
	if err != nil {
		return err
	}
	small, large := tree{priorSize, p.Root}, tree{latestSize, l.Root}
	if small.size > large.size {
		small, large = large, small
	}
	if small.size == 0 || small.size == large.size {
		return consistent(small, large, nil)
	}
	for _, c := range proofs {
		if c.OldSize == small.size && c.NewSize == large.size {
			return consistent(small, large, c.Hashes)
		}
	}
	return ErrNoProof
}

// tree is the size and the root of one tree.
type tree struct {
	size int64
	root modtlog.Hash
}

// consistent checks two trees with small.size <= large.size. The proof hashes
// are used only if both sizes are above 0 and different.
func consistent(small, large tree, hashes []modtlog.Hash) error {
	if small.size == 0 {
		empty, _ := modtlog.TreeHash(0, nil) // reads nothing, so it has no error
		if small.root != empty || (large.size == 0 && large.root != empty) {
			return ErrFork
		}
		return nil
	}
	if small.size == large.size {
		if small.root != large.root {
			return ErrFork
		}
		return nil
	}
	if modtlog.CheckTree(modtlog.TreeProof(hashes), large.size, large.root, small.size, small.root) != nil {
		return ErrFork
	}
	return nil
}
