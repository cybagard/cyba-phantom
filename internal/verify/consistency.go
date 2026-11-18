package verify

import (
	"errors"

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

// emptyRoot returns the root of the empty tree.
func emptyRoot() modtlog.Hash {
	h, _ := modtlog.TreeHash(0, nil) // reads nothing, so it has no error
	return h
}

// Consistency checks that two checkpoints belong to one log (SEC-18, FR-16).
// The two values come from ReadCheckpoint, so the key has verified both notes.
// The function parses no note. S is the size of the prior checkpoint and N is
// the size of the latest checkpoint.
//
// Two checkpoints with different origins are not one log. That gives ErrFork.
// If N is larger than S, a proof from S to N must verify. If N is smaller than
// S, a proof from N to S must verify. If the sizes are equal, the roots must be
// equal. A size of 0 needs no proof, but its root must be the root of the empty
// tree. The sizes do not have to be adjacent. The function does not read or
// write state.
//
// The zero value is not from ReadCheckpoint. It has size 0 and a root that is
// not the empty root, so it gives ErrFork.
//
// A proof that fails, roots that differ at one size, different origins, or a
// bad empty root give ErrFork. A list without the needed proof gives
// ErrNoProof.
func Consistency(prior, latest Checkpoint, proofs []ConsistencyProof) error {
	if prior.origin != latest.origin {
		return ErrFork
	}
	priorSize, err := toSize(prior.size)
	if err != nil {
		return err
	}
	latestSize, err := toSize(latest.size)
	if err != nil {
		return err
	}
	small, large := tree{priorSize, prior.root}, tree{latestSize, latest.root}
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
		empty := emptyRoot()
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
