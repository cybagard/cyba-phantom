package verify

import (
	"errors"

	"golang.org/x/mod/sumdb/note"
	modtlog "golang.org/x/mod/sumdb/tlog"
)

// The errors of the consistency check. ErrFork means that two signed roots
// cannot come from one log. ErrNoProof means that the list of proofs has no
// proof with the needed sizes. The text of both is fixed.
var (
	ErrFork    = errors.New("verify: checkpoints are not consistent: the log has a fork")
	ErrNoProof = errors.New("verify: no consistency proof has the needed sizes")
)

// Consistency checks that two checkpoints belong to one log (ADR-021, decision
// 7). The key v is the trust anchor for both notes. S is the size of the prior
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
	small, large := int64(p.Size), int64(l.Size) // ParseCheckpoint kept both inside 0 to 2^48
	smallRoot, largeRoot := p.Root, l.Root
	if small > large {
		small, large = large, small
		smallRoot, largeRoot = largeRoot, smallRoot
	}
	if small == 0 || small == large {
		return consistent(small, large, smallRoot, largeRoot, nil)
	}
	for _, c := range proofs {
		if c.OldSize == small && c.NewSize == large {
			return consistent(small, large, smallRoot, largeRoot, c.Hashes)
		}
	}
	return ErrNoProof
}

// consistent checks the roots of two trees with small <= large leaves. The
// proof hashes are used only if both sizes are above 0 and different.
func consistent(small, large int64, smallRoot, largeRoot modtlog.Hash, hashes []modtlog.Hash) error {
	if small == 0 {
		empty, _ := modtlog.TreeHash(0, nil) // reads nothing, so it has no error
		if smallRoot != empty || (large == 0 && largeRoot != empty) {
			return ErrFork
		}
		return nil
	}
	if small == large {
		if smallRoot != largeRoot {
			return ErrFork
		}
		return nil
	}
	if modtlog.CheckTree(modtlog.TreeProof(hashes), large, largeRoot, small, smallRoot) != nil {
		return ErrFork
	}
	return nil
}
