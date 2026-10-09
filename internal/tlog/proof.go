package tlog

import (
	"errors"
	"strings"

	"golang.org/x/mod/sumdb/tlog"
)

// The rules in the text of an Error from a proof or a root read. The text is
// fixed. It never holds tile bytes or hash bytes.
const (
	ruleProofInput = "proof input is not valid for the tree"
	ruleProofRead  = "tile on disk does not match the tree head"
)

// RootAt returns the root of the tree of the first size leaves. Size 0 gives
// the root of the empty tree. The size must not be above the size of the log.
// Each hash comes from a tile that was checked against the tree head of the
// log. If a tile does not match, RootAt returns an error and no root.
func (l *Log) RootAt(size int64) (tlog.Hash, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if size < 0 || size > l.size {
		return tlog.Hash{}, &Error{"root", ruleProofInput}
	}
	var root tlog.Hash
	err := l.read(func(r tlog.HashReader) (err error) {
		root, err = tlog.TreeHash(size, r)
		return err
	})
	return root, err
}

// ProveInclusion returns the proof that the leaf at position index is in the
// tree of the first size leaves. The index must be below the size, and the size
// must not be above the size of the log. Check the proof with VerifyInclusion
// and the root that RootAt gives for the size.
func (l *Log) ProveInclusion(index, size int64) (tlog.RecordProof, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if index < 0 || index >= size || size > l.size {
		return nil, &Error{"inclusion proof", ruleProofInput}
	}
	var proof tlog.RecordProof
	err := l.read(func(r tlog.HashReader) (err error) {
		proof, err = tlog.ProveRecord(size, index, r)
		return err
	})
	return proof, err
}

// ProveConsistency returns the proof that the tree of the first oldSize leaves
// is a prefix of the tree of the first newSize leaves. The sizes must follow
// 0 <= oldSize <= newSize <= the size of the log. For oldSize 0 and for equal
// sizes, the proof is empty and the check is the roots only. Check a proof with
// tlog.CheckTree and the roots that RootAt gives.
func (l *Log) ProveConsistency(oldSize, newSize int64) (tlog.TreeProof, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if oldSize < 0 || oldSize > newSize || newSize > l.size {
		return nil, &Error{"consistency proof", ruleProofInput}
	}
	if oldSize == 0 || oldSize == newSize {
		return tlog.TreeProof{}, nil
	}
	var proof tlog.TreeProof
	err := l.read(func(r tlog.HashReader) (err error) {
		proof, err = tlog.ProveTree(newSize, oldSize, r)
		return err
	})
	return proof, err
}

// read calls f with a hash reader that reads tiles from the store and checks
// each tile against the tree head of the log. The caller holds the lock.
func (l *Log) read(f func(tlog.HashReader) error) error {
	tr := &tileReader{s: l.store}
	err := f(tlog.TileHashReader(tlog.Tree{N: l.size, Hash: l.root}, tr))
	var e *Error
	switch {
	case err == nil:
		return nil
	case errors.As(err, &e):
		return e
	}
	// The check does not say which tile is wrong. Name the tiles that it read.
	names := make([]string, len(tr.read))
	for i, t := range tr.read {
		names[i] = t.Path()
	}
	if len(names) == 0 {
		names = append(names, "proof")
	}
	return &Error{strings.Join(names, ","), ruleProofRead}
}
