package tlog

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/mod/sumdb/tlog"
)

// withoutSync turns fsync off for a test that checks proofs, not durability.
func withoutSync(t *testing.T) {
	t.Helper()
	oldFile, oldDir := syncFile, syncDirFile
	syncFile, syncDirFile = func(*os.File) error { return nil }, func(*os.File) error { return nil }
	t.Cleanup(func() { syncFile, syncDirFile = oldFile, oldDir })
}

// checkProofs checks the inclusion proof of leaf index in the tree of size
// leaves, and the consistency proof from oldSize to size, with the checks of
// the verifier and with a root computed from crypto/sha256 only.
func checkProofs(t *testing.T, l *Log, events []EventHash, index, oldSize, size int64) {
	t.Helper()
	root, err := l.RootAt(size)
	if err != nil || root != rfcRoot(rfcLeaves(events[:size])) {
		t.Fatalf("root at %d: %x, error %v", size, root, err)
	}
	proof, err := l.ProveInclusion(index, size)
	if err != nil {
		t.Fatalf("inclusion %d in %d: %v", index, size, err)
	}
	if err := VerifyInclusion(events[index], index, size, root, proof); err != nil {
		t.Fatalf("inclusion %d in %d: %v", index, size, err)
	}
	if err := tlog.CheckRecord(proof, size, root, index, LeafHash(events[index])); err != nil {
		t.Fatalf("CheckRecord %d in %d: %v", index, size, err)
	}
	old, err := l.RootAt(oldSize)
	if err != nil {
		t.Fatal(err)
	}
	cp, err := l.ProveConsistency(oldSize, size)
	if err != nil {
		t.Fatalf("consistency %d to %d: %v", oldSize, size, err)
	}
	if oldSize == 0 || oldSize == size {
		if len(cp) != 0 || (oldSize == size && old != root) {
			t.Fatalf("consistency %d to %d: proof %d hashes", oldSize, size, len(cp))
		}
		return
	}
	if err := tlog.CheckTree(cp, size, root, oldSize, old); err != nil {
		t.Fatalf("CheckTree %d to %d: %v", oldSize, size, err)
	}
}

func TestTU07ProofsFromTheLogVerify(t *testing.T) {
	withoutSync(t)
	state, _ := newLogState(t)
	l := openTestLog(t, state)
	events := appendTo(t, l, 0, 600)
	for _, size := range []int64{1, 2, 3, 7, 8, 255, 256, 257, 511, 512, 513, 600} {
		for _, index := range []int64{0, size / 2, size - 1} {
			for _, oldSize := range []int64{0, 1, size / 2, size - 1, size} {
				checkProofs(t, l, events, index, oldSize, size)
			}
		}
	}
	// A tree that grows: a proof is still valid after more appends.
	oldRoot, _ := l.RootAt(300)
	appendTo(t, l, 600, 700)
	if root, err := l.RootAt(300); err != nil || root != oldRoot {
		t.Fatalf("root at 300 changed: %x, error %v", root, err)
	}
}

func TestTU07ProofInputsAreErrorsNotPanics(t *testing.T) {
	withoutSync(t)
	state, _ := newLogState(t)
	l := openTestLog(t, state)
	if root, err := l.RootAt(0); err != nil || root != emptyRoot {
		t.Fatalf("empty log root %x, error %v", root, err)
	}
	if p, err := l.ProveConsistency(0, 0); err != nil || len(p) != 0 {
		t.Fatalf("empty log consistency: %v, %v", p, err)
	}
	appendTo(t, l, 0, 10)
	bad := func(what string, err error) {
		t.Helper()
		var e *Error
		if !errors.As(err, &e) || e.Rule != ruleProofInput {
			t.Errorf("%s: error %v", what, err)
		}
	}
	for _, c := range [][2]int64{{0, 0}, {-1, 5}, {5, 5}, {6, 5}, {0, 11}, {10, 10}, {0, -1}, {1<<63 - 1, 1<<63 - 1}} {
		p, err := l.ProveInclusion(c[0], c[1])
		bad("inclusion", err)
		if p != nil {
			t.Errorf("inclusion %v: proof %v", c, p)
		}
	}
	for _, c := range [][2]int64{{6, 5}, {-1, 5}, {0, -1}, {5, 11}, {11, 11}, {1<<63 - 1, 1<<63 - 1}} {
		p, err := l.ProveConsistency(c[0], c[1])
		bad("consistency", err)
		if p != nil {
			t.Errorf("consistency %v: proof %v", c, p)
		}
	}
	for _, size := range []int64{-1, 11, 1<<63 - 1} {
		_, err := l.RootAt(size)
		bad("root", err)
	}
	// Equal sizes and size 0 are an empty proof, not an error.
	for _, c := range [][2]int64{{0, 10}, {10, 10}, {1, 1}} {
		if p, err := l.ProveConsistency(c[0], c[1]); err != nil || len(p) != 0 {
			t.Errorf("consistency %v: %v, %v", c, p, err)
		}
	}
}

func TestTS13ChangedTileByteGivesAnErrorNotAProof(t *testing.T) {
	withoutSync(t)
	// At 300 leaves, level 0 has a full tile and a partial tile, and level 1
	// has one hash. Each call reads the tile that the test changes. The result
	// is the number of hashes that the call gives.
	for _, c := range []struct {
		name string
		call func(l *Log) (int, error)
	}{
		{"tile/8/0/000", func(l *Log) (int, error) { p, err := l.ProveInclusion(5, 300); return len(p), err }},
		{"tile/8/0/000", func(l *Log) (int, error) { p, err := l.ProveConsistency(100, 300); return len(p), err }},
		{"tile/8/0/001.p/44", func(l *Log) (int, error) { p, err := l.ProveInclusion(290, 300); return len(p), err }},
		{"tile/8/1/000.p/1", func(l *Log) (int, error) {
			r, err := l.RootAt(300)
			if r != (tlog.Hash{}) {
				return 1, err
			}
			return 0, err
		}},
	} {
		for _, at := range []int{0, 17, -1} {
			t.Run(fmt.Sprintf("%s byte %d", c.name, at), func(t *testing.T) {
				state, dir := newLogState(t)
				l := openTestLog(t, state)
				appendTo(t, l, 0, 300)
				file := filepath.Join(dir, "tlog", filepath.FromSlash(c.name))
				b, err := os.ReadFile(file)
				if err != nil {
					t.Fatal(err)
				}
				b[(at+len(b))%len(b)] ^= 1
				if err := os.WriteFile(file, b, 0o600); err != nil {
					t.Fatal(err)
				}
				n, err := c.call(l)
				var e *Error
				if !errors.As(err, &e) || e.Rule != ruleProofRead || !strings.Contains(e.Name, "tile/8/") {
					t.Fatalf("error %v", err)
				}
				if n != 0 {
					t.Fatalf("%d hashes with an error", n)
				}
				if strings.Contains(e.Error(), hex.EncodeToString(b[:4])) {
					t.Fatalf("error text has hash bytes: %v", e)
				}
			})
		}
	}
}

func TestTU07AppendAndProofsRunTogether(t *testing.T) {
	withoutSync(t)
	state, _ := newLogState(t)
	l := openTestLog(t, state)
	const total = 300
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < total; i++ {
			if _, err := l.Append(testEvent(i)); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var lastSize int64
			var lastRoot tlog.Hash
			for lastSize < total {
				size, root := l.Head()
				if size == 0 {
					continue
				}
				if got, err := l.RootAt(size); err != nil || got != root {
					t.Errorf("root at %d: %x, error %v", size, got, err)
					return
				}
				p, err := l.ProveInclusion(size-1, size)
				if err != nil || VerifyInclusion(testEvent(int(size-1)), size-1, size, root, p) != nil {
					t.Errorf("inclusion at %d: %v", size, err)
					return
				}
				if lastSize > 0 {
					cp, err := l.ProveConsistency(lastSize, size)
					if err != nil || tlog.CheckTree(cp, size, root, lastSize, lastRoot) != nil {
						t.Errorf("consistency %d to %d: %v", lastSize, size, err)
						return
					}
				}
				lastSize, lastRoot = size, root
			}
		}()
	}
	wg.Wait()
}
