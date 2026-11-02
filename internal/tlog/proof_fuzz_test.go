package tlog

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/mod/sumdb/tlog"
)

const (
	fuzzMaxSize  = 10000
	fuzzMaxBatch = 600
)

// FuzzTU07Proofs checks the inclusion proof and the consistency proof for a
// random tree size from 1 to 10 000. One log serves all inputs. It grows to the
// largest size that an input needs. A proof for a smaller size is still valid
// in the larger log. The log grows with AppendBatch calls. The size of each
// call is random, from 1 to fuzzMaxBatch. The last call stops at the tree
// size. Thus a batch can cross a tile border. The seeds stop at size 2000, so
// that go test stays fast.
func FuzzTU07Proofs(f *testing.F) {
	// The fields are size, index, old size, and batch size. The size is
	// 1 + field % 10000. The batch size is 1 + field % 600. The seeds share
	// one log. They have a batch of 1 and size 257. They also have a call of
	// 300 hashes that crosses a tile border, and a call of 600 hashes.
	seeds := [][4]uint16{
		{1, 0, 0, 0}, {2, 1, 1, 0}, {3, 1, 2, 2}, {300, 255, 128, 250},
		{256, 255, 128, 0}, {999, 500, 700, 299}, {1999, 1500, 1200, 599},
	}
	for _, s := range seeds {
		f.Add(s[0], s[1], s[2], s[3])
	}
	withoutSync(f)
	dir := filepath.Join(f.TempDir(), "state")
	if err := os.Mkdir(dir, 0o700); err != nil {
		f.Fatal(err)
	}
	state, err := os.OpenRoot(dir)
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(func() { state.Close() })
	l, err := OpenLog(state, "tlog")
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(func() { l.Close() })
	f.Fuzz(func(t *testing.T, sizeIn, indexIn, oldIn, batchIn uint16) {
		size := 1 + int64(sizeIn)%fuzzMaxSize
		index, old := int64(indexIn)%size, int64(oldIn)%(size+1)
		batch := 1 + int64(batchIn)%fuzzMaxBatch
		for n, _ := l.Head(); n < size; {
			end := min(n+batch, size)
			if first, err := l.AppendBatch(batchOf(int(n), int(end))); err != nil || first != n {
				t.Fatalf("batch %d to %d: index %d, error %v", n, end, first, err)
			}
			n = end
		}
		root, err := l.RootAt(size)
		if err != nil {
			t.Fatal(err)
		}
		proof, err := l.ProveInclusion(index, size)
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyInclusion(testEvent(int(index)), index, size, root, proof); err != nil {
			t.Fatalf("inclusion %d in %d: %v", index, size, err)
		}
		oldRoot, err := l.RootAt(old)
		if err != nil {
			t.Fatal(err)
		}
		cp, err := l.ProveConsistency(old, size)
		if err != nil {
			t.Fatal(err)
		}
		switch {
		case old == 0 || old == size:
			if len(cp) != 0 || (old == size && oldRoot != root) {
				t.Fatalf("consistency %d to %d: proof of %d hashes", old, size, len(cp))
			}
		default:
			if err := tlog.CheckTree(cp, size, root, old, oldRoot); err != nil {
				t.Fatalf("consistency %d to %d: %v", old, size, err)
			}
		}
	})
}
