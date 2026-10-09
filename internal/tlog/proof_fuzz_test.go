package tlog

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/mod/sumdb/tlog"
)

const fuzzMaxSize = 10000

// FuzzTU07Proofs checks the inclusion proof and the consistency proof for a
// random tree size from 1 to 10 000. One log serves all inputs. It grows to the
// largest size that an input needs, and a proof for a smaller size is still
// valid in the larger log. The seeds are small, so that go test stays fast.
func FuzzTU07Proofs(f *testing.F) {
	for _, s := range [][3]uint16{{1, 0, 0}, {2, 1, 1}, {3, 1, 2}, {256, 255, 128}, {257, 256, 256}, {513, 7, 300}} {
		f.Add(s[0], s[1], s[2])
	}
	oldFile, oldDir := syncFile, syncDirFile
	syncFile, syncDirFile = func(*os.File) error { return nil }, func(*os.File) error { return nil }
	f.Cleanup(func() { syncFile, syncDirFile = oldFile, oldDir })
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
	f.Fuzz(func(t *testing.T, sizeIn, indexIn, oldIn uint16) {
		size := 1 + int64(sizeIn)%fuzzMaxSize
		index, old := int64(indexIn)%size, int64(oldIn)%(size+1)
		for n, _ := l.Head(); n < size; n++ {
			if _, err := l.Append(testEvent(int(n))); err != nil {
				t.Fatal(err)
			}
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
