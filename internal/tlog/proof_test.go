package tlog

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
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
// leaves. It also checks the consistency proof from oldSize to size. It uses
// the checks of the verifier and a root that crypto/sha256 gives.
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
	// The root of a size does not change when the log grows.
	oldRoot, _ := l.RootAt(300)
	appendTo(t, l, 600, 700)
	if root, err := l.RootAt(300); err != nil || root != oldRoot {
		t.Fatalf("root at 300 changed: %x, error %v", root, err)
	}
}

func TestTU07ProofForASizeIsTheSameAfterMoreAppends(t *testing.T) {
	withoutSync(t)
	state, _ := newLogState(t)
	l := openTestLog(t, state)
	appendTo(t, l, 0, 300)
	inclusion, err := l.ProveInclusion(150, 300)
	if err != nil {
		t.Fatal(err)
	}
	consistency, err := l.ProveConsistency(100, 300)
	if err != nil {
		t.Fatal(err)
	}
	appendTo(t, l, 300, 700)
	again, err := l.ProveInclusion(150, 300)
	if err != nil || !slices.Equal(inclusion, again) {
		t.Fatalf("inclusion changed after more appends: %v, error %v", again, err)
	}
	againTree, err := l.ProveConsistency(100, 300)
	if err != nil || !slices.Equal(consistency, againTree) {
		t.Fatalf("consistency changed after more appends: %v, error %v", againTree, err)
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

// A tile call is one proof call or root call that reads a tile. It gives the
// number of hashes in its result: 0 for a nil proof or a zero root.
type tileCall func(l *Log) (int, error)

func inclusionCall(index, size int64) tileCall {
	return func(l *Log) (int, error) { p, err := l.ProveInclusion(index, size); return len(p), err }
}

func consistencyCall(oldSize, newSize int64) tileCall {
	return func(l *Log) (int, error) { p, err := l.ProveConsistency(oldSize, newSize); return len(p), err }
}

func rootCall(size int64) tileCall {
	return func(l *Log) (int, error) {
		r, err := l.RootAt(size)
		if r != (tlog.Hash{}) {
			return 1, err
		}
		return 0, err
	}
}

// tileCases lists the calls of the T-S-13 tests. The tile is a file that the
// call reads. At 300 leaves, level 0 has a full tile and a partial tile, and
// level 1 has one hash. At 600 leaves, OpenLog does not read the full tiles
// 0/000 and 0/001, and only a proof call reads them.
var tileCases = []struct {
	call   string
	tile   string
	leaves int
	run    tileCall
}{
	{"inclusion", "tile/8/0/000", 300, inclusionCall(5, 300)},
	{"consistency", "tile/8/0/000", 300, consistencyCall(100, 300)},
	{"inclusion", "tile/8/0/001.p/44", 300, inclusionCall(290, 300)},
	{"root", "tile/8/1/000.p/1", 300, rootCall(300)},
	{"inclusion", "tile/8/0/000", 600, inclusionCall(5, 600)},
	{"inclusion", "tile/8/0/001", 600, inclusionCall(300, 600)},
}

// tileSubtest gives a name that has the call, the tile, and the size of the
// log. The name has no "/", so that -run can select it.
func tileSubtest(call, tile string, leaves int, what string) string {
	return fmt.Sprintf("%s %s at %d leaves %s", call, strings.ReplaceAll(tile, "/", "-"), leaves, what)
}

// tileLog gives a log of the leaves and the file of the tile.
func tileLog(t *testing.T, leaves int, tile string) (*Log, string) {
	t.Helper()
	state, dir := newLogState(t)
	l := openTestLog(t, state)
	appendTo(t, l, 0, leaves)
	return l, filepath.Join(dir, "tlog", filepath.FromSlash(tile))
}

var tileNames = regexp.MustCompile(`^[a-z0-9/.,]+$`)

// wantTileError checks the result of a call that read a bad tile. The result
// is an *Error with the rule, and no hashes. The text is the fixed form, and
// the name has tile paths only, so that no hash bytes are in it.
func wantTileError(t *testing.T, n int, err error, rule string) *Error {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) || e.Rule != rule {
		t.Fatalf("error %v, want the rule %q", err, rule)
	}
	if n != 0 {
		t.Fatalf("%d hashes with an error", n)
	}
	if e.Error() != "tlog: "+e.Name+": "+rule || !tileNames.MatchString(e.Name) {
		t.Fatalf("error text %q is not the fixed form", e.Error())
	}
	return e
}

func TestTS13ChangedTileByteGivesAnErrorNotAProof(t *testing.T) {
	withoutSync(t)
	for _, c := range tileCases {
		for _, pos := range []struct {
			name string
			at   func(n int) int
		}{
			{"first", func(int) int { return 0 }},
			{"middle", func(n int) int { return n / 2 }},
			{"last", func(n int) int { return n - 1 }},
		} {
			t.Run(tileSubtest(c.call, c.tile, c.leaves, pos.name+" byte"), func(t *testing.T) {
				l, file := tileLog(t, c.leaves, c.tile)
				b, err := os.ReadFile(file)
				if err != nil {
					t.Fatal(err)
				}
				b[pos.at(len(b))] ^= 1
				if err := os.WriteFile(file, b, 0o600); err != nil {
					t.Fatal(err)
				}
				n, err := c.run(l)
				e := wantTileError(t, n, err, ruleProofRead)
				if !strings.Contains(e.Name, c.tile) {
					t.Fatalf("name %q does not have the tile %s", e.Name, c.tile)
				}
			})
		}
	}
}

func TestTS13MissingOrShortTileGivesAnErrorNotAProof(t *testing.T) {
	withoutSync(t)
	for _, c := range tileCases {
		for _, d := range []struct {
			name, rule string
			damage     func(file string, b []byte) error
		}{
			{"missing", ruleMissing, func(file string, _ []byte) error { return os.Remove(file) }},
			{"short", ruleLength, func(file string, b []byte) error { return os.WriteFile(file, b[:len(b)-1], 0o600) }},
		} {
			t.Run(tileSubtest(c.call, c.tile, c.leaves, d.name+" tile"), func(t *testing.T) {
				l, file := tileLog(t, c.leaves, c.tile)
				b, err := os.ReadFile(file)
				if err != nil {
					t.Fatal(err)
				}
				if err := d.damage(file, b); err != nil {
					t.Fatal(err)
				}
				n, err := c.run(l)
				if e := wantTileError(t, n, err, d.rule); e.Name != c.tile {
					t.Fatalf("name %q, want %q", e.Name, c.tile)
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
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(done)
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
				select {
				case <-done: // The appender ended: no new size comes.
					return
				default:
				}
				size, root := l.Head()
				if size == 0 {
					runtime.Gosched()
					continue
				}
				if got, err := l.RootAt(size); err != nil || got != root {
					t.Errorf("root at %d: %x, error %v", size, got, err)
					return
				}
				p, err := l.ProveInclusion(size-1, size)
				if err == nil {
					err = VerifyInclusion(testEvent(int(size-1)), size-1, size, root, p)
				}
				if err != nil {
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
