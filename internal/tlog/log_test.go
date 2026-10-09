package tlog

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"sync"
	"testing"

	"golang.org/x/mod/sumdb/tlog"
)

func testEvent(i int) EventHash { return sha256.Sum256(fmt.Appendf(nil, "event %d", i)) }

// rfcRoot is the tree hash of RFC 6962 section 2.1, from crypto/sha256 only.
// The leaves are the leaf hashes.
func rfcRoot(leaves [][32]byte) [32]byte {
	switch len(leaves) {
	case 0:
		return sha256.Sum256(nil)
	case 1:
		return leaves[0]
	}
	k := 1
	for k*2 < len(leaves) {
		k *= 2
	}
	l, r := rfcRoot(leaves[:k]), rfcRoot(leaves[k:])
	return sha256.Sum256(append(append([]byte{1}, l[:]...), r[:]...))
}

// rfcLeaves returns the leaf hashes SHA-256(0x00 || event hash).
func rfcLeaves(events []EventHash) [][32]byte {
	out := make([][32]byte, len(events))
	for i, e := range events {
		out[i] = sha256.Sum256(append([]byte{0}, e[:]...))
	}
	return out
}

func openTestLog(t *testing.T, state *os.Root) *Log {
	t.Helper()
	l, err := OpenLog(state, "tlog")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l
}

// appendTo appends events number from..to-1 and returns them.
func appendTo(t *testing.T, l *Log, from, to int) []EventHash {
	t.Helper()
	var out []EventHash
	for i := from; i < to; i++ {
		idx, err := l.Append(testEvent(i))
		if err != nil || idx != int64(i) {
			t.Fatalf("append %d: index %d, error %v", i, idx, err)
		}
		out = append(out, testEvent(i))
	}
	return out
}

func TestTS13OneLeafRootIsHashOfZeroAndEventHash(t *testing.T) {
	state, _ := newLogState(t)
	l := openTestLog(t, state)
	h := testEvent(0)
	appendTo(t, l, 0, 1)
	want := sha256.Sum256(append([]byte{0}, h[:]...))
	if got := l.Root(); got != want || l.Size() != 1 {
		t.Fatalf("size %d, root %x, want %x", l.Size(), got, want)
	}
	if l.Root() == tlog.Hash(h) {
		t.Fatal("the root is the event hash")
	}
	// The store holds the leaf hash, never the event hash.
	b, err := l.store.readTile(tlog.Tile{H: TileHeight, N: 0, W: 1})
	if err != nil || !bytes.Equal(b, want[:]) || bytes.Equal(b, h[:]) {
		t.Fatalf("level 0 tile %x, error %v", b, err)
	}
	if LeafHash(h) != tlog.Hash(want) {
		t.Fatal("LeafHash does not follow the rule")
	}
}

func TestTS13ThreeLeafVector(t *testing.T) {
	raw, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		ThreeLeaves struct {
			Events []string `json:"events"`
			Root   string   `json:"root"`
		} `json:"three_leaves"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	state, _ := newLogState(t)
	l := openTestLog(t, state)
	var events []EventHash
	for _, s := range v.ThreeLeaves.Events {
		var h EventHash
		if b, err := hex.DecodeString(s); err != nil || copy(h[:], b) != 32 || len(b) != 32 {
			t.Fatalf("bad event %q", s)
		}
		events = append(events, h)
		if _, err := l.Append(h); err != nil {
			t.Fatal(err)
		}
	}
	want := rfcRoot(rfcLeaves(events))
	if len(events) != 3 || hex.EncodeToString(want[:]) != v.ThreeLeaves.Root {
		t.Fatalf("RFC 6962 root %x differs from the vector %s", want, v.ThreeLeaves.Root)
	}
	if l.Root() != tlog.Hash(want) {
		t.Fatalf("log root %x, want %x", l.Root(), want)
	}
	// A tree with the event hashes as leaf hashes has another root.
	var plain [][32]byte
	for _, e := range events {
		plain = append(plain, e)
	}
	if bad := rfcRoot(plain); l.Root() == tlog.Hash(bad) {
		t.Fatal("the root is the root of a tree with event hashes as leaf hashes")
	}
}

func TestTS13InclusionCheck(t *testing.T) {
	state, _ := newLogState(t)
	l := openTestLog(t, state)
	events := appendTo(t, l, 0, 10)
	size, root := l.Head()
	tree := tlog.Tree{N: size, Hash: root}
	for i, e := range events {
		proof, err := tlog.ProveRecord(size, int64(i), tlog.TileHashReader(tree, &tileReader{s: l.store}))
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyInclusion(e, int64(i), size, root, proof); err != nil {
			t.Fatalf("leaf %d: %v", i, err)
		}
		other := e
		other[0] ^= 1
		badRoot := root
		badRoot[0] ^= 1
		for name, err := range map[string]error{
			"changed event hash": VerifyInclusion(other, int64(i), size, root, proof),
			"changed index":      VerifyInclusion(e, int64(i+1), size, root, proof),
			"changed root":       VerifyInclusion(e, int64(i), size, badRoot, proof),
			"event as leaf hash": tlog.CheckRecord(proof, size, root, int64(i), tlog.Hash(e)),
		} {
			if err == nil {
				t.Fatalf("leaf %d: %s was accepted", i, name)
			}
		}
	}
	proof, _ := tlog.ProveRecord(size, 0, tlog.TileHashReader(tree, &tileReader{s: l.store}))
	for _, c := range []struct{ index, size int64 }{
		{-1, size}, {0, 0}, {0, -1}, {size, size}, {0, math.MaxInt64}, {math.MaxInt64, math.MaxInt64},
	} {
		if err := VerifyInclusion(events[0], c.index, c.size, root, proof); err == nil {
			t.Fatalf("index %d, size %d: accepted", c.index, c.size)
		}
	}
	if err := VerifyInclusion(events[0], 0, size, root, nil); err == nil {
		t.Fatal("empty proof accepted")
	}
}

func TestTU07CacheHoldsOneTileForEachLevel(t *testing.T) {
	// The test does not need fsync. It checks the cache and the root.
	oldFile, oldDir := syncFile, syncDirFile
	syncFile, syncDirFile = func(*os.File) error { return nil }, func(*os.File) error { return nil }
	t.Cleanup(func() { syncFile, syncDirFile = oldFile, oldDir })
	state, _ := newLogState(t)
	l := openTestLog(t, state)
	var events []EventHash
	for _, n := range []int{1, 255, 256, 257, 600} {
		events = append(events, appendTo(t, l, len(events), n)...)
		want := rfcRoot(rfcLeaves(events))
		if size, root := l.Head(); size != int64(n) || root != tlog.Hash(want) {
			t.Fatalf("size %d, root %x, want %d, %x", size, root, n, want)
		}
		checkCache(t, l)
	}
	if len(l.tiles[1].data) == 0 || len(l.tiles[0].data) == 0 {
		t.Fatal("expected tiles at level 0 and level 1")
	}

	// A log of 65 000 leaves is built in bulk. Open loads its right edge. The
	// appends then fill the second tile of level 1 and make the first tile of
	// level 2 (size 65 536), and go to 65 537. The reference is x/mod.
	state, _ = newLogState(t)
	s := openStore(t, state)
	var ref testLog
	ref.commit(t, s, 0, 65000)
	s.Close()
	l = openTestLog(t, state)
	checkCache(t, l)
	for i := 65000; i < 65537; i++ {
		e := testEvent(i)
		hs, err := tlog.StoredHashes(ref.n, e[:], &ref)
		if err != nil {
			t.Fatal(err)
		}
		ref.hashes, ref.n = append(ref.hashes, hs...), ref.n+1
		if idx, err := l.Append(testEvent(i)); err != nil || idx != int64(i) {
			t.Fatalf("append %d: %d, %v", i, idx, err)
		}
		if i == 65535 || i == 65536 {
			if size, root := l.Head(); size != int64(i+1) || root != ref.root(t, size) {
				t.Fatalf("size %d, root %x", size, root)
			}
			checkCache(t, l)
		}
	}
}

// checkCache checks that the log keeps at most the rightmost tile of each level.
func checkCache(t *testing.T, l *Log) {
	t.Helper()
	for lv, b := range l.tiles {
		if len(b.data) > fullWidth*tlog.HashSize {
			t.Fatalf("size %d: level %d holds %d bytes", l.size, lv, len(b.data))
		}
		if c := l.size >> (TileHeight * lv); len(b.data) > 0 && b.n != (c-1)/fullWidth {
			t.Fatalf("size %d: level %d holds tile %d", l.size, lv, b.n)
		}
	}
}

func TestTU07ReopenContinuesFromTheSameHead(t *testing.T) {
	state, _ := newLogState(t)
	l := openTestLog(t, state)
	if size, root := l.Head(); size != 0 || root != emptyRoot {
		t.Fatalf("new log: size %d, root %x", size, root)
	}
	var events []EventHash
	for _, n := range []int{5, 256, 300, 513} {
		events = append(events, appendTo(t, l, len(events), n)...)
		size, root := l.Head()
		l.Close()
		l = openTestLog(t, state)
		if s2, r2 := l.Head(); s2 != size || r2 != root {
			t.Fatalf("reopen at %d: size %d, root %x", n, s2, r2)
		}
	}
	events = append(events, appendTo(t, l, len(events), len(events)+1)...)
	if want := rfcRoot(rfcLeaves(events)); l.Root() != tlog.Hash(want) {
		t.Fatalf("root after reopen and append %x, want %x", l.Root(), want)
	}
}

func TestTU07FailedWriteKeepsTheOldHead(t *testing.T) {
	state, _ := newLogState(t)
	l := openTestLog(t, state)
	events := appendTo(t, l, 0, 255)
	size, root := l.Head()
	old := renameFile
	t.Cleanup(func() { renameFile = old })
	for _, fail := range []string{"tile", headName} { // a tile write, then the head write
		renameFile = func(r *os.Root, from, to string) error {
			if (fail == headName) == (to == headName) {
				return errors.New("injected")
			}
			return old(r, from, to)
		}
		// The append to size 256 changes the tiles of level 0 and level 1.
		if _, err := l.Append(testEvent(255)); err == nil {
			t.Fatalf("%s failure: Append returned nil", fail)
		}
		if s2, r2 := l.Head(); s2 != size || r2 != root {
			t.Fatalf("%s failure: head changed to %d, %x", fail, s2, r2)
		}
	}
	renameFile = old
	appendTo(t, l, 255, 256)
	events = append(events, testEvent(255))
	if want := rfcRoot(rfcLeaves(events)); l.Root() != tlog.Hash(want) || l.Size() != 256 {
		t.Fatalf("after retry: size %d, root %x, want %x", l.Size(), l.Root(), want)
	}
}

func TestTU07AppendAndReadRunTogether(t *testing.T) {
	state, _ := newLogState(t)
	l := openTestLog(t, state)
	var (
		wg, readers sync.WaitGroup
		mu          sync.Mutex
		seen        = map[int64]tlog.Hash{}
		done        = make(chan struct{})
	)
	for r := 0; r < 4; r++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				size, root := l.Head()
				mu.Lock()
				seen[size] = root
				mu.Unlock()
				select {
				case <-done:
					return
				default:
				}
			}
		}()
	}
	for a := 0; a < 4; a++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 70; i++ {
				if _, err := l.Append(testEvent(a*1000 + i)); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	wg.Wait()
	close(done)
	readers.Wait()
	size, root := l.Head()
	if size != 280 {
		t.Fatalf("size %d, want 280", size)
	}
	// A stored hash never changes, so the final log gives the root of each older size.
	tr := tlog.TileHashReader(tlog.Tree{N: size, Hash: root}, &tileReader{s: l.store})
	for n, got := range seen {
		if want, err := tlog.TreeHash(n, tr); err != nil || got != want {
			t.Fatalf("a read gave size %d and root %x, which the log never had (%v)", n, got, err)
		}
	}
}

func TestTU07FullLogIsAnError(t *testing.T) {
	state, _ := newLogState(t)
	l := openTestLog(t, state)
	l.size = maxSize
	if _, err := l.Append(testEvent(0)); err == nil {
		t.Fatal("Append to a full log returned nil")
	}
}
