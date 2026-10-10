package tlog

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"golang.org/x/mod/sumdb/tlog"
)

func testEvent(i int) EventHash { return sha256.Sum256(fmt.Appendf(nil, "event %d", i)) }

// sizeOf and rootOf each read one value of the head. The log has no Size and
// no Root.
func sizeOf(l *Log) int64 {
	n, _ := l.Head()
	return n
}

func rootOf(l *Log) tlog.Hash {
	_, r := l.Head()
	return r
}

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

// appendTo appends the events from `from` to `to-1` and returns them.
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
	if size, got := l.Head(); got != want || size != 1 {
		t.Fatalf("size %d, root %x, want %x", size, got, want)
	}
	if rootOf(l) == tlog.Hash(h) {
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
	if rootOf(l) != tlog.Hash(want) {
		t.Fatalf("log root %x, want %x", rootOf(l), want)
	}
	// A tree with the event hashes as leaf hashes has another root.
	var plain [][32]byte
	for _, e := range events {
		plain = append(plain, e)
	}
	if bad := rfcRoot(plain); rootOf(l) == tlog.Hash(bad) {
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

	// The test builds a log of 65 000 leaves in bulk. OpenLog loads the right
	// edge of that log. The test then appends up to size 65 793. Level L has
	// size>>(8*L) hashes. The appends make these tiles:
	// - Level 0, tiles 253 to 257. Tile 257 is new at size 65 793.
	// - Level 1, tile 0. It gets its 256th hash at size 65 536 and is full.
	// - Level 2, tile 0. It gets its first hash at size 65 536.
	// - Level 1, tile 1. It gets its first hash at size 65 792, after a full tile.
	// The reference is x/mod.
	state, _ = newLogState(t)
	s := openStore(t, state)
	var ref testLog
	ref.commit(t, s, 0, 65000)
	s.Close()
	l = openTestLog(t, state)
	checkCache(t, l)
	for i := 65000; i < 65793; i++ {
		e := testEvent(i)
		hs, err := tlog.StoredHashes(ref.n, e[:], &ref)
		if err != nil {
			t.Fatal(err)
		}
		ref.hashes, ref.n = append(ref.hashes, hs...), ref.n+1
		if idx, err := l.Append(testEvent(i)); err != nil || idx != int64(i) {
			t.Fatalf("append %d: %d, %v", i, idx, err)
		}
		if i == 65535 || i == 65536 || i == 65791 || i == 65792 {
			if size, root := l.Head(); size != int64(i+1) || root != ref.root(t, size) {
				t.Fatalf("size %d, root %x", size, root)
			}
			checkCache(t, l)
		}
	}
	if len(l.tiles[1].data) != tlog.HashSize || l.tiles[1].n != 1 {
		t.Fatalf("level 1 holds tile %d with %d bytes, want tile 1 with one hash", l.tiles[1].n, len(l.tiles[1].data))
	}
}

// checkCache checks that the log keeps at most the rightmost tile of each
// level, and that the width of each tile matches the size.
func checkCache(t *testing.T, l *Log) {
	t.Helper()
	for lv, b := range l.tiles {
		if len(b.data) > fullWidth*tlog.HashSize {
			t.Fatalf("size %d: level %d holds %d bytes", l.size, lv, len(b.data))
		}
		c := l.size >> (TileHeight * lv) // the number of hashes at this level
		switch {
		case len(b.data) == 0:
		case c == 0:
			t.Fatalf("size %d: level %d has no hashes but holds %d bytes", l.size, lv, len(b.data))
		case b.n != (c-1)/fullWidth:
			t.Fatalf("size %d: level %d holds tile %d", l.size, lv, b.n)
		case int64(len(b.data)/tlog.HashSize) != c-b.n*fullWidth:
			t.Fatalf("size %d: level %d holds %d bytes in tile %d", l.size, lv, len(b.data), b.n)
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
	if want := rfcRoot(rfcLeaves(events)); rootOf(l) != tlog.Hash(want) {
		t.Fatalf("root after reopen and append %x, want %x", rootOf(l), want)
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
		_, first := l.Append(testEvent(255))
		if first == nil {
			t.Fatalf("%s failure: Append returned nil", fail)
		}
		if s2, r2 := l.Head(); s2 != size || r2 != root {
			t.Fatalf("%s failure: head changed to %d, %x", fail, s2, r2)
		}
		// The log refuses each later Append with the same error, also when the writes work.
		renameFile = old
		if _, err := l.Append(testEvent(255)); !errors.Is(err, first) {
			t.Fatalf("%s failure: next Append gave %v, want %v", fail, err, first)
		}
		if s2, r2 := l.Head(); s2 != size || r2 != root {
			t.Fatalf("%s failure: head changed to %d, %x", fail, s2, r2)
		}
		// A reopen loads the state on disk, and the append works again.
		l.Close()
		l = openTestLog(t, state)
		if s2, r2 := l.Head(); s2 != size || r2 != root {
			t.Fatalf("%s failure: reopen gave %d, %x", fail, s2, r2)
		}
	}
	appendTo(t, l, 255, 256)
	events = append(events, testEvent(255))
	if want := rfcRoot(rfcLeaves(events)); rootOf(l) != tlog.Hash(want) || sizeOf(l) != 256 {
		t.Fatalf("after reopen: size %d, root %x, want %x", sizeOf(l), rootOf(l), want)
	}
}

// failDirSyncAfterRename makes the next fsync of a directory fail after the
// rename of the file name has worked. The returned function stops the fault.
// The test restores the real calls when it ends.
func failDirSyncAfterRename(t *testing.T, name string) (stop func()) {
	t.Helper()
	oldRename, oldDir := renameFile, syncDirFile
	stop = func() { renameFile, syncDirFile = oldRename, oldDir }
	t.Cleanup(stop)
	armed := false
	renameFile = func(r *os.Root, from, to string) error {
		err := oldRename(r, from, to)
		if err == nil && to == name {
			armed = true
		}
		return err
	}
	syncDirFile = func(f *os.File) error {
		if armed {
			armed = false
			return errors.New("injected")
		}
		return oldDir(f)
	}
	return stop
}

// diskHead reads the tree head file of the log below dir.
func diskHead(t *testing.T, dir string) (int64, tlog.Hash) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "tlog", headName))
	if err != nil || len(b) != headSize {
		t.Fatalf("read the head: %d bytes, %v", len(b), err)
	}
	var h tlog.Hash
	copy(h[:], b[sizeLen:])
	return int64(binary.BigEndian.Uint64(b)), h
}

// The rename of the head works and the fsync of the directory fails. Then the
// head on disk covers a leaf for which Append returned an error. The log must
// not write a second root for that size.
func TestTU07HeadRenameThenDirectorySyncFailureStopsAppends(t *testing.T) {
	state, dir := newLogState(t)
	l := openTestLog(t, state)
	events := appendTo(t, l, 0, 10)
	size, root := l.Head()
	stop := failDirSyncAfterRename(t, headName)
	a, b := testEvent(1000), testEvent(2000)
	_, first := l.Append(a)
	stop()
	if first == nil {
		t.Fatal("Append returned nil after the failed fsync")
	}
	if s2, r2 := l.Head(); s2 != size || r2 != root {
		t.Fatalf("head in memory changed to %d, %x", s2, r2)
	}
	rootA := tlog.Hash(rfcRoot(rfcLeaves(append(slices.Clone(events), a))))
	if s2, r2 := diskHead(t, dir); s2 != size+1 || r2 != rootA {
		t.Fatalf("head on disk is %d, %x, want %d, %x", s2, r2, size+1, rootA)
	}
	if _, err := l.Append(b); !errors.Is(err, first) {
		t.Fatalf("next Append gave %v, want %v", err, first)
	}
	if s2, r2 := diskHead(t, dir); s2 != size+1 || r2 != rootA {
		t.Fatalf("head on disk changed to %d, %x", s2, r2)
	}
	l.Close()
	l = openTestLog(t, state)
	if s2, r2 := l.Head(); s2 != size+1 || r2 != rootA {
		t.Fatalf("reopen gave %d, %x, want %d, %x", s2, r2, size+1, rootA)
	}
	tile, err := l.store.readTile(tlog.Tile{H: TileHeight, N: 0, W: int(size) + 1})
	leaf := LeafHash(a)
	if err != nil || !bytes.Equal(tile[size*tlog.HashSize:], leaf[:]) {
		t.Fatalf("the leaf of the failed Append is not on disk (%v)", err)
	}
}

// The rename of a tile works and the fsync of its directory fails. The log
// reopens, and the same Append finds the tile on disk and writes nothing. The
// store must still sync the tile directory before it writes the head.
func TestTU07TileDirectorySyncFailureThenReopenSyncsTheTileBeforeTheHead(t *testing.T) {
	state, dir := newLogState(t)
	l := openTestLog(t, state)
	appendTo(t, l, 0, 256)
	stop := failDirSyncAfterRename(t, "tile/8/0/001.p/1")
	if _, err := l.Append(testEvent(256)); err == nil {
		t.Fatal("Append returned nil after the failed fsync")
	}
	stop()
	l.Close()

	oldRename, oldDir := renameFile, syncDirFile
	t.Cleanup(func() { renameFile, syncDirFile = oldRename, oldDir })

	// If the fsync of the tile directory fails again, Append returns an error
	// and does not write the head.
	l = openTestLog(t, state)
	syncDirFile = func(*os.File) error { return errors.New("injected") }
	if _, err := l.Append(testEvent(256)); err == nil {
		t.Fatal("Append returned nil after the failed fsync of the retry")
	}
	syncDirFile = oldDir
	if size, _ := diskHead(t, dir); size != 256 {
		t.Fatalf("head on disk has size %d, want 256", size)
	}
	l.Close()

	// If the fsync works, it comes before the write of the head.
	l = openTestLog(t, state)
	var steps []string
	renameFile = func(r *os.Root, from, to string) error {
		if to == headName {
			steps = append(steps, "head")
		}
		return oldRename(r, from, to)
	}
	syncDirFile = func(f *os.File) error {
		steps = append(steps, "sync "+f.Name())
		return oldDir(f)
	}
	if idx, err := l.Append(testEvent(256)); err != nil || idx != 256 {
		t.Fatalf("Append gave %d, %v", idx, err)
	}
	tileSync := slices.IndexFunc(steps, func(s string) bool { return strings.HasSuffix(s, "tile/8/0/001.p") })
	head := slices.Index(steps, "head")
	if tileSync < 0 || head < 0 || tileSync > head {
		t.Fatalf("steps %q: want the fsync of the tile directory before the head", steps)
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
				if prev, ok := seen[size]; ok && prev != root {
					t.Errorf("two roots for size %d: %x and %x", size, prev, root)
				}
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
	if len(seen) <= 2 {
		t.Fatalf("the readers saw %d sizes, want more than 2", len(seen))
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

// batchOf returns the events from `from` to `to-1`.
func batchOf(from, to int) []EventHash {
	var out []EventHash
	for i := from; i < to; i++ {
		out = append(out, testEvent(i))
	}
	return out
}

// checkProof checks the inclusion proof of leaf i of the log.
func checkProof(t *testing.T, l *Log, i int) {
	t.Helper()
	size, root := l.Head()
	tree := tlog.Tree{N: size, Hash: root}
	proof, err := tlog.ProveRecord(size, int64(i), tlog.TileHashReader(tree, &tileReader{s: l.store}))
	if err != nil {
		t.Fatalf("proof of leaf %d: %v", i, err)
	}
	if err := VerifyInclusion(testEvent(i), int64(i), size, root, proof); err != nil {
		t.Fatalf("leaf %d: %v", i, err)
	}
}

func TestTU07BatchGivesTheHeadOfSingleAppends(t *testing.T) {
	// The test does not need fsync. It checks the tiles, the head, and the reopen.
	oldFile, oldDir := syncFile, syncDirFile
	syncFile, syncDirFile = func(*os.File) error { return nil }, func(*os.File) error { return nil }
	t.Cleanup(func() { syncFile, syncDirFile = oldFile, oldDir })
	// The batch from 0 fills tile 0. The batch from 100 fills tile 0 and tile 1.
	for _, start := range []int{0, 100} {
		t.Run(fmt.Sprint("start", start), func(t *testing.T) {
			state, _ := newLogState(t)
			l := openTestLog(t, state)
			appendTo(t, l, 0, start)
			refState, _ := newLogState(t)
			ref := openTestLog(t, refState)
			appendTo(t, ref, 0, start+500)

			oldRename := renameFile
			t.Cleanup(func() { renameFile = oldRename })
			heads := 0
			renameFile = func(r *os.Root, from, to string) error {
				if to == headName {
					heads++
				}
				return oldRename(r, from, to)
			}
			first, err := l.AppendBatch(batchOf(start, start+500))
			renameFile = oldRename
			if err != nil || first != int64(start) || heads != 1 {
				t.Fatalf("AppendBatch gave %d, %v after %d head writes, want %d, nil, 1", first, err, heads, start)
			}
			size, root := ref.Head()
			if s2, r2 := l.Head(); s2 != size || r2 != root {
				t.Fatalf("batch head %d, %x, want %d, %x", s2, r2, size, root)
			}
			checkCache(t, l)

			// The reopen reads the full tile, and the proof reads a leaf inside it.
			l.Close()
			l = openTestLog(t, state)
			if s2, r2 := l.Head(); s2 != size || r2 != root {
				t.Fatalf("reopen head %d, %x, want %d, %x", s2, r2, size, root)
			}
			checkProof(t, l, 200)
			checkProof(t, l, start+499)
			if start == 100 {
				checkProof(t, l, 300)
			}
			appendTo(t, l, start+500, start+501)
			appendTo(t, ref, start+500, start+501)
			if s2, r2 := l.Head(); s2 != size+1 || r2 != rootOf(ref) {
				t.Fatalf("head after the next append %d, %x", s2, r2)
			}
		})
	}
}

func TestTU07BatchEdges(t *testing.T) {
	state, _ := newLogState(t)
	l := openTestLog(t, state)
	appendTo(t, l, 0, 3)
	size, root := l.Head()
	if first, err := l.AppendBatch(nil); err != nil || first != size {
		t.Fatalf("empty batch gave %d, %v", first, err)
	}
	if s2, r2 := l.Head(); s2 != size || r2 != root {
		t.Fatal("an empty batch changed the head")
	}
	// A batch that does not fit, or has too many tiles, is refused before any write.
	l.size = maxSize - 1
	if _, err := l.AppendBatch(batchOf(0, 2)); err == nil {
		t.Fatal("a batch above the largest size returned nil")
	}
	l.size = 0
	if _, err := l.AppendBatch(make([]EventHash, maxBatchTiles*fullWidth+1)); err == nil {
		t.Fatal("a batch with too many tiles returned nil")
	}
	if l.err != nil {
		t.Fatalf("a refused batch stopped the log: %v", l.err)
	}
}

func TestTS13BatchWriteFailureKeepsTheOldHead(t *testing.T) {
	// The batch from size 255 to size 300 writes tile 0 in full, then tile 1
	// with 44 hashes, then the tile of level 1, then the head.
	for _, c := range []struct {
		name  string
		fault func(t *testing.T)
	}{
		{"second tile", func(t *testing.T) {
			old, tiles := renameFile, 0
			renameFile = func(r *os.Root, from, to string) error {
				if to != headName {
					if tiles++; tiles == 2 {
						return errors.New("injected")
					}
				}
				return old(r, from, to)
			}
		}},
		{"tile directory sync", func(t *testing.T) { failDirSyncAfterRename(t, "tile/8/0/001.p/44") }},
		{"head", func(t *testing.T) {
			old := renameFile
			renameFile = func(r *os.Root, from, to string) error {
				if to == headName {
					return errors.New("injected")
				}
				return old(r, from, to)
			}
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			state, dir := newLogState(t)
			l := openTestLog(t, state)
			appendTo(t, l, 0, 255)
			size, root := l.Head()
			oldRename, oldDir := renameFile, syncDirFile
			t.Cleanup(func() { renameFile, syncDirFile = oldRename, oldDir })
			c.fault(t)
			_, first := l.AppendBatch(batchOf(255, 300))
			renameFile, syncDirFile = oldRename, oldDir
			if first == nil {
				t.Fatal("AppendBatch returned nil")
			}
			check := func(l *Log, what string) {
				t.Helper()
				if s2, r2 := l.Head(); s2 != size || r2 != root {
					t.Fatalf("%s: head %d, %x, want %d, %x", what, s2, r2, size, root)
				}
				if s2, r2 := diskHead(t, dir); s2 != size || r2 != root {
					t.Fatalf("%s: head on disk %d, %x", what, s2, r2)
				}
			}
			check(l, "after the failure")
			// The log refuses each later call with the same error, also when the writes work.
			if _, err := l.Append(testEvent(255)); !errors.Is(err, first) {
				t.Fatalf("next Append gave %v, want %v", err, first)
			}
			if _, err := l.AppendBatch(batchOf(255, 256)); !errors.Is(err, first) {
				t.Fatalf("next AppendBatch gave %v, want %v", err, first)
			}
			if _, err := l.AppendBatch(nil); !errors.Is(err, first) {
				t.Fatalf("next empty AppendBatch gave %v, want %v", err, first)
			}
			check(l, "after the refused calls")

			// A reopen loads the old head, and the same batch works again.
			l.Close()
			l = openTestLog(t, state)
			check(l, "after the reopen")
			if idx, err := l.AppendBatch(batchOf(255, 300)); err != nil || idx != 255 {
				t.Fatalf("batch after the reopen gave %d, %v", idx, err)
			}
			if want := rfcRoot(rfcLeaves(batchOf(0, 300))); rootOf(l) != tlog.Hash(want) || sizeOf(l) != 300 {
				t.Fatalf("after the reopen: size %d, root %x, want %x", sizeOf(l), rootOf(l), want)
			}
		})
	}
}

// syncedAs returns the name in names that the directory f is, or "". A name is
// a path below the log directory log. The name ".." is the state directory.
func syncedAs(f *os.File, log string, names []string) string {
	fi, err := f.Stat()
	if err != nil {
		return ""
	}
	for _, d := range names {
		if di, err := os.Stat(filepath.Join(log, d)); err == nil && os.SameFile(di, fi) {
			return d
		}
	}
	return ""
}

// hookDirSync calls fn for each fsync of a directory in names. If fn returns an
// error, the fsync fails. The returned function restores the real call. The
// test restores it when it ends too.
func hookDirSync(t *testing.T, log string, names []string, fn func(name string) error) (restore func()) {
	t.Helper()
	old := syncDirFile
	restore = func() { syncDirFile = old }
	t.Cleanup(restore)
	syncDirFile = func(f *os.File) error {
		if d := syncedAs(f, log, names); d != "" {
			if err := fn(d); err != nil {
				return err
			}
		}
		return old(f)
	}
	return restore
}

// failDirSync makes each fsync of the directory name fail.
func failDirSync(t *testing.T, log, name string) (restore func()) {
	t.Helper()
	return hookDirSync(t, log, []string{name}, func(string) error { return errors.New("injected") })
}

// wantOpenError checks that OpenLog gave no Log, and checks the name and the
// rule of the Error.
func wantOpenError(t *testing.T, l *Log, err error, name, rule string) {
	t.Helper()
	var e *Error
	if l != nil || !errors.As(err, &e) || e.Name != name || e.Rule != rule {
		t.Fatalf("OpenLog gave %v, %v, want no Log and the error %q: %s", l, err, name, rule)
	}
}

func TestTU07OpenLogMakesLoadedHeadDurable(t *testing.T) {
	// crashed makes a log of 301 events. The Append of the last event renames the
	// tree head, and then the fsync of the log directory fails.
	crashed := func(t *testing.T) (*os.Root, string) {
		state, dir := newLogState(t)
		l := openTestLog(t, state)
		appendTo(t, l, 0, 300)
		stop := failDirSyncAfterRename(t, headName)
		if _, err := l.Append(testEvent(300)); err == nil {
			t.Fatal("Append returned nil after the failed fsync")
		}
		stop()
		l.Close()
		return state, filepath.Join(dir, "tlog")
	}

	t.Run("reopen", func(t *testing.T) {
		state, log := crashed(t)
		// The root computation reads the full tile, the partial tile, and the
		// partial tile of the next level.
		want := []string{"..", ".", "tile/8/0", "tile/8/0/001.p", "tile/8/1/000.p"}
		var synced []string
		hookDirSync(t, log, want, func(d string) error { synced = append(synced, d); return nil })
		l, err := OpenLog(state, "tlog")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { l.Close() })
		for _, d := range want {
			if !slices.Contains(synced, d) {
				t.Errorf("OpenLog did not call fsync on %q, only on %q", d, synced)
			}
		}
		if size, _ := l.Head(); size != 301 {
			t.Fatalf("head size %d, want 301", size)
		}
	})

	t.Run("log directory fsync fails", func(t *testing.T) {
		state, log := crashed(t)
		failDirSync(t, log, ".")
		l, err := OpenLog(state, "tlog")
		wantOpenError(t, l, err, "tlog directory", ruleWrite)
	})

	// plantStale makes a file that load deletes. The returned function checks
	// that the file is still there.
	plantStale := func(t *testing.T, log string) (check func()) {
		t.Helper()
		stale := filepath.Join(log, "tile/8/0/001.tmp")
		if err := os.WriteFile(stale, []byte("stale"), 0o600); err != nil {
			t.Fatal(err)
		}
		return func() {
			t.Helper()
			if _, err := os.Stat(stale); err != nil {
				t.Fatalf("the refused open deleted the stale file: %v", err)
			}
		}
	}

	t.Run("state directory mode refused before load", func(t *testing.T) {
		state, log := crashed(t)
		check := plantStale(t, log)
		if err := os.Chmod(filepath.Dir(log), 0o755); err != nil {
			t.Fatal(err)
		}
		l, err := OpenLog(state, "tlog")
		wantOpenError(t, l, err, "tlog directory", ruleMode)
		check()
	})

	t.Run("log directory link refused before load", func(t *testing.T) {
		state, log := crashed(t)
		real := filepath.Join(filepath.Dir(log), "real")
		if err := os.Rename(log, real); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("real", log); err != nil {
			t.Fatal(err)
		}
		check := plantStale(t, real)
		l, err := OpenLog(state, "tlog")
		wantOpenError(t, l, err, "tlog directory", ruleLink)
		check()
	})

	t.Run("empty log, log directory fsync fails", func(t *testing.T) {
		state, dir := newLogState(t)
		openTestLog(t, state).Close()
		failDirSync(t, filepath.Join(dir, "tlog"), ".")
		l, err := OpenLog(state, "tlog")
		wantOpenError(t, l, err, "tlog directory", ruleWrite)
	})

	t.Run("state directory fsync fails", func(t *testing.T) {
		state, log := crashed(t)
		failDirSync(t, log, "..")
		l, err := OpenLog(state, "tlog")
		wantOpenError(t, l, err, "tlog directory", ruleWrite)
	})

	t.Run("tile directory fsync fails", func(t *testing.T) {
		state, log := crashed(t)
		size, root := diskHead(t, filepath.Dir(log))
		restore := failDirSync(t, log, "tile/8/0/001.p")
		l, err := OpenLog(state, "tlog")
		wantOpenError(t, l, err, "tile/8/0/001.p", ruleWrite)
		restore()
		l = openTestLog(t, state)
		if s2, r2 := l.Head(); s2 != size || r2 != root {
			t.Fatalf("reopen gave %d, %x, want %d, %x", s2, r2, size, root)
		}
	})

	// The Append of event 255 writes the full tile, and then the write of the
	// tree head fails. The tree head has size 255, and the root computation
	// reads the tile from the full file. The partial-tile directory is not there.
	t.Run("tile read from the full file", func(t *testing.T) {
		state, dir := newLogState(t)
		log := filepath.Join(dir, "tlog")
		l := openTestLog(t, state)
		appendTo(t, l, 0, 255)
		oldRename := renameFile
		t.Cleanup(func() { renameFile = oldRename })
		renameFile = func(r *os.Root, from, to string) error {
			if to == headName {
				return errors.New("injected")
			}
			return oldRename(r, from, to)
		}
		if _, err := l.Append(testEvent(255)); err == nil {
			t.Fatal("Append returned nil after the failed write of the tree head")
		}
		renameFile = oldRename
		l.Close()
		if err := os.Remove(filepath.Join(log, "tile/8/0/000.p")); err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(log, "tile/8/0/000")); err != nil {
			t.Fatal(err)
		}
		var synced []string
		hookDirSync(t, log, []string{"tile/8/0"}, func(d string) error { synced = append(synced, d); return nil })
		l = openTestLog(t, state)
		if size, _ := l.Head(); size != 255 || len(synced) == 0 {
			t.Fatalf("head size %d, want 255; fsync calls on %q, want tile/8/0", size, synced)
		}
	})
}
