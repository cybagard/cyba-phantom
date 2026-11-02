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
	withoutSync(t)
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
		checkHead(t, fmt.Sprint("reopen at ", n), l.Head, size, root)
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
	// The append to size 256 writes the full tile 0 of level 0 first. Fail that
	// tile write, then the head write.
	for _, fail := range []string{"tile/8/0/000", headName} {
		restore := failRename(t, fail)
		_, stopErr := l.Append(testEvent(255))
		if stopErr == nil {
			t.Fatalf("%s failure: Append returned nil", fail)
		}
		checkHead(t, fail+" failure", l.Head, size, root)
		// The log refuses each later Append with the same error, also when the writes work.
		restore()
		if _, err := l.Append(testEvent(255)); !sameStop(err, stopErr) {
			t.Fatalf("%s failure: next Append gave %v, want %v", fail, err, stopErr)
		}
		checkHead(t, fail+" failure", l.Head, size, root)
		// A reopen loads the state on disk, and the append works again.
		l.Close()
		l = openTestLog(t, state)
		checkHead(t, fail+" reopen", l.Head, size, root)
	}
	appendTo(t, l, 255, 256)
	events = append(events, testEvent(255))
	if want := rfcRoot(rfcLeaves(events)); rootOf(l) != tlog.Hash(want) || sizeOf(l) != 256 {
		t.Fatalf("after reopen: size %d, root %x, want %x", sizeOf(l), rootOf(l), want)
	}
}

// failRename makes each rename to the file name fail. The returned function
// stops the fault. The test restores the earlier calls when it ends.
func failRename(t testing.TB, name string) (stop func()) {
	t.Helper()
	return failRenameIf(t, func(to string) bool { return to == name })
}

// failRenameIf makes each rename fail for which fail returns true. fail gets
// the new name of the file. The returned function stops the fault.
func failRenameIf(t testing.TB, fail func(to string) bool) (stop func()) {
	t.Helper()
	return setHooks(t, hooks{rename: func(r *os.Root, from, to string) error {
		if fail(to) {
			return errors.New("injected")
		}
		return realRename(r, from, to)
	}})
}

// checkHead fails t if get does not give the wanted size and root. get is
// l.Head, l.store.TreeHead, or the result of onDisk.
func checkHead(t testing.TB, what string, get func() (int64, tlog.Hash), size int64, root tlog.Hash) {
	t.Helper()
	if s, r := get(); s != size || r != root {
		t.Fatalf("%s: head %d, %x, want %d, %x", what, s, r, size, root)
	}
}

// fatalSpy counts the calls of Fatalf and does not stop the test.
type fatalSpy struct {
	testing.TB
	fatals int
}

func (s *fatalSpy) Fatalf(string, ...any) { s.fatals++ }

func TestTS13CheckHeadComparesTheRootAndTheSize(t *testing.T) {
	get := func() (int64, tlog.Hash) { return 3, tlog.Hash{1} }
	spy := &fatalSpy{TB: t}
	checkHead(spy, "same head", get, 3, tlog.Hash{1})
	if spy.fatals != 0 {
		t.Fatalf("a matching head recorded %d failures", spy.fatals)
	}
	checkHead(spy, "other root", get, 3, tlog.Hash{2})
	if spy.fatals != 1 {
		t.Fatalf("the same size with another root recorded %d failures, want 1", spy.fatals)
	}
	checkHead(spy, "other size", get, 4, tlog.Hash{1})
	if spy.fatals != 2 {
		t.Fatalf("another size with the same root recorded %d failures in all, want 2", spy.fatals)
	}
}

// onDisk returns a reader of the head file below dir, for checkHead.
func onDisk(t *testing.T, dir string) func() (int64, tlog.Hash) {
	return func() (int64, tlog.Hash) { return diskHead(t, dir) }
}

// failDirSyncAfterRename makes the next fsync of a directory fail after the
// rename of the file name works. The returned function stops the fault.
// The test restores the earlier calls when it ends.
func failDirSyncAfterRename(t *testing.T, name string) (stop func()) {
	t.Helper()
	armed := false
	rename := func(r *os.Root, from, to string) error {
		err := realRename(r, from, to)
		if err == nil && to == name {
			armed = true
		}
		return err
	}
	dir := func(f *os.File) error {
		if armed {
			armed = false
			return errors.New("injected")
		}
		return realSync(f)
	}
	return setHooks(t, hooks{dir: dir, rename: rename})
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
	_, stopErr := l.Append(a)
	stop()
	if stopErr == nil {
		t.Fatal("Append returned nil after the failed fsync")
	}
	checkHead(t, "head in memory", l.Head, size, root)
	rootA := tlog.Hash(rfcRoot(rfcLeaves(append(slices.Clone(events), a))))
	checkHead(t, "head on disk", onDisk(t, dir), size+1, rootA)
	if _, err := l.Append(b); !sameStop(err, stopErr) {
		t.Fatalf("next Append gave %v, want %v", err, stopErr)
	}
	checkHead(t, "head on disk after the next Append", onDisk(t, dir), size+1, rootA)
	l.Close()
	l = openTestLog(t, state)
	checkHead(t, "reopen", l.Head, size+1, rootA)
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

	// If the fsync of the tile directory fails again, Append returns an error
	// and does not write the head.
	l = openTestLog(t, state)
	restore := setHooks(t, hooks{dir: func(*os.File) error { return errors.New("injected") }})
	if _, err := l.Append(testEvent(256)); err == nil {
		t.Fatal("Append returned nil after the failed fsync of the retry")
	}
	restore()
	if size, _ := diskHead(t, dir); size != 256 {
		t.Fatalf("head on disk has size %d, want 256", size)
	}
	l.Close()

	l = openTestLog(t, state)
	appendSyncsTileBeforeHead(t, l)
}

// appendSyncsTileBeforeHead appends event 256. It checks that the fsync of the
// partial tile directory comes before the write of the head.
func appendSyncsTileBeforeHead(t *testing.T, l *Log) {
	t.Helper()
	var steps []string
	renameHook := func(r *os.Root, from, to string) error {
		if to == headName {
			steps = append(steps, "head")
		}
		return realRename(r, from, to)
	}
	dirHook := func(f *os.File) error {
		steps = append(steps, "sync "+filepath.Clean(f.Name()))
		return realSync(f)
	}
	setHooks(t, hooks{dir: dirHook, rename: renameHook})
	if idx, err := l.Append(testEvent(256)); err != nil || idx != 256 {
		t.Fatalf("Append gave %d, %v", idx, err)
	}
	tileSync := slices.IndexFunc(steps, func(s string) bool { return strings.HasSuffix(s, "tile/8/0/001.p") })
	head := slices.Index(steps, "head")
	if tileSync < 0 || head < 0 || tileSync > head {
		t.Fatalf("steps %q: want the fsync of the tile directory before the head", steps)
	}
}

// A failed batch leaves a wider partial file of the last tile. The next Append
// has the same first leaf, so the kept wider file has the data of the narrower
// tile. The store writes nothing and calls fsync on the directory of the kept
// file. If that fsync fails, Append returns an error for the kept file, and the
// tree head does not cover the hash. After the fault stops, the log opens again,
// and the fsync of the tile directory comes before the write of the head.
func TestTU07NarrowWriteSyncsTheDirectoryOfTheKeptWiderFile(t *testing.T) {
	withoutSync(t)
	state, dir := newLogState(t)
	l := openTestLog(t, state)
	events := appendTo(t, l, 0, 256)
	size, root := l.Head()
	wide := failDirSyncAfterRename(t, "tile/8/0/001.p/3")
	if _, err := l.AppendBatch(batchOf(256, 259)); err == nil {
		t.Fatal("AppendBatch returned nil after the failed fsync of the wide tile")
	}
	wide()
	l.Close()

	// The tile is 001.p/1 and the kept file is 001.p/3. If each fsync of a
	// directory fails, the error names the kept file and the head stays.
	const kept = "tile/8/0/001.p/3"
	l = openTestLog(t, state)
	restore := setHooks(t, hooks{dir: func(*os.File) error { return errors.New("injected") }})
	_, err := l.Append(testEvent(256))
	restore()
	var e *Error
	if !errors.As(err, &e) || e.Rule != ruleWrite || e.Name != kept {
		t.Fatalf("Append gave %v, want the rule %q for %s", err, ruleWrite, kept)
	}
	checkHead(t, "head in memory", l.Head, size, root)
	checkHead(t, "head on disk", onDisk(t, dir), size, root)
	l.Close()

	// If the fsync works, it comes before the write of the head.
	l = openTestLog(t, state)
	appendSyncsTileBeforeHead(t, l)
	events = append(events, testEvent(256))
	if want := rfcRoot(rfcLeaves(events)); rootOf(l) != tlog.Hash(want) || sizeOf(l) != 257 {
		t.Fatalf("after the retry: size %d, root %x, want %x", sizeOf(l), rootOf(l), want)
	}
	checkProof(t, l, 256)
}

// A failed batch leaves a wider partial file of the last tile. The next batch has
// other leaves, so its tile is narrower and differs beyond the tree head. The
// kept wider file is stale. The store writes the narrow file, and the rename
// works, but the fsync of the directory fails. The tree head must not cover the
// new hashes. After the fault stops, the log opens again and the same Append
// works.
func TestTU07NarrowWriteOverAStaleWiderFileFailsTheDirectorySync(t *testing.T) {
	withoutSync(t)
	state, dir := newLogState(t)
	l := openTestLog(t, state)
	events := appendTo(t, l, 0, 256)
	size, root := l.Head()
	wide := failDirSyncAfterRename(t, "tile/8/0/001.p/3")
	if _, err := l.AppendBatch(batchOf(1000, 1003)); err == nil {
		t.Fatal("AppendBatch returned nil after the failed fsync of the wide tile")
	}
	wide()
	l.Close()

	l = openTestLog(t, state)
	const narrow = "tile/8/0/001.p/1"
	stop := failDirSyncAfterRename(t, narrow)
	_, err := l.Append(testEvent(256))
	stop()
	var e *Error
	if !errors.As(err, &e) || e.Rule != ruleWrite || e.Name != narrow {
		t.Fatalf("Append gave %v, want the rule %q for %s", err, ruleWrite, narrow)
	}
	checkHead(t, "head in memory", l.Head, size, root)
	checkHead(t, "head on disk", onDisk(t, dir), size, root)
	l.Close()

	l = openTestLog(t, state)
	if idx, err := l.Append(testEvent(256)); err != nil || idx != 256 {
		t.Fatalf("Append after the fault gave %d, %v", idx, err)
	}
	events = append(events, testEvent(256))
	if want := rfcRoot(rfcLeaves(events)); rootOf(l) != tlog.Hash(want) || sizeOf(l) != 257 {
		t.Fatalf("after the retry: size %d, root %x, want %x", sizeOf(l), rootOf(l), want)
	}
	checkProof(t, l, 256)
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
	withoutSync(t)
	// The batch from 0 fills tile 0. The batch from 100 fills tile 0 and tile 1.
	for _, start := range []int{0, 100} {
		t.Run(fmt.Sprint("start", start), func(t *testing.T) {
			state, _ := newLogState(t)
			l := openTestLog(t, state)
			appendTo(t, l, 0, start)
			refState, _ := newLogState(t)
			ref := openTestLog(t, refState)
			appendTo(t, ref, 0, start+500)

			heads, tileWrites, dirSyncs := 0, 0, 0
			restore := setHooks(t, hooks{rename: func(r *os.Root, from, to string) error {
				if to == headName {
					heads++
				} else {
					tileWrites++
				}
				return realRename(r, from, to)
			}, dir: func(*os.File) error {
				dirSyncs++
				return nil
			}})
			first, err := l.AppendBatch(batchOf(start, start+500))
			restore()
			if err != nil || first != int64(start) || heads != 1 {
				t.Fatalf("AppendBatch gave %d, %v after %d head writes, want %d, nil, 1", first, err, heads, start)
			}
			// Each tile is written one time. From 0: tile 0 and tile 1 of level 0,
			// and tile 0 of level 1. From 100: tiles 0, 1, and 2 of level 0, and
			// tile 0 of level 1.
			if want := map[int]int{0: 3, 100: 4}[start]; tileWrites != want {
				t.Fatalf("AppendBatch wrote %d tiles, want %d", tileWrites, want)
			}
			// A second write of a tile skips the rename but syncs the
			// directories. So the count of syncs shows a repeated write.
			if want := map[int]int{0: 15, 100: 24}[start]; dirSyncs != want {
				t.Fatalf("AppendBatch synced directories %d times, want %d", dirSyncs, want)
			}
			size, root := ref.Head()
			checkHead(t, "batch", l.Head, size, root)
			checkCache(t, l)

			// The reopen reads the full tile, and the proof reads a leaf inside it.
			l.Close()
			l = openTestLog(t, state)
			checkHead(t, "reopen", l.Head, size, root)
			checkProof(t, l, 200)
			checkProof(t, l, start+499)
			if start == 100 {
				checkProof(t, l, 300)
			}
			appendTo(t, l, start+500, start+501)
			appendTo(t, ref, start+500, start+501)
			checkHead(t, "next append", l.Head, size+1, rootOf(ref))
		})
	}
}

func TestTU07BatchEdges(t *testing.T) {
	state, dir := newLogState(t)
	l := openTestLog(t, state)
	appendTo(t, l, 0, 3)
	size, root := l.Head()
	// The rename hook is on during the empty batch. An empty batch that
	// writes fails here.
	restore := failRenameIf(t, func(string) bool { return true })
	first, err := l.AppendBatch(nil)
	restore()
	if err != nil || first != size {
		t.Fatalf("empty batch gave %d, %v", first, err)
	}
	checkHead(t, "empty batch", l.Head, size, root)
	// A batch that does not fit, or has too many tiles, is refused before any write.
	l.size = maxSize - 1
	var e *Error
	if _, err := l.AppendBatch(batchOf(0, 2)); !errors.As(err, &e) || e.Rule != ruleFull || errors.Is(err, ErrHeadOnDisk) {
		t.Fatalf("a batch above the largest size gave %v, want the rule %q with no mark", err, ruleFull)
	}
	// One leaf fits at the largest size minus one. The tiles in memory are
	// those of a small log. So the cache check refuses it before a write.
	logDir := filepath.Join(dir, "tlog")
	before := snapshot(t, logDir)
	if _, err := l.AppendBatch(batchOf(0, 1)); !errors.As(err, &e) || e.Rule != ruleCache || errors.Is(err, ErrHeadOnDisk) {
		t.Fatalf("a batch of one leaf at the largest size minus one gave %v, want the rule %q", err, ruleCache)
	}
	if l.err != nil || snapshot(t, logDir) != before {
		t.Fatalf("a refused batch stopped the log (%v) or changed a file", l.err)
	}
	l.size = 0
	if _, err := l.AppendBatch(make([]EventHash, maxBatchTiles*fullWidth+1)); !errors.As(err, &e) || e.Rule != ruleBatch || errors.Is(err, ErrHeadOnDisk) {
		t.Fatalf("a batch with too many leaves gave %v, want the rule %q with no mark", err, ruleBatch)
	}
	if l.err != nil {
		t.Fatalf("a refused batch stopped the log: %v", l.err)
	}
}

// sameStop reports whether err and stopErr hold the same *Error.
func sameStop(err, stopErr error) bool {
	var a, b *Error
	return errors.As(err, &a) && errors.As(stopErr, &b) && a == b
}

// A batch with exactly maxBatchTiles changed tiles passes the check of the
// tile count. The tiles in memory do not match the tree, so the batch stops
// at the cache check, before a write. A batch with one leaf more fails the
// check of the tile count. Neither batch changes a file.
func TestTU07BatchAtTheTileBoundPassesTheTileCheck(t *testing.T) {
	state, dir := newLogState(t)
	l := openTestLog(t, state)
	appendTo(t, l, 0, 3)
	l.tiles[0].n++
	const end = 4079 * fullWidth
	if got := batchTiles(3, end); got != maxBatchTiles {
		t.Fatalf("the batch changes %d tiles, want %d", got, maxBatchTiles)
	}
	logDir := filepath.Join(dir, "tlog")
	before := snapshot(t, logDir)
	var e *Error
	_, err := l.AppendBatch(make([]EventHash, end-3))
	if !errors.As(err, &e) || e.Rule != ruleCache || errors.Is(err, ErrHeadOnDisk) {
		t.Fatalf("a batch at the tile bound gave %v, want the rule %q", err, ruleCache)
	}
	if snapshot(t, logDir) != before {
		t.Fatal("a refused batch changed a file")
	}

	// One leaf over the bound changes one tile more than the store accepts.
	const over = end + 1
	if got := batchTiles(3, over); got != maxBatchTiles+1 {
		t.Fatalf("the batch changes %d tiles, want %d", got, maxBatchTiles+1)
	}
	_, err = l.AppendBatch(make([]EventHash, over-3))
	if !errors.As(err, &e) || e.Rule != ruleBatch || errors.Is(err, ErrHeadOnDisk) {
		t.Fatalf("a batch over the tile bound gave %v, want the rule %q with no mark", err, ruleBatch)
	}
	if l.err != nil || snapshot(t, logDir) != before {
		t.Fatalf("a refused batch stopped the log (%v) or changed a file", l.err)
	}
}

// A batch that fits the leaf limit but changes more tiles than the store
// accepts for one tree head is refused before a write, with no mark.
func TestTS13BatchWithTooManyTilesIsNotMarked(t *testing.T) {
	state, dir := newLogState(t)
	l := openTestLog(t, state)
	logDir := filepath.Join(dir, "tlog")
	before := snapshot(t, logDir)
	var e *Error
	_, err := l.AppendBatch(make([]EventHash, maxBatchTiles*fullWidth))
	if !errors.As(err, &e) || e.Rule != ruleBatch || errors.Is(err, ErrHeadOnDisk) {
		t.Fatalf("a batch with too many tiles gave %v, want the rule %q with no mark", err, ruleBatch)
	}
	if l.err != nil || snapshot(t, logDir) != before {
		t.Fatalf("a refused batch stopped the log (%v) or changed a file", l.err)
	}
	// This batch is one leaf over the bound of the store. It gives new hashes
	// to 4080 tiles of level 0, 16 of level 1, and 1 of level 2.
	_, err = l.AppendBatch(make([]EventHash, 4079*fullWidth+1))
	if !errors.As(err, &e) || e.Rule != ruleBatch || errors.Is(err, ErrHeadOnDisk) {
		t.Fatalf("a batch one leaf over the bound gave %v, want the rule %q", err, ruleBatch)
	}
}

// Tiles in memory that do not match the tree are refused before a write, with
// no mark.
func TestTS13TilesInMemoryThatDoNotMatchAreNotMarked(t *testing.T) {
	state, dir := newLogState(t)
	l := openTestLog(t, state)
	appendTo(t, l, 0, 3)
	l.tiles[0].n++
	logDir := filepath.Join(dir, "tlog")
	before := snapshot(t, logDir)
	var e *Error
	_, err := l.AppendBatch(batchOf(3, 5))
	if !errors.As(err, &e) || e.Rule != ruleCache || errors.Is(err, ErrHeadOnDisk) {
		t.Fatalf("AppendBatch gave %v, want the rule %q with no mark", err, ruleCache)
	}
	if snapshot(t, logDir) != before {
		t.Fatal("a refused batch changed a file")
	}
	// A tile of the right number with one hash too many is refused as well.
	l.tiles[0].n--
	l.tiles[0].data = append(slices.Clone(l.tiles[0].data), make([]byte, tlog.HashSize)...)
	_, err = l.AppendBatch(batchOf(3, 5))
	if !errors.As(err, &e) || e.Rule != ruleCache || errors.Is(err, ErrHeadOnDisk) || l.err != nil {
		t.Fatalf("AppendBatch gave %v (log error %v), want the rule %q with no mark", err, l.err, ruleCache)
	}
	if snapshot(t, logDir) != before {
		t.Fatal("a refused batch changed a file")
	}
}

// The hash read of the cache and the tile save of the loader stop at the top
// level.
func TestTS13LevelBoundsOfTheCacheAndTheLoader(t *testing.T) {
	var tiles [maxLevel + 1]tileBuf
	hash := bytes.Repeat([]byte{7}, tlog.HashSize)
	tiles[maxLevel] = tileBuf{0, hash}
	view := cacheView{&tiles}
	top := tlog.StoredHashIndex(maxLevel*TileHeight, 0)
	if hs, err := view.ReadHashes([]int64{top}); err != nil || len(hs) != 1 || !bytes.Equal(hs[0][:], hash) {
		t.Fatalf("a hash at level %d gave %v, %v", maxLevel, hs, err)
	}
	var e *Error
	above := tlog.StoredHashIndex((maxLevel+1)*TileHeight, 0)
	if _, err := view.ReadHashes([]int64{above}); !errors.As(err, &e) || e.Rule != ruleCache {
		t.Fatalf("a hash at level %d gave %v, want the rule %q", maxLevel+1, err, ruleCache)
	}

	var saved [maxLevel + 1]tileBuf
	r := &loader{tiles: &saved}
	data := [][]byte{{1}, {2}, {3}}
	r.SaveTiles([]tlog.Tile{{L: maxLevel, N: 7}, {L: maxLevel + 1}, {L: -1}}, data)
	if saved[maxLevel].n != 7 || !bytes.Equal(saved[maxLevel].data, data[0]) {
		t.Fatalf("the tile at level %d is %+v", maxLevel, saved[maxLevel])
	}
}

// A failed batch keeps the spare capacity of the level 0 and level 1 buffers
// as they were.
func TestTS13FailedBatchKeepsTheTileBuffers(t *testing.T) {
	state, _ := newLogState(t)
	l := openTestLog(t, state)
	// At 511 leaves, the level 0 tile holds 255 hashes and the level 1 tile
	// holds 1. The batch adds to both. A batch that adds to a buffer
	// without a copy writes into its spare capacity.
	appendTo(t, l, 0, 511)
	var bufs, wants [2][]byte
	for lv := range bufs {
		old := l.tiles[lv].data
		bufs[lv] = make([]byte, len(old), len(old)+tlog.HashSize*fullWidth)
		copy(bufs[lv], old)
		l.tiles[lv].data = bufs[lv]
		wants[lv] = slices.Clone(bufs[lv][:cap(bufs[lv])])
	}
	restore := failRenameIf(t, func(string) bool { return true })
	_, err := l.AppendBatch(batchOf(511, 560))
	restore()
	if err == nil {
		t.Fatal("the batch with failing renames gave no error")
	}
	for lv, buf := range bufs {
		if !bytes.Equal(buf[:cap(buf)], wants[lv]) {
			t.Fatalf("a failed batch wrote into the level %d buffer of the log", lv)
		}
	}
}

// After a tile write failure, the next batch gets the same error with no mark.
func TestTS13StoppedLogAfterTileWriteFailureIsNotMarked(t *testing.T) {
	state, _ := newLogState(t)
	l := openTestLog(t, state)
	appendTo(t, l, 0, 255)
	restore := failRenameIf(t, func(string) bool { return true })
	_, stopErr := l.AppendBatch(batchOf(255, 300))
	restore()
	_, next := l.AppendBatch(batchOf(255, 300))
	if stopErr == nil || next == nil || errors.Is(stopErr, ErrHeadOnDisk) || errors.Is(next, ErrHeadOnDisk) || !sameStop(next, stopErr) {
		t.Fatalf("stop error %v, next error %v: want the same error with no mark", stopErr, next)
	}
}

// After a marked failure, the next batch gets the same *Error with no mark.
func TestTS13StoppedLogAfterMarkedFailureIsNotMarked(t *testing.T) {
	state, _ := newLogState(t)
	l := openTestLog(t, state)
	appendTo(t, l, 0, 255)
	failDirSyncAfterRename(t, headName)
	_, stopErr := l.AppendBatch(batchOf(255, 300))
	_, next := l.AppendBatch(batchOf(255, 300))
	if !errors.Is(stopErr, ErrHeadOnDisk) || next == nil || errors.Is(next, ErrHeadOnDisk) || !sameStop(next, stopErr) {
		t.Fatalf("stop error %v, next error %v: want a mark on the stop error only", stopErr, next)
	}
}

// OpenLog of a new log directory writes the first tree head. If the fsync of
// the directory fails after the rename, the error is a failed write with no
// mark: the mark is only for Append and AppendBatch.
func TestTS13OpenLogFirstHeadDirectorySyncFailureIsNotMarked(t *testing.T) {
	state, _ := newLogState(t)
	failDirSyncAfterRename(t, headName)
	l, err := OpenLog(state, "tlog")
	if err == nil {
		l.Close()
		t.Fatal("OpenLog returned nil after the failed fsync")
	}
	var e *Error
	if !errors.As(err, &e) || e.Rule != ruleWrite || errors.Is(err, ErrHeadOnDisk) {
		t.Fatalf("OpenLog gave %v, want the rule %q with no mark", err, ruleWrite)
	}
}

// The open of the log directory fails after the rename of the head file. The
// head on disk covers the batch, so the error has the mark.
func TestTS13HeadDirectoryOpenFailureAfterRenameIsMarked(t *testing.T) {
	state, dir := newLogState(t)
	l := openTestLog(t, state)
	appendTo(t, l, 0, 255)
	size, root := l.Head()
	logDir := filepath.Join(dir, "tlog")
	t.Cleanup(func() { os.Chmod(logDir, dirMode) })
	restore := setHooks(t, hooks{rename: func(r *os.Root, from, to string) error {
		err := realRename(r, from, to)
		if err == nil && to == headName {
			// The open of a directory with group access fails.
			err = os.Chmod(logDir, 0o750)
			if err == nil {
				return nil
			}
		}
		return err
	}})
	_, err := l.AppendBatch(batchOf(255, 300))
	restore()
	var e *Error
	if !errors.Is(err, ErrHeadOnDisk) || !errors.As(err, &e) || e.Rule != ruleWrite {
		t.Fatalf("AppendBatch gave %v, want the rule %q with the mark", err, ruleWrite)
	}
	checkHead(t, "head in memory", l.Head, size, root)
	// The Store keeps the old tree head, while the head file holds the new one.
	checkHead(t, "store head", l.store.TreeHead, size, root)
	wantRoot := tlog.Hash(rfcRoot(rfcLeaves(batchOf(0, 300))))
	checkHead(t, "head on disk", onDisk(t, dir), 300, wantRoot)
}

func TestTS13BatchWriteFailureKeepsTheHeadInMemory(t *testing.T) {
	// The batch from size 255 to size 300 writes the tiles in the order of
	// their first change. First is tile 0 of level 0 with 256 hashes. Next is
	// tile 0 of level 1 with one hash. Last is tile 1 of level 0 with 44
	// hashes. Then the batch writes the head.

	// failed is the name of the file whose rename failTileRename made fail.
	var failed string
	failTileRename := func(nth int) func(t *testing.T) {
		return func(t *testing.T) {
			tiles := 0
			failRenameIf(t, func(to string) bool {
				if to == headName {
					return false
				}
				tiles++
				fail := tiles == nth
				if fail {
					failed = to
				}
				return fail
			})
		}
	}
	batchRoot := tlog.Hash(rfcRoot(rfcLeaves(batchOf(0, 300))))
	for _, c := range []struct {
		name  string
		fault func(t *testing.T)
		// covers is true when the head on disk covers the batch after the failure.
		covers bool
		// file is the file whose rename fails, for the cases of failTileRename.
		file string
	}{
		{"level 0 tile 0 rename", failTileRename(1), false, "tile/8/0/000"},
		{"level 1 tile 0 rename", failTileRename(2), false, "tile/8/1/000.p/1"},
		{"level 0 tile 1 rename", failTileRename(3), false, "tile/8/0/001.p/44"},
		{"level 0 tile 1 directory sync", func(t *testing.T) { failDirSyncAfterRename(t, "tile/8/0/001.p/44") }, false, ""},
		{"head rename", func(t *testing.T) { failRename(t, headName) }, false, ""},
		// The rename of the head works and the fsync of its directory fails.
		{"head directory sync", func(t *testing.T) { failDirSyncAfterRename(t, headName) }, true, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			failed = ""
			state, dir := newLogState(t)
			l := openTestLog(t, state)
			appendTo(t, l, 0, 255)
			size, root := l.Head()
			// Save the calls. restore then stops the fault that c.fault sets.
			restore := setHooks(t, hooks{})
			c.fault(t)
			_, stopErr := l.AppendBatch(batchOf(255, 300))
			restore()
			if stopErr == nil {
				t.Fatal("AppendBatch returned nil")
			}
			if failed != c.file {
				t.Fatalf("the failed rename was of %q, want %q", failed, c.file)
			}
			// The head in memory is always the old head. The head on disk is the old
			// head, or it covers the batch.
			diskSize, diskRoot := size, root
			if c.covers {
				diskSize, diskRoot = 300, batchRoot
			}
			check := func(l *Log, what string, loaded bool) {
				t.Helper()
				wantSize, wantRoot := size, root
				if loaded {
					wantSize, wantRoot = diskSize, diskRoot
				}
				checkHead(t, what, l.Head, wantSize, wantRoot)
				checkHead(t, what+", on disk", onDisk(t, dir), diskSize, diskRoot)
			}
			check(l, "after the failure", false)
			// The Store keeps the old tree head in each case.
			checkHead(t, "store head", l.store.TreeHead, size, root)
			// A rename error can come after the rename took effect. So an error
			// of the head rename has the mark, also if the old head is on disk.
			marked := c.covers || c.name == "head rename"
			if got := errors.Is(stopErr, ErrHeadOnDisk); got != marked {
				t.Fatalf("errors.Is(stopErr, ErrHeadOnDisk) = %v, want %v", got, marked)
			}
			// The log refuses each later call with the same error, also when the writes work.
			if _, err := l.Append(testEvent(255)); !sameStop(err, stopErr) {
				t.Fatalf("next Append gave %v, want %v", err, stopErr)
			}
			if _, err := l.AppendBatch(batchOf(255, 256)); !sameStop(err, stopErr) {
				t.Fatalf("next AppendBatch gave %v, want %v", err, stopErr)
			}
			if _, err := l.AppendBatch(nil); !sameStop(err, stopErr) {
				t.Fatalf("next empty AppendBatch gave %v, want %v", err, stopErr)
			}
			check(l, "after the refused calls", false)

			// A reopen loads the head on disk. If that head is the old head, the same
			// batch works again. If it covers the batch, the log holds the batch already.
			l.Close()
			l = openTestLog(t, state)
			check(l, "after the reopen", true)
			if c.covers {
				checkProof(t, l, 299)
				if idx, err := l.Append(testEvent(300)); err != nil || idx != 300 {
					t.Fatalf("Append after the reopen gave %d, %v", idx, err)
				}
				if want := rfcRoot(rfcLeaves(batchOf(0, 301))); rootOf(l) != tlog.Hash(want) || sizeOf(l) != 301 {
					t.Fatalf("after the reopen: size %d, root %x, want %x", sizeOf(l), rootOf(l), want)
				}
				return
			}
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
// error, the fsync fails. The returned function restores the earlier call. The
// test restores it when it ends too.
func hookDirSync(t *testing.T, log string, names []string, fn func(name string) error) (restore func()) {
	t.Helper()
	return setHooks(t, hooks{dir: func(f *os.File) error {
		if d := syncedAs(f, log, names); d != "" {
			if err := fn(d); err != nil {
				return err
			}
		}
		return realSync(f)
	}})
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
		wantOpenError(t, l, err, "state directory", ruleMode)
		check()
	})

	t.Run("log directory link refused before load", func(t *testing.T) {
		state, log := crashed(t)
		target := filepath.Join(filepath.Dir(log), "real")
		if err := os.Rename(log, target); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("real", log); err != nil {
			t.Fatal(err)
		}
		check := plantStale(t, target)
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
		checkHead(t, "reopen", l.Head, size, root)
	})

	// The Append of event 255 writes the full tile, and then the write of the
	// tree head fails. The tree head has size 255, and the root computation
	// reads the tile from the full file. The partial-tile directory is not there.
	t.Run("tile read from the full file", func(t *testing.T) {
		state, dir := newLogState(t)
		log := filepath.Join(dir, "tlog")
		l := openTestLog(t, state)
		appendTo(t, l, 0, 255)
		restore := failRename(t, headName)
		if _, err := l.Append(testEvent(255)); err == nil {
			t.Fatal("Append returned nil after the failed write of the tree head")
		}
		restore()
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
