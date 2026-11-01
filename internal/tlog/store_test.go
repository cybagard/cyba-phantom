package tlog

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/tlog"
)

// testLog holds every stored hash of a log in memory. It builds the tiles that
// the store gets. Append is not part of the store.
type testLog struct {
	hashes []tlog.Hash
	n      int64
	label  string // text of the records; "record" if empty
}

// fork returns a log with the first n records of l. The records after n have
// the text label.
func (l *testLog) fork(t *testing.T, n int64, label string) *testLog {
	t.Helper()
	f := &testLog{hashes: slices.Clone(l.hashes[:tlog.StoredHashCount(n)]), n: n, label: label}
	return f
}

// tileData returns the data of tile t.
func (l *testLog) tileData(t tlog.Tile) []byte {
	var data []byte
	for j := 0; j < t.W; j++ {
		h := l.hashes[tlog.StoredHashIndex(t.H*t.L, t.N*fullWidth+int64(j))]
		data = append(data, h[:]...)
	}
	return data
}

func (l *testLog) ReadHashes(idx []int64) ([]tlog.Hash, error) {
	out := make([]tlog.Hash, len(idx))
	for i, x := range idx {
		out[i] = l.hashes[x]
	}
	return out, nil
}

func (l *testLog) root(t *testing.T, n int64) tlog.Hash {
	t.Helper()
	h, err := tlog.TreeHash(n, l)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// extend adds records until the log has n records.
func (l *testLog) extend(t *testing.T, n int64) {
	t.Helper()
	label := cmp.Or(l.label, "record")
	for ; l.n < n; l.n++ {
		hs, err := tlog.StoredHashes(l.n, []byte(fmt.Sprintf("%s %d", label, l.n)), l)
		if err != nil {
			t.Fatal(err)
		}
		l.hashes = append(l.hashes, hs...)
	}
}

// put writes the tiles for the growth from..to, without the tree head.
func (l *testLog) put(t *testing.T, s *Store, from, to int64) {
	t.Helper()
	l.extend(t, to)
	for _, tile := range tlog.NewTiles(TileHeight, from, to) {
		if err := s.WriteTile(tile, l.tileData(tile)); err != nil {
			t.Fatal(err)
		}
	}
}

// commit writes the tiles, then the tree head.
func (l *testLog) commit(t *testing.T, s *Store, from, to int64) {
	t.Helper()
	l.put(t, s, from, to)
	if err := s.SetHead(to, l.root(t, to)); err != nil {
		t.Fatal(err)
	}
}

func openStore(t *testing.T, state *os.Root) *Store {
	t.Helper()
	s, err := Open(state, "tlog")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// newLogState makes a state directory with mode 0700. The test directory of
// the testing package can have other modes.
func newLogState(t *testing.T) (*os.Root, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	r, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	return r, dir
}

func TestTU07ReopenGivesSameSizeAndRoot(t *testing.T) {
	state, _ := newLogState(t)
	s := openStore(t, state)
	if size, root := s.TreeHead(); size != 0 || root != emptyRoot {
		t.Fatalf("new log: size %d, root %x", size, root)
	}
	var l testLog
	var from int64
	for _, n := range []int64{1, 3, 255, 256, 257, 600} {
		l.commit(t, s, from, n)
		from = n
		s.Close()
		s = openStore(t, state)
		if size, root := s.TreeHead(); size != n || root != l.root(t, n) {
			t.Fatalf("after reopen at %d: size %d, root %x", n, size, root)
		}
	}
}

func TestTU07OpenAfterTilesBeforeHead(t *testing.T) {
	state, _ := newLogState(t)
	s := openStore(t, state)
	var l testLog
	l.commit(t, s, 0, 3)
	l.put(t, s, 3, 5) // a crash here leaves a wider tile and the old head
	s.Close()
	s = openStore(t, state)
	if size, root := s.TreeHead(); size != 3 || root != l.root(t, 3) {
		t.Fatalf("size %d, root %x", size, root)
	}
}

func TestTU07HeadIsWrittenLast(t *testing.T) {
	state, dir := newLogState(t)
	s := openStore(t, state)
	var l testLog
	l.extend(t, 3)
	head := filepath.Join(dir, "tlog", headName)
	empty, err := os.ReadFile(head)
	mustNil(t, err)
	if err := s.SetHead(3, l.root(t, 3)); err == nil {
		t.Fatal("tree head accepted with no tiles")
	}
	if now, _ := os.ReadFile(head); !bytes.Equal(now, empty) {
		t.Fatal("a refused tree head changed the head file")
	}
	l.put(t, s, 0, 3)
	var e *Error
	if err := s.SetHead(3, tlog.Hash{1}); !errors.As(err, &e) || e.Rule != ruleRoot {
		t.Fatalf("wrong root over stored tiles: %v", err)
	}
	mustNil(t, s.SetHead(3, l.root(t, 3)))
	if err := s.SetHead(2, l.root(t, 2)); err == nil {
		t.Fatal("tree head got smaller")
	}
}

// recordDurableSteps replaces the calls that make a write durable with hooks
// that record their order. Each hook also checks the state of the files at its
// step. The test restores the earlier calls when it ends.
func recordDurableSteps(t *testing.T, log, name string, data []byte) *[]string {
	t.Helper()
	var steps []string
	tmp := filepath.Join(log, name+tmpSuffix)
	final := filepath.Join(log, name)
	holds := func(file string) bool {
		b, err := os.ReadFile(file)
		return err == nil && bytes.Equal(b, data)
	}
	file := func(f *os.File) error {
		if !holds(tmp) || holds(final) {
			t.Error("file sync: the temporary file lacks the data, or the final file has it already")
		} else {
			// The data is in the temporary file now: the write is done.
			steps = append(steps, "write temp")
		}
		steps = append(steps, "sync file")
		return realSync(f)
	}
	rename := func(r *os.Root, from, to string) error {
		if from != name+tmpSuffix || to != name || !holds(tmp) || holds(final) {
			t.Errorf("rename %s to %s: wrong names or state", from, to)
		}
		steps = append(steps, "rename")
		return realRename(r, from, to)
	}
	dir := func(f *os.File) error {
		if _, err := os.Lstat(tmp); err == nil || !holds(final) {
			t.Error("directory sync: the temporary file is there, or the final file lacks the data")
		}
		fi, err := f.Stat()
		mustNil(t, err)
		for d := filepath.Dir(name); ; d = filepath.Dir(d) {
			if di, err := os.Stat(filepath.Join(log, d)); err == nil && os.SameFile(di, fi) {
				steps = append(steps, "sync dir "+d)
				break
			} else if d == "." {
				steps = append(steps, "sync of an unknown directory")
				break
			}
		}
		return realSync(f)
	}
	setHooks(t, hooks{file: file, dir: dir, rename: rename})
	return &steps
}

// The real calls. A hook of a test calls them when it only records or checks.
var (
	realSync   = (*os.File).Sync
	realRename = (*os.Root).Rename
)

// hooks holds the calls that setHooks replaces. A nil field keeps the call.
type hooks struct {
	file   func(*os.File) error                 // fsync of a file
	dir    func(*os.File) error                 // fsync of a directory
	rename func(*os.Root, string, string) error // rename of a file
}

// setHooks is the only code of the tests that sets the durability calls of the
// store. It sets the calls in h and restores the earlier calls when t ends. The
// returned function restores them earlier. The calls are package state. Two
// parallel tests that use them at the same time can race. t.Setenv panics if
// the test or an ancestor is parallel. t.Parallel panics after a call of
// setHooks. A parallel subtest of a test that calls setHooks is not refused.
// A fuzz test can call setHooks too.
func setHooks(t testing.TB, h hooks) (restore func()) {
	t.Helper()
	t.Setenv("TLOG_TEST_HOOKS", "1")
	oldFile, oldDir, oldRename := syncFile, syncDirFile, renameFile
	restore = func() { syncFile, syncDirFile, renameFile = oldFile, oldDir, oldRename }
	t.Cleanup(restore)
	if h.file != nil {
		syncFile = h.file
	}
	if h.dir != nil {
		syncDirFile = h.dir
	}
	if h.rename != nil {
		renameFile = h.rename
	}
	return restore
}

// A tile or the tree head is durable in this order. First, the store writes the
// temporary file and calls fsync on it. Then it renames the file. Last, it
// calls fsync on the directory and on each parent.
func TestTU07WriteOrderIsTempFsyncRenameDirectoryFsync(t *testing.T) {
	state, dir := newLogState(t)
	s := openStore(t, state)
	log := filepath.Join(dir, "tlog")
	var l testLog
	l.extend(t, 3)

	t.Run("tile", func(t *testing.T) {
		tile := tlog.Tile{H: TileHeight, L: 0, N: 0, W: 3}
		steps := recordDurableSteps(t, log, tile.Path(), l.tileData(tile))
		mustNil(t, s.WriteTile(tile, l.tileData(tile)))
		want := []string{"write temp", "sync file", "rename", "sync dir tile/8/0/000.p",
			"sync dir tile/8/0", "sync dir tile/8", "sync dir tile", "sync dir ."}
		if !slices.Equal(*steps, want) {
			t.Fatalf("got %q, want %q", *steps, want)
		}
	})
	t.Run("full tile", func(t *testing.T) {
		// A new store: no partial file is there to delete afterwards.
		state, dir := newLogState(t)
		s := openStore(t, state)
		var l testLog
		l.extend(t, fullWidth)
		tile := tlog.Tile{H: TileHeight, L: 0, N: 0, W: fullWidth}
		steps := recordDurableSteps(t, filepath.Join(dir, "tlog"), tile.Path(), l.tileData(tile))
		mustNil(t, s.WriteTile(tile, l.tileData(tile)))
		// The full tile and its temporary file are in the level directory.
		want := []string{"write temp", "sync file", "rename", "sync dir tile/8/0",
			"sync dir tile/8", "sync dir tile", "sync dir ."}
		if !slices.Equal(*steps, want) {
			t.Fatalf("got %q, want %q", *steps, want)
		}
	})
	t.Run("tree head", func(t *testing.T) {
		var head [headSize]byte
		binary.BigEndian.PutUint64(head[:], 3)
		root := l.root(t, 3)
		copy(head[sizeLen:], root[:])
		steps := recordDurableSteps(t, log, headName, head[:])
		mustNil(t, s.SetHead(3, root))
		want := []string{"write temp", "sync file", "rename", "sync dir ."}
		if !slices.Equal(*steps, want) {
			t.Fatalf("got %q, want %q", *steps, want)
		}
	})
}

// A new log has a tree head of size 0 before the first tile is written.
func TestTU07OpenWritesEmptyHead(t *testing.T) {
	state, dir := newLogState(t)
	s := openStore(t, state)
	var want [headSize]byte
	copy(want[sizeLen:], emptyRoot[:])
	if got, err := os.ReadFile(filepath.Join(dir, "tlog", headName)); err != nil || !bytes.Equal(got, want[:]) {
		t.Fatalf("head file after the first Open: %x, %v", got, err)
	}
	// A crash after the first tile and before the first tree head.
	var l testLog
	l.put(t, s, 0, 3)
	s.Close()
	s = openStore(t, state)
	if size, root := s.TreeHead(); size != 0 || root != emptyRoot {
		t.Fatalf("size %d, root %x", size, root)
	}
	// The log grows with other records over the stale tiles.
	o := l.fork(t, 0, "other")
	o.commit(t, s, 0, 5)
}

func TestTU07OpenWithLeftoverHeadTemporaryFile(t *testing.T) {
	state, dir := newLogState(t)
	mustNil(t, os.Mkdir(filepath.Join(dir, "tlog"), dirMode))
	mustNil(t, os.WriteFile(filepath.Join(dir, "tlog", headName+tmpSuffix), []byte("x"), fileMode))
	s := openStore(t, state)
	if size, root := s.TreeHead(); size != 0 || root != emptyRoot {
		t.Fatalf("size %d, root %x", size, root)
	}
	if _, err := os.Stat(filepath.Join(dir, "tlog", headName+tmpSuffix)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the temporary file stays: %v", err)
	}
}

// No head and a file that is not the temporary file of the head means loss or
// tampering. Open does not repair it.
func TestTS13OpenRefusesTilesWithoutHead(t *testing.T) {
	state, dir := newLogState(t)
	mustNil(t, os.Mkdir(filepath.Join(dir, "tlog"), dirMode))
	mustNil(t, os.WriteFile(filepath.Join(dir, "tlog", headName+tmpSuffix), []byte("x"), fileMode))
	mustNil(t, os.WriteFile(filepath.Join(dir, "tlog", "other"), nil, fileMode))
	snapshot := tree(t, dir)
	_, err := Open(state, "tlog")
	var e *Error
	if !errors.As(err, &e) || e.Rule != ruleEmpty || e.Name != headName {
		t.Fatalf("got %v", err)
	}
	if tree(t, dir) != snapshot {
		t.Fatal("Open changed the files")
	}
}

// A size above the limit is an error before any hash is computed. x/mod does
// not end for a size above 2^62.
func TestTS13HugeTreeSizeIsAnError(t *testing.T) {
	for _, size := range []uint64{maxSize + 1, 1 << 62, 1<<63 - 1, 1 << 63, 1<<64 - 1} {
		state, dir := newLogState(t)
		openStore(t, state).Close()
		var b [headSize]byte
		binary.BigEndian.PutUint64(b[:], size)
		mustNil(t, os.WriteFile(filepath.Join(dir, "tlog", headName), b[:], fileMode))
		err := within(t, func() error { _, err := Open(state, "tlog"); return err })
		var e *Error
		if !errors.As(err, &e) || e.Rule != ruleSize || e.Name != headName {
			t.Fatalf("size %d: %v", size, err)
		}
	}
	state, _ := newLogState(t)
	s := openStore(t, state)
	for _, size := range []int64{maxSize + 1, 1 << 62, math.MaxInt64} {
		err := within(t, func() error { return s.SetHead(size, tlog.Hash{}) })
		var e *Error
		if !errors.As(err, &e) || e.Rule != ruleSize {
			t.Fatalf("SetHead(%d): %v", size, err)
		}
	}
}

// within runs f and fails the test if f does not return in a short time.
func within(t *testing.T, f func() error) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- f() }()
	select {
	case err := <-done:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("call did not return")
		return nil
	}
}

func TestTU07FullTileIsNeverWrittenAgain(t *testing.T) {
	state, dir := newLogState(t)
	s := openStore(t, state)
	var l testLog
	l.commit(t, s, 0, 256)
	tile := tlog.Tile{H: TileHeight, L: 0, N: 0, W: fullWidth}
	file := filepath.Join(dir, "tlog", tile.Path())
	before, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.WriteTile(tile, before); err != nil {
		t.Fatalf("same bytes: %v", err)
	}
	other := bytes.Clone(before)
	other[0] ^= 1
	err = s.WriteTile(tile, other)
	var e *Error
	if !errors.As(err, &e) || e.Rule != ruleRewrite || e.Name != tile.Path() {
		t.Fatalf("other bytes: %v", err)
	}
	if after, _ := os.ReadFile(file); !bytes.Equal(after, before) {
		t.Fatal("the full tile changed")
	}
}

func TestTU07OnePartialFileForEachTile(t *testing.T) {
	state, dir := newLogState(t)
	s := openStore(t, state)
	var l testLog
	var from int64
	for _, n := range []int64{1, 2, 5, 256, 300} {
		l.commit(t, s, from, n)
		from = n
		perTile := map[string]int{}
		filepath.WalkDir(filepath.Join(dir, "tlog", "tile"), func(p string, d fs.DirEntry, _ error) error {
			if !d.IsDir() && strings.HasSuffix(filepath.Dir(p), ".p") {
				perTile[filepath.Dir(p)]++
			}
			return nil
		})
		for tile, count := range perTile {
			if count > 1 {
				t.Fatalf("size %d: %d partial files for %s", n, count, tile)
			}
		}
		full := filepath.Join(dir, "tlog", "tile", "8", "0", "000.p")
		if n >= 256 && perTile[full] != 0 {
			t.Fatalf("size %d: the full tile has a partial file", n)
		}
	}
}

func TestTS13OpenRejectsBadFiles(t *testing.T) {
	const size = 600
	// TreeHash at this size reads these two tiles.
	tail := tlog.Tile{H: TileHeight, L: 0, N: 2, W: size - 512}
	upper := tlog.Tile{H: TileHeight, L: 1, N: 0, W: 2}
	cases := []struct {
		name, file, rule string
		change           func(t *testing.T, file string)
	}{
		{"changed tile", upper.Path(), ruleRoot, func(t *testing.T, f string) { flipByte(t, f, 40) }},
		{"changed partial tile", tail.Path(), ruleRoot, func(t *testing.T, f string) { flipByte(t, f, 0) }},
		{"short tile", tail.Path(), ruleLength, func(t *testing.T, f string) { mustNil(t, os.Truncate(f, 64)) }},
		{"missing tile", upper.Path(), ruleMissing, func(t *testing.T, f string) { mustNil(t, os.Remove(f)) }},
		{"other root", headName, ruleRoot, func(t *testing.T, f string) { flipByte(t, f, 20) }},
		{"short head", headName, ruleHead, func(t *testing.T, f string) { mustNil(t, os.Truncate(f, 39)) }},
		{"missing head", headName, ruleEmpty, func(t *testing.T, f string) { mustNil(t, os.Remove(f)) }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			state, dir := newLogState(t)
			s := openStore(t, state)
			var l testLog
			l.commit(t, s, 0, size)
			s.Close()
			// A temporary file of the store stays too.
			mustNil(t, os.WriteFile(filepath.Join(dir, "tlog", tail.Path()+tmpSuffix), []byte("x"), fileMode))
			file := filepath.Join(dir, "tlog", c.file)
			c.change(t, file)
			snapshot := tree(t, dir)
			_, err := Open(state, "tlog")
			if err == nil {
				t.Fatal("open succeeded")
			}
			text := err.Error()
			if !strings.Contains(text, c.rule) || (c.file != headName && !strings.Contains(text, c.file)) {
				t.Fatalf("error does not name the file and the rule: %q", text)
			}
			raw, _ := os.ReadFile(file)
			for _, enc := range []string{
				hex.EncodeToString(raw),
				base64.StdEncoding.EncodeToString(raw),
				base64.URLEncoding.EncodeToString(raw),
				base64.RawStdEncoding.EncodeToString(raw),
			} {
				if len(raw) > 0 && strings.Contains(text, enc) {
					t.Fatalf("error holds file bytes: %q", text)
				}
			}
			if after := tree(t, dir); after != snapshot {
				t.Fatal("open changed the files")
			}
		})
	}
}

func TestTS13StoreNeverChangesModes(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("no source files: %v", err)
	}
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, call := range []string{"Chmod", "Chown", "Chtimes"} {
			if bytes.Contains(src, []byte(call)) {
				t.Errorf("%s names %s", file, call)
			}
		}
	}
}

// The error names the file that failed, not the narrower file that the reader
// asked for first. The name is never empty.
func TestTS13ErrorNamesTheFileThatFailed(t *testing.T) {
	state, dir := newLogState(t)
	s := openStore(t, state)
	var l testLog
	l.commit(t, s, 0, 600)
	s.Close()
	// The root computation reads the partial tile of width 88. A short file of
	// width 100 replaces it.
	tail := tlog.Tile{H: TileHeight, L: 0, N: 2, W: 88}
	wide := tail
	wide.W = 100
	mustNil(t, os.Remove(filepath.Join(dir, "tlog", tail.Path())))
	mustNil(t, os.WriteFile(filepath.Join(dir, "tlog", wide.Path()), make([]byte, 64), fileMode))
	_, err := Open(state, "tlog")
	var e *Error
	if !errors.As(err, &e) || e.Name != wide.Path() || e.Rule != ruleLength {
		t.Fatalf("got %v", err)
	}

	state, _ = newLogState(t)
	s = openStore(t, state)
	err = s.SetHead(0, tlog.Hash{1})
	if !errors.As(err, &e) || e.Name != headName || e.Rule != ruleRoot {
		t.Fatalf("wrong root for size 0: %v", err)
	}
}

// crashAfterTiles returns a store with a tree head of size head and the tiles
// up to size more, written by the log l, and the same store after a restart.
func crashAfterTiles(t *testing.T, head, more int64) (*os.Root, string, *testLog, *Store) {
	t.Helper()
	state, dir := newLogState(t)
	s := openStore(t, state)
	var l testLog
	l.commit(t, s, 0, head)
	l.put(t, s, head, more)
	s.Close()
	return state, dir, &l, openStore(t, state)
}

// Hashes beyond the tree head are not committed. After a crash, the log grows
// with other records over them, in the same partial width and in the full tile.
func TestTU07CrashAfterTilesThenOtherRecords(t *testing.T) {
	for _, to := range []int64{5, 256, 300} {
		_, _, l, s := crashAfterTiles(t, 3, to)
		o := l.fork(t, 3, "other")
		o.commit(t, s, 3, to)
		if size, root := s.TreeHead(); size != to || root != o.root(t, to) {
			t.Fatalf("size %d: head %d, %x", to, size, root)
		}
	}
}

// A stale file is wider than the new write and differs only beyond the tree
// head. The store writes the new file, then deletes the stale file.
func TestTU07NarrowerWriteReplacesStaleWiderFile(t *testing.T) {
	for _, stale := range []int64{5, 256} {
		state, dir, l, s := crashAfterTiles(t, 3, stale)
		o := l.fork(t, 3, "other")
		o.commit(t, s, 3, 4)
		if names := partialFiles(t, dir); !slices.Equal(names, []string{"4"}) {
			t.Fatalf("stale %d: files after the write: %v", stale, names)
		}
		full := tlog.Tile{H: TileHeight, L: 0, N: 0, W: fullWidth}
		if _, err := os.Stat(filepath.Join(dir, "tlog", full.Path())); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("stale %d: the stale full tile stays: %v", stale, err)
		}
		s.Close()
		s = openStore(t, state)
		if size, root := s.TreeHead(); size != 4 || root != o.root(t, 4) {
			t.Fatalf("stale %d: size %d, root %x", stale, size, root)
		}
		if names := partialFiles(t, dir); !slices.Equal(names, []string{"4"}) {
			t.Fatalf("stale %d: files after Open: %v", stale, names)
		}
	}
}

// A write that changes a covered hash is an error, at every width.
func TestTU07CoveredHashesNeverChange(t *testing.T) {
	cases := []struct {
		name         string
		head, stored int64
		width        int
	}{
		{"same width", 5, 5, 5},
		{"narrower than head", 5, 5, 3},
		{"wider than head", 5, 5, 7},
		{"wider than the stored file", 3, 3, 5},
		{"narrower than a wider stored file", 3, 5, 4},
		{"narrower after the full tile", 256, 256, 3},
		{"full tile", 256, 256, 256},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			state, dir := newLogState(t)
			s := openStore(t, state)
			var l testLog
			l.commit(t, s, 0, c.head)
			l.put(t, s, c.head, c.stored)
			// The first 3 records are other records: they differ in covered hashes.
			o := l.fork(t, 0, "other")
			o.extend(t, 300)
			tile := tlog.Tile{H: TileHeight, L: 0, N: 0, W: c.width}
			before := tree(t, dir)
			err := s.WriteTile(tile, o.tileData(tile))
			var e *Error
			if !errors.As(err, &e) || e.Rule != ruleRewrite || !strings.HasPrefix(e.Name, "tile/8/0/000") {
				t.Fatalf("got %v", err)
			}
			if tree(t, dir) != before {
				t.Fatal("the failed write changed a file")
			}
		})
	}
}

// A narrower write that matches the stored hashes is accepted and makes no file.
func TestTU07NarrowerMatchingWriteMakesNoFile(t *testing.T) {
	state, dir := newLogState(t)
	s := openStore(t, state)
	var l testLog
	l.commit(t, s, 0, 5)
	before := tree(t, dir)
	tile := tlog.Tile{H: TileHeight, L: 0, N: 0, W: 3}
	mustNil(t, s.WriteTile(tile, l.tileData(tile)))
	if tree(t, dir) != before {
		t.Fatal("the write changed a file")
	}
}

// SetHead refuses a new head if the tiles no longer give the stored head.
func TestTU07SetHeadChecksTheStoredHead(t *testing.T) {
	state, dir := newLogState(t)
	s := openStore(t, state)
	var l testLog
	l.commit(t, s, 0, 3)
	// A wider file with correct hashes. It is not a write through the store.
	l.extend(t, 5)
	wide := tlog.Tile{H: TileHeight, L: 0, N: 0, W: 5}
	mustNil(t, os.WriteFile(filepath.Join(dir, "tlog", wide.Path()), l.tileData(wide), fileMode))
	root := l.root(t, 5)
	// The file of the stored head changes in a covered hash.
	flipByte(t, filepath.Join(dir, "tlog", tlog.Tile{H: TileHeight, L: 0, N: 0, W: 3}.Path()), 0)
	err := s.SetHead(5, root)
	var e *Error
	if !errors.As(err, &e) || e.Rule != ruleRoot {
		t.Fatalf("got %v", err)
	}
	if size, _ := s.TreeHead(); size != 3 {
		t.Fatalf("size %d", size)
	}
}

// SetHead refuses a tree head if a stored file of a tile that the new root
// computation reads has other hashes in the range that the new head covers. The
// next Open would refuse that head. A refused call changes no file.
func TestTU07SetHeadRefusesFilesThatDisagree(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, s *Store, dir string, l *testLog) (size int64, other *testLog)
	}{
		{"planted wider file with other records", func(t *testing.T, s *Store, dir string, l *testLog) (int64, *testLog) {
			l.commit(t, s, 0, 3)
			o := l.fork(t, 0, "forged")
			o.extend(t, 5)
			wide := tlog.Tile{H: TileHeight, L: 0, N: 0, W: 5}
			mustNil(t, os.WriteFile(filepath.Join(dir, "tlog", wide.Path()), o.tileData(wide), fileMode))
			return 5, o
		}},
		{"stored file of the lost batch next to a file with other records", func(t *testing.T, s *Store, dir string, l *testLog) (int64, *testLog) {
			l.commit(t, s, 0, 3)
			l.put(t, s, 3, 9)
			o := l.fork(t, 3, "other")
			o.extend(t, 5)
			w5 := tlog.Tile{H: TileHeight, L: 0, N: 0, W: 5}
			mustNil(t, os.WriteFile(filepath.Join(dir, "tlog", w5.Path()), o.tileData(w5), fileMode))
			return 5, o
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			state, dir := newLogState(t)
			s := openStore(t, state)
			var l testLog
			size, other := c.setup(t, s, dir, &l)
			before := tree(t, dir)
			err := s.SetHead(size, other.root(t, size))
			var e *Error
			if !errors.As(err, &e) || e.Rule != ruleRewrite {
				t.Fatalf("got %v", err)
			}
			if n, _ := s.TreeHead(); n != 3 || tree(t, dir) != before {
				t.Fatalf("a refused SetHead changed the head (%d) or a file", n)
			}
		})
	}
}

// After a crash, the hashes of a lost batch are in a tile file, but this Store
// did not write them. SetHead refuses them until WriteTile accepts the same
// hashes.
func TestTU07SetHeadRefusesHashesThatThisStoreDidNotWrite(t *testing.T) {
	_, dir, l, s := crashAfterTiles(t, 3, 5)
	headFile := filepath.Join(dir, "tlog", headName)
	before, err := os.ReadFile(headFile)
	mustNil(t, err)
	err = s.SetHead(4, l.root(t, 4))
	var e *Error
	if !errors.As(err, &e) || e.Rule != ruleUnwritten {
		t.Fatalf("got %v", err)
	}
	if after, _ := os.ReadFile(headFile); !bytes.Equal(after, before) {
		t.Fatal("a refused SetHead changed the head file")
	}
	// The same records again: WriteTile finds the hashes in the wider file and
	// makes no file.
	tile := tlog.Tile{H: TileHeight, L: 0, N: 0, W: 4}
	files := tree(t, dir)
	mustNil(t, s.WriteTile(tile, l.tileData(tile)))
	if tree(t, dir) != files {
		t.Fatal("the write changed a file")
	}
	mustNil(t, s.SetHead(4, l.root(t, 4)))
	if len(s.written) != 0 {
		t.Fatalf("written tiles stay after SetHead: %v", s.written)
	}
}

func TestTU07WriteTileCountsTilesOfOneBatch(t *testing.T) {
	state, dir := newLogState(t)
	s := openStore(t, state)
	var l testLog
	l.extend(t, 300)
	for i := range maxBatchTiles {
		s.written[tlog.Tile{H: TileHeight, L: 0, N: int64(i) + 1000}] = 1
	}
	before := tree(t, dir)
	tile := tlog.Tile{H: TileHeight, L: 0, N: 0, W: 3}
	var e *Error
	if err := s.WriteTile(tile, l.tileData(tile)); !errors.As(err, &e) || e.Rule != ruleBatch || tree(t, dir) != before {
		t.Fatalf("got %v", err)
	}
	// A tile of the batch can be written again.
	tile.N = 1000
	s.written[tileKey(tile)] = 1
	mustNil(t, s.WriteTile(tile, make([]byte, 3*tlog.HashSize)))
}

// dirNames returns the names in the directory dir.
func dirNames(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	mustNil(t, err)
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	return names
}

// After a crash, a tile beyond the tree head can have two partial files. Open
// tidies the tiles from the first tile beyond the head up to maxBatchTiles
// tiles above it. It does not read a tile outside this range.
func TestTS13OpenTidiesTilesBeyondTheHeadOnlyInRange(t *testing.T) {
	state, dir := newLogState(t)
	s := openStore(t, state)
	var a testLog
	a.commit(t, s, 0, 256) // the first tile beyond the head is tile 1
	s.Close()
	plant := func(n int64) string {
		var partial string
		for _, w := range []int{3, 5} {
			file := filepath.Join(dir, "tlog", tlog.Tile{H: TileHeight, L: 0, N: n, W: w}.Path())
			partial = filepath.Dir(file)
			mustNil(t, os.MkdirAll(partial, dirMode))
			mustNil(t, os.WriteFile(file, make([]byte, w*tlog.HashSize), fileMode))
		}
		return partial
	}
	first, last := plant(1), plant(1+maxBatchTiles)
	outside := plant(2 + maxBatchTiles)
	openStore(t, state)
	for _, p := range []string{first, last} {
		if got := dirNames(t, p); !slices.Equal(got, []string{"5"}) {
			t.Fatalf("files of %s after Open: %v", p, got)
		}
	}
	if got := dirNames(t, outside); !slices.Equal(got, []string{"3", "5"}) {
		t.Fatalf("Open changed the tile outside the range: %v", got)
	}
	t.Run("not read", openSkipsATileOutsideTheRange)
}

// openSkipsATileOutsideTheRange shows that Open refuses a tile file with a
// wrong length in the range beyond the tree head. The same file outside it
// stays, because Open does not read it.
func openSkipsATileOutsideTheRange(t *testing.T) {
	state, dir := newLogState(t)
	s := openStore(t, state)
	var a testLog
	a.commit(t, s, 0, 256) // the first tile beyond the head is tile 1
	s.Close()
	// plant makes a good file of width 3 and a file of width 5 that holds four
	// hashes. A read of the second file gives a length error.
	plant := func(n int64) (string, []byte) {
		var bad string
		for _, w := range []int{3, 5} {
			file := filepath.Join(dir, "tlog", tlog.Tile{H: TileHeight, L: 0, N: n, W: w}.Path())
			size := w * tlog.HashSize
			if w == 5 {
				size = 4 * tlog.HashSize
			}
			mustNil(t, os.MkdirAll(filepath.Dir(file), dirMode))
			mustNil(t, os.WriteFile(file, make([]byte, size), fileMode))
			bad = file
		}
		b, err := os.ReadFile(bad)
		mustNil(t, err)
		return bad, b
	}
	outside, content := plant(2 + maxBatchTiles)
	before := tree(t, dir)
	openStore(t, state).Close()
	if tree(t, dir) != before {
		t.Fatal("Open changed a file outside the range")
	}
	if got, err := os.ReadFile(outside); err != nil || !bytes.Equal(got, content) {
		t.Fatalf("the file outside the range changed: %v", err)
	}
	// Control: the same file in the range gives an error.
	plant(1 + maxBatchTiles)
	s, err := Open(state, "tlog")
	if err == nil {
		s.Close()
		t.Fatal("Open accepted a wrong length file in the range")
	}
	bad := tlog.Tile{H: TileHeight, L: 0, N: 1 + maxBatchTiles, W: 5}.Path()
	var e *Error
	if !errors.As(err, &e) || e.Rule != ruleLength || e.Name != bad {
		t.Fatalf("got %v, want the rule %q for %s", err, ruleLength, bad)
	}
}

// A log that Open accepts can have more than 8 million leaves. Its level 0
// tiles are then in more than 32 group directories. Open must succeed. The
// names that it reads depend on the bound for the tiles beyond the head. They
// do not depend on the size of the log. The test builds the tiles of level 1
// and above from arbitrary hashes of the subtrees of 256 leaves. It links one
// file for all tiles of level 0. Open does not read the tiles of level 0,
// because the size is a multiple of 256.
func TestTS13OpenSucceedsWhenTilesSpanManyGroupDirectories(t *testing.T) {
	const tiles = 33*groupTiles + 1
	state, dir := newLogState(t)
	openStore(t, state).Close()
	var m testLog // the tree over the hashes of the subtrees of 256 leaves
	for j := range int64(tiles) {
		h := tlog.Hash(sha256.Sum256(binary.BigEndian.AppendUint64(nil, uint64(j))))
		hs, err := tlog.StoredHashesForRecordHash(j, h, &m)
		mustNil(t, err)
		m.hashes = append(m.hashes, hs...)
	}
	size := int64(tiles) * fullWidth
	log := filepath.Join(dir, "tlog")
	base := filepath.Join(log, "base")
	mustNil(t, os.WriteFile(base, make([]byte, fullWidth*tlog.HashSize), fileMode))
	for _, tile := range tlog.NewTiles(TileHeight, 0, size) {
		file := filepath.Join(log, tile.Path())
		mustNil(t, os.MkdirAll(filepath.Dir(file), dirMode))
		if tile.L == 0 {
			mustNil(t, os.Link(base, file))
			continue
		}
		up := tlog.Tile{H: TileHeight, L: tile.L - 1, N: tile.N, W: tile.W}
		mustNil(t, os.WriteFile(file, m.tileData(up), fileMode))
	}
	mustNil(t, os.Remove(base))
	head := binary.BigEndian.AppendUint64(nil, uint64(size))
	root := m.root(t, tiles)
	mustNil(t, os.WriteFile(filepath.Join(log, headName), append(head, root[:]...), fileMode))
	groups := 0
	for _, name := range dirNames(t, filepath.Join(log, "tile", "8", "0")) {
		if strings.HasPrefix(name, "x") {
			groups++
		}
	}
	if groups <= 32 {
		t.Fatalf("only %d group directories", groups)
	}
	if n, got := openStore(t, state).TreeHead(); n != size || got != root {
		t.Fatalf("Open gave %d, %x", n, got)
	}
}

// At most one partial file stays for a tile after a write of the tile, and after
// an Open that reads the tile.
func TestTU07OnePartialFileStaysAfterWriteAndAfterOpenThatReadsTheTile(t *testing.T) {
	state, dir := newLogState(t)
	s := openStore(t, state)
	var l testLog
	l.commit(t, s, 0, 3)
	l.put(t, s, 3, 5)
	if names := partialFiles(t, dir); !slices.Equal(names, []string{"5"}) {
		t.Fatalf("files after the write: %v", names)
	}
	s.Close()
	// A crash between the rename of width 5 and the delete of width 3.
	narrow := tlog.Tile{H: TileHeight, L: 0, N: 0, W: 3}
	mustNil(t, os.WriteFile(filepath.Join(dir, "tlog", narrow.Path()), l.tileData(narrow), fileMode))
	if names := partialFiles(t, dir); !slices.Equal(names, []string{"3", "5"}) {
		t.Fatalf("files after the crash: %v", names)
	}
	openStore(t, state)
	if names := partialFiles(t, dir); !slices.Equal(names, []string{"5"}) {
		t.Fatalf("files after Open: %v", names)
	}
}

func TestTU07DirectoryWithTooManyNamesIsAnError(t *testing.T) {
	fill := func(t *testing.T, dir string, from, n int) {
		for i := from; i < from+n; i++ {
			mustNil(t, os.WriteFile(filepath.Join(dir, fmt.Sprintf("junk%d", i)), nil, fileMode))
		}
	}
	const rel = "tile/8/0/000.p"
	state, dir := committedLog(t, 3)
	names, err := os.ReadDir(filepath.Join(dir, "tlog", rel))
	mustNil(t, err)
	fill(t, filepath.Join(dir, "tlog", rel), 0, maxPartialNames-len(names))
	openStore(t, state) // the limit is allowed
	fill(t, filepath.Join(dir, "tlog", rel), maxPartialNames, 1)
	if e := openErr(t, state, ruleTooMany); e.Name != rel {
		t.Fatalf("name %q", e.Name)
	}
}

// Open and WriteTile delete the temporary file of a full tile, which is in the
// level directory.
func TestTU07TidyDeletesTemporaryFileOfFullTile(t *testing.T) {
	state, dir := committedLog(t, 3) // Open reads tile 0
	full := filepath.Join(dir, "tlog", tlog.Tile{H: TileHeight, L: 0, N: 0, W: fullWidth}.Path()+tmpSuffix)
	mustNil(t, os.WriteFile(full, []byte("x"), fileMode))
	s := openStore(t, state)
	if _, err := os.Lstat(full); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("open: the temporary file stays: %v", err)
	}
	var l testLog
	l.extend(t, 258)
	next := tlog.Tile{H: TileHeight, L: 0, N: 1, W: 2}
	tmp := filepath.Join(dir, "tlog", tlog.Tile{H: TileHeight, L: 0, N: 1, W: fullWidth}.Path()+tmpSuffix)
	mustNil(t, os.WriteFile(tmp, []byte("x"), fileMode))
	mustNil(t, s.WriteTile(next, l.tileData(next)))
	if _, err := os.Lstat(tmp); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("write: the temporary file stays: %v", err)
	}
}

func TestTU07TileCoordinateBound(t *testing.T) {
	state, _ := newLogState(t)
	s := openStore(t, state)
	one := make([]byte, tlog.HashSize)
	for _, c := range []struct {
		l    int
		n    int64
		fail bool
	}{{0, 1 << 40, true}, {0, 1<<40 - 1, false}, {6, 0, false}, {6, 1, true}, {7, 0, true}} {
		err := s.WriteTile(tlog.Tile{H: TileHeight, L: c.l, N: c.n, W: 1}, one)
		var e *Error
		if bad := errors.As(err, &e) && e.Rule == ruleTile; bad != c.fail {
			t.Errorf("level %d, tile %d: %v", c.l, c.n, err)
		}
	}
}

// Open checks all files before it deletes one. A failed check deletes nothing,
// not even a temporary file.
func TestTU07OpenFailureDeletesNothing(t *testing.T) {
	state, dir := newLogState(t)
	s := openStore(t, state)
	var l testLog
	l.commit(t, s, 0, 3)
	l.put(t, s, 3, 5)
	s.Close()
	t3 := tlog.Tile{H: TileHeight, L: 0, N: 0, W: 3}
	t5 := tlog.Tile{H: TileHeight, L: 0, N: 0, W: 5}
	mustNil(t, os.WriteFile(filepath.Join(dir, "tlog", t3.Path()), l.tileData(t3), fileMode))
	flipByte(t, filepath.Join(dir, "tlog", t5.Path()), 0)
	for _, tmp := range []string{t5.Path(), tlog.Tile{H: TileHeight, L: 0, N: 0, W: fullWidth}.Path()} {
		mustNil(t, os.WriteFile(filepath.Join(dir, "tlog", tmp+tmpSuffix), []byte("x"), fileMode))
	}
	before := tree(t, dir)
	openErr(t, state, ruleRewrite)
	if tree(t, dir) != before {
		t.Fatal("a failed open changed a file")
	}
}

// The file that a rename replaces must agree in the covered hashes too.
func TestTU07WriteRefusesToReplaceAFileWithOtherCoveredHashes(t *testing.T) {
	state, dir := newLogState(t)
	s := openStore(t, state)
	var l testLog
	l.commit(t, s, 0, 3)
	l.put(t, s, 3, 9)
	o := l.fork(t, 0, "other")
	o.extend(t, 4)
	w4 := tlog.Tile{H: TileHeight, L: 0, N: 0, W: 4}
	mustNil(t, os.WriteFile(filepath.Join(dir, "tlog", w4.Path()), o.tileData(w4), fileMode))
	// The new data has the covered hashes of the widest file.
	f := l.fork(t, 3, "x")
	f.extend(t, 4)
	before := tree(t, dir)
	err := s.WriteTile(w4, f.tileData(w4))
	var e *Error
	if !errors.As(err, &e) || e.Rule != ruleRewrite || e.Name != w4.Path() || tree(t, dir) != before {
		t.Fatalf("got %v", err)
	}
}

// partialFiles returns the names in the partial directory of tile 0 at level 0.
func partialFiles(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(filepath.Join(dir, "tlog", "tile", "8", "0", "000.p"))
	mustNil(t, err)
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	return names
}

func TestTU07OpenDeletesNarrowerPartialFile(t *testing.T) {
	state, dir := newLogState(t)
	s := openStore(t, state)
	var l testLog
	l.commit(t, s, 0, 3)
	l.put(t, s, 3, 5)
	s.Close()
	// A crash between the rename of width 5 and the delete of width 3.
	narrow := tlog.Tile{H: TileHeight, L: 0, N: 0, W: 3}
	mustNil(t, os.WriteFile(filepath.Join(dir, "tlog", narrow.Path()), l.tileData(narrow), fileMode))
	mustNil(t, os.WriteFile(filepath.Join(dir, "tlog", narrow.Path()+tmpSuffix), []byte("x"), fileMode))
	openStore(t, state)
	if names := partialFiles(t, dir); !slices.Equal(names, []string{"5"}) {
		t.Fatalf("files after Open: %v", names)
	}
}

// Open tidies the tiles beyond the head in two partial directories that share
// their parents. It calls fsync on each of these directories one time.
func TestTU07OpenSyncsSharedParentsOnce(t *testing.T) {
	state, dir := newLogState(t)
	openStore(t, state).Close()
	for n := int64(1); n <= 2; n++ {
		file := filepath.Join(dir, "tlog", tlog.Tile{H: TileHeight, L: 0, N: n, W: 1}.Path())
		mustNil(t, os.MkdirAll(filepath.Dir(file), dirMode))
		mustNil(t, os.WriteFile(file, make([]byte, tlog.HashSize), fileMode))
	}
	counts := map[string]int{}
	setHooks(t, hooks{dir: func(f *os.File) error {
		counts[filepath.Clean(f.Name())]++
		return realSync(f)
	}})
	openStore(t, state)
	// Open calls fsync on the log directory two times: for the tree head and
	// for the tidy.
	logDir := filepath.Join(dir, "tlog")
	for name, n := range counts {
		want := 1
		if name == logDir {
			want = 2
		}
		if n != want {
			t.Errorf("fsync of %s: %d calls, want %d", name, n, want)
		}
	}
	if len(counts) < 3 {
		t.Fatalf("fsync calls: %v, want the shared parents and the partial directories", counts)
	}
}

func TestTU07WriteDeletesLeftoverFilesOfTheTile(t *testing.T) {
	state, dir := newLogState(t)
	s := openStore(t, state)
	var l testLog
	l.commit(t, s, 0, 600)
	// The root computation does not read tile 0. Open does not clean it.
	narrow := tlog.Tile{H: TileHeight, L: 0, N: 0, W: 2}
	mustNil(t, os.MkdirAll(filepath.Join(dir, "tlog", filepath.Dir(narrow.Path())), dirMode))
	mustNil(t, os.WriteFile(filepath.Join(dir, "tlog", narrow.Path()), l.tileData(narrow), fileMode))
	mustNil(t, os.WriteFile(filepath.Join(dir, "tlog", narrow.Path()+tmpSuffix), []byte("x"), fileMode))
	full := tlog.Tile{H: TileHeight, L: 0, N: 0, W: fullWidth}
	mustNil(t, s.WriteTile(full, l.tileData(full)))
	if names := partialFiles(t, dir); len(names) != 0 {
		t.Fatalf("files after the write: %v", names)
	}
}

// The store deletes a narrower file only if a wider file has the same covered
// hashes. If not, the narrower file can be the only copy of them.
func TestTU07NeverDeletesTheOnlyCopyOfCoveredHashes(t *testing.T) {
	state, dir := newLogState(t)
	s := openStore(t, state)
	var l testLog
	l.commit(t, s, 0, 3)
	s.Close()
	o := l.fork(t, 0, "other")
	o.extend(t, 5)
	wide := tlog.Tile{H: TileHeight, L: 0, N: 0, W: 5}
	mustNil(t, os.WriteFile(filepath.Join(dir, "tlog", wide.Path()), o.tileData(wide), fileMode))
	_, err := Open(state, "tlog")
	var e *Error
	if !errors.As(err, &e) || e.Rule != ruleRewrite {
		t.Fatalf("got %v", err)
	}
	if names := partialFiles(t, dir); !slices.Equal(names, []string{"3", "5"}) {
		t.Fatalf("files after Open: %v", names)
	}
}

// The store accepts a partial width only if the name is the width in decimal.
func TestTU07PartialNameMustBeTheWidth(t *testing.T) {
	state, dir := newLogState(t)
	s := openStore(t, state)
	var l testLog
	l.commit(t, s, 0, 3)
	l.put(t, s, 3, 5)
	s.Close()
	narrow := tlog.Tile{H: TileHeight, L: 0, N: 0, W: 3}
	for _, name := range []string{"03", "+3", "3x"} {
		mustNil(t, os.WriteFile(filepath.Join(dir, "tlog", filepath.Dir(narrow.Path()), name), l.tileData(narrow), fileMode))
	}
	openStore(t, state)
	if names := partialFiles(t, dir); !slices.Equal(names, []string{"+3", "03", "3x", "5"}) {
		t.Fatalf("files after Open: %v", names)
	}
}

func flipByte(t *testing.T, file string, at int) {
	t.Helper()
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	b[at] ^= 1
	mustNil(t, os.WriteFile(file, b, 0o600))
}

func mustNil(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// tree returns the path and the contents (in hex) of all files below dir.
func tree(t *testing.T, dir string) string {
	t.Helper()
	var sb strings.Builder
	mustNil(t, filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		fmt.Fprintf(&sb, "%s %x\n", p, b)
		return err
	}))
	return sb.String()
}

// A move of the tree head from 3 to 600 covers the full tiles 0 and 1 for the
// first time. The new root computation does not read them. SetHead checks them
// too.
func TestTU07SetHeadChecksEveryNewlyCoveredTile(t *testing.T) {
	const to = 600
	cases := []struct {
		name  string
		setup func(t *testing.T, l *testLog) (other *testLog, skip func(tlog.Tile) bool, rule string)
		plant bool // plant a partial file with other records after the writes
	}{
		{"tiles of a lost batch that the caller did not write", func(t *testing.T, l *testLog) (*testLog, func(tlog.Tile) bool, string) {
			// The caller writes only the tiles that the root computation reads.
			return l, func(x tlog.Tile) bool { return x.L == 0 && x.W == fullWidth }, ruleUnwritten
		}, false},
		{"full tile of a lost batch next to other records", func(t *testing.T, l *testLog) (*testLog, func(tlog.Tile) bool, string) {
			o := l.fork(t, 3, "other")
			o.extend(t, to)
			return o, func(x tlog.Tile) bool { return x.L == 0 && x.N == 1 }, ruleUnwritten
		}, false},
		{"partial file with other records next to a full tile", func(t *testing.T, l *testLog) (*testLog, func(tlog.Tile) bool, string) {
			return l, func(tlog.Tile) bool { return false }, ruleRewrite
		}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			state, dir, l, s := crashAfterTiles(t, 3, to)
			other, skip, rule := c.setup(t, l)
			for _, tile := range tlog.NewTiles(TileHeight, 3, to) {
				if !skip(tile) {
					mustNil(t, s.WriteTile(tile, other.tileData(tile)))
				}
			}
			if c.plant {
				o := l.fork(t, 3, "forged")
				o.extend(t, to)
				p := tlog.Tile{H: TileHeight, L: 0, N: 1, W: 5}
				mustNil(t, os.MkdirAll(filepath.Join(dir, "tlog", filepath.Dir(p.Path())), dirMode))
				mustNil(t, os.WriteFile(filepath.Join(dir, "tlog", p.Path()), o.tileData(p), fileMode))
			}
			before := tree(t, dir)
			err := s.SetHead(to, other.root(t, to))
			var e *Error
			if !errors.As(err, &e) || e.Rule != rule {
				t.Fatalf("want rule %q, got %v", rule, err)
			}
			if n, _ := s.TreeHead(); n != 3 || tree(t, dir) != before {
				t.Fatalf("a refused SetHead changed the head (%d) or a file", n)
			}
			s.Close()
			if n, root := openStore(t, state).TreeHead(); n != 3 || root != l.root(t, 3) {
				t.Fatalf("next Open: head %d, %x", n, root)
			}
		})
	}
}

// A write of a narrower width that makes no file does not lower the recorded
// width of the tile.
func TestTU07NarrowerWriteKeepsTheRecordedWidth(t *testing.T) {
	state, _ := newLogState(t)
	s := openStore(t, state)
	var l testLog
	l.commit(t, s, 0, 3)
	l.extend(t, 5)
	for _, w := range []int{5, 4} {
		tile := tlog.Tile{H: TileHeight, L: 0, N: 0, W: w}
		mustNil(t, s.WriteTile(tile, l.tileData(tile)))
	}
	mustNil(t, s.SetHead(5, l.root(t, 5)))
}

// A stored file of the tile with other covered hashes makes WriteTile refuse
// the call. This happens before it writes the new file. No file changes.
func TestTS13WriteTileChecksOtherFilesBeforeTheWrite(t *testing.T) {
	state, dir := newLogState(t)
	s := openStore(t, state)
	var l testLog
	l.commit(t, s, 0, 3)
	l.extend(t, 5)
	forged := l.fork(t, 0, "forged")
	forged.extend(t, 2)
	bad := tlog.Tile{H: TileHeight, L: 0, N: 0, W: 2}
	mustNil(t, os.WriteFile(filepath.Join(dir, "tlog", bad.Path()), forged.tileData(bad), fileMode))
	before := tree(t, dir)
	wide := tlog.Tile{H: TileHeight, L: 0, N: 0, W: 5}
	err := s.WriteTile(wide, l.tileData(wide))
	var e *Error
	if !errors.As(err, &e) || e.Rule != ruleRewrite || e.Name != bad.Path() {
		t.Fatalf("got %v, want the rule %q for %s", err, ruleRewrite, bad.Path())
	}
	if tree(t, dir) != before {
		t.Fatal("a refused WriteTile changed a file")
	}
}

// A newly covered full tile that the root computation does not read must agree
// with the tile one level up. The tile must give the hash for it there. Here a
// stored byte of tile 1 of level 0 changed after the write.
func TestTS13SetHeadChecksNewTileAgainstTheLevelAbove(t *testing.T) {
	state, dir := newLogState(t)
	s := openStore(t, state)
	var l testLog
	l.put(t, s, 0, 2*fullWidth)
	full := tlog.Tile{H: TileHeight, L: 0, N: 1, W: fullWidth}
	flipByte(t, filepath.Join(dir, "tlog", full.Path()), 5)
	before := tree(t, dir)
	err := s.SetHead(2*fullWidth, l.root(t, 2*fullWidth))
	above := tlog.Tile{H: TileHeight, L: 1, N: 0, W: 2}
	want := full.Path() + "," + above.Path()
	var e *Error
	if !errors.As(err, &e) || e.Rule != ruleRoot || e.Name != want {
		t.Fatalf("got %v, want the rule %q for %s", err, ruleRoot, want)
	}
	if n, _ := s.TreeHead(); n != 0 || tree(t, dir) != before {
		t.Fatalf("a refused SetHead changed the head (%d) or a file", n)
	}
}

// SetHead, WriteTile, and Log.AppendBatch use one bound: at most maxBatchTiles
// tiles get new hashes between two tree heads.
func TestTU07BatchBoundEdge(t *testing.T) {
	state, _ := newLogState(t)
	s := openStore(t, state)
	// 4079 full tiles of level 0, 16 of level 1, and 1 of level 2.
	const edge = 4079 * fullWidth
	if batchTiles(0, edge) != maxBatchTiles || batchTiles(0, edge+1) != maxBatchTiles+1 {
		t.Fatalf("batchTiles: %d and %d", batchTiles(0, edge), batchTiles(0, edge+1))
	}
	if n := len(tlog.NewTiles(TileHeight, 0, edge+1)); int64(n) != batchTiles(0, edge+1) {
		t.Fatalf("batchTiles differs from NewTiles: %d", n)
	}
	rule := func(err error) string {
		var e *Error
		if !errors.As(err, &e) {
			t.Fatalf("got %v", err)
		}
		return e.Rule
	}
	// The tiles are missing, so the call stops at the first check after the
	// bound.
	if got := rule(s.SetHead(edge, tlog.Hash{})); got == ruleBatch {
		t.Fatal("SetHead refused the largest batch")
	}
	if got := rule(s.SetHead(edge+1, tlog.Hash{})); got != ruleBatch {
		t.Fatalf("SetHead gave the rule %q for one tile over the bound", got)
	}
	var l testLog
	l.extend(t, 3)
	tile := tlog.Tile{H: TileHeight, L: 0, N: 0, W: 3}
	for i := range maxBatchTiles - 1 {
		s.written[tlog.Tile{H: TileHeight, L: 0, N: int64(i) + 1000}] = 1
	}
	mustNil(t, s.WriteTile(tile, l.tileData(tile)))
	tile.N = 1
	if got := rule(s.WriteTile(tile, make([]byte, 3*tlog.HashSize))); got != ruleBatch {
		t.Fatalf("WriteTile gave the rule %q for one tile over the bound", got)
	}
}

// The rename of the head file can take effect and still return an error. Each
// error of that rename has the mark, and the head file on disk has the new tree
// head. A tile rename keeps the plain error. The orphan-leaf count of a marked
// error is the test TestTU18AppendErrorWithTheMarkCountsOrphanLeaves in
// internal/store.
func TestTS13HeadRenameErrorAfterRenameIsMarked(t *testing.T) {
	// failAfterRename makes each rename do its work and then return an error.
	failAfterRename := func(t *testing.T) {
		setHooks(t, hooks{rename: func(r *os.Root, from, to string) error {
			if err := realRename(r, from, to); err != nil {
				return err
			}
			return errors.New("injected")
		}})
	}
	t.Run("store head", func(t *testing.T) {
		state, dir := newLogState(t)
		s := openStore(t, state)
		var l testLog
		l.put(t, s, 0, 3)
		failAfterRename(t)
		err := s.SetHead(3, l.root(t, 3))
		var e *Error
		if !errors.Is(err, ErrHeadOnDisk) || !errors.As(err, &e) || e.Rule != ruleWrite {
			t.Fatalf("got %v, want the rule %q with the mark", err, ruleWrite)
		}
		if n, _ := s.TreeHead(); n != 0 {
			t.Fatalf("head in memory changed to %d", n)
		}
		if n, root := diskHead(t, dir); n != 3 || root != l.root(t, 3) {
			t.Fatalf("head on disk is %d, %x", n, root)
		}
	})
	t.Run("log append", func(t *testing.T) {
		state, dir := newLogState(t)
		l := openTestLog(t, state)
		restore := setHooks(t, hooks{rename: func(r *os.Root, from, to string) error {
			err := realRename(r, from, to)
			if err == nil && to == headName {
				err = errors.New("injected")
			}
			return err
		}})
		_, err := l.Append(testEvent(0))
		restore()
		if !errors.Is(err, ErrHeadOnDisk) {
			t.Fatalf("got %v, want the mark", err)
		}
		if n, _ := diskHead(t, dir); n != 1 {
			t.Fatalf("head on disk has size %d, want 1", n)
		}
	})
	t.Run("tile", func(t *testing.T) {
		state, _ := newLogState(t)
		s := openStore(t, state)
		failAfterRename(t)
		err := s.writeFile("tile/8/0/000.p/1", make([]byte, tlog.HashSize))
		if err == nil || errors.As(err, new(*renamedError)) {
			t.Fatalf("got %v, want the plain error", err)
		}
	})
}
