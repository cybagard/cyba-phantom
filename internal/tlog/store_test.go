package tlog

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/mod/sumdb/tlog"
)

// testLog holds every stored hash of a log in memory. It builds the tiles that
// the store gets. Append is not part of the store.
type testLog struct {
	hashes []tlog.Hash
	n      int64
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
	for ; l.n < n; l.n++ {
		hs, err := tlog.StoredHashes(l.n, []byte(fmt.Sprintf("record %d", l.n)), l)
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
		var data []byte
		for j := 0; j < tile.W; j++ {
			h := l.hashes[tlog.StoredHashIndex(tile.H*tile.L, tile.N*fullWidth+int64(j))]
			data = append(data, h[:]...)
		}
		if err := s.WriteTile(tile, data); err != nil {
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

func newState(t *testing.T) (*os.Root, string) {
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
	state, _ := newState(t)
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
	state, _ := newState(t)
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
	state, dir := newState(t)
	s := openStore(t, state)
	var l testLog
	l.extend(t, 3)
	if err := s.SetHead(3, l.root(t, 3)); err == nil {
		t.Fatal("tree head accepted with no tiles")
	}
	if _, err := os.Stat(filepath.Join(dir, "tlog", headName)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("tree head file exists: %v", err)
	}
	l.commit(t, s, 0, 3)
	if err := s.SetHead(2, l.root(t, 2)); err == nil {
		t.Fatal("tree head got smaller")
	}
}

func TestTU07FullTileIsNeverWrittenAgain(t *testing.T) {
	state, dir := newState(t)
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
	state, dir := newState(t)
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
			state, dir := newState(t)
			s := openStore(t, state)
			var l testLog
			l.commit(t, s, 0, size)
			s.Close()
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
			if raw, _ := os.ReadFile(file); len(raw) > 8 && strings.Contains(text, hex.EncodeToString(raw[:8])) {
				t.Fatalf("error holds file bytes: %q", text)
			}
			if after := tree(t, dir); after != snapshot {
				t.Fatal("open changed the files")
			}
		})
	}
}

func TestTS13StoreNeverChangesModes(t *testing.T) {
	src, err := os.ReadFile("store.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, call := range []string{".Chmod(", ".Chown(", ".Chtimes("} {
		if bytes.Contains(src, []byte(call)) {
			t.Errorf("store.go calls %s", call)
		}
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

// tree returns the names, sizes and contents of all files below dir.
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
