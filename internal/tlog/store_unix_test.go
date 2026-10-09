//go:build unix

package tlog

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/mod/sumdb/tlog"
)

func TestTS13FilesAndDirectoriesHaveFixedModes(t *testing.T) {
	state, dir := newState(t)
	s := openStore(t, state)
	var l testLog
	l.commit(t, s, 0, 300)
	mustNil(t, filepath.WalkDir(filepath.Join(dir, "tlog"), func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		fi, err := d.Info()
		want := fs.FileMode(0o600)
		if d.IsDir() {
			want = 0o700
		}
		if err == nil && fi.Mode().Perm() != want {
			t.Errorf("%s has mode %o, want %o", p, fi.Mode().Perm(), want)
		}
		return err
	}))
}

// linkOut replaces the file name (below the log directory) with a symlink to
// target outside the state directory.
func linkOut(t *testing.T, dir, name, target string) {
	t.Helper()
	link := filepath.Join(dir, "tlog", name)
	rel, err := filepath.Rel(filepath.Dir(link), target)
	mustNil(t, err)
	os.Remove(link)
	mustNil(t, os.MkdirAll(filepath.Dir(link), 0o700))
	mustNil(t, os.Symlink(rel, link))
}

func TestTS13TileSymlinkOutOfStateDirectory(t *testing.T) {
	state, dir := newState(t)
	s := openStore(t, state)
	var l testLog
	l.commit(t, s, 0, 3)
	tile := tlog.Tile{H: TileHeight, L: 0, N: 0, W: 3}
	good, err := os.ReadFile(filepath.Join(dir, "tlog", tile.Path()))
	mustNil(t, err)
	s.Close()

	// The outside file holds a correct tile. A store that follows the link
	// opens the log with no error.
	outside := filepath.Join(filepath.Dir(dir), "outside")
	mustNil(t, os.WriteFile(outside, good, 0o644))
	before, err := os.Stat(outside)
	mustNil(t, err)
	linkOut(t, dir, tile.Path(), outside)
	if _, err := Open(state, "tlog"); err == nil {
		t.Fatal("open followed a symlink out of the state directory")
	}

	// A write to a tile path that is a link to a new outside file.
	created := filepath.Join(filepath.Dir(dir), "created")
	wide := tlog.Tile{H: TileHeight, L: 0, N: 0, W: 5}
	linkOut(t, dir, wide.Path(), created)
	l.extend(t, 5)
	s = &Store{}
	s.dir, err = state.OpenRoot("tlog")
	mustNil(t, err)
	defer s.Close()
	var data []byte
	for j := 0; j < 5; j++ {
		h := l.hashes[tlog.StoredHashIndex(0, int64(j))]
		data = append(data, h[:]...)
	}
	if err := s.WriteTile(wide, data); err == nil {
		t.Fatal("write followed a symlink out of the state directory")
	}
	if _, err := os.Lstat(created); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("write made the outside file: %v", err)
	}
	after, err := os.Stat(outside)
	mustNil(t, err)
	if now, _ := os.ReadFile(outside); !bytes.Equal(now, good) || !after.ModTime().Equal(before.ModTime()) {
		t.Fatal("the outside file changed")
	}
}

// openErr opens the log and returns the Error. It fails the test if Open does
// not return an Error with the given rule in a short time.
func openErr(t *testing.T, state *os.Root, rule string) *Error {
	t.Helper()
	err := within(t, func() error {
		s, err := Open(state, "tlog")
		if err == nil {
			s.Close()
		}
		return err
	})
	var e *Error
	if !errors.As(err, &e) || e.Rule != rule || e.Name == "" {
		t.Fatalf("want rule %q, got %v", rule, err)
	}
	return e
}

func committedLog(t *testing.T, size int64) (*os.Root, string) {
	t.Helper()
	state, dir := newState(t)
	s := openStore(t, state)
	var l testLog
	l.commit(t, s, 0, size)
	s.Close()
	return state, dir
}

func TestTS13FifoAtTilePathIsAnError(t *testing.T) {
	state, dir := committedLog(t, 3)
	tile := tlog.Tile{H: TileHeight, L: 0, N: 0, W: 3}
	file := filepath.Join(dir, "tlog", tile.Path())
	mustNil(t, os.Remove(file))
	mustNil(t, syscall.Mkfifo(file, 0o600))
	if e := openErr(t, state, ruleType); e.Name != tile.Path() {
		t.Fatalf("name %q", e.Name)
	}
}

func TestTS13FileModeWithGroupOrOtherBitsIsAnError(t *testing.T) {
	for _, name := range []string{headName, tlog.Tile{H: TileHeight, L: 0, N: 0, W: 3}.Path()} {
		for _, mode := range []os.FileMode{0o640, 0o604, 0o644, 0o666} {
			state, dir := committedLog(t, 3)
			mustNil(t, os.Chmod(filepath.Join(dir, "tlog", name), mode))
			if e := openErr(t, state, ruleMode); e.Name != name {
				t.Fatalf("mode %o: name %q", mode, e.Name)
			}
		}
	}
	state, dir := committedLog(t, 3)
	mustNil(t, os.Chmod(filepath.Join(dir, "tlog"), 0o750))
	if e := openErr(t, state, ruleMode); e.Name != "tlog directory" {
		t.Fatalf("name %q", e.Name)
	}
}

func TestTS13HeadSymlinkOutOfStateDirectory(t *testing.T) {
	state, dir := committedLog(t, 3)
	good, err := os.ReadFile(filepath.Join(dir, "tlog", headName))
	mustNil(t, err)
	outside := filepath.Join(filepath.Dir(dir), "outside")
	mustNil(t, os.WriteFile(outside, good, fileMode))
	linkOut(t, dir, headName, outside)
	if e := openErr(t, state, ruleRead); e.Name != headName {
		t.Fatalf("name %q", e.Name)
	}
}

func TestTS13LogDirectorySymlinkOutOfStateDirectory(t *testing.T) {
	state, dir := committedLog(t, 3)
	outside := filepath.Join(filepath.Dir(dir), "outdir")
	mustNil(t, os.Rename(filepath.Join(dir, "tlog"), outside))
	mustNil(t, os.Symlink(outside, filepath.Join(dir, "tlog")))
	if e := openErr(t, state, ruleOpenRoot); e.Name != "tlog directory" {
		t.Fatalf("name %q", e.Name)
	}
	// A link to a missing directory makes no directory outside.
	mustNil(t, os.Remove(filepath.Join(dir, "tlog")))
	missing := filepath.Join(filepath.Dir(dir), "missing")
	mustNil(t, os.Symlink(missing, filepath.Join(dir, "tlog")))
	if _, err := Open(state, "tlog"); err == nil {
		t.Fatal("open followed a symlink to a missing directory")
	}
	if _, err := os.Lstat(missing); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("open made a directory outside: %v", err)
	}
}

// The store deletes a stale temporary file first and makes the new one with
// O_EXCL, so a link, a FIFO, or a file with another mode does not stay.
func TestTS13StaleTemporaryFileIsReplaced(t *testing.T) {
	state, dir := newState(t)
	s := openStore(t, state)
	var l testLog
	l.commit(t, s, 0, 256)
	full := tlog.Tile{H: TileHeight, L: 0, N: 0, W: fullWidth}
	fullFile := filepath.Join(dir, "tlog", full.Path())
	before, err := os.ReadFile(fullFile)
	mustNil(t, err)

	// A link inside the log directory at the temporary name of the next tile.
	l.extend(t, 258)
	next := tlog.Tile{H: TileHeight, L: 0, N: 1, W: 2}
	link := filepath.Join(dir, "tlog", next.Path()+tmpSuffix)
	mustNil(t, os.MkdirAll(filepath.Dir(link), dirMode))
	rel, err := filepath.Rel(filepath.Dir(link), fullFile)
	mustNil(t, err)
	mustNil(t, os.Symlink(rel, link))
	mustNil(t, s.WriteTile(next, l.tileData(next)))
	if after, _ := os.ReadFile(fullFile); !bytes.Equal(after, before) {
		t.Fatal("the write changed the full tile through the link")
	}

	// A stale temporary file of the head with mode 0666.
	tmp := filepath.Join(dir, "tlog", headName+tmpSuffix)
	mustNil(t, os.WriteFile(tmp, []byte("x"), 0o666))
	mustNil(t, os.Chmod(tmp, 0o666))
	mustNil(t, within(t, func() error { return s.SetHead(258, l.root(t, 258)) }))
	if fi, err := os.Stat(filepath.Join(dir, "tlog", headName)); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("head: %v, %v", fi, err)
	}

	// A FIFO at the temporary name.
	mustNil(t, syscall.Mkfifo(tmp, 0o600))
	mustNil(t, within(t, func() error {
		l.put(t, s, 258, 259)
		return s.SetHead(259, l.root(t, 259))
	}))
}
