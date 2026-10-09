//go:build unix

package tlog

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
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

// linkOut replaces the file at path (below the log directory) with a symlink
// to target outside the state directory.
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
