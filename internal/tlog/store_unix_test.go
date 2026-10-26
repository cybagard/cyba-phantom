//go:build unix

package tlog

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/mod/sumdb/tlog"
)

func TestTS13FilesAndDirectoriesHaveFixedModes(t *testing.T) {
	state, dir := newLogState(t)
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

// outsideFiles returns the path and the contents of all files next to the state
// directory dir, and below those that are not in it.
func outsideFiles(t *testing.T, dir string) string {
	t.Helper()
	var sb strings.Builder
	mustNil(t, filepath.WalkDir(filepath.Dir(dir), func(p string, d fs.DirEntry, err error) error {
		if err != nil || p == dir {
			return filepath.SkipDir
		}
		if !d.IsDir() {
			b, err := os.ReadFile(p)
			fmt.Fprintf(&sb, "%s %x\n", p, b)
			return err
		}
		return nil
	}))
	return sb.String()
}

func TestTS13TileSymlinkOutOfStateDirectory(t *testing.T) {
	state, dir := committedLog(t, 3)
	tile := tlog.Tile{H: TileHeight, L: 0, N: 0, W: 3}
	good, err := os.ReadFile(filepath.Join(dir, "tlog", tile.Path()))
	mustNil(t, err)

	// The outside file holds a correct tile. A store that follows the link
	// opens the log with no error.
	outside := filepath.Join(filepath.Dir(dir), "outside")
	mustNil(t, os.WriteFile(outside, good, 0o644))
	linkOut(t, dir, tile.Path(), outside)
	before := outsideFiles(t, dir)
	if e := openErr(t, state, ruleRead); e.Name != tile.Path() {
		t.Fatalf("name %q", e.Name)
	}

	// A write to a tile path that is a link to a new outside file.
	created := filepath.Join(filepath.Dir(dir), "created")
	wide := tlog.Tile{H: TileHeight, L: 0, N: 0, W: 5}
	linkOut(t, dir, wide.Path(), created)
	var l testLog
	l.extend(t, 5)
	sub, err := state.OpenRoot("tlog")
	mustNil(t, err)
	s := &Store{dir: sub, written: map[tlog.Tile]int{}}
	defer s.Close()
	var e *Error
	if err := s.WriteTile(wide, l.tileData(wide)); !errors.As(err, &e) || e.Rule != ruleRead || e.Name != wide.Path() {
		t.Fatalf("write: %v", err)
	}
	if _, err := os.Lstat(created); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("write made the outside file: %v", err)
	}
	if now, _ := os.ReadFile(outside); !bytes.Equal(now, good) || outsideFiles(t, dir) != before {
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
	state, dir := newLogState(t)
	s := openStore(t, state)
	var l testLog
	l.commit(t, s, 0, size)
	s.Close()
	return state, dir
}

// A directory link inside the log directory makes the store list and delete
// the files of another tile. Open refuses the link and deletes nothing.
func TestTS13DirectoryLinkInsideLogDirectoryIsAnError(t *testing.T) {
	state, dir := newLogState(t)
	s := openStore(t, state)
	var l testLog
	l.commit(t, s, 0, 3)
	l.put(t, s, 3, 9) // only the file of width 9 holds the covered hashes
	s.Close()
	level := filepath.Join(dir, "tlog", "tile", "8", "0")
	// The partial-tile directory of the tile that Open reads is a link to the
	// directory that holds the only copy of the covered hashes.
	mustNil(t, os.Rename(filepath.Join(level, "000.p"), filepath.Join(level, "000.real")))
	mustNil(t, os.Symlink("000.real", filepath.Join(level, "000.p")))
	mustNil(t, os.WriteFile(filepath.Join(level, "000"), make([]byte, fullWidth*tlog.HashSize), fileMode))
	before := snapshot(t, filepath.Join(dir, "tlog"))
	w9 := tlog.Tile{H: TileHeight, L: 0, N: 0, W: 9}
	if e := openErr(t, state, ruleLink); e.Name != "tile/8/0/000.p" {
		t.Fatalf("name %q", e.Name)
	}
	got, err := os.ReadFile(filepath.Join(level, "000.real", "9"))
	if err != nil || !bytes.Equal(got, l.tileData(w9)) {
		t.Fatalf("the only copy of the covered hashes changed: %v", err)
	}
	if snapshot(t, filepath.Join(dir, "tlog")) != before {
		t.Fatal("a failed open changed a file")
	}
}

// snapshot returns the type of each entry below dir and the contents of each
// regular file. It does not follow a link.
func snapshot(t *testing.T, dir string) string {
	t.Helper()
	var sb strings.Builder
	mustNil(t, filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		fmt.Fprintf(&sb, "%s %v", p, d.Type())
		if d.Type().IsRegular() {
			b, err := os.ReadFile(p)
			fmt.Fprintf(&sb, " %x", b)
			if err != nil {
				return err
			}
		}
		sb.WriteString("\n")
		return nil
	}))
	return sb.String()
}

// A directory link that appears after Open must not make WriteTile write,
// rename, or delete through it. This holds also when the tile has no partial-tile
// directory yet.
func TestTS13WriteTileRefusesDirectoryLinkPlantedAfterOpen(t *testing.T) {
	cases := []struct {
		name string
		link string // the directory that becomes a link, below the log directory
		to   string // the target of the link, relative to the link
		tile tlog.Tile
	}{
		// Level 1 becomes a link to level 0. The tile has no partial-tile
		// directory, and a write would rename over the covered tile 1 of level 0.
		{"level directory", "tile/8/1", "0", tlog.Tile{H: TileHeight, L: 1, N: 1, W: fullWidth}},
		{"group directory", "tile/8/0/x001", ".", tlog.Tile{H: TileHeight, L: 0, N: 1000, W: fullWidth}},
		{"partial-tile directory", "tile/8/0/002.p", "../1", tlog.Tile{H: TileHeight, L: 0, N: 2, W: 89}},
		{"tile directory", "tile", "tile.real", tlog.Tile{H: TileHeight, L: 0, N: 1000, W: fullWidth}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			state, dir := newLogState(t)
			s := openStore(t, state)
			var l testLog
			l.commit(t, s, 0, 600) // one batch: tile 1 is full and has no partial-tile directory
			link := filepath.Join(dir, "tlog", filepath.FromSlash(c.link))
			if c.link == "tile" {
				mustNil(t, os.Rename(link, link+".real"))
			} else if err := os.RemoveAll(link); err != nil {
				t.Fatal(err)
			}
			mustNil(t, os.Symlink(c.to, link))
			covered := filepath.Join(dir, "tlog", "tile", "8", "0", "001")
			before := snapshot(t, filepath.Join(dir, "tlog"))
			err := s.WriteTile(c.tile, bytes.Repeat([]byte{0xAB}, c.tile.W*tlog.HashSize))
			var e *Error
			if !errors.As(err, &e) || e.Rule != ruleLink || e.Name != c.link {
				t.Fatalf("got %v", err)
			}
			full := tlog.Tile{H: TileHeight, L: 0, N: 1, W: fullWidth}
			if got, err := os.ReadFile(covered); err != nil || !bytes.Equal(got, l.tileData(full)) {
				t.Fatalf("the covered tile changed: %v", err)
			}
			if snapshot(t, filepath.Join(dir, "tlog")) != before {
				t.Fatal("a refused write changed a file")
			}
		})
	}
}

// A directory link that appears after WriteTile must not let SetHead read a
// newly covered tile through it, also when no root computation reads the tile.
func TestTS13SetHeadRefusesDirectoryLinkOverNewlyCoveredTile(t *testing.T) {
	cases := []struct {
		name       string
		link       string // the directory that becomes a link, below the log directory
		to         string // the target of the link, relative to the link's directory
		from, size int64  // the log grows from..size; the root computation does not read the tile
	}{
		// Tile 1999 is full at tile/8/0/x001/999 and has no partial-tile
		// directory. The root of 2000*256+1 reads only the group x002.
		{"group directory", "tile/8/0/x001", "x001.real", 1999 * fullWidth, 2000*fullWidth + 1},
		// Tile 0 of level 1 is full. The root of 65536 reads only level 2.
		{"level directory", "tile/8/1", "1.real", 0, fullWidth * fullWidth},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			state, dir := newLogState(t)
			s := openStore(t, state)
			var l testLog
			if c.from > 0 {
				l.commit(t, s, 0, c.from)
			}
			l.put(t, s, c.from, c.size)
			link := filepath.Join(dir, "tlog", filepath.FromSlash(c.link))
			mustNil(t, os.Rename(link, link+".real"))
			mustNil(t, os.Symlink(c.to, link))
			size0, root0 := s.TreeHead()
			head := filepath.Join(dir, "tlog", headName)
			before, err := os.ReadFile(head)
			mustNil(t, err)
			files := snapshot(t, filepath.Join(dir, "tlog"))
			err = s.SetHead(c.size, l.root(t, c.size))
			var e *Error
			if !errors.As(err, &e) || e.Rule != ruleLink || e.Name != c.link {
				t.Fatalf("got %v", err)
			}
			if size, root := s.TreeHead(); size != size0 || root != root0 {
				t.Fatal("a refused call changed the tree head in memory")
			}
			if now, err := os.ReadFile(head); err != nil || !bytes.Equal(now, before) {
				t.Fatal("a refused call changed the head file")
			}
			if snapshot(t, filepath.Join(dir, "tlog")) != files {
				t.Fatal("a refused call changed a file")
			}
		})
	}
}

// Open reads a tile through a level directory that is a link. It refuses the
// link.
func TestTS13OpenRefusesLevelDirectoryLink(t *testing.T) {
	state, dir := committedLog(t, 600)
	level := filepath.Join(dir, "tlog", "tile", "8", "1")
	mustNil(t, os.Rename(level, level+".real"))
	mustNil(t, os.Symlink("1.real", level))
	before := snapshot(t, filepath.Join(dir, "tlog"))
	if e := openErr(t, state, ruleLink); e.Name != "tile/8/1" {
		t.Fatalf("name %q", e.Name)
	}
	if snapshot(t, filepath.Join(dir, "tlog")) != before {
		t.Fatal("a failed open changed a file")
	}
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
	before := outsideFiles(t, dir)
	if e := openErr(t, state, ruleRead); e.Name != headName {
		t.Fatalf("name %q", e.Name)
	}
	if now, _ := os.ReadFile(outside); !bytes.Equal(now, good) || outsideFiles(t, dir) != before {
		t.Fatal("the outside file changed")
	}
}

func TestTS13LogDirectorySymlinkOutOfStateDirectory(t *testing.T) {
	state, dir := committedLog(t, 3)
	outside := filepath.Join(filepath.Dir(dir), "outdir")
	mustNil(t, os.Rename(filepath.Join(dir, "tlog"), outside))
	mustNil(t, os.Symlink(outside, filepath.Join(dir, "tlog")))
	before := outsideFiles(t, dir)
	if e := openErr(t, state, ruleOpenRoot); e.Name != "tlog directory" {
		t.Fatalf("name %q", e.Name)
	}
	if outsideFiles(t, dir) != before {
		t.Fatal("open changed a file outside")
	}
	// A link to a missing directory makes no directory outside.
	mustNil(t, os.Remove(filepath.Join(dir, "tlog")))
	missing := filepath.Join(filepath.Dir(dir), "missing")
	mustNil(t, os.Symlink(missing, filepath.Join(dir, "tlog")))
	if e := openErr(t, state, ruleOpenRoot); e.Name != "tlog directory" {
		t.Fatalf("name %q", e.Name)
	}
	if _, err := os.Lstat(missing); !errors.Is(err, fs.ErrNotExist) || outsideFiles(t, dir) != before {
		t.Fatalf("open made a directory or file outside: %v", err)
	}
}

// Every directory below the log directory must have no group or other bit.
func TestTS13TileDirectoryWithGroupOrOtherBitsIsAnError(t *testing.T) {
	for _, name := range []string{"tile", "tile/8", "tile/8/0", "tile/8/0/000.p"} {
		for _, mode := range []os.FileMode{0o777, 0o750, 0o705} {
			state, dir := committedLog(t, 3)
			mustNil(t, os.Chmod(filepath.Join(dir, "tlog", name), mode))
			openErr(t, state, ruleMode)
		}
	}
}

// The store deletes a stale temporary file first and makes the new one with
// O_EXCL, so a link, a FIFO, or a file with another mode does not stay.
func TestTS13StaleTemporaryFileIsReplaced(t *testing.T) {
	state, dir := newLogState(t)
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

// plantFile writes a file of size bytes at name below the log directory. It
// makes the directories of the name.
func plantFile(t *testing.T, dir, name string, size int) {
	t.Helper()
	file := filepath.Join(dir, "tlog", name)
	mustNil(t, os.MkdirAll(filepath.Dir(file), dirMode))
	mustNil(t, os.WriteFile(file, make([]byte, size), fileMode))
}

// A group directory with no search bit lists with no error, but the store
// cannot read below it. Open must refuse it as it does with no listing.
func TestTS13OpenRefusesGroupDirectoryWithNoSearchBit(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can search a directory with mode 0600")
	}
	state, dir := newLogState(t)
	openStore(t, state).Close()
	group := filepath.Join(dir, "tlog", "tile", "8", "0", "x001")
	mustNil(t, os.MkdirAll(group, dirMode))
	mustNil(t, os.Chmod(group, 0o600))
	t.Cleanup(func() { os.Chmod(group, dirMode) })
	openErr(t, state, ruleRead)
}

// A group directory that is a link can point to another directory. Open must
// refuse the link. The listing of a link fails, so Open asks for each name.
func TestTS13OpenRefusesGroupDirectoryLink(t *testing.T) {
	state, dir := newLogState(t)
	openStore(t, state).Close()
	plantFile(t, dir, "real/234.tmp", 3)
	level := filepath.Join(dir, "tlog", "tile", "8", "0")
	mustNil(t, os.MkdirAll(level, dirMode))
	mustNil(t, os.Symlink("../../../real", filepath.Join(level, "x001")))
	if e := openErr(t, state, ruleLink); e.Name != "tile/8/0/x001" {
		t.Fatalf("name %q", e.Name)
	}
}

// A group directory with more than 4*groupTiles names is too large to list.
// Open must still delete the temporary file of a tile in the range.
func TestTS13OpenTidiesGroupDirectoryWithManyNames(t *testing.T) {
	state, dir := newLogState(t)
	openStore(t, state).Close()
	for i := 0; i <= 4*groupTiles; i++ {
		plantFile(t, dir, fmt.Sprintf("tile/8/0/x001/j%05d", i), 0)
	}
	plantFile(t, dir, "tile/8/0/x001/234.tmp", 3)
	openStore(t, state).Close()
	tmp := filepath.Join(dir, "tlog", "tile", "8", "0", "x001", "234.tmp")
	if _, err := os.Lstat(tmp); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the temporary file is still there: %v", err)
	}
}

// A directory that Open lists must have no group or other bit. So must each
// entry of the listing that is a directory. Tile 0 of this log is full, so its
// partial-tile directory is empty and Open reads no file there. The cases are
// that directory and an entry of the partial-tile directory of tile 2. The
// last case is the empty group directory of level 2.
func TestTS13OpenRefusesListedDirectoryWithGroupOrOtherBits(t *testing.T) {
	for _, name := range []string{"tile/8/0/000.p", "tile/8/0/002.p/x", "tile/8/2"} {
		for _, mode := range []os.FileMode{0o750, 0o705} {
			state, dir := newLogState(t)
			s := openStore(t, state)
			var l testLog
			l.commit(t, s, 0, 100)
			l.commit(t, s, 100, 600)
			s.Close()
			listed := filepath.Join(dir, "tlog", name)
			mustNil(t, os.MkdirAll(listed, dirMode))
			mustNil(t, os.Chmod(listed, mode))
			if e := openErr(t, state, ruleMode); e.Name != name {
				t.Fatalf("%s with mode %o: name %q", name, mode, e.Name)
			}
		}
	}
}

// swapBeforeSync makes the n-th call of syncDirFile run swap first. A
// failed swap fails the test and the fsync. The hook runs off the test
// goroutine, so it must not stop the test.
func swapBeforeSync(t *testing.T, n int, swap func() error) {
	t.Helper()
	old := syncDirFile
	t.Cleanup(func() { syncDirFile = old })
	var calls int
	syncDirFile = func(f *os.File) error {
		if calls++; calls == n {
			if err := swap(); err != nil {
				t.Error(err)
				return err
			}
		}
		return old(f)
	}
}

// Each cause of a failed fsync of a directory has its own rule. The hook
// replaces the partial-tile directory with a link before its fsync.
func TestTS13OpenGivesLinkRuleForDirectoryReplacedBeforeFsync(t *testing.T) {
	state, dir := committedLog(t, 3)
	level := filepath.Join(dir, "tlog", "tile", "8", "0")
	// Calls 1 and 2 sync the log directory and the state directory.
	// Call 3 is the first one of the pass over the tiles.
	swapBeforeSync(t, 3, func() error {
		if err := os.Rename(filepath.Join(level, "000.p"), filepath.Join(level, "000.real")); err != nil {
			return err
		}
		return os.Symlink("000.real", filepath.Join(level, "000.p"))
	})
	if e := openErr(t, state, ruleLink); e.Name != "tile/8/0/000.p" {
		t.Fatalf("name %q", e.Name)
	}
}

// A directory replaced by a regular file before its fsync gives the
// not-a-directory rule and names the directory.
func TestTS13OpenGivesNotDirRuleForDirectoryReplacedBeforeFsync(t *testing.T) {
	state, dir := committedLog(t, 3)
	level := filepath.Join(dir, "tlog", "tile", "8", "0")
	// Call 3 is the first fsync of the pass over the tiles.
	swapBeforeSync(t, 3, func() error {
		if err := os.Rename(filepath.Join(level, "000.p"), filepath.Join(level, "000.real")); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(level, "000.p"), []byte("x"), 0o600)
	})
	if e := openErr(t, state, ruleNotDir); e.Name != "tile/8/0/000.p" {
		t.Fatalf("name %q", e.Name)
	}
}

// The error names the directory whose check failed. This can be a parent of
// the directory that the fsync opens. A link out of the state directory gets
// the link rule. A parent that is a regular file gets the not-a-directory
// rule. The last case is tile/8 replaced by a link inside the state directory.
func TestTS13OpenNamesPartReplacedBeforeFsync(t *testing.T) {
	outside := t.TempDir()
	for _, c := range []struct {
		part, rule string
		place      func(real, p string) error
	}{
		{"tile/8/0/000.p", ruleLink, func(_, p string) error { return os.Symlink(outside, p) }},
		{"tile/8/0", ruleNotDir, func(_, p string) error { return os.WriteFile(p, []byte("x"), 0o600) }},
		{"tile/8", ruleLink, func(real, p string) error { return os.Symlink(filepath.Base(real), p) }},
	} {
		state, dir := committedLog(t, 3)
		p := filepath.Join(dir, "tlog", filepath.FromSlash(c.part))
		swapBeforeSync(t, 3, func() error {
			if err := os.Rename(p, p+".real"); err != nil {
				return err
			}
			return c.place(p+".real", p)
		})
		if e := openErr(t, state, c.rule); e.Name != c.part {
			t.Errorf("%s: name %q", c.part, e.Name)
		}
	}
}

// The create path gives the rule and the name of a part of the path. The hook
// replaces the state-relative directory "a" at the first fsync.
func TestTS13OpenCreatePathNamesPartReplacedBeforeFsync(t *testing.T) {
	outside := t.TempDir()
	for _, c := range []struct {
		rule  string
		place func(p string) error
	}{
		{ruleLink, func(p string) error { return os.Symlink(outside, p) }},
		{ruleNotDir, func(p string) error { return os.WriteFile(p, []byte("x"), 0o600) }},
	} {
		state, dir := newLogState(t)
		a := filepath.Join(dir, "a")
		swapBeforeSync(t, 1, func() error {
			if err := os.Rename(a, a+".real"); err != nil {
				return err
			}
			return c.place(a)
		})
		err := within(t, func() error { _, err := Open(state, "a/tlog"); return err })
		var e *Error
		if !errors.As(err, &e) || e.Rule != c.rule || e.Name != "a" {
			t.Errorf("want rule %q for a, got %v", c.rule, err)
		}
	}
}

// A state directory with a group bit gives the mode rule at the first Open.
// This is the same rule as at the second Open.
func TestTS13OpenGivesModeRuleForNewLogInStateWithGroupBit(t *testing.T) {
	state, dir := newLogState(t)
	mustNil(t, os.Chmod(dir, 0o750))
	for range 2 {
		if e := openErr(t, state, ruleMode); e.Name != "state directory" {
			t.Fatalf("name %q", e.Name)
		}
	}
}

// A regular file in place of a group directory is an error with its own rule
// and text.
func TestTS13OpenRefusesFileInPlaceOfGroupDirectory(t *testing.T) {
	state, dir := committedLog(t, 3)
	plantFile(t, dir, "tile/8/0/x001", 1)
	e := openErr(t, state, ruleNotDir)
	const want = "tlog: tile/8/0/x001: path part is not a directory"
	if e.Name != "tile/8/0/x001" || e.Error() != want {
		t.Fatalf("got %q, want %q", e.Error(), want)
	}
}
