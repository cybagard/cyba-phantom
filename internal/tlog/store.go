// Package tlog is the tiled Merkle log of the sensor (FR-07, SEC-16). It uses
// golang.org/x/mod/sumdb/tlog for the tile and hash types.
//
// This file is the tile store. It keeps tiles and the tree head (size and
// root) in one directory below the state directory. The store never changes
// or deletes a hash that the tree head covers. It deletes narrower partial
// files, stale files of a tile (files that differ from a durable new file only
// beyond the tree head), and its own temporary files. It never repairs,
// truncates, or rebuilds any other file. A file that is wrong makes Open return
// an error, and the caller stops the log.
package tlog

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"io/fs"
	"maps"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/mod/sumdb/tlog"
)

const (
	// TileHeight is the height of a tile. A full tile holds 256 hashes.
	TileHeight = 8

	fullWidth = 1 << TileHeight

	// maxLevel is the highest tile level. A tree of maxSize leaves has one
	// hash at this level. x/mod does not return for a size above 2^62, so the
	// bound is much lower.
	maxLevel = 6
	maxSize  = 1 << (TileHeight * maxLevel)

	// A partial-tile directory holds at most 255 widths and 255 temporary
	// files. A level directory holds at most 1000 tiles, 1000 partial-tile
	// directories, 1000 temporary files, and 1000 group directories. A longer
	// listing is an error. The scans of one level (at most two) read at most
	// maxScanNames names together: a listing that goes over the bound is an
	// error.
	maxPartialNames = 1024
	maxLevelNames   = 4096
	maxScanNames    = 65536

	// maxBatchTiles is the number of tiles that WriteTile accepts between two
	// calls of SetHead.
	maxBatchTiles = 4096

	headName  = "head"
	tmpSuffix = ".tmp"
	sizeLen   = 8                       // the size field of the head file, big endian
	headSize  = sizeLen + tlog.HashSize // the head file: size, then root
	dirMode   = 0o700
	fileMode  = 0o600
	otherBits = 0o077 // group and other permission bits
)

// The rules in the text of an Error. The text is fixed. It never holds tile
// bytes.
const (
	ruleHead     = "tree head is not valid"
	ruleSize     = "tree size is above the limit"
	ruleShrink   = "tree head must not get smaller"
	ruleEmpty    = "tree head is missing but the directory is not empty"
	ruleRoot     = "tiles do not give the root of the tree head"
	ruleTile     = "tile coordinate is not valid"
	ruleMissing  = "tile is missing"
	ruleLength   = "tile length does not match its width"
	ruleType     = "file is not a regular file"
	ruleMode     = "file or directory allows access for group or other"
	ruleRead     = "file cannot be read below the state directory"
	ruleWrite    = "file cannot be written below the state directory"
	ruleRewrite  = "a stored hash of the tree head never changes"
	ruleOpenRoot = "directory cannot be opened below the state directory"
	ruleTooMany  = "directory has too many names"
	ruleUnwrit   = "tile of the new tree head was not written by this store"
	ruleBatch    = "too many tiles since the last tree head"
	ruleLink     = "directory is a link"
)

var (
	errTooMany = errors.New("too many names")
	errLength  = errors.New("length")
	errNotFile = errors.New("not a regular file")
	errNotDir  = errors.New("not a directory")
	errMode    = errors.New("mode")
	errLink    = errors.New("link")

	emptyRoot = tlog.Hash(sha256.Sum256(nil))
)

// Error names the file that failed and the rule that failed. The name is a
// tile path, the name of the tree head, a directory, a comma-separated list
// of tile paths, or a fixed word. It is never empty.
type Error struct {
	Name string
	Rule string
}

func (e *Error) Error() string { return "tlog: " + e.Name + ": " + e.Rule }

// Store keeps the tiles and the tree head of one log. A Store is not safe for
// use by more than one goroutine. The caller must hold a lock for each call;
// the append change adds that lock.
type Store struct {
	dir  *os.Root
	head tlog.Tree

	// written holds the width of each tile that WriteTile accepted since the
	// last SetHead. The key has width 0.
	written map[tlog.Tile]int
}

// Open opens the log directory dir below the state directory. The path dir is
// relative to state. Open makes the directory (mode 0700) if it does not
// exist. The directory must have no group or other permission bits. Open
// reads the tree head and the tiles that the root computation reads, and
// checks that they give the root of the tree head. Open does not read the
// other tiles. A later change checks them with authenticated reads. Open
// checks the files of the tiles at and beyond the rightmost tile of the tree
// head, so that at most one partial file stays for each tile after a crash.
// It deletes files only after all checks pass: when Open returns an error from
// a check, it has deleted nothing. A directory with no tree head must be
// empty, or hold only the temporary file of the tree head. Open writes a tree
// head of size 0 for it, before any tile can be written.
func Open(state *os.Root, dir string) (*Store, error) {
	sub, err := state.OpenRoot(dir)
	if errors.Is(err, fs.ErrNotExist) {
		if err = state.MkdirAll(dir, dirMode); err == nil {
			err = syncDirs(state, dir)
		}
		if err != nil {
			return nil, &Error{"tlog directory", ruleWrite}
		}
		sub, err = state.OpenRoot(dir)
	}
	if err != nil {
		return nil, &Error{"tlog directory", ruleOpenRoot}
	}
	fi, err := sub.Stat(".")
	if err == nil && fi.Mode().Perm()&otherBits != 0 {
		err = errMode
	}
	if err != nil {
		sub.Close()
		return nil, &Error{"tlog directory", fileRule(err)}
	}
	s := &Store{dir: sub, head: tlog.Tree{Hash: emptyRoot}, written: map[tlog.Tile]int{}}
	if err := s.load(); err != nil {
		sub.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the log directory.
func (s *Store) Close() error { return s.dir.Close() }

// TreeHead returns the size and the root of the stored tree head.
func (s *Store) TreeHead() (int64, tlog.Hash) { return s.head.N, s.head.Hash }

func (s *Store) load() error {
	b, err := s.readFile(headName, headSize)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return s.initHead()
	case errors.Is(err, errLength):
		return &Error{headName, ruleHead}
	case err != nil:
		return &Error{headName, fileRule(err)}
	}
	size := binary.BigEndian.Uint64(b)
	if size > maxSize {
		return &Error{headName, ruleSize}
	}
	s.head.N = int64(size)
	copy(s.head.Hash[:], b[sizeLen:])
	if _, err := s.verify(s.head); err != nil {
		return err
	}
	var rm []string
	for l := 0; l <= maxLevel; l++ {
		tiles, err := s.tilesBeyond(l)
		if err != nil {
			return err
		}
		for _, t := range tiles {
			names, err := s.stale(t, 0, s.committed(t))
			if err != nil {
				return err
			}
			rm = append(rm, names...)
		}
	}
	return s.remove(rm)
}

// initHead writes the tree head of an empty log. The directory must be empty
// or hold only the temporary file of the tree head. A directory with other
// files and no tree head means loss or tampering: the store does not repair it.
func (s *Store) initHead() error {
	d, err := openDir(s.dir, ".")
	if err != nil {
		return &Error{headName, ruleRead}
	}
	entries, err := d.ReadDir(2)
	d.Close()
	if err != nil && !errors.Is(err, io.EOF) {
		return &Error{headName, ruleRead}
	}
	for _, e := range entries {
		if e.Name() != headName+tmpSuffix {
			return &Error{headName, ruleEmpty}
		}
	}
	return s.writeHead(tlog.Tree{Hash: emptyRoot})
}

func (s *Store) writeHead(tree tlog.Tree) error {
	var b [headSize]byte
	binary.BigEndian.PutUint64(b[:], uint64(tree.N))
	copy(b[sizeLen:], tree.Hash[:])
	if err := s.writeFile(headName, b[:]); err != nil {
		return &Error{headName, ruleWrite}
	}
	s.head = tree
	return nil
}

// verify checks that the tiles give the tree head. The size must not be above
// maxSize. The tile reader checks each tile that it reads against the tree
// head. verify does not read the other tiles. It returns the tiles that it
// read.
func (s *Store) verify(tree tlog.Tree) ([]tlog.Tile, error) {
	if tree.N < 0 || tree.N > maxSize {
		return nil, &Error{headName, ruleSize}
	}
	r := &tileReader{s: s}
	got, err := tlog.TreeHash(tree.N, tlog.TileHashReader(tree, r))
	var e *Error
	switch {
	case errors.As(err, &e):
		return nil, e
	case err != nil || got != tree.Hash:
		// The check does not say which tile is wrong. Name the tiles that it read.
		names := make([]string, len(r.read))
		for i, t := range r.read {
			names[i] = t.Path()
		}
		if len(names) == 0 {
			names = append(names, headName)
		}
		return nil, &Error{strings.Join(names, ","), ruleRoot}
	}
	return r.read, nil
}

// SetHead writes the tree head. The caller must call WriteTile for each new
// tile of the tree first, and must call SetHead only after each WriteTile
// returned nil. SetHead refuses a size that is smaller than the stored size
// and a size above maxSize. It reads the tiles and refuses the call if they no
// longer give the stored tree head, or if they do not give the new one. For
// each tile that the new root computation reads, and for each tile that the new
// tree head covers for the first time (at every level), every stored file of
// the tile must agree with the other files in the hashes that the new tree head
// covers. Else the next Open would refuse the tree head. For each tile that the
// new tree head covers for the first time, SetHead also refuses hashes that
// this Store did not write or check since the last SetHead (a tile that
// WriteTile did not accept). SetHead refuses a size that adds more than
// maxBatchTiles full tiles. A refused call changes no file.
func (s *Store) SetHead(size int64, root tlog.Hash) error {
	next := tlog.Tree{N: size, Hash: root}
	switch {
	case size < 0 || size > maxSize:
		return &Error{headName, ruleSize}
	case size < s.head.N:
		return &Error{headName, ruleShrink}
	case (size-s.head.N)/fullWidth > maxBatchTiles:
		return &Error{headName, ruleBatch}
	}
	if _, err := s.verify(s.head); err != nil {
		return err
	}
	read, err := s.verify(next)
	if err != nil {
		return err
	}
	seen := map[tlog.Tile]bool{}
	for _, t := range slices.Concat(read, tlog.NewTiles(TileHeight, s.head.N, next.N)) {
		if seen[tileKey(t)] {
			continue
		}
		seen[tileKey(t)] = true
		c := covered(next.N, t)
		if _, err := s.stale(t, 0, c); err != nil {
			return err
		}
		if c > s.committed(t) && s.written[tileKey(t)] < c {
			return &Error{tilePath(t, c), ruleUnwrit}
		}
	}
	if err := s.writeHead(next); err != nil {
		return err
	}
	clear(s.written)
	return nil
}

// covered returns how many hashes of tile t a tree of n leaves covers.
func covered(n int64, t tlog.Tile) int {
	c := n>>(TileHeight*t.L) - t.N*fullWidth
	return int(max(0, min(c, fullWidth)))
}

// committed returns how many hashes of tile t the stored tree head covers.
func (s *Store) committed(t tlog.Tile) int { return covered(s.head.N, t) }

// tileKey returns the key of tile t in the set of written tiles.
func tileKey(t tlog.Tile) tlog.Tile {
	t.W = 0
	return t
}

// WriteTile writes one tile. The data is the t.W hashes of the tile. A hash
// that the tree head covers never changes: if data differs from a stored file
// in a covered hash, the call returns an error. A tile that the tree head
// covers in full is never written again. WriteTile replaces hashes beyond the
// tree head with a temporary file and an atomic rename, and writes nothing if
// a stored file has the data already. A stored file that is wider than the
// data and differs beyond the tree head is stale: WriteTile writes the new
// file first, then deletes the stale files. After the write, the store
// deletes the narrower partial files, so that at most one partial file stays.
// WriteTile accepts at most maxBatchTiles different tiles between two calls of
// SetHead.
func (s *Store) WriteTile(t tlog.Tile, data []byte) error {
	if t.H != TileHeight || t.L < 0 || t.L > maxLevel || t.N < 0 ||
		t.N > maxTileN(t.L) || t.W < 1 ||
		t.W > fullWidth || len(data) != t.W*tlog.HashSize {
		return &Error{"tile", ruleTile}
	}
	c := s.committed(t)
	if _, ok := s.written[tileKey(t)]; !ok && t.W > c && len(s.written) >= maxBatchTiles {
		return &Error{"tile", ruleBatch}
	}
	widths, _, err := s.partials(t)
	if err != nil {
		return err
	}
	w, old, name, err := s.widest(t, widths)
	if err != nil {
		return err
	}
	if w < c {
		return &Error{tilePath(t, c), ruleMissing}
	}
	n := min(c, t.W) * tlog.HashSize
	if !bytes.Equal(data[:n], old[:n]) {
		return &Error{name, ruleRewrite}
	}
	keep := 0
	switch {
	case t.W <= c:
	case t.W < w && bytes.Equal(data, old[:len(data)]):
	case t.W == w && bytes.Equal(data, old):
	default:
		// The file that the rename replaces must agree in the covered hashes too.
		if slices.Contains(widths, t.W) && t.W != w {
			b, err := s.readFile(t.Path(), t.W*tlog.HashSize)
			if err != nil {
				return &Error{t.Path(), fileRule(err)}
			}
			if !bytes.Equal(b[:n], data[:n]) {
				return &Error{t.Path(), ruleRewrite}
			}
		}
		if err := s.writeFile(t.Path(), data); err != nil {
			return &Error{t.Path(), ruleWrite}
		}
		if t.W < w {
			// The wider files differ beyond the tree head: they are stale.
			keep = t.W
		}
	}
	if err := s.tidy(t, keep); err != nil {
		return err
	}
	if t.W > c {
		s.written[tileKey(t)] = max(s.written[tileKey(t)], t.W)
	}
	return nil
}

// maxTileN returns the largest tile number of level l. A level has
// ceil(hashes / fullWidth) tiles at the largest tree size.
func maxTileN(l int) int64 {
	return (maxSize>>(TileHeight*l)+fullWidth-1)/fullWidth - 1
}

func tilePath(t tlog.Tile, w int) string {
	t.W = w
	return t.Path()
}

// partials lists the partial files and the temporary files of tile t. A name
// counts only if it is a width in decimal with no extra characters.
func (s *Store) partials(t tlog.Tile) (widths []int, tmps []string, err error) {
	dir := path.Dir(tilePath(t, 1))
	entries, err := s.names(dir, maxPartialNames)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil, nil
	} else if err != nil {
		return nil, nil, &Error{dir, fileRule(err)}
	}
	for _, name := range entries {
		base, isTmp := strings.CutSuffix(name, tmpSuffix)
		w, err := strconv.Atoi(base)
		if err != nil || w < 1 || w >= fullWidth || strconv.Itoa(w) != base {
			continue
		}
		if isTmp {
			tmps = append(tmps, name)
		} else {
			widths = append(widths, w)
		}
	}
	return widths, tmps, nil
}

// widest reads the widest stored file of tile t: the full file, or else the
// widest of the partial files. It returns width 0 if there is no file.
func (s *Store) widest(t tlog.Tile, widths []int) (int, []byte, string, error) {
	w := fullWidth
	b, err := s.readFile(tilePath(t, w), w*tlog.HashSize)
	if errors.Is(err, fs.ErrNotExist) {
		if len(widths) == 0 {
			return 0, nil, "", nil
		}
		w = slices.Max(widths)
		b, err = s.readFile(tilePath(t, w), w*tlog.HashSize)
	}
	if err != nil {
		return 0, nil, "", &Error{tilePath(t, w), fileRule(err)}
	}
	return w, b, tilePath(t, w), nil
}

// tidy deletes the files that stale returns for tile t.
func (s *Store) tidy(t tlog.Tile, keep int) error {
	rm, err := s.stale(t, keep, s.committed(t))
	if err != nil {
		return err
	}
	return s.remove(rm)
}

// stale checks the files of tile t against c, the number of hashes that the
// tree head covers. It returns the temporary files of the tile and every stored
// file of the tile except the file of width keep. If keep is 0, it keeps the
// widest file, so it returns only narrower files. A file of tile t that is
// wider than keep is stale: the caller has written the file of width keep, and
// the files differ only beyond the tree head. The kept file must hold all c
// covered hashes, and a file in the result must have the same covered hashes.
// Else stale returns an error, because the file can be the only copy of covered
// hashes. stale deletes nothing.
func (s *Store) stale(t tlog.Tile, keep, c int) ([]string, error) {
	widths, tmps, err := s.partials(t)
	if err != nil {
		return nil, err
	}
	w, top, _, err := s.widest(t, widths)
	if err != nil {
		return nil, err
	}
	if w == fullWidth {
		widths = append(widths, w)
	}
	if keep > 0 && keep != w {
		if top, err = s.readFile(tilePath(t, keep), keep*tlog.HashSize); err != nil {
			return nil, &Error{tilePath(t, keep), fileRule(err)}
		}
		w = keep
	}
	if w < c {
		return nil, &Error{tilePath(t, c), ruleMissing}
	}
	dir := path.Dir(tilePath(t, 1))
	var rm []string
	for _, name := range tmps {
		rm = append(rm, path.Join(dir, name))
	}
	// The temporary file of a full tile is in the level directory.
	rm = append(rm, tilePath(t, fullWidth)+tmpSuffix)
	for _, p := range widths {
		if p == w {
			continue
		}
		file := tilePath(t, p)
		b, err := s.readFile(file, p*tlog.HashSize)
		if err != nil {
			return nil, &Error{file, fileRule(err)}
		}
		n := min(p, c) * tlog.HashSize
		if !bytes.Equal(b[:n], top[:n]) {
			return nil, &Error{file, ruleRewrite}
		}
		rm = append(rm, file)
	}
	return rm, nil
}

// remove deletes the files in names, in order, and then calls fsync on their
// directories. A name that is not there is skipped.
func (s *Store) remove(names []string) error {
	var dirs []string
	for _, name := range names {
		if err := s.dir.Remove(name); errors.Is(err, fs.ErrNotExist) {
			continue
		} else if err != nil {
			return &Error{name, ruleWrite}
		}
		dirs = append(dirs, path.Dir(name))
	}
	slices.Sort(dirs)
	for _, dir := range slices.Compact(dirs) {
		if err := syncDirs(s.dir, dir); err != nil {
			return &Error{dir, ruleWrite}
		}
	}
	return nil
}

// names lists the directory dir in batches. It returns errTooMany if the
// directory has more than limit names.
func (s *Store) names(dir string, limit int) ([]string, error) {
	d, err := openDir(s.dir, dir)
	if err != nil {
		return nil, err
	}
	defer d.Close()
	var names []string
	for {
		entries, err := d.ReadDir(256)
		for _, e := range entries {
			names = append(names, e.Name())
		}
		switch {
		case len(names) > limit:
			return nil, errTooMany
		case errors.Is(err, io.EOF):
			return names, nil
		case err != nil:
			return nil, err
		}
	}
}

// tilesBeyond returns the tiles of level l that have a stored file and a tile
// number not below the rightmost tile of the stored tree head. If a lost batch
// went on to a longer tile number (more groups of 3 digits), the tiles from the
// first such number are in the result too.
func (s *Store) tilesBeyond(l int) ([]tlog.Tile, error) {
	first := max(0, (s.head.N>>(TileHeight*l)-1)/fullWidth)
	found := map[int64]bool{}
	starts := []int64{first}
	if first >= 1000 {
		next := int64(1000)
		for next <= first {
			next *= 1000
		}
		starts = append(starts, next)
	}
	sc := newScan(s, l, found)
	for _, from := range starts {
		sc.from = from
		for sc.groups = 1; pow1000(sc.groups) <= from; sc.groups++ {
		}
		if err := sc.dir(path.Dir(tilePath(tlog.Tile{H: TileHeight, L: l}, fullWidth)), 0, 0); err != nil {
			return nil, err
		}
	}
	var tiles []tlog.Tile
	for _, n := range slices.Sorted(maps.Keys(found)) {
		tiles = append(tiles, tlog.Tile{H: TileHeight, L: l, N: n})
	}
	return tiles, nil
}

func pow1000(n int) int64 {
	p := int64(1)
	for ; n > 0; n-- {
		p *= 1000
	}
	return p
}

// scan finds the tile numbers of one level that are not below from. A tile
// path holds the number in groups of 3 digits: the directory x001 holds tiles
// 1000 to 1999. The scan ignores a tile number above the largest valid number
// of the level, and does not descend below the groups of that number.
type scan struct {
	s         *Store
	level     int
	from      int64
	groups    int // groups of 3 digits in from
	maxN      int64
	maxGroups int // groups of 3 digits in maxN
	found     map[int64]bool
	left      int // names that the scans of the level can still use
}

func newScan(s *Store, level int, found map[int64]bool) *scan {
	c := &scan{s: s, level: level, maxN: maxTileN(level), found: found, left: maxScanNames}
	for c.maxGroups = 1; pow1000(c.maxGroups) <= c.maxN; c.maxGroups++ {
	}
	return c
}

// dir scans the directory dir, which holds the tiles with the number prefix
// (and the groups below it): depth is the number of groups in prefix.
func (c *scan) dir(dir string, prefix int64, depth int) error {
	names, err := c.s.names(dir, min(maxLevelNames, c.left))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	} else if err == nil {
		c.left -= len(names)
	}
	if err != nil {
		return &Error{dir, fileRule(err)}
	}
	for _, name := range names {
		base, _ := strings.CutSuffix(name, ".p")
		base = strings.TrimSuffix(base, tmpSuffix)
		if g, ok := digits(base); ok && len(base) == 3 {
			if n := prefix*1000 + g; n >= c.from && n <= c.maxN {
				c.found[n] = true
			}
		} else if g, ok := digits(strings.TrimPrefix(name, "x")); ok && len(name) == 4 && name[0] == 'x' {
			// Descend if the group directory holds tile numbers not below from,
			// and if a tile number can have one more group.
			sub := prefix*1000 + g
			if depth+1 < c.maxGroups && (depth+1 >= c.groups || sub >= c.from/pow1000(c.groups-depth-1)) {
				if err := c.dir(path.Join(dir, name), sub, depth+1); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// digits returns the number in s, if s has only the digits 0 to 9.
func digits(s string) (int64, bool) {
	n, err := strconv.ParseUint(s, 10, 32)
	return int64(n), err == nil
}

// readTile returns the hashes of tile t. If the file of that exact width is
// not there, it uses the first wider partial file or the full file. A stored
// hash that the tree head covers never changes, so a prefix of a wider tile is
// correct. This is the case when a crash comes after a wider tile and before
// the tree head.
func (s *Store) readTile(t tlog.Tile) ([]byte, error) {
	want := t.W
	for w := want; w <= fullWidth; w++ {
		file := tilePath(t, w)
		b, err := s.readFile(file, w*tlog.HashSize)
		switch {
		case err == nil:
			return b[:want*tlog.HashSize], nil
		case !errors.Is(err, fs.ErrNotExist):
			return nil, &Error{file, fileRule(err)}
		}
	}
	return nil, &Error{tilePath(t, want), ruleMissing}
}

// openDir opens the directory name. It does not block on a FIFO. The root
// refuses a link out of the state directory and follows a link that stays
// inside it, but openDir refuses a directory that is a link. The directory
// name and each parent below r must have no group or other permission bit.
func openDir(r *os.Root, name string) (*os.File, error) {
	f, err := openOne(r, name)
	if err != nil {
		return nil, err
	}
	for d := name; d != "."; {
		d = path.Dir(d)
		p, err := openOne(r, d)
		if err != nil {
			f.Close()
			return nil, err
		}
		p.Close()
	}
	return f, nil
}

// openOne opens the directory name and checks its type, its mode, and that it
// is not a link: the open directory must be the one that Lstat gives for name.
func openOne(r *os.Root, name string) (*os.File, error) {
	f, err := r.OpenFile(name, readFlags, 0)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	switch {
	case err != nil:
	case !fi.IsDir():
		err = errNotDir
	case fi.Mode().Perm()&otherBits != 0:
		err = errMode
	default:
		if li, lerr := r.Lstat(name); lerr != nil || !os.SameFile(li, fi) {
			err = errLink
		}
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// readFile reads the regular file name, which must have exactly n bytes. It
// reads the type and the mode from the open file. The mode must have no group
// or other bit. It reads at most n+1 bytes.
func (s *Store) readFile(name string, n int) ([]byte, error) {
	f, err := s.dir.OpenFile(name, readFlags, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, errNotFile
	}
	if fi.Mode().Perm()&otherBits != 0 {
		return nil, errMode
	}
	b, err := io.ReadAll(io.LimitReader(f, int64(n)+1))
	if err != nil {
		return nil, err
	}
	if len(b) != n {
		return nil, errLength
	}
	return b, nil
}

func fileRule(err error) string {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return ruleMissing
	case errors.Is(err, errLength):
		return ruleLength
	case errors.Is(err, errNotFile):
		return ruleType
	case errors.Is(err, errMode):
		return ruleMode
	case errors.Is(err, errTooMany):
		return ruleTooMany
	case errors.Is(err, errLink):
		return ruleLink
	}
	return ruleRead
}

// writeFile writes name in four steps: a temporary file in the same
// directory, fsync of the file, rename, and fsync of the directories. It
// deletes an old temporary file first and makes the new one with O_EXCL and
// mode 0600. The store does not change a mode afterwards.
func (s *Store) writeFile(name string, data []byte) error {
	dir := path.Dir(name)
	if err := s.dir.MkdirAll(dir, dirMode); err != nil {
		return err
	}
	tmp := name + tmpSuffix
	if err := s.dir.Remove(tmp); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	f, err := s.dir.OpenFile(tmp, createFlags, fileMode)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = s.dir.Rename(tmp, name)
	}
	if err == nil {
		return syncDirs(s.dir, dir)
	}
	s.dir.Remove(tmp)
	return err
}

// syncDirs calls fsync on dir and on each parent of dir up to the root r.
func syncDirs(r *os.Root, dir string) error {
	for {
		d, err := openDir(r, dir)
		if err != nil {
			return err
		}
		err = d.Sync()
		d.Close()
		if err != nil || dir == "." {
			return err
		}
		dir = path.Dir(dir)
	}
}

// tileReader gives tiles to tlog.TileHashReader. SaveTiles does nothing:
// the tiles are on disk already.
type tileReader struct {
	s    *Store
	read []tlog.Tile // the tiles that the reader gave
}

func (r *tileReader) Height() int { return TileHeight }

func (r *tileReader) ReadTiles(ts []tlog.Tile) ([][]byte, error) {
	out := make([][]byte, len(ts))
	for i, t := range ts {
		r.read = append(r.read, t)
		b, err := r.s.readTile(t)
		if err != nil {
			return nil, err
		}
		out[i] = b
	}
	return out, nil
}

func (r *tileReader) SaveTiles([]tlog.Tile, [][]byte) {}
