// Package tlog is the tiled Merkle log of the sensor (FR-07, SEC-16). It uses
// golang.org/x/mod/sumdb/tlog for the tile and hash types.
//
// This file is the tile store. It keeps tiles and the tree head (size and
// root) in one directory below the state directory. The store never changes
// or deletes a hash that the tree head covers. It deletes only narrower
// partial files and its own temporary files. It never repairs, truncates, or
// rebuilds any other file. A file that is wrong makes Open return an error,
// and the caller stops the log.
package tlog

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"io/fs"
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
	// hash at this level. x/mod does not end for a size above 2^62, so the
	// bound is much lower.
	maxLevel = 6
	maxSize  = 1 << (TileHeight * maxLevel)

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
)

var (
	errLength  = errors.New("length")
	errNotFile = errors.New("not a regular file")
	errNotDir  = errors.New("not a directory")
	errMode    = errors.New("mode")

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
}

// Open opens the log directory dir below the state directory. The path dir is
// relative to state. Open makes the directory (mode 0700) if it does not
// exist. The directory must have no group or other permission bits. Open
// reads the tree head and the tiles that the root computation reads, and
// checks that they give the root of the tree head. Open does not read the
// other tiles. A later change checks them with authenticated reads. A
// directory with no tree head must be empty, or hold only the temporary file
// of the tree head. Open writes a tree head of size 0 for it, before any tile
// can be written.
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
	s := &Store{dir: sub, head: tlog.Tree{Hash: emptyRoot}}
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
	read, err := s.verify(s.head)
	if err != nil {
		return err
	}
	for _, t := range read {
		if err := s.tidy(t); err != nil {
			return err
		}
	}
	return nil
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

// SetHead writes the tree head. The caller writes it after the tiles of the
// tree are durable. SetHead refuses a size that is smaller than the stored
// size and a size above maxSize. It reads the tiles and refuses the call if
// they no longer give the stored tree head, or if they do not give the new
// one.
func (s *Store) SetHead(size int64, root tlog.Hash) error {
	next := tlog.Tree{N: size, Hash: root}
	switch {
	case size < 0 || size > maxSize:
		return &Error{headName, ruleSize}
	case size < s.head.N:
		return &Error{headName, ruleShrink}
	}
	if _, err := s.verify(s.head); err != nil {
		return err
	}
	if _, err := s.verify(next); err != nil {
		return err
	}
	return s.writeHead(next)
}

// committed returns how many hashes of tile t the stored tree head covers.
func (s *Store) committed(t tlog.Tile) int {
	n := s.head.N>>(TileHeight*t.L) - t.N*fullWidth
	return int(max(0, min(n, fullWidth)))
}

// WriteTile writes one tile. The data is the t.W hashes of the tile. A hash
// that the tree head covers never changes: if data differs from a stored file
// in a covered hash, the call returns an error. A tile that the tree head
// covers in full is never written again. WriteTile replaces hashes beyond the
// tree head with a temporary file and an atomic rename, and writes nothing if
// a stored file has the data already. A write that is narrower than a stored
// file must match that file. After the write, the store deletes the partial
// files that are narrower than the widest file, so that one partial file
// stays.
func (s *Store) WriteTile(t tlog.Tile, data []byte) error {
	if t.H != TileHeight || t.L < 0 || t.L > maxLevel || t.N < 0 ||
		t.N > (maxSize>>(TileHeight*t.L))/fullWidth || t.W < 1 ||
		t.W > fullWidth || len(data) != t.W*tlog.HashSize {
		return &Error{"tile", ruleTile}
	}
	c := s.committed(t)
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
	switch {
	case t.W <= c:
	case t.W < w:
		if !bytes.Equal(data, old[:len(data)]) {
			return &Error{name, ruleRewrite}
		}
	case t.W == w && bytes.Equal(data, old):
	default:
		if err := s.writeFile(t.Path(), data); err != nil {
			return &Error{t.Path(), ruleWrite}
		}
	}
	return s.tidy(t)
}

func tilePath(t tlog.Tile, w int) string {
	t.W = w
	return t.Path()
}

// partials lists the partial files and the temporary files of tile t. A name
// counts only if it is a width in decimal with no extra characters.
func (s *Store) partials(t tlog.Tile) (widths []int, tmps []string, err error) {
	dir := path.Dir(tilePath(t, 1))
	d, err := openDir(s.dir, dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil, nil
	} else if err != nil {
		return nil, nil, &Error{dir, ruleRead}
	}
	entries, err := d.ReadDir(-1)
	d.Close()
	if err != nil {
		return nil, nil, &Error{dir, ruleRead}
	}
	for _, e := range entries {
		base, isTmp := strings.CutSuffix(e.Name(), tmpSuffix)
		w, err := strconv.Atoi(base)
		if err != nil || w < 1 || w >= fullWidth || strconv.Itoa(w) != base {
			continue
		}
		if isTmp {
			tmps = append(tmps, e.Name())
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

// tidy deletes the temporary files of tile t, and the partial files that are
// narrower than the widest file. It deletes a narrower file only if the widest
// file holds all covered hashes and has the same covered hashes. Else it
// returns an error and deletes nothing more, because the narrower file can be
// the only copy of covered hashes.
func (s *Store) tidy(t tlog.Tile) error {
	widths, tmps, err := s.partials(t)
	if err != nil {
		return err
	}
	w, top, _, err := s.widest(t, widths)
	if err != nil {
		return err
	}
	c := s.committed(t)
	if w < c {
		return &Error{tilePath(t, c), ruleMissing}
	}
	dir := path.Dir(tilePath(t, 1))
	changed := false
	for _, name := range tmps {
		if err := s.dir.Remove(path.Join(dir, name)); err != nil {
			return &Error{path.Join(dir, name), ruleWrite}
		}
		changed = true
	}
	for _, p := range widths {
		if p >= w {
			continue
		}
		file := tilePath(t, p)
		b, err := s.readFile(file, p*tlog.HashSize)
		if err != nil {
			return &Error{file, fileRule(err)}
		}
		n := min(p, c) * tlog.HashSize
		if !bytes.Equal(b[:n], top[:n]) {
			return &Error{file, ruleRewrite}
		}
		if err := s.dir.Remove(file); err != nil {
			return &Error{file, ruleWrite}
		}
		changed = true
	}
	if changed {
		if err := syncDirs(s.dir, dir); err != nil {
			return &Error{dir, ruleWrite}
		}
	}
	return nil
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

// openDir opens the directory name. It does not block on a FIFO and does not
// follow a symlink at the last name part.
func openDir(r *os.Root, name string) (*os.File, error) {
	f, err := r.OpenFile(name, readFlags, 0)
	if err != nil {
		return nil, err
	}
	if fi, err := f.Stat(); err != nil || !fi.IsDir() {
		f.Close()
		if err == nil {
			err = errNotDir
		}
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
