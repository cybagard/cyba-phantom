// Package tlog is the tiled Merkle log of the sensor (FR-07, SEC-16). It uses
// golang.org/x/mod/sumdb/tlog for the tile and hash types.
//
// This file is the tile store. It keeps tiles and the tree head (size and
// root) in one directory below the state directory. The store never repairs,
// truncates, or rebuilds a file. A file that is wrong makes Open return an
// error, and the caller stops the log.
package tlog

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"io/fs"
	"math"
	"os"
	"path"
	"strconv"
	"strings"

	"golang.org/x/mod/sumdb/tlog"
)

const (
	// TileHeight is the height of a tile. A full tile holds 256 hashes.
	TileHeight = 8

	fullWidth = 1 << TileHeight
	maxLevel  = 63
	headName  = "head"
	headSize  = 8 + tlog.HashSize // size (big endian), then root
	dirMode   = 0o700
	fileMode  = 0o600
)

// The rules in the text of an Error. The text is fixed. It never holds tile
// bytes.
const (
	ruleHead     = "tree head is not valid"
	ruleShrink   = "tree head must not get smaller"
	ruleEmpty    = "tree head is missing but the directory is not empty"
	ruleRoot     = "tiles do not give the root of the tree head"
	ruleTile     = "tile coordinate is not valid"
	ruleMissing  = "tile is missing"
	ruleLength   = "tile length does not match its width"
	ruleType     = "file is not a regular file"
	ruleRead     = "file cannot be read below the state directory"
	ruleWrite    = "file cannot be written below the state directory"
	ruleRewrite  = "a stored tile never changes"
	ruleOpenRoot = "directory cannot be opened below the state directory"
)

var (
	errLength  = errors.New("length")
	errNotFile = errors.New("not a regular file")

	emptyRoot = tlog.Hash(sha256.Sum256(nil))
)

// Error names the file (a tile coordinate or the tree head) and the rule that
// failed.
type Error struct {
	Name string
	Rule string
}

func (e *Error) Error() string { return "tlog: " + e.Name + ": " + e.Rule }

// Store keeps the tiles and the tree head of one log. A Store is not safe for
// use by more than one goroutine. The caller holds the lock.
type Store struct {
	dir  *os.Root
	size int64
	root tlog.Hash
}

// Open opens the log directory dir below the state directory. The path dir is
// relative to state. Open makes the directory (mode 0700) if it does not
// exist. Then it reads the tree head, reads the tiles, and checks that the
// tiles give the root of the tree head. A directory with no tree head must be
// empty: that is a new log with size 0.
func Open(state *os.Root, dir string) (*Store, error) {
	if err := state.MkdirAll(dir, dirMode); err != nil {
		return nil, &Error{"tlog directory", ruleWrite}
	}
	if err := syncDirs(state, dir); err != nil {
		return nil, &Error{"tlog directory", ruleWrite}
	}
	sub, err := state.OpenRoot(dir)
	if err != nil {
		return nil, &Error{"tlog directory", ruleOpenRoot}
	}
	s := &Store{dir: sub, root: emptyRoot}
	if err := s.load(); err != nil {
		sub.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the log directory.
func (s *Store) Close() error { return s.dir.Close() }

// TreeHead returns the size and the root of the stored tree head.
func (s *Store) TreeHead() (int64, tlog.Hash) { return s.size, s.root }

func (s *Store) load() error {
	b, err := s.readFile(headName, headSize)
	if errors.Is(err, fs.ErrNotExist) {
		return s.checkEmpty()
	}
	if err != nil {
		return &Error{headName, ruleHead}
	}
	size := binary.BigEndian.Uint64(b)
	if size > math.MaxInt64 {
		return &Error{headName, ruleHead}
	}
	s.size = int64(size)
	copy(s.root[:], b[8:])
	return s.verify(s.size, s.root)
}

func (s *Store) checkEmpty() error {
	d, err := s.dir.Open(".")
	if err != nil {
		return &Error{headName, ruleRead}
	}
	defer d.Close()
	if _, err := d.ReadDir(1); !errors.Is(err, io.EOF) {
		return &Error{headName, ruleEmpty}
	}
	return nil
}

// verify checks that the tiles give root for a tree of the given size. The
// tile reader checks each tile against the tree head.
func (s *Store) verify(size int64, root tlog.Hash) error {
	r := &tileReader{s: s}
	got, err := tlog.TreeHash(size, tlog.TileHashReader(tlog.Tree{N: size, Hash: root}, r))
	var e *Error
	switch {
	case errors.As(err, &e):
		return e
	case err != nil || got != root:
		// The check does not say which tile is wrong. Name the tiles that it read.
		return &Error{strings.Join(r.last, ","), ruleRoot}
	}
	return nil
}

// SetHead writes the tree head. The caller writes it after the tiles of the
// tree are durable. SetHead reads the tiles and refuses a size or root that
// they do not give, and a size that is smaller than the stored size.
func (s *Store) SetHead(size int64, root tlog.Hash) error {
	if size < s.size {
		return &Error{headName, ruleShrink}
	}
	if err := s.verify(size, root); err != nil {
		return err
	}
	var b [headSize]byte
	binary.BigEndian.PutUint64(b[:], uint64(size))
	copy(b[8:], root[:])
	if err := s.writeFile(headName, b[:]); err != nil {
		return &Error{headName, ruleWrite}
	}
	s.size, s.root = size, root
	return nil
}

// WriteTile writes one tile. The data is the t.W hashes of the tile. A tile
// that is already stored is never written again: the same bytes are accepted
// and do nothing, other bytes are an error. After the tile is durable, the
// store deletes the older partial files of the same tile, so that at most one
// partial file stays.
func (s *Store) WriteTile(t tlog.Tile, data []byte) error {
	if t.H != TileHeight || t.L < 0 || t.L > maxLevel || t.N < 0 || t.W < 1 ||
		t.W > fullWidth || len(data) != t.W*tlog.HashSize {
		return &Error{"tile", ruleTile}
	}
	name := t.Path()
	old, err := s.readFile(name, len(data))
	switch {
	case err == nil:
		if !bytes.Equal(old, data) {
			return &Error{name, ruleRewrite}
		}
	case errors.Is(err, fs.ErrNotExist):
		if err := s.writeFile(name, data); err != nil {
			return &Error{name, ruleWrite}
		}
	default:
		return &Error{name, fileRule(err)}
	}
	return s.dropPartials(t, t.W)
}

// dropPartials deletes the partial files of tile t that are narrower than
// keep.
func (s *Store) dropPartials(t tlog.Tile, keep int) error {
	t.W = 1
	dir := path.Dir(t.Path())
	d, err := s.dir.Open(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	} else if err != nil {
		return &Error{dir, ruleRead}
	}
	entries, err := d.ReadDir(-1)
	d.Close()
	if err != nil {
		return &Error{dir, ruleRead}
	}
	for _, e := range entries {
		// The path to delete comes from the integer width only.
		w, err := strconv.Atoi(e.Name())
		if err != nil || w < 1 || w >= keep {
			continue
		}
		t.W = w
		if err := s.dir.Remove(t.Path()); err != nil {
			return &Error{t.Path(), ruleWrite}
		}
	}
	if err := syncDirs(s.dir, dir); err != nil {
		return &Error{dir, ruleWrite}
	}
	return nil
}

// readTile returns the hashes of tile t. If the file of that exact width is
// not there, it uses the first wider partial file or the full file. Stored
// hashes never change, so a prefix of a wider tile is correct. This is the
// case when a crash comes after a wider tile and before the tree head.
func (s *Store) readTile(t tlog.Tile) ([]byte, error) {
	want := t.W
	for w := want; w <= fullWidth; w++ {
		t.W = w
		b, err := s.readFile(t.Path(), w*tlog.HashSize)
		switch {
		case err == nil:
			return b[:want*tlog.HashSize], nil
		case !errors.Is(err, fs.ErrNotExist):
			t.W = want
			return nil, &Error{t.Path(), fileRule(err)}
		}
	}
	t.W = want
	return nil, &Error{t.Path(), ruleMissing}
}

// readFile reads the regular file name, which must have exactly n bytes. It
// reads the type from the open file and reads at most n+1 bytes.
func (s *Store) readFile(name string, n int) ([]byte, error) {
	f, err := s.dir.Open(name)
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
	}
	return ruleRead
}

// writeFile writes name in four steps: a temporary file in the same
// directory, fsync of the file, rename, and fsync of the directories. The
// mode is set at create time. The store does not change a mode afterwards.
func (s *Store) writeFile(name string, data []byte) error {
	dir := path.Dir(name)
	if err := s.dir.MkdirAll(dir, dirMode); err != nil {
		return err
	}
	tmp := name + ".tmp"
	f, err := s.dir.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, fileMode)
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
		d, err := r.Open(dir)
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
	last []string // paths of the tiles in the last read
}

func (r *tileReader) Height() int { return TileHeight }

func (r *tileReader) ReadTiles(ts []tlog.Tile) ([][]byte, error) {
	r.last = r.last[:0]
	out := make([][]byte, len(ts))
	for i, t := range ts {
		r.last = append(r.last, t.Path())
		b, err := r.s.readTile(t)
		if err != nil {
			return nil, err
		}
		out[i] = b
	}
	return out, nil
}

func (r *tileReader) SaveTiles([]tlog.Tile, [][]byte) {}
