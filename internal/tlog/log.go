package tlog

import (
	"crypto/sha256"
	"errors"
	"os"
	"slices"
	"sync"

	"golang.org/x/mod/sumdb/tlog"
)

// The rules in the text of an Error from the log.
const (
	ruleFull      = "log has the largest size"
	ruleCache     = "tile in memory does not match the tree"
	ruleInclusion = "proof does not match the event hash, the index, and the tree head"
)

// EventHash is the SHA-256 hash of the canonical bytes of one event. It is the
// record data of a leaf. It is never a hash of the tree.
type EventHash [sha256.Size]byte

// LeafHash returns the leaf hash of an event: SHA-256(0x00 || event hash)
// (RFC 6962, SEC-16). The log, the verifier, and the SDK use this one rule.
func LeafHash(h EventHash) tlog.Hash { return tlog.RecordHash(h[:]) }

// VerifyInclusion checks that the event is the leaf at position index in the
// tree that has size leaves and the root root. It returns nil only if the
// proof, with the leaf hash of the event, gives the root. It never panics for
// any input.
func VerifyInclusion(h EventHash, index, size int64, root tlog.Hash, proof tlog.RecordProof) error {
	if index < 0 || size < 1 || size > maxSize || index >= size ||
		tlog.CheckRecord(proof, size, root, index, LeafHash(h)) != nil {
		return &Error{"inclusion proof", ruleInclusion}
	}
	return nil
}

// tileBuf is the rightmost tile of one level: its number and its hashes. A
// buffer with no data is empty.
type tileBuf struct {
	n    int64
	data []byte
}

// Log is the append-only tiled Merkle log. It keeps the rightmost tile of each
// level in memory (at most 8 KiB each) and no older tile. One lock guards the
// log and its Store.
type Log struct {
	mu    sync.RWMutex
	store *Store
	size  int64
	root  tlog.Hash
	tiles [maxLevel + 1]tileBuf
	err   error // the first write error; Append returns it until the caller reopens the log
}

// OpenLog opens the store in dir below state, checks the tiles that the tree
// head covers on its right edge, and keeps them in memory.
func OpenLog(state *os.Root, dir string) (*Log, error) {
	s, err := Open(state, dir)
	if err != nil {
		return nil, err
	}
	l := &Log{store: s}
	l.size, l.root = s.TreeHead()
	// The tile reader checks each tile against the tree head, then saves it.
	ld := &loader{tileReader: tileReader{s: s}, tiles: &l.tiles}
	got, err := tlog.TreeHash(l.size, tlog.TileHashReader(tlog.Tree{N: l.size, Hash: l.root}, ld))
	var e *Error
	switch {
	case errors.As(err, &e):
		s.Close()
		return nil, e
	case err != nil || got != l.root:
		s.Close()
		return nil, &Error{"log", ruleRoot}
	}
	return l, nil
}

// Close closes the store.
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.store.Close()
}

// Head returns the size and the root of the log in one read.
func (l *Log) Head() (int64, tlog.Hash) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.size, l.root
}

// Append adds one leaf for the event and returns its index. It writes the
// rightmost tile of each level that changes, then the tree head. The size and
// the root in memory change only after the tree head is durable. If a write
// fails, Append returns an error, and the size and the root in memory do not
// change. The leaf can still be on disk after the error. The log then refuses
// each later Append with the same error. The caller must close the log and
// open it again with OpenLog. OpenLog loads the state on disk.
func (l *Log) Append(h EventHash) (int64, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.err != nil {
		return 0, l.err
	}
	n := l.size
	if n >= maxSize {
		return 0, &Error{"log", ruleFull}
	}
	hs, err := tlog.StoredHashes(n, h[:], cacheView{&l.tiles})
	if err != nil {
		return 0, &Error{"log", ruleCache}
	}
	next := l.tiles // Append copies the buffers by value. A changed buffer gets new data.
	var changed []int
	for i, hash := range hs {
		if i%TileHeight != 0 {
			continue // The store keeps only the hashes of the tile levels.
		}
		lv, k := i/TileHeight, n>>i // the new hash is number k of its level
		var data []byte
		if pos := int(k % fullWidth); pos > 0 {
			old := l.tiles[lv]
			if old.n != k/fullWidth || len(old.data) != pos*tlog.HashSize {
				return 0, &Error{"log", ruleCache}
			}
			data = slices.Clone(old.data)
		}
		next[lv] = tileBuf{k / fullWidth, append(data, hash[:]...)}
		changed = append(changed, lv)
	}
	root, err := tlog.TreeHash(n+1, cacheView{&next})
	if err != nil {
		return 0, &Error{"log", ruleCache}
	}
	for _, lv := range changed {
		b := next[lv]
		t := tlog.Tile{H: TileHeight, L: lv, N: b.n, W: len(b.data) / tlog.HashSize}
		if err := l.store.WriteTile(t, b.data); err != nil {
			l.err = err
			return 0, err
		}
	}
	if err := l.store.SetHead(n+1, root); err != nil {
		l.err = err
		return 0, err
	}
	l.tiles, l.size, l.root = next, n+1, root
	return n, nil
}

// cacheView gives stored hashes from the tiles in memory.
type cacheView struct{ tiles *[maxLevel + 1]tileBuf }

func (v cacheView) ReadHashes(indexes []int64) ([]tlog.Hash, error) {
	out := make([]tlog.Hash, len(indexes))
	for i, x := range indexes {
		if x < 0 {
			return nil, &Error{"log", ruleCache}
		}
		t := tlog.TileForIndex(TileHeight, x)
		if t.L > maxLevel || v.tiles[t.L].n != t.N {
			return nil, &Error{"log", ruleCache}
		}
		b := v.tiles[t.L]
		t.W = len(b.data) / tlog.HashSize
		h, err := tlog.HashFromTile(t, b.data, x)
		if err != nil {
			return nil, &Error{"log", ruleCache}
		}
		out[i] = h
	}
	return out, nil
}

// loader reads tiles from the store. tlog.TileHashReader calls SaveTiles only
// after it has checked the tiles against the tree head; loader keeps them.
type loader struct {
	tileReader
	tiles *[maxLevel + 1]tileBuf
}

func (r *loader) SaveTiles(ts []tlog.Tile, data [][]byte) {
	for i, t := range ts {
		if t.L >= 0 && t.L <= maxLevel {
			r.tiles[t.L] = tileBuf{t.N, data[i]}
		}
	}
}
