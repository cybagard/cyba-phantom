package tlog

import (
	"errors"
	"os"
	"slices"
	"sync"

	"github.com/cybagard/cyba-phantom/internal/tlog/verifier"
	"golang.org/x/mod/sumdb/tlog"
)

// The rules in the text of an Error from the log.
const (
	ruleFull  = "log has the largest size"
	ruleCache = "tile in memory does not match the tree"
)

// EventHash is the hash of the canonical bytes of one event.
type EventHash = verifier.EventHash

// LeafHash returns the leaf hash of an event (SEC-16).
func LeafHash(h EventHash) tlog.Hash { return verifier.LeafHash(h) }

// VerifyInclusion checks an inclusion proof. The rules are in
// internal/tlog/verifier.
func VerifyInclusion(h EventHash, index, size int64, root tlog.Hash, proof tlog.RecordProof) error {
	return verifier.VerifyInclusion(h, index, size, root, proof)
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
	err   error // the first write error or tile-read error; each later Append, proof, and root read returns it until the caller opens the log again
}

// OpenLog opens the store in dir below state, checks the tiles that the tree
// head covers on its right edge, and keeps them in memory. OpenLog makes the
// loaded tree head durable before it returns. It calls fsync on the log
// directory, on its parents up to the state directory, and on the directories
// of the tiles that it read. If an fsync fails, OpenLog returns an error and no
// Log. It repairs nothing.
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
		return nil, newError("log", ruleRoot)
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

// Append adds one leaf for the event and returns its index. It is AppendBatch
// with one hash.
func (l *Log) Append(h EventHash) (int64, error) {
	return l.AppendBatch([]EventHash{h})
}

// AppendBatch adds one leaf for each event hash, in order, and returns the index
// of the first leaf. It writes each tile that the batch changes one time, with
// its final width, and then it writes the tree head one time. A tile that the
// batch fills is written in full, also if the batch starts the next tile. The
// size and the root in memory change only after the tree head is durable. An
// empty batch writes nothing and returns the size. If the batch does not fit in
// the log, or if it changes more tiles than the store accepts for one tree head,
// AppendBatch returns an error before it writes. If a write fails, AppendBatch
// returns an error, and the size and the root in memory do not change. The old
// tree head stays, so no leaf of the batch is in the tree. The leaves can still
// be on disk after the error. The log then refuses each later Append and
// AppendBatch with the same error. A proof or root read that finds a bad tile
// stops the log in the same way. The caller must close the log and open it
// again with OpenLog. OpenLog loads the state on disk.
func (l *Log) AppendBatch(hs []EventHash) (int64, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.err != nil {
		return 0, l.err
	}
	n := l.size
	if len(hs) == 0 {
		return n, nil
	}
	if int64(len(hs)) > maxSize-n {
		return 0, newError("log", ruleFull)
	}
	if len(hs) > maxBatchTiles*fullWidth {
		return 0, newError("log", ruleBatch)
	}
	// Work on a copy of the tiles. The batch clones a buffer when it first
	// changes it, so the buffers of the log stay as they are until the head is durable.
	work := l.tiles
	var owned [maxLevel + 1]bool
	type slot struct {
		lv int
		n  int64
	}
	final := map[slot][]byte{} // the last data of each tile that the batch changes
	var order []slot
	for j, h := range hs {
		size := n + int64(j)
		stored, err := tlog.StoredHashes(size, h[:], cacheView{&work})
		if err != nil {
			return 0, newError("log", ruleCache)
		}
		for i, hash := range stored {
			if i%TileHeight != 0 {
				continue // The store keeps only the hashes of the tile levels.
			}
			lv, k := i/TileHeight, size>>i // the new hash is number k of its level
			var data []byte
			if pos := int(k % fullWidth); pos > 0 {
				old := work[lv]
				if old.n != k/fullWidth || len(old.data) != pos*tlog.HashSize {
					return 0, newError("log", ruleCache)
				}
				if data = old.data; !owned[lv] {
					data = slices.Clone(data)
				}
			}
			work[lv], owned[lv] = tileBuf{k / fullWidth, append(data, hash[:]...)}, true
			s := slot{lv, k / fullWidth}
			if _, ok := final[s]; !ok {
				order = append(order, s)
			}
			final[s] = work[lv].data
		}
	}
	if len(order) > maxBatchTiles {
		return 0, newError("log", ruleBatch)
	}
	end := n + int64(len(hs))
	root, err := tlog.TreeHash(end, cacheView{&work})
	if err != nil {
		return 0, newError("log", ruleCache)
	}
	for _, s := range order {
		data := final[s]
		t := tlog.Tile{H: TileHeight, L: s.lv, N: s.n, W: len(data) / tlog.HashSize}
		if err := l.store.WriteTile(t, data); err != nil {
			l.err = err
			return 0, err
		}
	}
	if err := l.store.SetHead(end, root); err != nil {
		l.err = err
		return 0, err
	}
	l.tiles, l.size, l.root = work, end, root
	return n, nil
}

// cacheView gives stored hashes from the tiles in memory.
type cacheView struct{ tiles *[maxLevel + 1]tileBuf }

func (v cacheView) ReadHashes(indexes []int64) ([]tlog.Hash, error) {
	out := make([]tlog.Hash, len(indexes))
	for i, x := range indexes {
		if x < 0 {
			return nil, newError("log", ruleCache)
		}
		t := tlog.TileForIndex(TileHeight, x)
		if t.L > maxLevel || v.tiles[t.L].n != t.N {
			return nil, newError("log", ruleCache)
		}
		b := v.tiles[t.L]
		t.W = len(b.data) / tlog.HashSize
		h, err := tlog.HashFromTile(t, b.data, x)
		if err != nil {
			return nil, newError("log", ruleCache)
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
