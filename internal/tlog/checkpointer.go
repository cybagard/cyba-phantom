package tlog

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

// stateName is the signer state: the bytes of the last signed checkpoint note.
// It is one file directly below the state directory.
const stateName = "checkpoint.state"

// NoteSink takes each signed note. *Spool satisfies it.
type NoteSink interface {
	Add(size uint64, msg []byte) error
}

var _ NoteSink = (*Spool)(nil)

// CheckpointOption changes the checkpointer. The tests use it for the ticks.
type CheckpointOption func(*Checkpointer)

// Checkpointer signs a checkpoint at each interval when the tree size changed
// (FR-09). Before each signature it applies the sign guard (SEC-16): the new
// tree must be consistent with the last signed checkpoint. A failed check stops
// the signing for good. Healthy and Err then report the fault.
type Checkpointer struct {
	log      *Log
	signer   note.Signer
	verifier note.Verifier
	sink     NoteSink
	state    *os.Root
	origin   string
	interval time.Duration
	lg       *slog.Logger
	ticks    <-chan time.Time // nil: a ticker with the interval

	last    Checkpoint // only the constructor and the Run goroutine use these two fields
	hasLast bool

	mu  sync.Mutex
	err error // the first fault; it never clears
}

// NewCheckpointer makes the checkpointer. The key name of the signer and of
// the verifier must be the origin. It returns an error if the interval is not
// positive, if the origin is empty, or if the signer state names another origin
// or cannot be read (a symlink, a file that is not regular, or a file above
// 1 KiB). If the stored note does not verify, or the tiles at its size do not
// give its root, the checkpointer is returned but it is not healthy and it
// never signs. No state file means the first start.
func NewCheckpointer(log *Log, signer note.Signer, verifier note.Verifier, sink NoteSink, state *os.Root,
	origin string, interval time.Duration, lg *slog.Logger, opts ...CheckpointOption) (*Checkpointer, error) {
	switch {
	case interval <= 0:
		return nil, errors.New("checkpointer: the interval must be positive")
	case origin == "":
		return nil, errors.New("checkpointer: the origin must not be empty")
	case signer.Name() != origin || verifier.Name() != origin:
		return nil, errors.New("checkpointer: the key name must be the origin")
	}
	if lg == nil {
		lg = slog.New(slog.DiscardHandler)
	}
	c := &Checkpointer{log: log, signer: signer, verifier: verifier, sink: sink, state: state, origin: origin, interval: interval, lg: lg}
	for _, o := range opts {
		o(c)
	}
	msg, ok, err := readState(state)
	if err != nil || !ok {
		return c.ifNil(err)
	}
	if line, _, _ := bytes.Cut(msg, []byte("\n")); string(line) != origin {
		return nil, errors.New("checkpointer: the signer state has another origin")
	}
	if c.last, err = c.stored(msg); err != nil {
		c.fail(err)
		return c, nil
	}
	c.hasLast = true
	return c, nil
}

func (c *Checkpointer) ifNil(err error) (*Checkpointer, error) {
	if err != nil {
		return nil, err
	}
	return c, nil
}

// stored checks the stored note: it verifies with the key, and the tiles at its
// size give its root.
func (c *Checkpointer) stored(msg []byte) (Checkpoint, error) {
	cp, err := ParseCheckpoint(msg, c.origin, c.verifier)
	if err != nil {
		return cp, err
	}
	n, ok := toSize(cp.Size)
	if !ok {
		return cp, errors.New("checkpointer: the size in the signer state is too large")
	}
	root, err := c.log.RootAt(n)
	if err != nil {
		return cp, err
	}
	if root != cp.Root {
		return cp, errors.New("checkpointer: the tiles do not give the root in the signer state")
	}
	return cp, nil
}

// Healthy reports whether the checkpointer can sign. It is safe for concurrent
// use.
func (c *Checkpointer) Healthy() bool { return c.Err() == nil }

// Err returns the first fault, or nil. It is safe for concurrent use.
func (c *Checkpointer) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

func (c *Checkpointer) fail(err error) {
	c.mu.Lock()
	first := c.err == nil
	if first {
		c.err = err
	}
	c.mu.Unlock()
	if first {
		c.lg.Error("checkpoint signing stopped: not healthy", "error", err)
	}
}

// Run is the one goroutine of the checkpointer. It signs at each tick and
// returns when ctx ends. Call it one time.
func (c *Checkpointer) Run(ctx context.Context) {
	ticks := c.ticks
	if ticks == nil {
		t := time.NewTicker(c.interval)
		defer t.Stop()
		ticks = t.C
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticks:
			c.sign()
		}
	}
}

// sign makes one checkpoint if the size changed. Head only shows the size. The
// root always comes from RootAt, which returns the error of a stopped log, and
// the consistency proof comes from the tiles. The state file is durable before
// the note goes to the sink. The log lock is not held while the sink runs.
func (c *Checkpointer) sign() {
	if c.Err() != nil {
		return
	}
	n, _ := c.log.Head()
	size, ok := toUint(n)
	switch {
	case !ok:
		c.fail(errors.New("checkpointer: the tree size is negative"))
		return
	case !c.hasLast && n == 0:
		return
	case c.hasLast && size < c.last.Size:
		c.fail(errors.New("checkpointer: the tree is smaller than the last signed checkpoint"))
		return
	}
	root, err := c.log.RootAt(n)
	if err != nil {
		c.fail(err)
		return
	}
	if c.hasLast {
		if size == c.last.Size {
			if root != c.last.Root {
				c.fail(errors.New("checkpointer: the root at the last signed size changed"))
			}
			return
		}
		if err := c.consistent(n, root); err != nil {
			c.fail(err)
			return
		}
	}
	msg, err := SignCheckpoint(c.signer, size, root)
	if err == nil {
		_, err = ParseCheckpoint(msg, c.origin, c.verifier) // the verifier must match the signer
	}
	if err == nil {
		err = writeState(c.state, msg)
	}
	if err != nil {
		c.fail(err)
		return
	}
	c.last, c.hasLast = Checkpoint{c.origin, size, root}, true
	if err := c.sink.Add(size, msg); err != nil {
		c.lg.Warn("checkpoint cannot go to the spool", "size", size, "error", err)
	}
}

// consistent checks that the tree of n leaves with the root root has the last
// signed tree as a prefix.
func (c *Checkpointer) consistent(n int64, root tlog.Hash) error {
	old, ok := toSize(c.last.Size)
	if !ok {
		return errors.New("checkpointer: the last signed size is too large")
	}
	if old == 0 {
		return nil // the empty tree is a prefix of every tree
	}
	proof, err := c.log.ProveConsistency(old, n)
	if err != nil {
		return err
	}
	if tlog.CheckTree(proof, n, root, old, c.last.Root) != nil {
		return errors.New("checkpointer: the tree has no consistency proof to the last signed checkpoint")
	}
	return nil
}

// toSize converts a size from a note to a log size. toUint converts back.
func toSize(u uint64) (int64, bool) { return int64(u), u <= maxSize }

func toUint(n int64) (uint64, bool) { return uint64(n), n >= 0 }

func stateError(rule string) error {
	return fmt.Errorf("checkpoint signer state %s: %s", stateName, rule)
}

// readState reads the signer state through root. A missing file is the first
// start. A symlink or a file that is not regular is an error, and so is a file
// above 1 KiB. The note is not verified here.
func readState(root *os.Root) (msg []byte, ok bool, err error) {
	lfi, err := root.Lstat(stateName)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	} else if err != nil {
		return nil, false, stateError("cannot be examined")
	}
	f, _, rule := openChecked(root, stateName, lfi)
	if rule != "" {
		return nil, false, stateError(rule)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxNoteSize+1))
	if err != nil || len(b) > maxNoteSize {
		return nil, false, stateError("cannot be read within 1 KiB")
	}
	return b, true, nil
}

// SignerState tells whether a signer state exists below root and gives the size
// in it. The wiring uses it for LoadOrCreateSigner, before a verifier exists, so
// SignerState does not verify the note. The checkpointer verifies it at start.
func SignerState(root *os.Root) (size uint64, exists bool, err error) {
	msg, ok, err := readState(root)
	if err != nil || !ok {
		return 0, false, err
	}
	lines := strings.SplitN(string(msg), "\n", 3)
	if len(lines) < 3 || !canonicalDecimal(lines[1]) {
		return 0, false, stateError("has no canonical size")
	}
	if size, err = strconv.ParseUint(lines[1], 10, 64); err != nil {
		return 0, false, stateError("has a size that is too large")
	}
	return size, true, nil
}

// writeState replaces the signer state with the crash-safe rule: a temporary
// file in the same directory, fsync, rename, fsync of the directory. The mode
// is 0600. It does not follow a symlink and it does not change a mode.
func writeState(root *os.Root, msg []byte) error {
	tmp := stateName + ".tmp"
	err := root.Remove(tmp)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return stateError("cannot be written")
	}
	if err = writeNew(root, tmp, string(msg)); err != nil {
		return stateError("cannot be written")
	}
	if err = root.Rename(tmp, stateName); err != nil {
		_ = root.Remove(tmp)
		return stateError("cannot be written")
	}
	if err = syncDir(root, "."); err != nil {
		return stateError("directory cannot be synced")
	}
	return nil
}
