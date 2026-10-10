package tlog

import (
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
	"sync/atomic"
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

// Checkpointer signs a checkpoint at each interval when the tree size changed
// (FR-09). Before each signature it applies the sign guard (SEC-16): the new
// tree must be consistent with the last signed checkpoint. A failed check stops
// the signing until the process starts again. The operator decides. Healthy and
// Err then report the fault.
//
// The signer state is the last signed note. LoadOrCreateSigner writes a note of
// the empty tree when it makes the key. A key with no signer state is a fault.
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
	running  atomic.Bool      // a second Run returns at once

	// Only the constructor, the Run goroutine, and the tests use these fields.
	last    Checkpoint // the last signed checkpoint, or the stored one
	lastMsg []byte     // the note of last
	pending bool       // lastMsg is durable but the sink has not taken it

	mu  sync.Mutex
	err error // the first fault; it stays until the process starts again
}

// NewCheckpointer makes the checkpointer. The key name of the signer and of
// the verifier must be the origin. It returns an error in these cases:
//   - the interval is not positive, or the origin is empty;
//   - the key name or the key hash of the signer and of the verifier differ;
//   - the signer state cannot be read (a symlink, a file that is not regular,
//     or a file above 1 KiB);
//   - the first line of the signer state is not the origin, and the state is
//     empty, is not a note, or names another origin.
//
// The checkpointer is returned but it is not healthy and it never signs in
// these cases:
//   - the signer state is missing (the operator decides);
//   - the first line of the signer state is the origin, but the state does not
//     parse as a note or the note does not verify;
//   - the size in the signer state is too large;
//   - the size in the signer state is above the size of the log;
//   - the tiles at the size of the stored note do not give its root.
//
// A checkpointer that is not healthy writes no state. The constructor does not
// call the sink. It marks the stored note as pending, except the note of the
// empty tree. Each tick gives a pending note to the sink before it checks the
// current tree. So the stored note reaches the sink when the tree grew or the
// log stopped before the first tick.
func NewCheckpointer(log *Log, signer note.Signer, verifier note.Verifier, sink NoteSink, state *os.Root,
	origin string, interval time.Duration, lg *slog.Logger) (*Checkpointer, error) {
	switch {
	case interval <= 0:
		return nil, errors.New("checkpointer: the interval must be positive")
	case origin == "":
		return nil, errors.New("checkpointer: the origin must not be empty")
	case signer.Name() != origin || verifier.Name() != origin:
		return nil, errors.New("checkpointer: the key name must be the origin")
	case signer.KeyHash() != verifier.KeyHash():
		return nil, errors.New("checkpointer: the signer and the verifier must have the same key")
	}
	if lg == nil {
		lg = slog.New(slog.DiscardHandler)
	}
	c := &Checkpointer{log: log, signer: signer, verifier: verifier, sink: sink, state: state, origin: origin, interval: interval, lg: lg}
	msg, ok, err := readState(state)
	if err != nil {
		return nil, err
	}
	if !ok {
		c.fail(errors.New("checkpointer: the signer state is missing; the operator decides"))
		return c, nil
	}
	if err := checkOrigin(msg, origin); err != nil {
		return nil, err
	}
	if c.last, err = c.stored(msg); err != nil {
		c.fail(err)
		return c, nil
	}
	c.lastMsg, c.pending = msg, c.last.Size > 0
	return c, nil
}

// checkOrigin refuses a signer state that cannot be a note of this origin. Only
// a well-formed body with another origin line is "another origin". The caller
// checks the rest of the note.
func checkOrigin(msg []byte, origin string) error {
	lines := strings.SplitN(string(msg), "\n", 3)
	switch {
	case lines[0] == origin:
		return nil
	case lines[0] == "" || len(lines) < 3 || !canonicalDecimal(lines[1]):
		return errors.New("checkpointer: the signer state is empty or is not a checkpoint note")
	}
	return errors.New("checkpointer: the signer state has another origin")
}

// stored checks the stored note: it verifies with the key, and the tiles at its
// size give its root.
func (c *Checkpointer) stored(msg []byte) (Checkpoint, error) {
	cp, err := ParseCheckpoint(msg, c.origin, c.verifier)
	if err != nil {
		return cp, fmt.Errorf("checkpointer: %w", err)
	}
	n, ok := toSize(cp.Size)
	if !ok {
		return cp, errors.New("checkpointer: the size in the signer state is too large")
	}
	root, err := c.log.RootAt(n)
	if err != nil {
		return cp, fmt.Errorf("checkpointer: %w", err)
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
// returns when ctx ends. A call while another Run is active returns at once.
func (c *Checkpointer) Run(ctx context.Context) {
	if !c.running.CompareAndSwap(false, true) {
		return
	}
	defer c.running.Store(false)
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
// the note goes to the sink. The log lock is not held while the sink runs. After
// the fault check, sign gives a pending note to the sink. The note was verified
// at start or written durable before, so this signs nothing new.
func (c *Checkpointer) sign() {
	if c.Err() != nil {
		return
	}
	c.resend()
	n, _ := c.log.Head()
	size, ok := toUint(n)
	switch {
	case !ok:
		c.fail(errors.New("checkpointer: the tree size is negative"))
		return
	case size < c.last.Size:
		c.fail(errors.New("checkpointer: the tree is smaller than the last signed checkpoint"))
		return
	}
	root, err := c.log.RootAt(n)
	if err != nil {
		c.fail(fmt.Errorf("checkpointer: %w", err))
		return
	}
	if size == c.last.Size {
		if root != c.last.Root {
			c.fail(errors.New("checkpointer: the root at the last signed size changed"))
		}
		return
	}
	// At last size 0, consistent runs no proof, so only RootAt checks the tree.
	if err := c.consistent(n, root); err != nil {
		c.fail(err)
		return
	}
	msg, err := SignCheckpoint(c.signer, size, root)
	if err == nil {
		_, err = ParseCheckpoint(msg, c.origin, c.verifier) // the verifier must match the signer
	}
	if err != nil {
		c.fail(fmt.Errorf("checkpointer: %w", err))
		return
	}
	if err = writeState(c.state, msg); err != nil {
		c.fail(err)
		return
	}
	c.last, c.lastMsg, c.pending = Checkpoint{Origin: c.origin, Size: size, Root: root}, msg, true
	c.resend()
}

// resend gives the last note to the sink if the sink has not taken it. A failed
// Add leaves the note pending, and the next tick tries again while the size does
// not change. A new note replaces a pending note. Spool.Add replaces the file of
// that size, so a second Add is safe.
func (c *Checkpointer) resend() {
	if !c.pending {
		return
	}
	if err := c.sink.Add(c.last.Size, c.lastMsg); err != nil {
		c.lg.Warn("checkpoint cannot go to the spool; the next tick tries again while the size does not change", "size", c.last.Size, "error", err)
		return
	}
	c.pending = false
}

// consistent checks that the tree of n leaves with the root root has the last
// signed tree as a prefix.
func (c *Checkpointer) consistent(n int64, root tlog.Hash) error {
	old, ok := toSize(c.last.Size)
	if !ok {
		return errors.New("checkpointer: the last signed size is too large")
	}
	if old == 0 {
		return nil // the empty tree is a prefix of every tree, so no proof runs
	}
	proof, err := c.log.ProveConsistency(old, n)
	if err != nil {
		return fmt.Errorf("checkpointer: %w", err)
	}
	if tlog.CheckTree(proof, n, root, old, c.last.Root) != nil {
		return errors.New("checkpointer: the tree has no consistency proof to the last signed checkpoint")
	}
	return nil
}

// toSize converts a size from a note to a log size. toUint converts back.
func toSize(u uint64) (int64, bool) { return int64(u), u <= maxSize }

func toUint(n int64) (uint64, bool) { return uint64(n), n >= 0 }

// stateError names the failed rule. It wraps a cause that is not nil with %w.
func stateError(rule string, cause error) error {
	if cause == nil {
		return fmt.Errorf("checkpointer: signer state %s: %s", stateName, rule)
	}
	return fmt.Errorf("checkpointer: signer state %s: %s: %w", stateName, rule, cause)
}

// readState reads the signer state through root. A missing file gives ok false.
// A symlink or a file that is not regular is an error, and so is a file above
// 1 KiB. The note is not verified here.
func readState(root *os.Root) (msg []byte, ok bool, err error) {
	lfi, err := root.Lstat(stateName)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	} else if err != nil {
		return nil, false, stateError("cannot be examined", err)
	}
	f, _, rule := openChecked(root, stateName, lfi)
	if rule != "" {
		return nil, false, stateError(rule, nil)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxNoteSize+1))
	if err != nil || len(b) > maxNoteSize {
		return nil, false, stateError("cannot be read within 1 KiB", err)
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
		return 0, false, stateError("has no canonical size", nil)
	}
	if size, err = strconv.ParseUint(lines[1], 10, 64); err != nil { // the error of strconv quotes the text, so it stays out
		return 0, false, stateError("has a size that is too large", nil)
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
		return stateError("temporary file "+tmp+" cannot be removed", err)
	}
	if err = writeNew(root, tmp, string(msg)); err != nil {
		return stateError("cannot be written", err)
	}
	if err = root.Rename(tmp, stateName); err != nil {
		_ = root.Remove(tmp)
		return stateError("cannot be written", err)
	}
	if err = syncDir(root, "."); err != nil {
		return stateError("directory cannot be synced", err)
	}
	return nil
}
