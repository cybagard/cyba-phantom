package tlog

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/mod/sumdb/note"
)

// The spool files are at fixed names below the state directory (ADR-020).
const (
	spoolDir       = "checkpoints"
	noteSuffix     = ".note"
	cursorPrefix   = "target-"
	tmpSuffix      = ".tmp"
	maxSpoolNotes  = 1025
	skipLogEvery   = time.Hour
	cursorHexChars = 16
)

// Sender is the contract between the spool and a publisher. It sends one note
// to one target. It returns nil only if the target has the note. The HTTPS
// publisher and the fake sender of the tests use this one contract.
type Sender interface {
	Send(target string, size uint64, note []byte) error
}

// errBadNote marks a spool note that is too large to be a checkpoint note.
var errBadNote = errors.New("bad note")

// cursor is the last size that a target published. set is false before the
// first success.
type cursor struct {
	size uint64
	set  bool
}

func (c cursor) covers(size uint64) bool { return c.set && size <= c.size }

// SpoolStats are the counters of a spool.
type SpoolStats struct {
	Skipped  []uint64 // for each target, in the order of the targets
	Rejected uint64   // notes that failed to parse or verify
}

// Spool holds the signed notes that wait for the publish targets. All calls
// are safe for concurrent use.
type Spool struct {
	root     *os.Root
	log      *slog.Logger
	origin   string
	verifier note.Verifier
	targets  []string
	now      func() time.Time

	mu       sync.Mutex
	skipped  []uint64
	unlogged []uint64
	lastLog  []time.Time
	rejected uint64
}

// OpenSpool opens the spool in root, the state directory that the caller
// opened one time. It makes checkpoints/ (mode 0700) if it is missing. A
// checkpoints entry that is not a real directory (a symlink, for example) is an
// error. Every note is parsed with origin and verified with verifier before it
// goes to a Sender (SEC-17).
func OpenSpool(root *os.Root, log *slog.Logger, origin string, verifier note.Verifier, targets []string) (*Spool, error) {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	fi, err := root.Lstat(spoolDir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if err := root.MkdirAll(spoolDir, 0o700); err != nil {
			return nil, spoolError(spoolDir, "cannot be made")
		}
	case err != nil:
		return nil, spoolError(spoolDir, "cannot be examined")
	case !fi.IsDir():
		return nil, spoolError(spoolDir, "must be a real directory and not a symlink")
	}
	n := len(targets)
	return &Spool{root: root, log: log, origin: origin, verifier: verifier, targets: slices.Clone(targets), now: time.Now,
		skipped: make([]uint64, n), unlogged: make([]uint64, n), lastLog: make([]time.Time, n)}, nil
}

func spoolError(name, rule string) error { return fmt.Errorf("checkpoint spool %s: %s", name, rule) }

func noteName(size uint64) string { return spoolDir + "/" + strconv.FormatUint(size, 10) + noteSuffix }

// cursorName is derived from a hash, so a URL never becomes a file name.
func (s *Spool) cursorName(i int) string {
	sum := sha256.Sum256([]byte(s.targets[i]))
	return fmt.Sprintf("%s/%s%x", spoolDir, cursorPrefix, sum[:cursorHexChars/2])
}

// Stats returns a copy of the counters.
func (s *Spool) Stats() SpoolStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return SpoolStats{Skipped: slices.Clone(s.skipped), Rejected: s.rejected}
}

// Add stores a signed note as checkpoints/<size>.note. It then deletes the
// oldest notes while the spool holds more than 1025, and the notes that every
// target published (the newest note stays).
func (s *Spool) Add(size uint64, msg []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.replace(noteName(size), string(msg)); err != nil {
		return err
	}
	sizes, err := s.sizes()
	if err != nil {
		return err
	}
	for ; len(sizes) > maxSpoolNotes; sizes = sizes[1:] {
		if err := s.drop(sizes[0]); err != nil {
			return err
		}
	}
	return s.collect(sizes)
}

// Publish gives the notes after the cursor of target i to send, in increasing
// size. The cursor moves only after Send returns nil. At the first error from
// Send, Publish stops and returns it; a later call sends that note again.
func (s *Spool) Publish(i int, send Sender) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, err := s.readCursor(i)
	if err != nil {
		return err
	}
	sizes, err := s.sizes()
	if err != nil {
		return err
	}
	for _, size := range sizes {
		if cur.covers(size) {
			continue
		}
		msg, err := s.verified(size)
		if errors.Is(err, errBadNote) {
			if err := s.remove(size); err != nil {
				return err
			}
			s.rejected++
			s.log.Warn("checkpoint spool deleted a note that does not verify", "size", size)
			continue
		}
		if err != nil {
			return err
		}
		if err := send.Send(s.targets[i], size, msg); err != nil {
			return fmt.Errorf("checkpoint spool: send of size %d to target %d failed: %w", size, i, err)
		}
		cur = cursor{size, true}
		if err := s.replace(s.cursorName(i), strconv.FormatUint(size, 10)); err != nil {
			return err
		}
	}
	if sizes, err = s.sizes(); err != nil { // a bad note may have been the newest
		return err
	}
	return s.collect(sizes)
}

// verified reads a note and checks it. A note that is too large, does not
// parse, does not verify, or has another size than its name gives errBadNote.
// Any other error (a symlink, a read error) is not a bad note.
func (s *Spool) verified(size uint64) ([]byte, error) {
	msg, err := s.readFile(noteName(size))
	if err != nil {
		return nil, err
	}
	if c, err := ParseCheckpoint(msg, s.origin, s.verifier); err != nil || c.Size != size {
		return nil, errBadNote
	}
	return msg, nil
}

// readFile reads a regular file of at most 1 KiB through the root. A symlink
// is an error and its target is not opened.
func (s *Spool) readFile(name string) ([]byte, error) {
	lfi, err := s.root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if lfi.Mode().IsRegular() && lfi.Size() > maxNoteSize {
		return nil, errBadNote
	}
	f, _, rule := openChecked(s.root, name, lfi)
	if rule != "" {
		return nil, spoolError(name, rule)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxNoteSize+1))
	if err != nil || len(b) > maxNoteSize {
		return nil, spoolError(name, "cannot be read within 1 KiB")
	}
	return b, nil
}

func (s *Spool) readCursor(i int) (cursor, error) {
	name := s.cursorName(i)
	b, err := s.readFile(name)
	if errors.Is(err, fs.ErrNotExist) {
		return cursor{}, nil
	}
	if err != nil {
		return cursor{}, err
	}
	size, perr := strconv.ParseUint(string(b), 10, 64)
	if !canonicalDecimal(string(b)) || perr != nil {
		return cursor{}, spoolError(name, "is not a canonical decimal size")
	}
	return cursor{size, true}, nil
}

// sizes lists the sizes of the notes, smallest first. A name that is not
// <canonical decimal>.note is not a note. A symlink with such a name is listed:
// the read then gives an error.
func (s *Spool) sizes() ([]uint64, error) {
	d, err := s.root.Open(spoolDir)
	if err != nil {
		return nil, spoolError(spoolDir, "cannot be opened")
	}
	defer d.Close()
	names, err := d.Readdirnames(-1)
	if err != nil {
		return nil, spoolError(spoolDir, "cannot be listed")
	}
	var sizes []uint64
	for _, name := range names {
		digits, ok := strings.CutSuffix(name, noteSuffix)
		if !ok || !canonicalDecimal(digits) {
			continue
		}
		if size, err := strconv.ParseUint(digits, 10, 64); err == nil {
			sizes = append(sizes, size)
		}
	}
	slices.Sort(sizes)
	return sizes, nil
}

// replace writes name with the crash-safe rule: a temporary file in the same
// directory, write, fsync, rename, fsync of the directory. A file that an
// earlier crash left is removed first. The rename replaces a symlink at name
// and does not follow it.
func (s *Spool) replace(name, text string) error {
	tmp := name + tmpSuffix
	if err := s.root.Remove(tmp); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return spoolError(name, "cannot be written")
	}
	if err := writeNew(s.root, tmp, text); err != nil {
		return spoolError(name, "cannot be written")
	}
	if err := s.root.Rename(tmp, name); err != nil {
		_ = s.root.Remove(tmp)
		return spoolError(name, "cannot be written")
	}
	if err := syncDir(s.root, spoolDir); err != nil {
		return spoolError(name, "directory cannot be synced")
	}
	return nil
}

func (s *Spool) remove(size uint64) error {
	if err := s.root.Remove(noteName(size)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return spoolError(noteName(size), "cannot be deleted")
	}
	return nil
}

// drop deletes the oldest note because the spool is full. It counts the note
// as skipped for each target whose cursor is below its size.
func (s *Spool) drop(size uint64) error {
	for i := range s.targets {
		cur, err := s.readCursor(i)
		if err != nil {
			return err
		}
		if !cur.covers(size) {
			s.skip(i)
		}
	}
	return s.remove(size)
}

// skip counts a skipped note and logs at most one summary line each hour for
// the target. The line has the target index, never the URL.
func (s *Spool) skip(i int) {
	s.skipped[i]++
	s.unlogged[i]++
	if now := s.now(); now.Sub(s.lastLog[i]) >= skipLogEvery {
		s.log.Warn("checkpoint spool is full; notes were skipped for a target", "target", i, "skipped", s.unlogged[i], "skipped_total", s.skipped[i])
		s.unlogged[i], s.lastLog[i] = 0, now
	}
}

// collect deletes the notes that every target published, except the newest.
func (s *Spool) collect(sizes []uint64) error {
	if len(s.targets) == 0 || len(sizes) < 2 {
		return nil
	}
	published := sizes[len(sizes)-1] // the newest note stays, so it is the upper limit
	for i := range s.targets {
		cur, err := s.readCursor(i)
		if err != nil {
			return err
		}
		if !cur.set {
			return nil
		}
		published = min(published, cur.size)
	}
	for _, size := range sizes[:len(sizes)-1] {
		if size <= published {
			if err := s.remove(size); err != nil {
				return err
			}
		}
	}
	return nil
}
