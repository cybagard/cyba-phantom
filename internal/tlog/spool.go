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

// SpoolDirName is the spool directory below the state directory, for the code
// outside this package.
const SpoolDirName = spoolDir

// The spool files are at fixed names below the state directory (ADR-020).
const (
	spoolDir       = "checkpoints"
	noteSuffix     = ".note"
	cursorPrefix   = "target-"
	spoolTmpSuffix = ".tmp"
	maxSpoolNotes  = 1025
	skipLogEvery   = time.Hour
	cursorHexChars = 16
)

// Sender is the interface between the spool and a publisher. It sends one note
// to one target. It returns nil only if the target has the note. The HTTPS
// publisher and the fake sender of the tests use this one interface.
type Sender interface {
	Send(target string, size uint64, note []byte) error
}

// errBadNote marks a bad note: a note that Publish deletes, counts, and does not
// send. The cause is always a property of the note. Publish returns an error
// only for the two causes of entryError.
var errBadNote = errors.New("bad note")

// entryError is a bad note with a cause that Publish reports. The cause is an
// entry that is not a regular file, or a regular note that the open refuses
// with permission denied. Its text names the file and the rule. errors.Is
// reports errBadNote for it.
type entryError struct{ error }

func (entryError) Is(target error) bool { return target == errBadNote }

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
	Rejected uint64   // each time a target meets an entry that must not be sent
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

	// mu guards the fields below and every file change in the spool. Add holds
	// it for the whole call. Publish holds it to read the cursor and the note,
	// to handle a bad note, to write the cursor, and to delete the published
	// notes. Publish does not hold it during Send.
	mu         sync.Mutex
	skipped    []uint64
	unlogged   []uint64
	lastLog    []time.Time
	rejected   uint64
	publishing []bool // for each target: a Publish call runs
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
		skipped: make([]uint64, n), unlogged: make([]uint64, n), lastLog: make([]time.Time, n), publishing: make([]bool, n)}, nil
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
// oldest entries while the spool lists more than 1025, and the notes that every
// target published (the newest regular note stays).
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
	// The bound counts every listed entry. If the oldest entry cannot be
	// deleted, it stays and the loop continues with the next entry. The spool
	// then holds that entry and up to 1025 other entries.
	for len(sizes) > maxSpoolNotes {
		if err := s.drop(sizes[0]); err != nil {
			s.log.Warn("checkpoint spool cannot delete an entry", "size", sizes[0])
		}
		sizes = sizes[1:]
	}
	s.collect(sizes)
	return nil
}

// Publish gives the notes after the cursor of target i to send, in increasing
// size. The cursor moves only after Send returns nil. At the first error from
// Send, Publish stops and returns it; a later call sends that note again. A
// bad note does not stop Publish. Publish does not send it, deletes it if it
// can, counts it, and continues with the next notes. For the causes of
// entryError, Publish then returns an error. Any other error to examine, open,
// or read a note is not a bad note. Publish keeps the note, does not count it,
// stops for this target, and returns an error that names the file and the rule.
//
// Publish handles one note in each cycle. It holds the lock to read the cursor
// and the note, and to handle a bad note. It calls Send with no lock. It holds
// the lock again to check the cursor and to write it. If the cursor changed
// during Send, Publish does not write it and returns an error. At the end,
// Publish holds the lock to delete the notes that every target published. A
// second call for a target returns an error at once while a call for that
// target runs. It sends nothing. While Send runs, Add can drop the note that
// Send sends because the spool is full. Add counts it as skipped for this
// target. If Send then succeeds, the cursor moves to that size.
//
// The limit of one call is the largest size in the first listing. Publish sends
// no size above the limit, so a call ends even if Add adds notes during it. It
// sends the notes above the limit in the next call.
func (s *Spool) Publish(i int, send Sender) error {
	if i < 0 || i >= len(s.targets) {
		return fmt.Errorf("checkpoint spool: target %d is not a target of the spool", i)
	}
	s.mu.Lock()
	busy := s.publishing[i]
	s.publishing[i] = true
	s.mu.Unlock()
	if busy {
		return spoolError(s.cursorName(i), "has a publish that runs for this target")
	}
	defer func() {
		s.mu.Lock()
		s.publishing[i] = false
		s.mu.Unlock()
	}()
	var (
		entryErrs []error
		lim       limit
	)
	for {
		cur, size, msg, found, err := s.next(i, &entryErrs, &lim)
		if err != nil {
			return err
		}
		if !found {
			return errors.Join(entryErrs...)
		}
		if err := send.Send(s.targets[i], size, msg); err != nil {
			return fmt.Errorf("checkpoint spool: send of size %d to target %d failed: %w", size, i, err)
		}
		if err := s.advance(i, cur, size); err != nil {
			return err
		}
	}
}

// limit is the largest size that one Publish call sends. set is false before
// the first listing.
type limit struct {
	size uint64
	set  bool
}

// next finds the first note after the cursor of target i that is not bad and is
// not above the limit. It holds s.mu. The first call sets the limit to the
// largest size in its listing. next handles each bad note on the way. If no note
// is left, it deletes the notes that every target published and gives found as
// false.
func (s *Spool) next(i int, entryErrs *[]error, lim *limit) (cur cursor, size uint64, msg []byte, found bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cur, err = s.readCursor(i); err != nil {
		return
	}
	sizes, err := s.sizes()
	if err != nil {
		return
	}
	if !lim.set {
		lim.set = true
		if len(sizes) > 0 {
			lim.size = sizes[len(sizes)-1]
		}
	}
	for _, size = range sizes {
		if size > lim.size {
			break
		}
		if cur.covers(size) {
			continue
		}
		var verr error
		msg, verr = s.verified(size)
		if errors.Is(verr, errBadNote) {
			s.rejected++
			if ee := (entryError{}); errors.As(verr, &ee) {
				*entryErrs = append(*entryErrs, verr)
			}
			if err := s.remove(size); err != nil { // for example a directory that is not empty
				s.log.Warn("checkpoint spool cannot delete a note that must not be sent", "size", size)
			} else {
				s.log.Warn("checkpoint spool deleted a note that must not be sent", "size", size)
			}
			continue
		}
		return cur, size, msg, verr == nil, verr
	}
	if sizes, err = s.sizes(); err != nil { // a bad note can be the newest
		return
	}
	s.collect(sizes)
	return cur, 0, nil, false, nil
}

// advance writes the cursor of target i after a successful send. It holds
// s.mu. If the cursor is not the value that next read, advance does not write.
func (s *Spool) advance(i int, before cursor, size uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now, err := s.readCursor(i)
	if err != nil {
		return err
	}
	if now != before {
		return spoolError(s.cursorName(i), "changed while the lock was free")
	}
	return s.replace(s.cursorName(i), strconv.FormatUint(size, 10))
}

// verified reads a note and checks it. It gives errBadNote for a note that is
// larger than 1 KiB, does not parse or verify, or has another size than its name
// gives. It gives entryError for an entry that is not a regular file (a symlink,
// a directory, a FIFO) and for a note that the open refuses with permission
// denied. Any other error is not a property of the note. verified returns it,
// with the file and the rule in the text.
func (s *Spool) verified(size uint64) ([]byte, error) {
	name := noteName(size)
	if fi, err := s.root.Lstat(name); err == nil && !fi.Mode().IsRegular() {
		return nil, entryError{spoolError(name, "must be a regular file and not a symlink")}
	} else if err == nil && fi.Size() > maxNoteSize {
		return nil, errBadNote
	}
	msg, err := s.readFile(name)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, spoolError(name, "is gone before it is read")
	case err != nil && s.denied(name):
		return nil, entryError{err}
	case err != nil:
		return nil, err
	}
	if c, err := ParseCheckpoint(msg, s.origin, s.verifier); err != nil || c.Size != size {
		return nil, errBadNote
	}
	return msg, nil
}

// denied reports whether the open of name fails with permission denied.
// openChecked does not return the cause of an open error.
func (s *Spool) denied(name string) bool {
	f, err := s.root.OpenFile(name, readFlags, 0)
	if err == nil {
		f.Close()
	}
	return errors.Is(err, fs.ErrPermission)
}

// readFile reads a regular file of at most 1 KiB through the root. A symlink
// is an error and its target is not opened. A missing file gives the error of
// the system, so that a caller can test for fs.ErrNotExist.
func (s *Spool) readFile(name string) ([]byte, error) {
	lfi, err := s.root.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, err
	} else if err != nil {
		return nil, spoolError(name, "cannot be examined")
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

// sizes lists the sizes in the names <canonical decimal>.note, smallest first.
// It lists an entry of any type with such a name, also a directory. Publish
// treats an entry that is not a regular file as a bad note. A name in another
// form is skipped.
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
	tmp := name + spoolTmpSuffix
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

// drop deletes the oldest entry because the spool is full. It deletes the entry
// for every cursor state, also for a note that a target published. This keeps
// the bound. Then drop counts the note as skipped for each target whose
// cursor is below its size. A cursor that cannot be read counts as below,
// because the spool cannot show that the target has the note.
func (s *Spool) drop(size uint64) error {
	if err := s.remove(size); err != nil {
		return err
	}
	for i := range s.targets {
		if cur, err := s.readCursor(i); err != nil || !cur.covers(size) {
			s.skip(i)
		}
	}
	return nil
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

// collect deletes the notes that every target published, except the newest
// regular note. An entry that is not a regular file never counts as the newest
// note. collect deletes nothing while a cursor cannot be read, because that
// target can still need a note. The error shows in Publish for that target. An
// entry that cannot be deleted stays and does not stop the work.
func (s *Spool) collect(sizes []uint64) {
	if len(s.targets) == 0 || len(sizes) < 2 {
		return
	}
	newest, ok := s.newestRegular(sizes)
	if !ok {
		return
	}
	published := newest // the newest regular note stays, so it is the upper limit
	for i := range s.targets {
		cur, err := s.readCursor(i)
		if err != nil || !cur.set {
			return
		}
		published = min(published, cur.size)
	}
	for _, size := range sizes {
		if size != newest && size <= published {
			_ = s.remove(size)
		}
	}
}

// newestRegular returns the largest size in sizes whose entry is a regular file.
func (s *Spool) newestRegular(sizes []uint64) (uint64, bool) {
	for _, size := range slices.Backward(sizes) {
		if fi, err := s.root.Lstat(noteName(size)); err == nil && fi.Mode().IsRegular() {
			return size, true
		}
	}
	return 0, false
}
