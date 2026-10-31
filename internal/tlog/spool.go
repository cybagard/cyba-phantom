package tlog

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/mod/sumdb/note"

	"github.com/cybagard/cyba-phantom/internal/safefile"
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
	listStep       = 128 // names that one read of checkpoints/ returns at most
)

// spoolDirRule is the rule of checkpoints/ when the spool reads a file below
// it: a real directory. It has no owner and mode rule.
var spoolDirRule = safefile.Rule{Type: safefile.Dir, Owner: safefile.OwnerAny}

// Flags of Spool.stuck: what the spool already did for an entry.
const (
	stuckLogged   uint8 = 1 << iota // a path logged the entry
	stuckRejected                   // the entry is in Rejected
)

// Sender is the interface between the spool and a publisher. It sends one note
// to one target. It returns nil only if the target has the note. The HTTPS
// publisher and the fake sender of the tests use this one interface.
type Sender interface {
	Send(target string, size uint64, note []byte) error
}

// errBadNote marks a bad note. Publish does not send a bad note. It counts the
// note and deletes it if it can. The cause is a property of the note. One cause
// is not: a policy can refuse to open the note with EACCES, and that note is
// also bad. Among the bad notes, Publish returns an error only for the causes
// of entryError.
var errBadNote = errors.New("bad note")

// entryError is a bad note with a cause that Publish reports. The cause is an
// entry that is not a regular file. It can also be a regular note that fails
// to open with EACCES. Its text names the file and the rule. errors.Is reports
// errBadNote for it. errors.Is and errors.As also find the wrapped error.
type entryError struct{ error }

func (entryError) Is(target error) bool { return target == errBadNote }

func (e entryError) Unwrap() error { return e.error }

// causedError is an error with the text of its error field, not the text of
// cause. errors.Is and errors.As also find cause.
type causedError struct {
	error
	cause error
}

func (e causedError) Unwrap() error { return e.cause }

// cursor is the last size that a target published. set is false before the
// first success.
type cursor struct {
	size uint64
	set  bool
}

func (c cursor) covers(size uint64) bool { return c.set && size <= c.size }

// SpoolStats are the counters of a spool.
type SpoolStats struct {
	Skipped []uint64 // for each target, in the order of the targets
	// Rejected counts entries that must not be sent. A name counts one time
	// until a listing shows that it is gone.
	Rejected uint64
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

	// stuck holds the entries that cannot be deleted, with flags for what the
	// spool did for them. It has one entry for each entry in checkpoints/ that
	// the spool could not delete. It forgets an entry at the next listing after
	// the entry is gone. Only a user with write access to the state directory
	// can make such entries.
	stuck map[string]uint8
}

// OpenSpool opens the spool in root, the state directory that the caller
// opened one time. It makes checkpoints/ (mode 0700) if it is missing. A
// checkpoints entry that is not a real directory (a symlink, for example) is an
// error. Every note is parsed with origin and verified with verifier before it
// goes to a Sender (SEC-17). It deletes every temporary file that a crash left
// in checkpoints/.
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
	s := &Spool{root: root, log: log, origin: origin, verifier: verifier, targets: slices.Clone(targets), now: time.Now,
		skipped: make([]uint64, n), unlogged: make([]uint64, n), lastLog: make([]time.Time, n), publishing: make([]bool, n),
		stuck: map[string]uint8{}}
	// If the listing fails, the sweep stops and logs one line. OpenSpool still
	// succeeds. An Add or Publish that meets the same fault gives its own
	// error. A temporary file that the sweep did not delete can stay until the
	// next open.
	if err := s.eachName(func(name string) {
		if !strings.HasSuffix(name, spoolTmpSuffix) {
			return
		}
		if err := root.Remove(spoolDir + "/" + name); err != nil {
			log.Warn("checkpoint spool cannot delete a temporary file", "name", name)
		}
	}); err != nil {
		log.Warn("checkpoint spool cannot list checkpoints/ to delete temporary files")
	}
	return s, nil
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
	// then holds that entry and up to 1025 other entries. Add logs that entry
	// if no path logged it.
	for len(sizes) > maxSpoolNotes {
		if err := s.drop(sizes[0]); err != nil && s.first(noteName(sizes[0]), stuckLogged) {
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
// entryError, Publish then returns an error. If a later error stops Publish, it
// returns that error joined with the errors of the bad notes. Any other error
// to examine, open, or read a note is not a bad note. Publish keeps the note
// and does not count it. It stops for this target and returns an error that
// names the file and the rule.
//
// Publish handles one note in each cycle. It holds the lock to read the cursor
// and the note, and to handle a bad note. It calls Send with no lock. It holds
// the lock again to check the cursor and to write it. If the cursor changed
// during Send, Publish does not write it and returns an error. At the end,
// Publish holds the lock to delete the notes that every target published. A
// second call for a target returns an error immediately while a call for that
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
			return errors.Join(append(entryErrs, err)...)
		}
		if !found {
			return errors.Join(entryErrs...)
		}
		if err := send.Send(s.targets[i], size, msg); err != nil {
			err = fmt.Errorf("checkpoint spool: send of size %d to target %d failed: %w", size, i, err)
			return errors.Join(append(entryErrs, err)...)
		}
		if err := s.advance(i, cur, size); err != nil {
			return errors.Join(append(entryErrs, err)...)
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
// largest size in its listing. next handles each bad note when it finds it. If
// no note is left, it deletes the notes that every target published, and found
// is false.
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
			if ee := (entryError{}); errors.As(verr, &ee) {
				*entryErrs = append(*entryErrs, verr)
			}
			s.reject(noteName(size))
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

// verified reads a note and checks it. It returns errBadNote for a note that is
// larger than maxNoteSize or does not parse or verify. It also returns
// errBadNote for a size that differs from the name. It returns entryError in
// two cases. One is an entry that is not a regular file (a symlink, a
// directory, a FIFO). The other is a regular note that fails to open with
// EACCES. Any other error is not a property of the note. verified returns it,
// with the file and the rule in the text.
func (s *Spool) verified(size uint64) ([]byte, error) {
	name := noteName(size)
	msg, err := s.readFile(name)
	switch {
	case errors.Is(err, safefile.ErrSymlink), errors.Is(err, safefile.ErrType):
		return nil, entryError{err}
	case errors.Is(err, safefile.ErrSize):
		return nil, errBadNote
	case errors.Is(err, safefile.ErrOpen) && errors.Is(err, syscall.EACCES):
		return nil, entryError{err}
	case err != nil:
		return nil, err
	}
	if c, err := ParseCheckpoint(msg, s.origin, s.verifier); err != nil || c.Size != size {
		return nil, errBadNote
	}
	return msg, nil
}

// readFile reads a regular file of at most maxNoteSize bytes of checkpoints/.
// The name has the form checkpoints/<file>. The error has the file and the
// rule in its text. It has the refusal of safefile as its cause, so errors.Is
// finds the reason and the system error. A missing file gives an error for
// which errors.Is finds fs.ErrNotExist.
func (s *Spool) readFile(name string) ([]byte, error) {
	if fault("examine", name) != nil {
		return nil, spoolError(name, "cannot be examined")
	}
	b, err := s.read(name)
	switch {
	case missing(err), errors.Is(err, safefile.ErrOpen) && errors.Is(err, fs.ErrNotExist):
		return nil, causedError{spoolError(name, "is gone before it is read"), err}
	case err != nil:
		return nil, causedError{spoolError(name, ruleText(err, maxNoteSize)), err}
	}
	return b, nil
}

// read opens checkpoints/ again and reads the file below it. A swap of the
// directory name then has no effect. The steps "open" and "read" are test
// hooks.
func (s *Spool) read(name string) ([]byte, error) {
	if err := fault("open", name); err != nil {
		return nil, &safefile.Error{Reason: safefile.ErrOpen, Cause: err}
	}
	dir, err := safefile.OpenRoot(s.root, spoolDir, spoolDirRule)
	switch {
	case missing(err):
		return nil, err
	case err != nil: // not a property of the note
		return nil, &safefile.Error{Reason: safefile.ErrExamine}
	}
	defer dir.Close()
	b, err := safefile.ReadFile(dir, path.Base(name), noteRule)
	if err == nil {
		if err = fault("read", name); err != nil {
			err = &safefile.Error{Reason: safefile.ErrExamine, Cause: err}
		}
	}
	return b, err
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
// form is skipped. A decimal above uint64 is not a valid size: sizes rejects
// that entry. Publish gives no error for it, also if sizes cannot delete it.
// A note-name entry that is not a regular file gives an error.
func (s *Spool) sizes() ([]uint64, error) {
	for name := range s.stuck { // forget the entries that are gone
		if _, err := s.root.Lstat(name); errors.Is(err, fs.ErrNotExist) {
			delete(s.stuck, name)
		}
	}
	var sizes []uint64
	err := s.eachName(func(name string) {
		digits, ok := strings.CutSuffix(name, noteSuffix)
		if !ok || !canonicalDecimal(digits) {
			return
		}
		if size, err := strconv.ParseUint(digits, 10, 64); err != nil {
			s.reject(spoolDir + "/" + name)
		} else {
			sizes = append(sizes, size)
		}
	})
	slices.Sort(sizes)
	return sizes, err
}

// eachName calls fn for each name in checkpoints/. It reads listStep names at a
// time, so one read has a bound.
func (s *Spool) eachName(fn func(name string)) error {
	d, err := s.root.Open(spoolDir)
	if err != nil {
		return spoolError(spoolDir, "cannot be opened")
	}
	defer d.Close()
	for {
		names, err := d.Readdirnames(listStep)
		for _, name := range names {
			fn(name)
		}
		if errors.Is(err, io.EOF) {
			return nil
		} else if err != nil {
			return spoolError(spoolDir, "cannot be listed")
		}
	}
}

// first reports true the first time that it marks name with flag.
func (s *Spool) first(name string, flag uint8) bool {
	seen := s.stuck[name]&flag != 0
	s.stuck[name] |= flag
	return !seen
}

// reject deletes an entry that must not be sent. It counts the entry one time.
// It logs the entry only if no path logged it. An entry can stay because it
// cannot be deleted (a directory that is not empty). A later call that meets
// it does not count it again.
func (s *Spool) reject(name string) {
	err := s.root.Remove(name)
	stuck := err != nil && !errors.Is(err, fs.ErrNotExist)
	counts := s.first(name, stuckRejected)
	logs := s.first(name, stuckLogged)
	if !stuck {
		delete(s.stuck, name) // gone: a new entry with this name counts
	}
	if counts {
		s.rejected++
	}
	if !logs {
		return
	}
	if stuck {
		s.log.Warn("checkpoint spool cannot delete a note that must not be sent", "name", name)
	} else {
		s.log.Warn("checkpoint spool deleted a note that must not be sent", "name", name)
	}
}

// replace writes name with replaceFile. The error has the rule and not the
// cause, which can name a path.
func (s *Spool) replace(name, text string) error {
	if rule, err := replaceFile(s.root, name, text, spoolDir); err != nil {
		return spoolError(name, rule)
	}
	return nil
}

// The rules that replaceFile gives for a failed step.
const (
	ruleTmpRemove = "temporary file cannot be removed"
	ruleFileWrite = "cannot be written"
	ruleDirSync   = "directory cannot be synced"
)

// replaceFile writes name in a crash-safe way. It writes a temporary file in
// the same directory, then runs fsync, rename, and fsync of the directory dir.
// A file that an earlier crash left is removed first. The rename replaces a
// symlink at name and does not follow it. For a failed step, it returns the
// rule and the cause.
func replaceFile(root *os.Root, name, text, dir string) (rule string, err error) {
	tmp := name + spoolTmpSuffix
	if err = root.Remove(tmp); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return ruleTmpRemove, err
	}
	if err = writeNew(root, tmp, text); err != nil {
		return ruleFileWrite, err
	}
	if err = root.Rename(tmp, name); err != nil {
		_ = root.Remove(tmp)
		return ruleFileWrite, err
	}
	if err = syncDir(root, dir); err != nil {
		return ruleDirSync, err
	}
	return "", nil
}

func (s *Spool) remove(size uint64) error {
	if err := s.root.Remove(noteName(size)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return spoolError(noteName(size), "cannot be deleted")
	}
	return nil
}

// drop deletes the oldest entry because the spool is full. It deletes the entry
// for every cursor state, also for a note that a target published. This keeps
// the bound. drop counts the entry as skipped, except an entry that is not a
// regular file. An entry that is gone before drop examines it counts as
// skipped. drop counts it for each target whose cursor is below its size. A
// cursor that cannot be read counts as below. The spool cannot show that the
// target has the note.
func (s *Spool) drop(size uint64) error {
	fi, lerr := s.root.Lstat(noteName(size))
	if err := s.remove(size); err != nil {
		return err
	}
	if lerr == nil && !fi.Mode().IsRegular() {
		return nil
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
			_ = s.remove(size) // the note stays for a later collect
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
