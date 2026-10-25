package verify

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/mod/sumdb/note"

	"github.com/cybagard/cyba-phantom/internal/safefile"
)

// The errors of the verifier state (ADR-021, decision 6). ErrState covers each
// fault of the state: there is no usable state directory, or the state cannot
// be opened, read, or written, or it does not parse with the key.
// ErrStateChanged means that the state file changed between the load and the
// write: the bytes differ, or the file is now absent or present.
// ErrStateLocked means that another run held the lock for the whole of
// the lock wait. It also matches ErrState.
// ErrStateSync means that the new checkpoint is already the state file, but the
// sync of the directory failed, so the file may not survive a crash. It also
// matches ErrState. The text of each is fixed. A parse error is never wrapped:
// a state of another key is a state fault, not a bad signature.
var (
	ErrState        = errors.New("verify: the state is not valid")
	ErrStateChanged = errors.New("verify: the state changed during the run")
	ErrStateLocked  = &stateFault{"verify: another run holds the state lock: the state is not valid"}
	ErrStateSync    = &stateFault{"verify: the state was written, but the directory sync failed: the state is not valid"}
)

// stateFault is a fault of the state with a fixed text. It matches ErrState.
// Its text has the "verify:" prefix once.
type stateFault struct{ text string }

func (e *stateFault) Error() string { return e.text }
func (e *stateFault) Unwrap() error { return ErrState }

// StateOptions are the two values of LoadState that a test changes. The zero
// value of each field gives the production behavior.
type StateOptions struct {
	// LockWait is the longest time that LoadState waits for the lock of another
	// run. Zero means 30 seconds.
	LockWait time.Duration
	// DirSync syncs the open state directory. Nil means the Sync method of the
	// directory.
	DirSync func(*os.File) error
}

// defaultLockWait is the lock wait when StateOptions.LockWait is zero.
const defaultLockWait = 30 * time.Second

// StateChange tells what Update did to the state. The zero value is not a
// change: Update returns it with an error that left the state as it was.
type StateChange int

const (
	StateFirstUse  StateChange = iota + 1 // No state existed. The checkpoint is now the state.
	StateUpdated                          // The checkpoint was larger. It replaced the state.
	StateUnchanged                        // The checkpoint was not larger. The file is the same.
)

// StateFileName returns the name of the state file of the key v: the hash of
// the key as 8 hex digits, and ".note".
func StateFileName(v note.Verifier) string { return fmt.Sprintf("%08x.note", v.KeyHash()) }

// State is the last accepted checkpoint of one key. It holds the directory
// open as an os.Root. It also holds an exclusive lock on the directory until
// the caller closes the state. A second run on the same directory waits for
// the lock for at most the lock wait. The kernel releases the lock when the
// process ends.
type State struct {
	sync   func(*os.File) error // the sync of the directory
	root   *os.Root
	lock   *os.File // the open directory that holds the flock
	v      note.Verifier
	name   string // the file name: <key hash>.note
	loaded bool   // a state file existed at load
	raw    []byte // the bytes of that file
	size   uint64 // the size in that note
}

// DefaultStateDir returns the state directory: phantom-verify in
// $XDG_STATE_HOME if that is an absolute path, else in $HOME/.local/state.
func DefaultStateDir() (string, error) {
	if x := os.Getenv("XDG_STATE_HOME"); filepath.IsAbs(x) {
		return filepath.Join(x, "phantom-verify"), nil
	}
	if h := os.Getenv("HOME"); filepath.IsAbs(h) {
		return filepath.Join(h, ".local", "state", "phantom-verify"), nil
	}
	return "", ErrState
}

// LoadState opens the state directory and loads the state of the key v. It
// makes a missing directory with mode 0700. If the file does not exist, this is
// the first use, and Bytes is nil. These give ErrState: a symlink, a file that
// is not regular, or a file with a second link. A file past the note cap and a
// note that does not parse with v give ErrState too.
//
// LoadState refuses an existing directory or state file with a group or other
// permission bit. It also refuses one that another user owns. It checks the
// directory and the file on the open descriptor. It checks the directory before
// it takes the lock. Then it takes an exclusive lock on the directory.
// If another run holds the lock, LoadState waits for at most opts.LockWait (30
// seconds if it is zero) and then gives ErrStateLocked. A run holds the lock
// until it closes the state. The kernel releases it when the process ends. A
// failure to take the lock gives ErrState. The caller must call Close.
func LoadState(dir string, v note.Verifier, opts StateOptions) (*State, error) {
	if opts.LockWait == 0 {
		opts.LockWait = defaultLockWait
	}
	if opts.DirSync == nil {
		opts.DirSync = func(d *os.File) error { return d.Sync() }
	}
	if os.MkdirAll(dir, 0o700) != nil {
		return nil, ErrState
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, ErrState
	}
	lock, err := lockDir(root, opts.LockWait)
	if err != nil {
		root.Close()
		return nil, err
	}
	s := &State{sync: opts.DirSync, root: root, lock: lock, v: v, name: StateFileName(v)}
	raw, exists, err := s.read()
	if err == nil && exists {
		c, perr := ParseCheckpoint(raw, v)
		if perr != nil {
			err = ErrState
		} else {
			s.loaded, s.raw, s.size = true, raw, c.Size
		}
	}
	if err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

// Bytes returns the note that was loaded. It is nil on first use.
func (s *State) Bytes() []byte { return s.raw }

// Close releases the lock and closes the state directory. A run holds the lock
// until it closes the state.
func (s *State) Close() error {
	return errors.Join(s.lock.Close(), s.root.Close())
}

// stateFileRule is the rule of the state file. The state file is a regular
// file with one link, and the user of the run owns it. It has no group or
// other permission bit, and it is not larger than the note cap.
var stateFileRule = safefile.Rule{
	Type:    safefile.Regular,
	Owner:   safefile.OwnerSelf,
	Forbid:  0o077,
	OneLink: true,
	MaxSize: MaxNoteBytes,
}

// read reads the state file. It returns false only if the Lstat finds no file.
// Each other fault gives ErrState, also a file that goes away after the check.
// The safefile package opens the file without a block. It checks stateFileRule
// on the open descriptor. read refuses a symlink, a FIFO, or a file with a
// second link.
func (s *State) read() ([]byte, bool, error) {
	f, fi, err := safefile.Open(s.root, s.name, stateFileRule)
	if errors.Is(err, safefile.ErrExamine) && errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, ErrState
	}
	defer f.Close()
	b, err := safefile.ReadAll(f, fi, stateFileRule)
	if err != nil {
		return nil, false, ErrState
	}
	return b, true, nil
}

// Update makes the checkpoint latest the state. The caller must have checked
// latest with Consistency against Bytes. Update writes only on first use, or
// when the size of latest is larger than the size of the state. Else it leaves
// the file as it is.
//
// The write uses a temporary file with mode 0600, Sync, and Rename. Before the
// rename, Update reads the state file again. If the bytes differ, or the file
// is now absent or present, Update returns ErrStateChanged. If the second read
// fails, it returns ErrState. After the rename, Update syncs the directory. On
// each failure before the rename, Update removes the temporary file and returns
// 0 with the error.
//
// If the sync fails, the rename is done: the new checkpoint is the state file.
// Update then sets the state to the new checkpoint, and returns the change that
// it made (StateFirstUse or StateUpdated) with ErrStateSync.
func (s *State) Update(latest []byte) (StateChange, error) {
	c, err := ParseCheckpoint(latest, s.v)
	if err != nil {
		return 0, ErrState
	}
	if s.loaded && c.Size <= s.size {
		return StateUnchanged, nil
	}
	werr := s.write(latest)
	if werr != nil && !errors.Is(werr, ErrStateSync) {
		return 0, werr
	}
	change := StateUpdated
	if !s.loaded {
		change = StateFirstUse
	}
	s.loaded, s.raw, s.size = true, bytes.Clone(latest), c.Size
	return change, werr
}

// write is the temporary file, the second read, and the rename.
func (s *State) write(latest []byte) (err error) {
	var r [8]byte
	if _, err := rand.Read(r[:]); err != nil {
		return ErrState
	}
	tmp := s.name + ".tmp-" + hex.EncodeToString(r[:])
	f, err := s.root.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return ErrState
	}
	defer func() {
		if err != nil && !errors.Is(err, ErrStateSync) { // the rename is done, so tmp has its new name
			s.root.Remove(tmp)
		}
	}()
	_, werr := f.Write(latest)
	serr := f.Sync()
	cerr := f.Close()
	if werr != nil || serr != nil || cerr != nil {
		return ErrState
	}
	cur, exists, err := s.read()
	if err != nil {
		return err
	}
	if exists != s.loaded || !bytes.Equal(cur, s.raw) {
		return ErrStateChanged
	}
	if s.root.Rename(tmp, s.name) != nil {
		return ErrState
	}
	return s.syncDir()
}

// syncDir syncs the state directory, so that the rename survives a crash. A
// failure gives ErrStateSync, because the caller has done the rename.
func (s *State) syncDir() error {
	d, err := s.root.Open(".")
	if err != nil {
		return ErrStateSync
	}
	serr := s.sync(d)
	cerr := d.Close()
	if serr != nil || cerr != nil {
		return ErrStateSync
	}
	return nil
}
