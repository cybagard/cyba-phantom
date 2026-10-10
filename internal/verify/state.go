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

	"golang.org/x/mod/sumdb/note"
)

// The errors of the verifier state (ADR-021, decision 6). ErrState covers each
// fault of the state: it cannot be opened, read, or written, or it does not
// parse with the key. ErrStateChanged means that the state file changed between
// the load and the write. The text of both is fixed. A parse error is never
// wrapped: a state of another key is a state fault, not a bad signature.
var (
	ErrState        = errors.New("verify: the state is not valid")
	ErrStateChanged = errors.New("verify: the state changed during the run")
)

// StateChange tells what Update did to the state.
type StateChange int

const (
	StateFirstUse  StateChange = iota // No state existed. The checkpoint is now the state.
	StateUpdated                      // The checkpoint was larger. It replaced the state.
	StateUnchanged                    // The checkpoint was not larger. The file is the same.
)

// State is the last accepted checkpoint of one key. It holds the directory
// open as an os.Root.
type State struct {
	root   *os.Root
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
// the first use, and Bytes is nil. A symlink, a file that is not regular, a
// file past the note cap, and a note that does not parse with v give ErrState.
// The caller must call Close.
func LoadState(dir string, v note.Verifier) (*State, error) {
	if os.MkdirAll(dir, 0o700) != nil {
		return nil, ErrState
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, ErrState
	}
	s := &State{root: root, v: v, name: fmt.Sprintf("%08x.note", v.KeyHash())}
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
		root.Close()
		return nil, err
	}
	return s, nil
}

// Bytes returns the note that was loaded. It is nil on first use.
func (s *State) Bytes() []byte { return s.raw }

// Close closes the state directory.
func (s *State) Close() error { return s.root.Close() }

// read reads the state file. It returns false if the file does not exist. The
// file must be a regular file, and the open file must be the file that Lstat
// saw. Root.Open follows a symlink that stays inside the root, so Lstat comes
// first.
func (s *State) read() ([]byte, bool, error) {
	li, err := s.root.Lstat(s.name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil || !li.Mode().IsRegular() {
		return nil, false, ErrState
	}
	f, err := s.root.Open(s.name)
	if err != nil {
		return nil, false, ErrState
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil || !os.SameFile(li, fi) {
		return nil, false, ErrState
	}
	b, err := readCapped(f, MaxNoteBytes)
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
// rename, Update reads the state file again. If it is not the file that was
// loaded, Update removes the temporary file and returns ErrStateChanged. On
// each failure, Update removes the temporary file.
func (s *State) Update(latest []byte) (StateChange, error) {
	c, err := ParseCheckpoint(latest, s.v)
	if err != nil {
		return 0, ErrState
	}
	if s.loaded && c.Size <= s.size {
		return StateUnchanged, nil
	}
	if err := s.write(latest); err != nil {
		return 0, err
	}
	first := !s.loaded
	s.loaded, s.raw, s.size = true, bytes.Clone(latest), c.Size
	if first {
		return StateFirstUse, nil
	}
	return StateUpdated, nil
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
		if err != nil {
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
	return nil
}
