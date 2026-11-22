//go:build unix

package safefile

import (
	"crypto/rand"
	"errors"
	"io/fs"
	"os"
	"strings"
	"syscall"

	"github.com/cybagard/cyba-phantom/internal/safefile/internal/seam"
)

// The steps of a write. Each one is the Step field of a *WriteError.
var (
	ErrTempRemove = errors.New("safefile: write: temporary file cannot be removed")
	ErrCreate     = errors.New("safefile: write: temporary file cannot be created")
	ErrWrite      = errors.New("safefile: write: data cannot be written")
	ErrSync       = errors.New("safefile: write: file cannot be synced")
	ErrClose      = errors.New("safefile: write: file cannot be closed")
	ErrCheck      = errors.New("safefile: write: check before the rename failed")
	ErrRename     = errors.New("safefile: write: file cannot be renamed")
	ErrLink       = errors.New("safefile: write: file cannot be linked")
	ErrDirSync    = errors.New("safefile: write: directory cannot be synced")
	ErrExist      = errors.New("safefile: write: name exists")
)

// ErrMayBeRenamed is not a step. A *WriteError matches it when the new file
// can already be under its final name. The rename, the link and each step
// after them match it. The removal of a temporary file matches it only when it
// comes after a link.
var ErrMayBeRenamed = errors.New("safefile: write: new file may be in place")

// WriteError is the failure of one step of a write. Its text is the fixed text
// of the step. It holds no path, no name and no file bytes.
type WriteError struct {
	Step  error // one of the step values
	Cause error // the system error without its path, or nil

	// After is true when the step ran after the rename or the link.
	After bool
}

// Error gives the fixed text of the step.
func (e *WriteError) Error() string { return e.Step.Error() }

// mayBeRenamed is true for a step that can run when the new file is in place.
func (e *WriteError) mayBeRenamed() bool {
	switch e.Step {
	case ErrRename, ErrLink, ErrDirSync:
		return true
	case ErrTempRemove:
		return e.After
	}
	return false
}

// Unwrap gives the step, the cause and, when it applies, ErrMayBeRenamed, so
// errors.Is finds each one.
func (e *WriteError) Unwrap() []error {
	errs := []error{e.Step}
	if e.Cause != nil {
		errs = append(errs, e.Cause)
	}
	if e.mayBeRenamed() {
		errs = append(errs, ErrMayBeRenamed)
	}
	return errs
}

// writeFail makes the error of a failed step. A path error and a link error
// lose their paths. Only the cause itself is looked at. An error that wraps
// one keeps all that it wraps, so a refusal inside it still matches.
func writeFail(step, cause error, after bool) error {
	switch e := cause.(type) {
	case *fs.PathError:
		cause = e.Err
	case *os.LinkError:
		cause = e.Err
	}
	return &WriteError{Step: step, Cause: cause, After: after}
}

// stepErrs maps the name of a step in the Step hook to its error.
var stepErrs = map[string]error{
	"remove":  ErrTempRemove,
	"create":  ErrCreate,
	"write":   ErrWrite,
	"sync":    ErrSync,
	"close":   ErrClose,
	"check":   ErrCheck,
	"rename":  ErrRename,
	"link":    ErrLink,
	"dirsync": ErrDirSync,
}

// runStep runs the step with fn. The name is the file or directory of the
// step. With no Step hook it runs fn. A hook error that is not seam.Crash
// fails the step, and fn does not run. The caller then runs its cleanup.
// seam.Crash returns at once, and the caller runs no later step and no
// cleanup. A hook never makes a failed fn pass. after is true for a step
// after the rename or the link.
func runStep(h *seam.Hooks, step, name string, after bool, fn func() error) error {
	if h.Step != nil {
		if err := h.Step(step, name); err != nil {
			if errors.Is(err, seam.Crash) {
				return seam.Crash
			}
			return writeFail(stepErrs[step], err, after)
		}
	}
	if err := fn(); err != nil {
		return writeFail(stepErrs[step], err, after)
	}
	return nil
}

// syncCloser is the part of *os.File that syncAndClose needs.
type syncCloser interface {
	Sync() error
	Close() error
}

// syncAndClose syncs the open directory f and closes it. It closes f on every
// path, also after seam.Crash: a crash closes a descriptor too. The sync error
// comes first. A close error is kept.
func syncAndClose(h *seam.Hooks, name string, f syncCloser) error {
	err := runStep(h, "dirsync", name, true, f.Sync)
	if cerr := f.Close(); err == nil && cerr != nil {
		err = writeFail(ErrDirSync, cerr, true)
	}
	return err
}

// syncRoot opens the root d itself, syncs it and closes it.
func syncRoot(d *os.Root, dir string) error {
	f, err := d.Open(".")
	if err != nil {
		return writeFail(ErrDirSync, err, true)
	}
	return syncAndClose(hooks(), dir, f)
}

// dirRoot gives the directory dir below root, checked with the rule r, and the
// function that releases it. The name "." is the root itself: the rule is run
// on it, and releasing it does nothing. The caller releases the directory.
func dirRoot(root *os.Root, dir string, r Rule) (*os.Root, func() error, error) {
	if dir != "." {
		sub, err := OpenRoot(root, dir, r)
		if err != nil {
			return nil, nil, err
		}
		return sub, sub.Close, nil
	}
	fi, err := root.Stat(".")
	if err != nil {
		return nil, nil, fail(ErrExamine, err)
	}
	if err := checkOpen(fi, r, hooks()); err != nil {
		return nil, nil, err
	}
	return root, func() error { return nil }, nil
}

// SyncDir opens dir below root with OpenRoot and the directory rule r, syncs
// the directory and closes it. A link at any part of dir gives ErrSymlink, as
// for OpenRoot. The name "." is the root itself, and r is applied to it too.
// Each error other than seam.Crash is a *WriteError with the step ErrDirSync.
// It holds the refusal of OpenRoot, the sync error or the close error as its
// cause. Each such error matches ErrMayBeRenamed, also when no rename came
// before the call. A nil root, or a rule that is not a rule for a directory,
// gives ErrRule. A Step hook that gives seam.Crash makes SyncDir return that
// error.
func SyncDir(root *os.Root, dir string, r Rule) error {
	if root == nil || !r.valid() || r.Type != Dir {
		return writeFail(ErrDirSync, fail(ErrRule, nil), true)
	}
	d, release, err := dirRoot(root, dir, r)
	if err != nil {
		return writeFail(ErrDirSync, err, true)
	}
	err = syncRoot(d, dir)
	if cerr := release(); err == nil && cerr != nil {
		err = writeFail(ErrDirSync, cerr, true)
	}
	return err
}

// TempName is the rule for the name of the temporary file.
type TempName uint8

// The temporary names.
const (
	TempFixed  TempName = iota + 1 // "<name>.tmp"; an old one is removed first
	TempRandom                     // Prefix and a random text
)

// WriteRule is the rule of one writer. The zero value is refused with ErrRule.
type WriteRule struct {
	Mode      fs.FileMode  // exact permission bits of the new file
	Temp      TempName     // how the temporary file is named
	Prefix    string       // TempRandom only: not empty, with no slash
	NoDirSync bool         // Replace does not sync the directory
	Dir       Rule         // the rule for the directory of the name
	Check     func() error // runs after the file sync, before the rename
}

// valid is false for the zero rule and for each value that is not defined.
func (w WriteRule) valid() bool {
	if w.Mode&^fs.ModePerm != 0 || !w.Dir.valid() || w.Dir.Type != Dir {
		return false
	}
	switch w.Temp {
	case TempFixed:
		return w.Prefix == ""
	case TempRandom:
		return w.Prefix != "" && !strings.Contains(w.Prefix, "/")
	}
	return false
}

// WriteTemp writes data to a new temporary file next to name. It syncs and
// closes the file, and gives its name relative to root. The directory part of
// name is opened with OpenRoot and w.Dir. A name with no directory part uses
// root, checked with w.Dir too. Each file step uses a name in that open
// directory, so a link is never followed. The file is made with O_EXCL and
// O_NOFOLLOW. The mode is set with Chmod, so umask does not change it. A
// failed step removes the temporary file. Each error is a *WriteError of its
// step. An invalid rule, a nil root or a name that OpenRoot does not accept
// gives ErrRule. seam.Crash returns at once, with no removal.
func WriteTemp(root *os.Root, name string, data []byte, w WriteRule) (string, error) {
	return write(root, name, data, w, false)
}

// Replace is WriteTemp, then w.Check when it is set, then the rename of the
// temporary file over name. Then it syncs the open directory, unless
// w.NoDirSync. A failure before the rename keeps the old file. An error that
// matches ErrMayBeRenamed can leave the new file in place. ErrCheck holds the
// error of w.Check as its cause.
func Replace(root *os.Root, name string, data []byte, w WriteRule) error {
	_, err := write(root, name, data, w, true)
	return err
}

func write(root *os.Root, name string, data []byte, w WriteRule, replace bool) (string, error) {
	ps, ok := parts(name)
	if root == nil || !w.valid() || !ok {
		return "", fail(ErrRule, nil)
	}
	dir := "."
	if len(ps) > 1 {
		dir = strings.Join(ps[:len(ps)-1], "/")
	}
	d, release, err := dirRoot(root, dir, w.Dir)
	if err != nil {
		return "", writeFail(ErrCreate, err, false)
	}
	defer release()
	h := hooks()
	tmp, err := stage(h, d, ps[len(ps)-1], data, w)
	if err == nil && replace {
		err = publish(h, d, dir, tmp, ps[len(ps)-1], w)
	}
	if err != nil {
		return "", err
	}
	if dir != "." {
		tmp = dir + "/" + tmp
	}
	return tmp, nil
}

// discard removes the temporary file after the failure err. It gives err, or
// seam.Crash when a crash stops the removal. After a crash it removes nothing.
func discard(h *seam.Hooks, d *os.Root, tmp string, err error) error {
	if errors.Is(err, seam.Crash) {
		return err
	}
	rerr := runStep(h, "remove", tmp, false, func() error { return d.Remove(tmp) })
	if errors.Is(rerr, seam.Crash) {
		return rerr
	}
	return err
}

// stage makes the synced and closed temporary file in d and gives its name.
func stage(h *seam.Hooks, d *os.Root, base string, data []byte, w WriteRule) (string, error) {
	tmp := w.Prefix
	if w.Temp == TempFixed {
		tmp = base + ".tmp"
		err := runStep(h, "remove", tmp, false, func() error {
			if err := d.Remove(tmp); !errors.Is(err, fs.ErrNotExist) {
				return err
			}
			return nil
		})
		if err != nil {
			return "", err
		}
	} else {
		tmp += rand.Text()
	}
	const flags = os.O_WRONLY | os.O_CREATE | os.O_EXCL | syscall.O_NOFOLLOW | syscall.O_CLOEXEC
	var f *os.File
	err := runStep(h, "create", tmp, false, func() (err error) {
		if f, err = d.OpenFile(tmp, flags, 0o600); err != nil {
			return err
		}
		return f.Chmod(w.Mode)
	})
	if err != nil && f == nil {
		return "", err // nothing was made, so nothing is removed
	}
	closed := false
	steps := []struct {
		name string
		fn   func() error
	}{{"write", func() error { _, err := f.Write(data); return err }},
		{"sync", func() error { return f.Sync() }},
		{"close", func() error { closed = true; return f.Close() }}}
	for _, s := range steps {
		if err != nil {
			break
		}
		err = runStep(h, s.name, tmp, false, s.fn)
	}
	if !closed { // a crash closes a descriptor too
		_ = f.Close()
	}
	if err != nil {
		return "", discard(h, d, tmp, err)
	}
	return tmp, nil
}

// publish runs the check, the rename and the directory sync of Replace.
func publish(h *seam.Hooks, d *os.Root, dir, tmp, base string, w WriteRule) error {
	if w.Check != nil {
		if err := runStep(h, "check", tmp, false, w.Check); err != nil {
			return discard(h, d, tmp, err)
		}
	}
	err := runStep(h, "rename", tmp, false, func() error { return d.Rename(tmp, base) })
	if err != nil {
		return discard(h, d, tmp, err)
	}
	if w.NoDirSync {
		return nil
	}
	return syncRoot(d, dir)
}
