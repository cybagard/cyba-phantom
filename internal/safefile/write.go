//go:build unix

package safefile

import (
	"errors"
	"io/fs"
	"os"

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
// lose their paths.
func writeFail(step, cause error, after bool) error {
	var pe *fs.PathError
	var le *os.LinkError
	switch {
	case errors.As(cause, &pe):
		cause = pe.Err
	case errors.As(cause, &le):
		cause = le.Err
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

// SyncDir opens dir below root with OpenRoot and the directory rule r, syncs
// the directory and closes it. A link at any part of dir gives ErrSymlink, as
// for OpenRoot. The name "." is the root itself. The caller opened it, so r is
// not applied to it. Each error is a *WriteError with the step ErrDirSync. It
// holds the refusal of OpenRoot, the sync error or the close error as its
// cause. A nil root, or a rule that is not a rule for a directory, gives
// ErrRule. A Step hook that gives seam.Crash makes SyncDir return that error.
func SyncDir(root *os.Root, dir string, r Rule) error {
	if root == nil || !r.valid() || r.Type != Dir {
		return writeFail(ErrDirSync, fail(ErrRule, nil), true)
	}
	if dir == "." {
		return syncRoot(root, dir)
	}
	sub, err := OpenRoot(root, dir, r)
	if err != nil {
		return writeFail(ErrDirSync, err, true)
	}
	err = syncRoot(sub, dir)
	if cerr := sub.Close(); err == nil && cerr != nil {
		err = writeFail(ErrDirSync, cerr, true)
	}
	return err
}
