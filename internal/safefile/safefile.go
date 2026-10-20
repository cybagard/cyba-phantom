// Package safefile opens and checks files with one rule type. Each caller
// gives its own rule. The package applies the rule before and after the open
// (SEC-27).
package safefile

import (
	"errors"
	"io/fs"

	"github.com/cybagard/cyba-phantom/internal/safefile/internal/seam"
)

// Type is the file type that a rule needs.
type Type uint8

// The file types.
const (
	Regular Type = iota + 1
	Dir
)

// Owner is the owner check.
type Owner uint8

// The owner checks.
const (
	OwnerSelf       Owner = iota + 1 // the effective user only
	OwnerSelfOrRoot                  // the effective user or root
	OwnerAny                         // no owner check
)

// Rule is the rule of one caller. The zero value is not valid. Open refuses
// it, so a caller cannot get "no checks" by mistake.
type Rule struct {
	Type    Type
	Owner   Owner
	Forbid  fs.FileMode // permission and special bits that must be 0
	Exact   fs.FileMode // when not 0, permission and special bits equal it
	OneLink bool        // the link count must be 1
	MaxSize int64       // when > 0, the size of the open file is at most this
}

// FileID is the device and inode of a file.
type FileID = seam.FileID

// The refusals. Each one is the Reason field of an *Error.
var (
	ErrRule        = errors.New("safefile: rule is not valid")
	ErrName        = errors.New("safefile: name is not one path element")
	ErrType        = errors.New("safefile: file has the wrong type")
	ErrSymlink     = errors.New("safefile: file is a symbolic link")
	ErrOwner       = errors.New("safefile: file has the wrong owner")
	ErrMode        = errors.New("safefile: file has the wrong mode")
	ErrLinks       = errors.New("safefile: file has more than one link")
	ErrSize        = errors.New("safefile: file is too large")
	ErrChanged     = errors.New("safefile: file changed during the check")
	ErrExamine     = errors.New("safefile: file cannot be examined")
	ErrOpen        = errors.New("safefile: file cannot be opened")
	ErrUnsupported = errors.New("safefile: system is not supported")
)

// Error is a refusal. Its text is the fixed text of the refusal. It holds
// no path and no file bytes.
type Error struct {
	Reason error // one of the Err values
	Cause  error // the system error, or nil
}

// Error gives the fixed text of the refusal.
func (e *Error) Error() string { return e.Reason.Error() }

// Unwrap gives the refusal and the cause, so errors.Is finds both.
func (e *Error) Unwrap() []error {
	if e.Cause == nil {
		return []error{e.Reason}
	}
	return []error{e.Reason, e.Cause}
}

// fail makes the error of a refusal. A path error loses its path.
func fail(reason, cause error) error {
	var pe *fs.PathError
	if errors.As(cause, &pe) {
		cause = pe.Err
	}
	return &Error{Reason: reason, Cause: cause}
}

const modeBits = fs.ModePerm | fs.ModeSetuid | fs.ModeSetgid | fs.ModeSticky

// valid is false for the zero rule and for any value that is not defined.
func (r Rule) valid() bool {
	return (r.Type == Regular || r.Type == Dir) &&
		r.Owner >= OwnerSelf && r.Owner <= OwnerAny &&
		r.MaxSize >= 0 && (r.Forbid|r.Exact)&^modeBits == 0
}
