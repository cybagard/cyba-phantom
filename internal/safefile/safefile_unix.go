//go:build unix

package safefile

import (
	"errors"
	"io/fs"
	"os"
	"strings"
	"syscall"

	"github.com/cybagard/cyba-phantom/internal/safefile/internal/seam"
)

// Identity gives the device and inode of fi.
func Identity(fi fs.FileInfo) (FileID, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return FileID{}, false
	}
	return FileID{Dev: uint64(st.Dev), Ino: uint64(st.Ino)}, true
}

// Open checks name below root, opens it and checks the open file. The name is
// one path element. Open refuses an empty name and a name with a slash. It
// does not walk a directory below the root. A nil root or a rule that is not
// valid gives ErrRule. The open does not block. Open refuses a symlink at the
// name before the open. A symlink that replaces the file after the check
// gives ErrChanged when it points to another file. It gives ErrOpen when it
// leaves the root. A link to the checked file opens that file, and the whole
// rule runs on it. The identity compare does not see a new file that gets
// the inode number of the checked file. The whole rule runs on that file too.
// The caller closes the file.
func Open(root *os.Root, name string, r Rule) (*os.File, fs.FileInfo, error) {
	if root == nil || !r.valid() {
		return nil, nil, fail(ErrRule, nil)
	}
	if name == "" || strings.Contains(name, "/") {
		return nil, nil, fail(ErrName, nil)
	}
	h := hooks()
	call(h.BeforeCheck, name)
	li, err := root.Lstat(name)
	if err != nil {
		return nil, nil, fail(ErrExamine, err)
	}
	if err := checkType(li, r); err != nil {
		return nil, nil, err
	}
	call(h.AfterCheck, name)
	// os.Root follows a last symlink that stays in the root, also with
	// O_NOFOLLOW. The identity compare below catches a link to another file.
	flags := os.O_RDONLY | syscall.O_NONBLOCK | syscall.O_NOCTTY |
		syscall.O_NOFOLLOW
	if r.Type == Dir {
		flags |= syscall.O_DIRECTORY
	}
	f, err := root.OpenFile(name, flags, 0)
	if err != nil {
		return nil, nil, openError(err)
	}
	return checkOpened(f, name, li, r, h)
}

// checkOpened checks the open file f of name against the checked fi. It runs
// the AfterOpen hook, the identity compare and the whole rule. On an error it
// closes f.
func checkOpened(f *os.File, name string, checked fs.FileInfo, r Rule,
	h *seam.Hooks) (*os.File, fs.FileInfo, error) {
	call(h.AfterOpen, name)
	fi, err := f.Stat()
	switch {
	case err != nil:
		err = fail(ErrExamine, err)
	case !os.SameFile(checked, fi):
		err = fail(ErrChanged, nil)
	default:
		err = checkOpen(fi, r, h)
	}
	if err != nil {
		_ = f.Close()
		return nil, nil, err
	}
	return f, fi, nil
}

// call runs a hook when it is set.
func call(hook func(name string), name string) {
	if hook != nil {
		hook(name)
	}
}

// openError names the refusal of a failed open. ELOOP or EMLINK gives
// ErrSymlink. ENOTDIR gives ErrType. Each other error gives ErrOpen.
func openError(err error) error {
	switch {
	case errors.Is(err, syscall.ELOOP), errors.Is(err, syscall.EMLINK):
		return fail(ErrSymlink, err)
	case errors.Is(err, syscall.ENOTDIR):
		return fail(ErrType, err)
	}
	return fail(ErrOpen, err)
}

// checkType refuses a symlink, and a file that is not of the type of r.
func checkType(fi fs.FileInfo, r Rule) error {
	m := fi.Mode()
	switch {
	case m&fs.ModeSymlink != 0:
		return fail(ErrSymlink, nil)
	case r.Type == Regular && !m.IsRegular(), r.Type == Dir && !m.IsDir():
		return fail(ErrType, nil)
	}
	return nil
}

// checkOpen applies the whole rule to fi.
func checkOpen(fi fs.FileInfo, r Rule, h *seam.Hooks) error {
	if err := checkType(fi, r); err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fail(ErrExamine, nil)
	}
	if r.Owner != OwnerAny {
		self := uint32(os.Geteuid())
		ok := st.Uid == self || (r.Owner == OwnerSelfOrRoot && st.Uid == 0)
		id, _ := Identity(fi)
		if !ok || (h.OtherOwner != nil && h.OtherOwner(id)) {
			return fail(ErrOwner, nil)
		}
	}
	mode := fi.Mode() & modeBits
	if mode&r.Forbid != 0 || (r.Exact != 0 && mode != r.Exact) {
		return fail(ErrMode, nil)
	}
	if r.OneLink && uint64(st.Nlink) != 1 {
		return fail(ErrLinks, nil)
	}
	if r.MaxSize > 0 && fi.Size() > r.MaxSize {
		return fail(ErrSize, nil)
	}
	return nil
}
