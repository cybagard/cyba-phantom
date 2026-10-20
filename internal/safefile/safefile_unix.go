//go:build unix

package safefile

import (
	"errors"
	"io/fs"
	"os"
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

// Open checks name below root, opens it and checks the open file. The open
// does not block. A symlink at the name is refused before the open. A symlink
// that replaces the file after the check is refused by the identity compare,
// or by the open when it leaves the root. The caller closes the file.
func Open(root *os.Root, name string, r Rule) (*os.File, fs.FileInfo, error) {
	if root == nil || !r.valid() {
		return nil, nil, fail(ErrRule, nil)
	}
	h := seam.Current()
	if h == nil {
		h = &seam.Hooks{}
	}
	if h.BeforeCheck != nil {
		h.BeforeCheck(name)
	}
	li, err := root.Lstat(name)
	if err != nil {
		return nil, nil, fail(ErrExamine, err)
	}
	if err := checkType(li, r); err != nil {
		return nil, nil, err
	}
	if h.AfterCheck != nil {
		h.AfterCheck(name)
	}
	flags := os.O_RDONLY | syscall.O_NONBLOCK | syscall.O_NOCTTY |
		syscall.O_NOFOLLOW
	if r.Type == Dir {
		flags |= syscall.O_DIRECTORY
	}
	f, err := root.OpenFile(name, flags, 0)
	if err != nil {
		return nil, nil, openError(err)
	}
	if h.AfterOpen != nil {
		h.AfterOpen(name)
	}
	fi, err := f.Stat()
	if err == nil && !os.SameFile(li, fi) {
		err = fail(ErrChanged, nil)
	} else if err != nil {
		err = fail(ErrExamine, err)
	} else {
		err = checkOpen(fi, r, h)
	}
	if err != nil {
		_ = f.Close()
		return nil, nil, err
	}
	return f, fi, nil
}

// openError names the refusal of a failed open. A symlink or a directory
// that replaced the checked file is a refusal of its own.
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

// checkOpen applies the whole rule to the fstat result of the open file.
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
