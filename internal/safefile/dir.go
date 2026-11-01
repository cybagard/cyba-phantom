//go:build unix

package safefile

import (
	"io/fs"
	"os"
	"strings"
	"syscall"

	"github.com/cybagard/cyba-phantom/internal/safefile/internal/seam"
)

// parts splits name into its parts. It gives false for an empty name or a
// name that starts with a slash. It gives false for an empty, "." or ".." part.
func parts(name string) ([]string, bool) {
	if name == "" || strings.HasPrefix(name, "/") {
		return nil, false
	}
	ps := strings.Split(name, "/")
	for _, p := range ps {
		if p == "" || p == "." || p == ".." {
			return nil, false
		}
	}
	return ps, true
}

// walkArgs checks the arguments of OpenRoot and CheckParents.
func walkArgs(root *os.Root, name string, dir Rule) ([]string, error) {
	if root == nil || !dir.valid() || dir.Type != Dir {
		return nil, fail(ErrRule, nil)
	}
	ps, ok := parts(name)
	if !ok {
		return nil, fail(ErrName, nil)
	}
	return ps, nil
}

// OpenRoot opens the directory name below root, one part at a time. For each
// part it runs the Lstat and the type rule. Then it opens the part without
// blocking and compares that descriptor with the Lstat result. Then it opens
// the root and compares it with the Lstat result too. Then it runs the whole
// rule on the open directory. A link at a part at the check gives ErrSymlink.
// Another directory swapped in after the check gives ErrChanged. A link to
// another directory gives ErrChanged too. A link to the checked directory
// opens it. A FIFO, a device, a socket or a regular file swapped in gives
// ErrType, and the open does not block. A link that leaves the parent
// directory of the part gives ErrOpen. A swap after the first open and before
// the root open is still possible. A FIFO swapped in there can still block the
// root open. A terminal swapped in there can still become the controlling
// terminal. The window is smaller, but it is not closed. The rule dir must be
// a rule for a directory. The caller closes the root that it gets.
func OpenRoot(root *os.Root, name string, dir Rule) (*os.Root, error) {
	ps, err := walkArgs(root, name, dir)
	if err != nil {
		return nil, err
	}
	h := hooks()
	cur := root
	for _, p := range ps {
		next, err := openPart(cur, p, dir, h)
		if cur != root {
			_ = cur.Close()
		}
		if err != nil {
			return nil, err
		}
		cur = next
	}
	return cur, nil
}

// openPart opens the directory part of cur and checks it. It closes the new
// root on an error.
func openPart(cur *os.Root, part string, dir Rule, h *seam.Hooks) (*os.Root, error) {
	call(h.BeforeCheck, part)
	li, err := cur.Lstat(part)
	if err != nil {
		return nil, fail(ErrExamine, err)
	}
	if err := checkType(li, dir); err != nil {
		return nil, err
	}
	call(h.AfterCheck, part)
	if err := probePart(cur, part, li, h); err != nil {
		return nil, err
	}
	next, err := cur.OpenRoot(part)
	if err != nil {
		return nil, openError(err)
	}
	fi, err := next.Stat(".")
	switch {
	case err != nil:
		err = fail(ErrExamine, err)
	case !os.SameFile(li, fi):
		err = fail(ErrChanged, nil)
	default:
		err = checkOpen(fi, dir, h)
	}
	if err != nil {
		_ = next.Close()
		return nil, err
	}
	return next, nil
}

// probePart opens part of cur without blocking and compares the open
// directory with the Lstat result li. The open refuses a FIFO, a terminal or
// any other file that is not a directory before it can block. The open
// follows a link at the part if the link stays in cur, and the compare with
// li then refuses another directory. The descriptor is closed on every path.
// os.Root opens a part with neither O_DIRECTORY nor O_NONBLOCK, so openPart
// calls this function before cur.OpenRoot.
func probePart(cur *os.Root, part string, li fs.FileInfo, h *seam.Hooks) error {
	const flags = os.O_RDONLY | syscall.O_DIRECTORY | syscall.O_NONBLOCK |
		syscall.O_NOFOLLOW | syscall.O_NOCTTY
	f, err := cur.OpenFile(part, flags, 0)
	if err != nil {
		return openError(err)
	}
	defer f.Close()
	call(h.AfterOpen, part)
	fi, err := f.Stat()
	if err != nil {
		return fail(ErrExamine, err)
	}
	if !os.SameFile(li, fi) {
		return fail(ErrChanged, nil)
	}
	return nil
}

// CheckParents applies dir to "." and to each directory above the last part
// of name. It uses Lstat and opens nothing. A missing directory gives
// ErrExamine, and the cause holds fs.ErrNotExist. A link gives ErrSymlink.
// The name follows the same limits as for OpenRoot.
func CheckParents(root *os.Root, name string, dir Rule) error {
	ps, err := walkArgs(root, name, dir)
	if err != nil {
		return err
	}
	h := hooks()
	for i := range ps {
		d := "."
		if i > 0 {
			d = strings.Join(ps[:i], "/")
		}
		li, err := root.Lstat(d)
		if err != nil {
			return fail(ErrExamine, err)
		}
		if err := checkOpen(li, dir, h); err != nil {
			return err
		}
	}
	return nil
}
