//go:build unix

package safefile

import (
	"os"
	"strings"

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
// part it runs the Lstat, the type rule, and the open. Then it compares the
// open directory with the Lstat result. Then it runs the whole rule on the
// open directory. A link at a part gives ErrSymlink or ErrChanged. A directory
// that is replaced after its check gives ErrChanged. The rule dir must be a
// rule for a directory. The caller closes the root that it gets.
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
