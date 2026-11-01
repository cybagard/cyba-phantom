//go:build unix

package safefile

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// maxLinks is the maximum number of symlinks that CheckPathParents follows. It
// is the limit of the Linux kernel.
const maxLinks = 40

// validPath is true for an absolute path with a last element that is not
// empty, "." or "..". The kernel follows a link when a "/" comes after it.
func validPath(path string) bool {
	if !strings.HasPrefix(path, "/") {
		return false
	}
	switch path[strings.LastIndexByte(path, '/')+1:] {
	case "", ".", "..":
		return false
	}
	return true
}

// OpenPath checks the absolute path, opens it and checks the open file. It
// does not use os.Root. A path that is not absolute gives ErrName. A path that
// ends in "/", "/." or "/.." gives ErrName too, also "/" itself. A rule that
// is not valid gives ErrRule. The open does not block. The order is: stat, the
// type rule, the open, the identity compare, and the whole rule on the open
// file. A symlink at the last part gives ErrSymlink before the open. With
// FollowEnd, OpenPath follows that symlink. It then applies the type rule to
// the target before the open. A link loop at the last part gives ErrSymlink.
// With or without FollowEnd, OpenPath follows a symlink in a directory part.
// CheckPathParents checks those directories. A file that replaces the checked
// file gives ErrChanged. The caller closes the file.
func OpenPath(path string, r Rule) (*os.File, fs.FileInfo, error) {
	if !r.valid() {
		return nil, nil, fail(ErrRule, nil)
	}
	if !validPath(path) {
		return nil, nil, fail(ErrName, nil)
	}
	h := hooks()
	call(h.BeforeCheck, path)
	flags := os.O_RDONLY | syscall.O_NONBLOCK | syscall.O_NOCTTY
	stat := os.Lstat
	if r.FollowEnd {
		stat = os.Stat
	} else {
		flags |= syscall.O_NOFOLLOW
	}
	si, err := stat(path)
	if errors.Is(err, syscall.ELOOP) {
		return nil, nil, fail(ErrSymlink, err)
	}
	if err != nil {
		return nil, nil, fail(ErrExamine, err)
	}
	if err := checkType(si, r); err != nil {
		return nil, nil, err
	}
	call(h.AfterCheck, path)
	if r.Type == Dir {
		flags |= syscall.O_DIRECTORY
	}
	f, err := os.OpenFile(path, flags, 0)
	if err != nil {
		return nil, nil, openError(err)
	}
	return checkOpened(f, path, si, r, h)
}

// CheckPathParents applies dir to "/" and to each directory that the walk of
// the absolute path enters. The walk resolves one part at a time. It follows
// each symlink, also at the last part, up to 40 links. So it checks the
// directories of the path as written, of each symlink, and of each target. It
// does not apply dir to the last part. It uses Lstat and Readlink and opens
// nothing. The walk resolves each symlink from its Readlink text. It resolves
// a /proc magic link, for example /proc/self/root, as text. It does not use
// the object behind the link. A missing part gives ErrExamine, and the cause
// holds fs.ErrNotExist. A part on the way that is not a directory gives
// ErrType. More than 40 links give ErrSymlink. A path that is not absolute
// gives ErrName. A path that ends in "/", "/." or "/.." gives ErrName too.
// A rule that is not valid, or not for a directory, gives ErrRule. A rule
// with FollowEnd, OneLink or MaxSize gives ErrRule too.
func CheckPathParents(path string, dir Rule) error {
	if !dir.valid() || dir.Type != Dir ||
		dir.FollowEnd || dir.OneLink || dir.MaxSize != 0 {
		return fail(ErrRule, nil)
	}
	if !validPath(path) {
		return fail(ErrName, nil)
	}
	h := hooks()
	cur, links := "/", 0
	li, err := os.Lstat(cur)
	if err != nil {
		return fail(ErrExamine, err)
	}
	if err := checkOpen(li, dir, h); err != nil {
		return err
	}
	for rest := path; ; {
		rest = strings.TrimLeft(rest, "/")
		if rest == "" {
			return nil
		}
		var part string
		part, rest, _ = strings.Cut(rest, "/")
		switch part {
		case ".":
			continue
		case "..":
			cur = filepath.Dir(cur)
			continue
		}
		next := filepath.Join(cur, part)
		li, err := os.Lstat(next)
		if err != nil {
			return fail(ErrExamine, err)
		}
		if li.Mode()&fs.ModeSymlink != 0 {
			if links++; links > maxLinks {
				return fail(ErrSymlink, nil)
			}
			target, err := os.Readlink(next)
			if err != nil || target == "" {
				return fail(ErrExamine, err)
			}
			if strings.HasPrefix(target, "/") {
				cur = "/"
			}
			rest = target + "/" + rest
			continue
		}
		if strings.TrimLeft(rest, "/") == "" {
			return nil
		}
		if err := checkOpen(li, dir, h); err != nil {
			return err
		}
		cur = next
	}
}
