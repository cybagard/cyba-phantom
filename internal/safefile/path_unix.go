//go:build unix

package safefile

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// maxLinks is the number of symlinks that CheckPathParents follows. It is the
// limit of filepath.EvalSymlinks.
const maxLinks = 255

// OpenPath checks the absolute path, opens it and checks the open file. It
// does not use os.Root. A path that is not absolute gives ErrName. A rule that
// is not valid gives ErrRule. The open does not block. The order is: stat, the
// type rule, the open, the identity compare, and the whole rule on the open
// file. A symlink at the last part gives ErrSymlink before the open. With
// FollowEnd, OpenPath follows that symlink. It then applies the type rule to
// the target before the open. A file that replaces the checked file gives
// ErrChanged. OpenPath does not check the directories above the file; see
// CheckPathParents. The caller closes the file.
func OpenPath(path string, r Rule) (*os.File, fs.FileInfo, error) {
	if !r.valid() {
		return nil, nil, fail(ErrRule, nil)
	}
	if !strings.HasPrefix(path, "/") {
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
	call(h.AfterOpen, path)
	fi, err := f.Stat()
	switch {
	case err != nil:
		err = fail(ErrExamine, err)
	case !os.SameFile(si, fi):
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

// CheckPathParents applies dir to "/" and to each directory that the walk of
// the absolute path enters. The walk resolves one part at a time. It follows
// each symlink, also at the last part, up to 255 links. So it checks the
// directories of the path as written, of each symlink, and of each target. It
// does not apply dir to the last part. It uses Lstat and Readlink and opens
// nothing. A missing part gives ErrExamine, and the cause holds
// fs.ErrNotExist. A part on the way that is not a directory gives ErrType.
// More than 255 links give ErrSymlink. A path that is not absolute gives
// ErrName. A rule that is not valid, or not for a directory, gives ErrRule.
func CheckPathParents(path string, dir Rule) error {
	if !dir.valid() || dir.Type != Dir {
		return fail(ErrRule, nil)
	}
	if !strings.HasPrefix(path, "/") {
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
