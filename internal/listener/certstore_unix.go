//go:build unix

package listener

import (
	"errors"
	"io/fs"
	"os"
	"syscall"
)

// readFlags opens a file or a directory for read. A call of os.Root.OpenFile
// follows a link in the last part of a name, if the link stays inside the root.
// It does this also with O_NOFOLLOW. Only O_CREATE|O_EXCL does not follow a link.
// O_NONBLOCK stops a FIFO from blocking the open.
const readFlags = os.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_NONBLOCK | syscall.O_CLOEXEC

// createFlags makes a new file. The open fails if the name exists.
const createFlags = os.O_WRONLY | os.O_CREATE | os.O_EXCL | syscall.O_NOFOLLOW | syscall.O_CLOEXEC

// otherOwner is a test hook. When it is not nil, ownedByUs gives it the device and
// the inode of a file or a directory. If it gives true, ownedByUs returns false.
// So a test gives another owner to one inode only, with no need for root. It is
// nil in production.
var otherOwner func(dev, ino uint64) bool

// ownedByUs reports whether the effective user owns the file. It returns false
// when the system gives no owner.
func ownedByUs(fi fs.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	if otherOwner != nil && otherOwner(uint64(st.Dev), uint64(st.Ino)) {
		return false
	}
	return int64(st.Uid) == int64(os.Geteuid())
}

// linkCount returns the number of hard links of the file. It returns false when
// the system gives no count.
func linkCount(fi fs.FileInfo) (uint64, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return uint64(st.Nlink), true
}

// isLoop reports whether err is ELOOP. ELOOP comes back when a name has more
// symbolic links than os.Root allows. This is a loop of symbolic links or a long
// chain of them. ELOOP also comes back when the open (or Stat) gave ELOOP and the
// following readlinkat fails. An ENOTDIR stays ENOTDIR.
func isLoop(err error) bool { return errors.Is(err, syscall.ELOOP) }
