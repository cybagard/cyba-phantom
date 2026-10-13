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

// geteuid is a test hook. A test uses it to check an owner mismatch without root.
var geteuid = os.Geteuid

// ownedByUs reports whether the effective user owns the file. It returns false
// when the system gives no owner.
func ownedByUs(fi fs.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && int64(st.Uid) == int64(geteuid())
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

// isLoop reports whether err is ELOOP. A call of os.Root gives ELOOP when it
// finds a loop of links, and when the open fails because of a link that the call
// then cannot read, for example after a race that replaces the link.
func isLoop(err error) bool { return errors.Is(err, syscall.ELOOP) }
