//go:build unix

package listener

import (
	"errors"
	"io/fs"
	"os"
	"syscall"
)

// readFlags open a file or a directory for read. O_NOFOLLOW refuses a link in
// the last part, and O_NONBLOCK stops a FIFO from blocking the open.
const readFlags = os.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_NONBLOCK | syscall.O_CLOEXEC

// createFlags make a new file. They fail if the name exists.
const createFlags = os.O_WRONLY | os.O_CREATE | os.O_EXCL | syscall.O_NOFOLLOW | syscall.O_CLOEXEC

// geteuid is a test hook. A test uses it to check an owner mismatch without root.
var geteuid = os.Geteuid

// ownedByUs reports whether the effective user owns the file. It fails closed.
func ownedByUs(fi fs.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && int64(st.Uid) == int64(geteuid())
}

// isLoop reports whether err is the error of a link that O_NOFOLLOW refused.
func isLoop(err error) bool { return errors.Is(err, syscall.ELOOP) }
