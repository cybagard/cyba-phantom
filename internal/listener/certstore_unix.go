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

// moreThanOneLink reports whether the file has more than one hard link. It also
// returns true when the system gives no count. A count of 0 is a file that a
// rename or a Delete removed after the open. The open file still holds the
// whole value. The shared rule refuses 0, so this check is not in that rule.
func moreThanOneLink(fi fs.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return !ok || st.Nlink > 1
}

// isLoop reports whether err is ELOOP. ELOOP comes back when a name has more
// symbolic links than os.Root allows. This is a loop of symbolic links or a long
// chain of them. ELOOP also comes back when the open (or Stat) gave ELOOP and the
// following readlinkat fails. An ENOTDIR stays ENOTDIR.
func isLoop(err error) bool { return errors.Is(err, syscall.ELOOP) }
