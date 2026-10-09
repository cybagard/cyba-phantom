//go:build unix

package tlog

import (
	"io/fs"
	"os"
	"syscall"
)

// readFlags open the key for read. O_NOFOLLOW refuses a symlink. O_NONBLOCK
// stops a FIFO from blocking the open.
const readFlags = os.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_NONBLOCK

// geteuid is a test hook. A test uses it to check an owner mismatch without root.
var geteuid = os.Geteuid

// ownedByEUID reports whether the owner of the file is the effective user.
func ownedByEUID(fi fs.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && int64(st.Uid) == int64(geteuid())
}
