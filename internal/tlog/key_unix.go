//go:build unix

package tlog

import (
	"io/fs"
	"os"
	"syscall"
)

// geteuid is a seam, so that a test can check an owner mismatch without root.
var geteuid = os.Geteuid

// ownedByEUID reports whether the owner of the file is the effective user.
func ownedByEUID(fi fs.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && int64(st.Uid) == int64(geteuid())
}
