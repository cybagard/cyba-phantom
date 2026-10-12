//go:build unix

package store

import (
	"io/fs"
	"os"
	"syscall"
)

// geteuid is a test hook. A test uses it to check an owner mismatch without root.
var geteuid = os.Geteuid

// euid returns the effective user of the process.
func euid() int64 { return int64(geteuid()) }

// fileFacts is a test variable: a test replaces it to give one directory or file
// another owner without root. It returns the link count and the owner of a file.
// ok is false when the system gives neither.
var fileFacts = systemFacts

func systemFacts(fi fs.FileInfo) (nlink, uid uint64, ok bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return uint64(st.Nlink), uint64(st.Uid), true
}

// fileIdentity returns the device and the inode of a file. ok is false when the
// system gives neither.
func fileIdentity(fi fs.FileInfo) (dev, ino uint64, ok bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return uint64(st.Dev), uint64(st.Ino), true
}
