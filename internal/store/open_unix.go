//go:build unix

package store

import (
	"io/fs"
	"os"
	"syscall"
)

// euid returns the effective user of the process.
func euid() int64 { return int64(os.Geteuid()) }

// openHeld opens an existing database file through root for reading. It does not
// follow a symlink, and the descriptor does not pass to a child process.
func openHeld(root *os.Root, rel string) (*os.File, error) {
	return root.OpenFile(rel, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
}

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
