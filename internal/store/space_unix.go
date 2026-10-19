//go:build unix

package store

import (
	"os"
	"syscall"
)

// diskSpace is a test variable: a test replaces it to give a size without a
// full disk. It returns the size of the database file and the size and the free
// space of its file system, in bytes. ok is false when the system gives none.
var diskSpace = systemDiskSpace

// systemDiskSpace opens the database file through root, and reads its size and
// the statfs of its file system from the one descriptor. The free space is the
// space for a user that is not the superuser.
func systemDiskSpace(root *os.Root, rel string) (size, fsSize, free uint64, ok bool) {
	f, err := root.Open(rel)
	if err != nil {
		return 0, 0, 0, false
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return 0, 0, 0, false
	}
	var st syscall.Statfs_t
	if err := syscall.Fstatfs(int(f.Fd()), &st); err != nil {
		return 0, 0, 0, false
	}
	block := uint64(st.Bsize) // the type of the field is not the same on each system
	return uint64(fi.Size()), uint64(st.Blocks) * block, uint64(st.Bavail) * block, true
}
