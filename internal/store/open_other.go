//go:build !unix

package store

import (
	"io/fs"
	"os"
)

// euid cannot find the user on this system.
func euid() int64 { return -1 }

// openHeld opens an existing database file through root for reading.
func openHeld(root *os.Root, rel string) (*os.File, error) {
	return root.OpenFile(rel, os.O_RDONLY, 0)
}

// fileFacts cannot find the link count or the owner on this system. So the
// directory and file checks fail closed, and Open always fails here.
func fileFacts(fs.FileInfo) (nlink, uid uint64, ok bool) { return 0, 0, false }

// fileIdentity cannot find the device or the inode on this system, so the
// identity check fails closed.
func fileIdentity(fs.FileInfo) (dev, ino uint64, ok bool) { return 0, 0, false }
