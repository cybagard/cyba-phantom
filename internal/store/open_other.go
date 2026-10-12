//go:build !unix

package store

import "io/fs"

// euid cannot find the user on this system.
func euid() int64 { return -1 }

// fileFacts cannot find the link count or the owner on this system. So the
// directory and file checks fail closed, and Open always fails here.
func fileFacts(fs.FileInfo) (nlink, uid uint64, ok bool) { return 0, 0, false }

// fileIdentity cannot find the device or the inode on this system, so the
// identity check fails closed.
func fileIdentity(fs.FileInfo) (dev, ino uint64, ok bool) { return 0, 0, false }
