//go:build !unix

package store

import "io/fs"

// euid cannot find the user on this system.
func euid() int64 { return -1 }

// fileFacts cannot find the link count or the owner on this system, so the
// file checks fail closed for an existing file.
func fileFacts(fs.FileInfo) (nlink, uid uint64, ok bool) { return 0, 0, false }
