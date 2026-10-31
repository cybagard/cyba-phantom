//go:build unix

package tlog

import (
	"os"
	"syscall"
)

// readFlags open a file for read. O_NONBLOCK stops a FIFO from blocking the
// open. os.Root adds O_NOFOLLOW itself, but it does not stop an in-root symlink.
const readFlags = os.O_RDONLY | syscall.O_NONBLOCK
