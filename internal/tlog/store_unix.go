//go:build unix

package tlog

import (
	"os"
	"syscall"
)

const (
	// readFlags opens a file without a block on a FIFO and without a symlink
	// at the last name part.
	readFlags = os.O_RDONLY | syscall.O_NONBLOCK | syscall.O_NOFOLLOW

	// createFlags makes a new file. It fails if the name exists.
	createFlags = os.O_WRONLY | os.O_CREATE | os.O_EXCL | syscall.O_NOFOLLOW
)
