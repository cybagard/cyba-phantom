//go:build unix

package tlog

import (
	"os"
	"syscall"
)

const (
	// readFlags opens a file without a block on a FIFO. O_NOFOLLOW does not
	// decide what happens to a symlink here: os.Root follows a link that stays
	// inside the state directory, and refuses only a link out of it.
	readFlags = os.O_RDONLY | syscall.O_NONBLOCK | syscall.O_NOFOLLOW

	// createFlags makes a new file. It fails if the name exists.
	createFlags = os.O_WRONLY | os.O_CREATE | os.O_EXCL | syscall.O_NOFOLLOW
)
