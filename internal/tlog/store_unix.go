//go:build unix

package tlog

import (
	"os"
	"syscall"
)

// createFlags makes a new file. It fails if the name exists.
const createFlags = os.O_WRONLY | os.O_CREATE | os.O_EXCL | syscall.O_NOFOLLOW
