//go:build unix

package verify

import (
	"errors"
	"os"
	"syscall"
)

// lockDir opens the state directory and takes an exclusive flock on it. It
// waits until it has the lock. The kernel releases the lock when the file is
// closed, or when the process ends. A signal can interrupt the wait, so the
// call repeats on EINTR. Any other fault gives ErrState.
func lockDir(root *os.Root) (*os.File, error) {
	d, err := root.Open(".")
	if err != nil {
		return nil, ErrState
	}
	rc, err := d.SyscallConn()
	if err != nil {
		d.Close()
		return nil, ErrState
	}
	var ferr error
	if err := rc.Control(func(fd uintptr) {
		for {
			ferr = syscall.Flock(int(fd), syscall.LOCK_EX)
			if !errors.Is(ferr, syscall.EINTR) {
				return
			}
		}
	}); err != nil || ferr != nil {
		d.Close()
		return nil, ErrState
	}
	return d, nil
}
