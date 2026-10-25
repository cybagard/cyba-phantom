//go:build linux || darwin

package verify

import (
	"errors"
	"os"
	"syscall"
	"time"

	"github.com/cybagard/cyba-phantom/internal/safefile"
)

// lockRetry is the time between two tries to take the lock.
const lockRetry = 10 * time.Millisecond

// flock takes the lock. Only tests change it.
var flock = syscall.Flock

// stateDirRule is the rule of the state directory. The user of the run must
// own it, and it must have no group or other permission bit.
var stateDirRule = safefile.Rule{
	Type:   safefile.Dir,
	Owner:  safefile.OwnerSelf,
	Forbid: 0o077,
}

// lockDir opens the state directory with safefile, which checks its mode and
// owner, and takes an exclusive flock on it. The check is on the open
// directory, which is the directory that the lock covers. It comes before the
// lock. If another run holds the lock, lockDir tries again until wait has
// passed. Then it gives ErrStateLocked. The kernel releases the lock when the
// caller closes the file, or when the process ends. A signal can interrupt the
// call, so it repeats on EINTR. Any other fault gives ErrState.
func lockDir(root *os.Root, wait time.Duration) (*os.File, error) {
	d, _, err := safefile.Open(root, ".", stateDirRule)
	if err != nil {
		return nil, ErrState
	}
	rc, err := d.SyscallConn()
	if err != nil {
		d.Close()
		return nil, ErrState
	}
	var ferr error
	deadline := time.Now().Add(wait)
	if err := rc.Control(func(fd uintptr) {
		for {
			ferr = flock(int(fd), syscall.LOCK_EX|syscall.LOCK_NB)
			switch {
			case ferr == nil:
				return
			case errors.Is(ferr, syscall.EINTR):
				continue
			case !errors.Is(ferr, syscall.EWOULDBLOCK):
				return
			case !time.Now().Before(deadline):
				ferr = ErrStateLocked
				return
			}
			time.Sleep(lockRetry)
		}
	}); err != nil || ferr != nil {
		d.Close()
		if errors.Is(ferr, ErrStateLocked) {
			return nil, ErrStateLocked
		}
		return nil, ErrState
	}
	return d, nil
}
