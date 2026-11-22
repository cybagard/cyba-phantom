//go:build unix

package safefile

import "os"

// SyncFile syncs the open file f. The caller opened f through a checked root.
// The name is the file name that the Step hook gets. SyncFile opens no path.
// It runs the step "sync". Each error other than seam.Crash is a *WriteError
// with the step ErrSync and no path. A Step hook error fails the step. A hook
// never makes a failed sync pass. A Step hook that gives seam.Crash makes
// SyncFile return that error.
func SyncFile(f *os.File, name string) error {
	return runStep(hooks(), "sync", name, false, f.Sync)
}

// CloseFile closes the open file f. The name is the file name that the Step
// hook gets. It runs the step "close". Each error other than seam.Crash is a
// *WriteError with the step ErrClose and no path. A hook never makes a failed
// close pass. CloseFile closes f on every path: also after a hook error and
// after seam.Crash. A Step hook that gives seam.Crash makes CloseFile return
// that error.
func CloseFile(f *os.File, name string) error {
	closed := false
	err := runStep(hooks(), "close", name, false, func() error {
		closed = true
		return f.Close()
	})
	if !closed {
		// The hook stopped the step. A crash closes a descriptor too.
		_ = f.Close()
	}
	return err
}
