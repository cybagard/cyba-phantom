//go:build unix

package safefile

import "os"

// SyncFile syncs the open file f. The caller must open f through a checked
// root. The name is the file name that a Step hook gets. SyncFile opens no
// path. It runs the step "sync". Each error other than seam.Crash is a
// *WriteError with the step ErrSync and no path. A Step hook error fails the
// step. A Step hook never makes a failed sync pass. A Step hook that gives
// seam.Crash makes SyncFile return that error.
func SyncFile(f *os.File, name string) error {
	return runStep(hooks(), "sync", name, false, f.Sync)
}

// CloseFile closes the open file f. The name is the file name that a Step
// hook gets. It runs the step "close". Each error other than seam.Crash is a
// *WriteError with the step ErrClose and no path. A Step hook error fails the
// step. A Step hook never makes a failed close pass. CloseFile closes f on
// each path, also after a Step hook error, seam.Crash, or panic. A Step hook
// that gives seam.Crash makes CloseFile return that error.
func CloseFile(f *os.File, name string) error {
	closed := false
	defer func() {
		if !closed {
			// The hook stopped the step, or it panicked. Close f here.
			_ = f.Close()
		}
	}()
	return runStep(hooks(), "close", name, false, func() error {
		closed = true
		return f.Close()
	})
}
