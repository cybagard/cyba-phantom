//go:build unix && !aix && !solaris

package safefile

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/cybagard/cyba-phantom/internal/safefile/safefiletest"
)

func openTemp(t *testing.T) *os.File {
	t.Helper()
	f, err := os.Create(filepath.Join(t.TempDir(), "file"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

// isClosed is true when the descriptor of f is closed.
func isClosed(f *os.File) bool { return errors.Is(f.Close(), os.ErrClosed) }

// stepCall is one call of the Step hook.
type stepCall struct{ step, name string }

// steps records each call of the Step hook and gives err for the step. The
// returned function gives the calls so far.
func steps(t *testing.T, only string, err error) func() []stepCall {
	t.Helper()
	var seen []stepCall
	safefiletest.Set(t, safefiletest.Hooks{Step: func(step, name string) error {
		seen = append(seen, stepCall{step, name})
		if step == only {
			return err
		}
		return nil
	}})
	return func() []stepCall { return seen }
}

func TestTS38_SyncFileAndCloseFileNoHook(t *testing.T) {
	f := openTemp(t)
	if err := SyncFile(f, "file"); err != nil {
		t.Errorf("SyncFile = %v", err)
	}
	if err := CloseFile(f, "file"); err != nil {
		t.Errorf("CloseFile = %v", err)
	}
	if !isClosed(f) {
		t.Error("the file is open after CloseFile")
	}
}

func TestTS38_SyncFileAndCloseFileRunOneStep(t *testing.T) {
	f := openTemp(t)
	seen := steps(t, "", nil)
	if err := SyncFile(f, "a.db"); err != nil {
		t.Fatal(err)
	}
	if err := CloseFile(f, "b.db"); err != nil {
		t.Fatal(err)
	}
	want := []stepCall{{"sync", "a.db"}, {"close", "b.db"}}
	if got := seen(); !slices.Equal(got, want) {
		t.Errorf("steps = %q, want %q", got, want)
	}
}

func TestTS38_SyncFileHookError(t *testing.T) {
	f := openTemp(t)
	steps(t, "sync", syscall.ENOSPC)
	err := SyncFile(f, secret)
	var we *WriteError
	if !errors.As(err, &we) || we.Step != ErrSync || !errors.Is(err, syscall.ENOSPC) {
		t.Fatalf("err = %v, want a *WriteError of ErrSync with ENOSPC", err)
	}
	if errors.Is(err, ErrMayBeRenamed) || errors.Is(err, safefiletest.Crash) {
		t.Errorf("err = %v matches ErrMayBeRenamed or Crash", err)
	}
	if strings.Contains(err.Error(), "secret") {
		t.Errorf("the error text has the name: %v", err)
	}
}

func TestTS38_SyncFileCrash(t *testing.T) {
	f := openTemp(t)
	steps(t, "sync", safefiletest.Crash)
	err := SyncFile(f, "file")
	var we *WriteError
	if !errors.Is(err, safefiletest.Crash) || errors.As(err, &we) {
		t.Errorf("err = %v, want Crash and no *WriteError", err)
	}
	if isClosed(f) {
		t.Error("SyncFile closed the file")
	}
}

func TestTS38_SyncFileHookCannotMakeFailedSyncPass(t *testing.T) {
	f := openTemp(t)
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	steps(t, "", nil)
	err := SyncFile(f, "file")
	var we *WriteError
	if !errors.As(err, &we) || we.Step != ErrSync || !errors.Is(err, os.ErrClosed) {
		t.Errorf("err = %v, want a *WriteError of ErrSync with ErrClosed", err)
	}
}

func TestTS38_CloseFileClosesOnEveryPath(t *testing.T) {
	for _, c := range []struct {
		name   string
		hook   error
		panics bool  // the hook panics and the test recovers
		is     error // nil: CloseFile gives nil
	}{
		{"no hook error", nil, false, nil},
		{"hook error", syscall.EIO, false, ErrClose},
		{"crash", safefiletest.Crash, false, safefiletest.Crash},
		{"hook panic", nil, true, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := openTemp(t)
			safefiletest.Set(t, safefiletest.Hooks{Step: func(step, _ string) error {
				if step != "close" {
					return nil
				}
				if c.panics {
					panic("hook panic")
				}
				return c.hook
			}})
			var err error
			func() {
				defer func() {
					if r := recover(); c.panics != (r != nil) {
						t.Errorf("recover = %v, want a panic: %v", r, c.panics)
					}
				}()
				err = CloseFile(f, secret)
			}()
			if c.is == nil && err != nil || c.is != nil && !errors.Is(err, c.is) {
				t.Errorf("err = %v, want %v", err, c.is)
			}
			if c.hook != nil && !errors.Is(err, c.hook) {
				t.Errorf("err = %v, want the hook error", err)
			}
			if !isClosed(f) {
				t.Error("the descriptor is open")
			}
			if err != nil && strings.Contains(err.Error(), "secret") {
				t.Errorf("the error text has the name: %v", err)
			}
		})
	}
}

func TestTS38_CloseFileHookErrorIsAWriteError(t *testing.T) {
	f := openTemp(t)
	steps(t, "close", syscall.EIO)
	err := CloseFile(f, "file")
	var we *WriteError
	if !errors.As(err, &we) || we.Step != ErrClose || errors.Is(err, safefiletest.Crash) {
		t.Errorf("err = %v, want a *WriteError of ErrClose", err)
	}
}

func TestTS38_CloseFileHookCannotMakeFailedClosePass(t *testing.T) {
	f := openTemp(t)
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	steps(t, "", nil)
	err := CloseFile(f, "file")
	var we *WriteError
	if !errors.As(err, &we) || we.Step != ErrClose || !errors.Is(err, os.ErrClosed) {
		t.Errorf("err = %v, want a *WriteError of ErrClose with ErrClosed", err)
	}
}
