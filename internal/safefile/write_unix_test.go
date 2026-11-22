//go:build unix && !aix && !solaris

package safefile

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/cybagard/cyba-phantom/internal/safefile/internal/seam"
	"github.com/cybagard/cyba-phantom/internal/safefile/safefiletest"
)

// secret is the path in the cause of the errors that the tests make.
const secret = "/secret/dir/secret-name"

var allSteps = []error{
	ErrTempRemove, ErrCreate, ErrWrite, ErrSync, ErrClose, ErrCheck,
	ErrRename, ErrLink, ErrDirSync, ErrExist,
}

func TestTS38_WriteErrorTable(t *testing.T) {
	// The steps that match ErrMayBeRenamed with no link before them.
	always := map[error]bool{ErrRename: true, ErrLink: true, ErrDirSync: true}
	for _, step := range allSteps {
		for _, after := range []bool{false, true} {
			pe := &fs.PathError{Op: "open", Path: secret, Err: syscall.ENOSPC}
			err := writeFail(step, pe, after)
			if !errors.Is(err, step) {
				t.Errorf("%v after=%v: errors.Is does not find the step", step, after)
			}
			for _, other := range allSteps {
				if other != step && errors.Is(err, other) {
					t.Errorf("%v matches the step %v", step, other)
				}
			}
			if !errors.Is(err, syscall.ENOSPC) {
				t.Errorf("%v: errors.Is does not find ENOSPC", step)
			}
			var got *fs.PathError
			if errors.As(err, &got) {
				t.Errorf("%v: the cause is still a path error", step)
			}
			if err.Error() != step.Error() {
				t.Errorf("%v: text %q is not the fixed text", step, err.Error())
			}
			if strings.Contains(err.Error(), "secret") {
				t.Errorf("%v: text holds the path", step)
			}
			want := always[step] || (step == ErrTempRemove && after)
			if got := errors.Is(err, ErrMayBeRenamed); got != want {
				t.Errorf("%v after=%v: matches ErrMayBeRenamed = %v, want %v",
					step, after, got, want)
			}
		}
	}
}

func TestTS38_WriteErrorTempRemoveBeforeAndAfterLink(t *testing.T) {
	before := writeFail(ErrTempRemove, syscall.EIO, false)
	if errors.Is(before, ErrMayBeRenamed) {
		t.Error("a removal before the create matches ErrMayBeRenamed")
	}
	after := writeFail(ErrTempRemove, syscall.EIO, true)
	if !errors.Is(after, ErrMayBeRenamed) {
		t.Error("a removal after a link does not match ErrMayBeRenamed")
	}
}

func TestTS38_WriteErrorDropsLinkPaths(t *testing.T) {
	le := &os.LinkError{Op: "link", Old: secret, New: secret + "2", Err: syscall.EEXIST}
	err := writeFail(ErrExist, le, false)
	if !errors.Is(err, fs.ErrExist) || !errors.Is(err, ErrExist) {
		t.Errorf("err = %v: EEXIST or ErrExist not found", err)
	}
	var got *os.LinkError
	if errors.As(err, &got) {
		t.Error("the cause is still a link error")
	}
}

func TestTS38_WriteErrorNilCause(t *testing.T) {
	err := writeFail(ErrCheck, nil, false)
	if !errors.Is(err, ErrCheck) || err.Error() != ErrCheck.Error() {
		t.Errorf("err = %v", err)
	}
}

func TestTS38_StepNamesHaveErrors(t *testing.T) {
	names := []string{
		"create", "write", "sync", "close", "check", "rename", "link", "remove",
		"dirsync",
	}
	if len(stepErrs) != len(names) {
		t.Fatalf("%d step names, want %d", len(stepErrs), len(names))
	}
	for _, n := range names {
		if stepErrs[n] == nil {
			t.Errorf("step %q has no error", n)
		}
	}
}

func TestTS38_RunStepNoHook(t *testing.T) {
	ran := 0
	if err := runStep(&seam.Hooks{}, "sync", "n", false, func() error {
		ran++
		return nil
	}); err != nil || ran != 1 {
		t.Errorf("err = %v, ran = %d", err, ran)
	}
	err := runStep(&seam.Hooks{}, "sync", "n", false, func() error {
		return &fs.PathError{Op: "sync", Path: secret, Err: syscall.EIO}
	})
	if !errors.Is(err, ErrSync) || !errors.Is(err, syscall.EIO) ||
		strings.Contains(err.Error(), "secret") {
		t.Errorf("err = %v", err)
	}
}

func TestTS38_RunStepHookError(t *testing.T) {
	var gotStep, gotName string
	h := &seam.Hooks{Step: func(step, name string) error {
		gotStep, gotName = step, name
		return syscall.ENOSPC
	}}
	ran := false
	err := runStep(h, "write", "file", false, func() error { ran = true; return nil })
	if ran {
		t.Error("the step ran after a hook error")
	}
	if !errors.Is(err, ErrWrite) || !errors.Is(err, syscall.ENOSPC) {
		t.Errorf("err = %v, want ErrWrite with ENOSPC", err)
	}
	var we *WriteError
	if !errors.As(err, &we) || we.Step != ErrWrite {
		t.Errorf("err = %v is not a *WriteError of ErrWrite", err)
	}
	if errors.Is(err, seam.Crash) {
		t.Error("a plain hook error matches Crash")
	}
	if gotStep != "write" || gotName != "file" {
		t.Errorf("hook got %q, %q", gotStep, gotName)
	}
}

func TestTS38_RunStepHookCannotMakeStepPass(t *testing.T) {
	h := &seam.Hooks{Step: func(string, string) error { return nil }}
	err := runStep(h, "close", "n", false, func() error { return syscall.EIO })
	if !errors.Is(err, ErrClose) || !errors.Is(err, syscall.EIO) {
		t.Errorf("err = %v, want ErrClose with EIO", err)
	}
	ran := false
	if err := runStep(h, "close", "n", false, func() error { ran = true; return nil }); err != nil || !ran {
		t.Errorf("a nil hook result: err = %v, ran = %v", err, ran)
	}
}

func TestTS38_RunStepCrash(t *testing.T) {
	h := &seam.Hooks{Step: func(string, string) error { return seam.Crash }}
	ran := false
	err := runStep(h, "rename", "n", false, func() error { ran = true; return nil })
	if ran {
		t.Error("the step ran after Crash")
	}
	if !errors.Is(err, safefiletest.Crash) {
		t.Errorf("err = %v, want Crash", err)
	}
	var we *WriteError
	if errors.As(err, &we) {
		t.Error("Crash became a *WriteError")
	}
}

// fakeDir counts the calls of syncAndClose on a directory.
type fakeDir struct {
	syncErr, closeErr error
	syncs, closes     int
}

func (f *fakeDir) Sync() error  { f.syncs++; return f.syncErr }
func (f *fakeDir) Close() error { f.closes++; return f.closeErr }

func TestTS38_SyncAndClose(t *testing.T) {
	step := func(err error) *seam.Hooks {
		return &seam.Hooks{Step: func(string, string) error { return err }}
	}
	tests := []struct {
		name      string
		h         *seam.Hooks
		f         *fakeDir
		syncs     int
		is, isNot error
		wantNil   bool
		wantCrash bool
	}{
		{name: "ok", h: &seam.Hooks{}, f: &fakeDir{}, syncs: 1, wantNil: true},
		{name: "sync error", h: &seam.Hooks{}, f: &fakeDir{syncErr: syscall.EIO},
			syncs: 1, is: syscall.EIO},
		{name: "close error", h: &seam.Hooks{}, f: &fakeDir{closeErr: syscall.EBADF},
			syncs: 1, is: syscall.EBADF},
		{name: "sync error first", h: &seam.Hooks{},
			f:     &fakeDir{syncErr: syscall.EIO, closeErr: syscall.EBADF},
			syncs: 1, is: syscall.EIO, isNot: syscall.EBADF},
		{name: "hook error", h: step(syscall.ENOSPC), f: &fakeDir{},
			is: syscall.ENOSPC},
		{name: "crash", h: step(seam.Crash), f: &fakeDir{}, wantCrash: true},
		{name: "crash drops close error", h: step(seam.Crash),
			f: &fakeDir{closeErr: syscall.EBADF}, wantCrash: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := syncAndClose(tc.h, "d", tc.f)
			if tc.f.closes != 1 {
				t.Errorf("closes = %d, want 1", tc.f.closes)
			}
			if tc.f.syncs != tc.syncs {
				t.Errorf("syncs = %d, want %d", tc.f.syncs, tc.syncs)
			}
			switch {
			case tc.wantNil:
				if err != nil {
					t.Errorf("err = %v", err)
				}
				return
			case tc.wantCrash:
				if !errors.Is(err, safefiletest.Crash) || errors.Is(err, ErrDirSync) {
					t.Errorf("err = %v, want Crash only", err)
				}
				return
			}
			if !errors.Is(err, ErrDirSync) || !errors.Is(err, ErrMayBeRenamed) ||
				!errors.Is(err, tc.is) {
				t.Errorf("err = %v, want ErrDirSync with %v", err, tc.is)
			}
			if tc.isNot != nil && errors.Is(err, tc.isNot) {
				t.Errorf("err matches %v", tc.isNot)
			}
		})
	}
}

// fdCount gives the number of open descriptors of this process.
func fdCount(t *testing.T) int {
	t.Helper()
	es, err := os.ReadDir("/dev/fd")
	if err != nil {
		t.Skipf("no /dev/fd: %v", err)
	}
	return len(es)
}

func TestTS38_SyncDir(t *testing.T) {
	r, dir := root(t)
	tree(t, dir)
	var steps []string
	safefiletest.Set(t, safefiletest.Hooks{Step: func(step, name string) error {
		steps = append(steps, step+":"+name)
		return nil
	}})
	for _, d := range []string{"a", "a/b/c", "."} {
		if err := SyncDir(r, d, dirRule); err != nil {
			t.Errorf("SyncDir %q: %v", d, err)
		}
	}
	want := []string{"dirsync:a", "dirsync:a/b/c", "dirsync:."}
	if strings.Join(steps, " ") != strings.Join(want, " ") {
		t.Errorf("steps = %v, want %v", steps, want)
	}
}

func TestTS38_SyncDirNoHook(t *testing.T) {
	r, dir := root(t)
	tree(t, dir)
	for _, d := range []string{"a", "."} {
		if err := SyncDir(r, d, dirRule); err != nil {
			t.Errorf("SyncDir %q: %v", d, err)
		}
	}
}

func TestTS38_SyncDirSymlinkRefused(t *testing.T) {
	r, dir := root(t)
	tree(t, dir)
	for link, target := range map[string]string{"link": "a", "a/inner": "b"} {
		if err := os.Symlink(target, filepath.Join(dir, link)); err != nil {
			t.Fatal(err)
		}
	}
	for _, d := range []string{"link", "a/inner", "link/b", "a/inner/c"} {
		err := SyncDir(r, d, dirRule)
		if !errors.Is(err, ErrDirSync) || !errors.Is(err, ErrSymlink) {
			t.Errorf("SyncDir %q: err = %v, want ErrDirSync and ErrSymlink", d, err)
		}
	}
}

func TestTS38_SyncDirRefusals(t *testing.T) {
	r, dir := root(t)
	tree(t, dir)
	tests := []struct {
		name string
		root *os.Root
		dir  string
		rule Rule
		want error
	}{
		{"nil root", nil, "a", dirRule, ErrRule},
		{"nil root dot", nil, ".", dirRule, ErrRule},
		{"zero rule", r, "a", Rule{}, ErrRule},
		{"zero rule dot", r, ".", Rule{}, ErrRule},
		{"file rule", r, "a", base, ErrRule},
		{"file rule dot", r, ".", base, ErrRule},
		{"empty name", r, "", dirRule, ErrName},
		{"parent name", r, "..", dirRule, ErrName},
		{"absolute name", r, "/a", dirRule, ErrName},
		{"missing dir", r, "none", dirRule, ErrExamine},
	}
	for _, tc := range tests {
		err := SyncDir(tc.root, tc.dir, tc.rule)
		if !errors.Is(err, ErrDirSync) || !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, want ErrDirSync and %v", tc.name, err, tc.want)
		}
	}
}

func TestTS38_SyncDirHookError(t *testing.T) {
	r, dir := root(t)
	tree(t, dir)
	safefiletest.Set(t, safefiletest.Hooks{Step: func(string, string) error {
		return &fs.PathError{Op: "fsync", Path: secret, Err: syscall.EIO}
	}})
	before := fdCount(t)
	for _, d := range []string{"a", "."} {
		err := SyncDir(r, d, dirRule)
		if !errors.Is(err, ErrDirSync) || !errors.Is(err, syscall.EIO) ||
			!errors.Is(err, ErrMayBeRenamed) {
			t.Errorf("SyncDir %q: err = %v", d, err)
		}
		if strings.Contains(err.Error(), "secret") {
			t.Errorf("SyncDir %q: text holds the path", d)
		}
	}
	if after := fdCount(t); after != before {
		t.Errorf("descriptors: %d before, %d after a hook error", before, after)
	}
}

func TestTS38_SyncDirCrash(t *testing.T) {
	r, dir := root(t)
	tree(t, dir)
	calls := 0
	safefiletest.Set(t, safefiletest.Hooks{Step: func(string, string) error {
		calls++
		return safefiletest.Crash
	}})
	before := fdCount(t)
	for _, d := range []string{"a/b", "."} {
		err := SyncDir(r, d, dirRule)
		if !errors.Is(err, safefiletest.Crash) || errors.Is(err, ErrDirSync) {
			t.Errorf("SyncDir %q: err = %v, want Crash only", d, err)
		}
	}
	if calls != 2 {
		t.Errorf("hook calls = %d, want 2", calls)
	}
	if after := fdCount(t); after != before {
		t.Errorf("descriptors: %d before, %d after a crash", before, after)
	}
}
