//go:build unix && !aix && !solaris

package safefile

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
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

func TestTS38_WriteErrorKeepsNestedCause(t *testing.T) {
	inner := &Error{Reason: ErrSymlink,
		Cause: &fs.PathError{Op: "open", Path: secret, Err: syscall.ELOOP}}
	err := writeFail(ErrCheck, fmt.Errorf("wrapped: %w", inner), false)
	if !errors.Is(err, ErrSymlink) || !errors.Is(err, ErrCheck) {
		t.Errorf("err = %v: ErrSymlink or ErrCheck not found", err)
	}
	var got *Error
	if !errors.As(err, &got) || got != inner {
		t.Error("the nested error was replaced")
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
		{"bad bits dot", r, ".", Rule{Type: Dir, Owner: OwnerSelf, Forbid: fs.ModeDir}, ErrRule},
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

// fdTargets gives the targets of the descriptor links of this process.
func fdTargets(t *testing.T) []string {
	t.Helper()
	es, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skipf("no /proc/self/fd: %v", err)
	}
	var out []string
	for _, e := range es {
		if p, err := os.Readlink(filepath.Join("/proc/self/fd", e.Name())); err == nil {
			out = append(out, p)
		}
	}
	return out
}

func TestTS38_SyncDirSyncsCheckedDirectory(t *testing.T) {
	r, dir := root(t)
	tree(t, dir)
	other := filepath.Join(dir, "other")
	if err := os.Mkdir(other, 0o700); err != nil {
		t.Fatal(err)
	}
	fdTargets(t) // skips the test when there is no /proc/self/fd
	var moved, wrong int
	safefiletest.Set(t, safefiletest.Hooks{Step: func(string, string) error {
		b := filepath.Join(dir, "a", "b")
		if err := os.Rename(b, filepath.Join(dir, "a", "moved")); err != nil {
			t.Error(err)
		}
		if err := os.Symlink(other, b); err != nil {
			t.Error(err)
		}
		for _, p := range fdTargets(t) {
			switch {
			case strings.HasSuffix(p, "/a/moved"):
				moved++
			case strings.HasSuffix(p, "/other"):
				wrong++
			}
		}
		return nil
	}})
	if err := SyncDir(r, "a/b", dirRule); err != nil {
		t.Fatalf("SyncDir: %v", err)
	}
	// The root of the checked directory and the file of "." point to it.
	if moved < 2 {
		t.Errorf("%d descriptors to the checked directory, want 2 or more", moved)
	}
	if wrong != 0 {
		t.Errorf("%d descriptors to the directory behind the new link", wrong)
	}
}

func TestTS38_SyncDirOpenRootDirFails(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores the mode")
	}
	r, dir := root(t)
	if err := os.Chmod(dir, 0o300); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	err := SyncDir(r, ".", dirRule)
	if !errors.Is(err, ErrDirSync) || !errors.Is(err, syscall.EACCES) {
		t.Fatalf("err = %v, want ErrDirSync with EACCES", err)
	}
	if strings.Contains(err.Error(), dir) || strings.Contains(err.Error(), "/") {
		t.Errorf("text %q holds a path", err.Error())
	}
}

func TestTS38_SyncDirRootRule(t *testing.T) {
	r, dir := root(t)
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	err := SyncDir(r, ".", dirRule)
	if !errors.Is(err, ErrDirSync) || !errors.Is(err, ErrMode) {
		t.Errorf("err = %v, want ErrDirSync with ErrMode", err)
	}
	if err := SyncDir(r, ".", Rule{Type: Dir, Owner: OwnerAny}); err != nil {
		t.Errorf("a rule that the root meets: %v", err)
	}
}

// The directory is swapped for a link after OpenRoot has checked it and
// before the sync. A sync that opens the directory by path again fails or
// syncs the wrong directory.
func TestTS38_SyncDirDoesNotReopenByPath(t *testing.T) {
	r, dir := root(t)
	tree(t, dir)
	other := filepath.Join(dir, "other")
	if err := os.Mkdir(other, 0o700); err != nil {
		t.Fatal(err)
	}
	calls := 0
	safefiletest.Set(t, safefiletest.Hooks{
		// The owner check of the last part runs after its open.
		OtherOwner: func(FileID) bool {
			if calls++; calls == 2 {
				b := filepath.Join(dir, "a", "b")
				if err := os.Rename(b, filepath.Join(dir, "a", "moved")); err != nil {
					t.Error(err)
				}
				if err := os.Symlink(other, b); err != nil {
					t.Error(err)
				}
			}
			return false
		},
	})
	if err := SyncDir(r, "a/b", dirRule); err != nil {
		t.Fatalf("SyncDir: %v", err)
	}
	if calls != 2 {
		t.Errorf("owner checks = %d, want 2", calls)
	}
}

var (
	fixedRule  = WriteRule{Mode: 0o600, Temp: TempFixed, Dir: dirRule}
	randomRule = WriteRule{Mode: 0o600, Temp: TempRandom, Prefix: ".tmp-", Dir: dirRule}
)

// privateRoot is root with the mode 0700, as dirRule needs.
func privateRoot(t *testing.T) (*os.Root, string) {
	t.Helper()
	r, dir := root(t)
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return r, dir
}

// names gives the sorted names in dir.
func names(t *testing.T, dir string) []string {
	t.Helper()
	es, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range es {
		out = append(out, e.Name())
	}
	slices.Sort(out)
	return out
}

func content(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		return "<" + err.Error() + ">"
	}
	return string(b)
}

func TestTS38_WriteRuleRefused(t *testing.T) {
	r, dir := root(t)
	tree(t, dir)
	with := func(f func(*WriteRule)) WriteRule { w := fixedRule; f(&w); return w }
	rules := map[string]WriteRule{
		"zero":           {},
		"no temp":        with(func(w *WriteRule) { w.Temp = 0 }),
		"bad temp":       with(func(w *WriteRule) { w.Temp = 9 }),
		"mode bits":      with(func(w *WriteRule) { w.Mode = fs.ModeSetuid | 0o600 }),
		"mode type bits": with(func(w *WriteRule) { w.Mode = fs.ModeDir | 0o600 }),
		"zero dir rule":  with(func(w *WriteRule) { w.Dir = Rule{} }),
		"file dir rule":  with(func(w *WriteRule) { w.Dir = base }),
		"fixed prefix":   with(func(w *WriteRule) { w.Prefix = ".tmp-" }),
		"random no pref": with(func(w *WriteRule) { w.Temp = TempRandom }),
		"random slash":   with(func(w *WriteRule) { w.Temp, w.Prefix = TempRandom, "a/b-" }),
	}
	check := func(label string, root *os.Root, name string, w WriteRule) {
		t.Helper()
		if _, err := WriteTemp(root, name, []byte("x"), w); !errors.Is(err, ErrRule) {
			t.Errorf("%s: WriteTemp err = %v, want ErrRule", label, err)
		}
		if err := Replace(root, name, []byte("x"), w); !errors.Is(err, ErrRule) {
			t.Errorf("%s: Replace err = %v, want ErrRule", label, err)
		}
	}
	for label, w := range rules {
		check(label, r, "f", w)
	}
	check("nil root", nil, "f", fixedRule)
	for _, name := range []string{"", ".", "..", "/f", "a/../f", "a//f", "a/./f", "a/"} {
		check("name "+name, r, name, fixedRule)
	}
	if got := names(t, dir); len(got) != 1 || got[0] != "a" {
		t.Errorf("entries = %v, want only a", got)
	}
}

func TestTS38_WriteTemp(t *testing.T) {
	r, dir := root(t)
	tree(t, dir)
	for _, w := range []WriteRule{fixedRule, randomRule} {
		for _, name := range []string{"f", "a/b/f"} {
			tmp, err := WriteTemp(r, name, []byte("data"), w)
			if err != nil {
				t.Fatalf("WriteTemp %q: %v", name, err)
			}
			p := filepath.Join(dir, tmp)
			fi, err := os.Lstat(p)
			if err != nil || fi.Mode() != 0o600 || content(t, p) != "data" {
				t.Errorf("temp %q: %v, %v, %q", tmp, fi, err, content(t, p))
			}
			if w.Temp == TempFixed && tmp != name+".tmp" {
				t.Errorf("temp = %q, want %q", tmp, name+".tmp")
			}
			if w.Temp == TempRandom && (!strings.HasPrefix(filepath.Base(tmp), ".tmp-") ||
				filepath.Dir(tmp) != filepath.Dir(name)) {
				t.Errorf("temp = %q", tmp)
			}
			if _, err := os.Lstat(filepath.Join(dir, name)); err == nil {
				t.Errorf("WriteTemp made %q", name)
			}
		}
	}
}

func TestTS38_ReplaceWritesAndReplaces(t *testing.T) {
	r, dir := root(t)
	tree(t, dir)
	var seen []string
	safefiletest.Set(t, safefiletest.Hooks{Step: func(step, name string) error {
		seen = append(seen, step+":"+name)
		return nil
	}})
	w := fixedRule
	w.Check = func() error { return nil }
	for _, name := range []string{"f", "a/b/f"} {
		for _, data := range []string{"one", "two"} {
			if err := Replace(r, name, []byte(data), w); err != nil {
				t.Fatalf("Replace %q: %v", name, err)
			}
			if got := content(t, filepath.Join(dir, name)); got != data {
				t.Errorf("%q = %q, want %q", name, got, data)
			}
		}
	}
	want := "remove:f.tmp create:f.tmp write:f.tmp sync:f.tmp close:f.tmp check:f.tmp rename:f.tmp dirsync:."
	if got := strings.Join(seen[:8], " "); got != want {
		t.Errorf("steps = %q, want %q", got, want)
	}
	if last := seen[len(seen)-1]; last != "dirsync:a/b" {
		t.Errorf("last step = %q, want dirsync:a/b", last)
	}
	if got := names(t, filepath.Join(dir, "a", "b")); !slices.Equal(got, []string{"c", "f"}) {
		t.Errorf("entries = %v", got)
	}
	w.NoDirSync = true
	seen = nil
	if err := Replace(r, "f", []byte("three"), w); err != nil || strings.Contains(strings.Join(seen, " "), "dirsync") {
		t.Errorf("NoDirSync: err = %v, steps = %v", err, seen)
	}
}

func TestTS38_WriteAppliesRuleToRoot(t *testing.T) {
	r, dir := root(t)
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	if err := Replace(r, "f", []byte("x"), fixedRule); !errors.Is(err, ErrMode) {
		t.Errorf("err = %v, want ErrMode", err)
	}
	if got := names(t, dir); len(got) != 0 {
		t.Errorf("entries = %v, want none", got)
	}
}

func TestTS38_ReplaceCrashMatrix(t *testing.T) {
	steps := []string{"remove", "create", "write", "sync", "close", "check", "rename", "dirsync"}
	for _, fixed := range []bool{true, false} {
		for _, old := range []bool{true, false} {
			for _, step := range steps {
				if step == "remove" && !fixed {
					continue
				}
				t.Run(fmt.Sprintf("fixed=%v/old=%v/%s", fixed, old, step), func(t *testing.T) {
					r, dir := privateRoot(t)
					w := randomRule
					if fixed {
						w = fixedRule
						put(t, dir, "f.tmp", "stale")
					}
					w.Check = func() error { return nil }
					if old {
						put(t, dir, "f", "OLD")
					}
					armed, last := true, ""
					safefiletest.Set(t, safefiletest.Hooks{Step: func(s, _ string) error {
						if armed {
							last = s
						}
						if armed && s == step {
							return safefiletest.Crash
						}
						return nil
					}})
					err := Replace(r, "f", []byte("new"), w)
					if !errors.Is(err, safefiletest.Crash) || last != step {
						t.Fatalf("err = %v, last step = %q", err, last)
					}
					_, statErr := os.Lstat(filepath.Join(dir, "f"))
					got := content(t, filepath.Join(dir, "f"))
					switch {
					case step == "dirsync" && got != "new":
						t.Errorf("final name = %q, want new", got)
					case step != "dirsync" && old && got != "OLD":
						t.Errorf("final name = %q, want OLD", got)
					case step != "dirsync" && !old && !errors.Is(statErr, fs.ErrNotExist):
						t.Errorf("final name = %q, want none", got)
					}
					if fixed && step == "remove" && content(t, filepath.Join(dir, "f.tmp")) != "stale" {
						t.Error("a crash at the removal removed the old temporary file")
					}
					armed = false
					if err := Replace(r, "f", []byte("again"), w); err != nil {
						t.Fatalf("next Replace: %v", err)
					}
					if got := content(t, filepath.Join(dir, "f")); got != "again" {
						t.Errorf("after the next call = %q", got)
					}
					if got := names(t, dir); fixed && !slices.Equal(got, []string{"f"}) {
						t.Errorf("entries after the next call = %v, want f only", got)
					}
				})
			}
		}
	}
}

func TestTS38_ReplaceStepFailure(t *testing.T) {
	tests := []struct {
		step    string
		is      error
		renamed bool // the new file can be in place
	}{
		{"remove", ErrTempRemove, false},
		{"create", ErrCreate, false},
		{"write", ErrWrite, false},
		{"sync", ErrSync, false},
		{"close", ErrClose, false},
		{"check", ErrCheck, false},
		{"rename", ErrRename, true},
		{"dirsync", ErrDirSync, true},
	}
	for _, w := range []WriteRule{fixedRule, randomRule} {
		w.Check = func() error { return nil }
		for _, tc := range tests {
			if tc.step == "remove" && w.Temp != TempFixed {
				continue
			}
			t.Run(fmt.Sprintf("temp=%d/%s", w.Temp, tc.step), func(t *testing.T) {
				r, dir := privateRoot(t)
				put(t, dir, "f", "OLD")
				safefiletest.Set(t, safefiletest.Hooks{Step: func(s, _ string) error {
					if s == tc.step {
						return &fs.PathError{Op: "x", Path: secret, Err: syscall.EIO}
					}
					return nil
				}})
				err := Replace(r, "f", []byte("new"), w)
				var we *WriteError
				if !errors.As(err, &we) || we.Step != tc.is || !errors.Is(err, syscall.EIO) {
					t.Fatalf("err = %v, want a *WriteError of %v with EIO", err, tc.is)
				}
				if errors.Is(err, ErrMayBeRenamed) != tc.renamed {
					t.Errorf("matches ErrMayBeRenamed = %v, want %v", !tc.renamed, tc.renamed)
				}
				if strings.Contains(err.Error(), "secret") {
					t.Error("the text holds the path")
				}
				want := "OLD"
				if tc.step == "dirsync" {
					want = "new"
				}
				if got := content(t, filepath.Join(dir, "f")); got != want {
					t.Errorf("f = %q, want %q", got, want)
				}
				if got := names(t, dir); !slices.Equal(got, []string{"f"}) {
					t.Errorf("entries = %v, want f only", got)
				}
			})
		}
	}
}

func TestTS38_ReplaceCheckFailureKeepsCause(t *testing.T) {
	r, dir := privateRoot(t)
	put(t, dir, "f", "OLD")
	errCallback := errors.New("callback refused")
	w := fixedRule
	w.Check = func() error { return fmt.Errorf("verify: %w", errCallback) }
	err := Replace(r, "f", []byte("new"), w)
	if !errors.Is(err, ErrCheck) || !errors.Is(err, errCallback) || errors.Is(err, ErrMayBeRenamed) {
		t.Errorf("err = %v", err)
	}
	if got := content(t, filepath.Join(dir, "f")); got != "OLD" {
		t.Errorf("f = %q, want OLD", got)
	}
	if got := names(t, dir); !slices.Equal(got, []string{"f"}) {
		t.Errorf("entries = %v, want f only", got)
	}
}

func TestTS38_ReplaceRenameFailureRemovesTemp(t *testing.T) {
	r, dir := privateRoot(t)
	if err := os.MkdirAll(filepath.Join(dir, "f", "inner"), 0o700); err != nil {
		t.Fatal(err)
	}
	err := Replace(r, "f", []byte("new"), fixedRule)
	if !errors.Is(err, ErrRename) || !errors.Is(err, ErrMayBeRenamed) {
		t.Errorf("err = %v, want ErrRename with ErrMayBeRenamed", err)
	}
	if got := names(t, dir); !slices.Equal(got, []string{"f"}) {
		t.Errorf("entries = %v, want f only", got)
	}
}

func TestTS38_ReplaceCreateFailure(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores the mode")
	}
	r, dir := root(t)
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	err := Replace(r, "f", []byte("new"), randomRule)
	if !errors.Is(err, ErrCreate) || !errors.Is(err, syscall.EACCES) || errors.Is(err, ErrMayBeRenamed) {
		t.Errorf("err = %v, want ErrCreate with EACCES", err)
	}
}

func TestTS38_WriteDirLinkRefused(t *testing.T) {
	r, dir := root(t)
	tree(t, dir)
	if err := os.Symlink("a", filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"link/f", "link/b/f"} {
		if err := Replace(r, name, []byte("x"), fixedRule); !errors.Is(err, ErrSymlink) {
			t.Errorf("Replace %q: err = %v, want ErrSymlink", name, err)
		}
		if _, err := WriteTemp(r, name, []byte("x"), fixedRule); !errors.Is(err, ErrSymlink) {
			t.Errorf("WriteTemp %q: err = %v, want ErrSymlink", name, err)
		}
	}
	if got := names(t, filepath.Join(dir, "a")); !slices.Equal(got, []string{"b"}) {
		t.Errorf("entries below the link target = %v", got)
	}
}

func TestTS38_ReplaceNeverFollowsLinks(t *testing.T) {
	for _, where := range []string{"temp", "final"} {
		for _, outside := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/outside=%v", where, outside), func(t *testing.T) {
				top := t.TempDir()
				dir := filepath.Join(top, "root")
				if err := os.Mkdir(dir, 0o700); err != nil {
					t.Fatal(err)
				}
				r, err := os.OpenRoot(dir)
				if err != nil {
					t.Fatal(err)
				}
				defer r.Close()
				target, linkTo := filepath.Join(dir, "target"), "target"
				if outside {
					target = filepath.Join(top, "outside")
					linkTo = target
				}
				if err := os.WriteFile(target, []byte("TARGET"), 0o600); err != nil {
					t.Fatal(err)
				}
				link := "f"
				if where == "temp" {
					link = "f.tmp"
				}
				if err := os.Symlink(linkTo, filepath.Join(dir, link)); err != nil {
					t.Fatal(err)
				}
				if err := Replace(r, "f", []byte("new"), fixedRule); err != nil {
					t.Fatalf("Replace: %v", err)
				}
				if got := content(t, target); got != "TARGET" {
					t.Errorf("target = %q, want it unchanged", got)
				}
				fi, err := os.Lstat(filepath.Join(dir, "f"))
				if err != nil || !fi.Mode().IsRegular() || content(t, filepath.Join(dir, "f")) != "new" {
					t.Errorf("f: %v, %v", fi, err)
				}
			})
		}
	}
}

func TestTS38_WriteModeIsExactUnderUmask(t *testing.T) {
	r, dir := privateRoot(t)
	old := syscall.Umask(0o377)
	defer syscall.Umask(old)
	for _, mode := range []fs.FileMode{0o640, 0o666, 0o444, 0o755} {
		w := fixedRule
		w.Mode = mode
		if err := Replace(r, "f", []byte("x"), w); err != nil {
			t.Fatalf("Replace: %v", err)
		}
		fi, err := os.Stat(filepath.Join(dir, "f"))
		if err != nil || fi.Mode().Perm() != mode {
			t.Errorf("mode = %v, %v, want %v", fi.Mode(), err, mode)
		}
	}
}
