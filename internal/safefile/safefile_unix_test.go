//go:build unix && !aix && !solaris

package safefile

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/cybagard/cyba-phantom/internal/safefile/internal/seam"
	"github.com/cybagard/cyba-phantom/internal/safefile/safefiletest"
)

var base = Rule{Type: Regular, Owner: OwnerSelf}

// fakeT records a failure and returns, so the caller runs on after Fatalf.
type fakeT struct {
	testing.TB
	msg      string
	cleanups []func()
}

func (f *fakeT) Helper() {}

func (f *fakeT) Fatalf(format string, args ...any) {
	f.msg = fmt.Sprintf(format, args...)
}

func (f *fakeT) Cleanup(fn func()) { f.cleanups = append(f.cleanups, fn) }

// root makes a directory with a root on it.
func root(t *testing.T) (*os.Root, string) {
	t.Helper()
	dir := t.TempDir()
	r, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	return r, dir
}

// file makes a file of 10 bytes with the mode m.
func file(t *testing.T, dir, name string, m fs.FileMode) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("0123456789"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, m); err != nil {
		t.Fatal(err)
	}
}

// open calls Open and closes the file. It gives the error.
func open(t *testing.T, r *os.Root, name string, rule Rule) error {
	t.Helper()
	f, fi, err := Open(r, name, rule)
	return verdict(t, f, fi, err)
}

// verdict checks the result of Open, closes the file and gives the error.
func verdict(t *testing.T, f *os.File, fi fs.FileInfo, err error) error {
	t.Helper()
	if err == nil {
		defer f.Close()
		if fi == nil {
			t.Fatal("Open gave no FileInfo")
		}
		return nil
	}
	if f != nil || fi != nil {
		t.Fatal("Open gave a file with an error")
	}
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("error %v is not an *Error", err)
	}
	return err
}

// timed runs Open and fails the test when it takes 2 s or more.
func timed(t *testing.T, r *os.Root, name string, rule Rule) error {
	t.Helper()
	type result struct {
		f   *os.File
		fi  fs.FileInfo
		err error
	}
	done := make(chan result, 1)
	go func() {
		f, fi, err := Open(r, name, rule)
		done <- result{f, fi, err}
	}()
	select {
	case res := <-done:
		return verdict(t, res.f, res.fi, res.err)
	case <-time.After(2 * time.Second):
		t.Fatal("Open did not return before the deadline")
		return nil
	}
}

func TestTS23_RuleTable(t *testing.T) {
	r, dir := root(t)
	file(t, dir, "f600", 0o600)
	file(t, dir, "f640", 0o640)
	file(t, dir, "f400", 0o400)
	file(t, dir, "setuid", 0o600|fs.ModeSetuid)
	file(t, dir, "linked", 0o600)
	if err := os.Link(filepath.Join(dir, "linked"), filepath.Join(dir, "l2")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "d"), 0o700); err != nil {
		t.Fatal(err)
	}
	other := safefiletest.Hooks{OtherOwner: func(seam.FileID) bool { return true }}
	with := func(r Rule, f func(*Rule)) Rule { f(&r); return r }
	tests := []struct {
		name  string
		file  string
		rule  Rule
		hooks *safefiletest.Hooks
		want  error
	}{
		{"regular", "f600", base, nil, nil},
		{"dir", "d", Rule{Type: Dir, Owner: OwnerSelf}, nil, nil},
		{"dir is a file", "f600", Rule{Type: Dir, Owner: OwnerSelf}, nil, ErrType},
		{"self or root", "f600", with(base, func(r *Rule) { r.Owner = OwnerSelfOrRoot }), nil, nil},
		{"any owner", "f600", with(base, func(r *Rule) { r.Owner = OwnerAny }), nil, nil},
		{"self, other owner", "f600", base, &other, ErrOwner},
		{"self or root, other owner", "f600", with(base, func(r *Rule) { r.Owner = OwnerSelfOrRoot }), &other, ErrOwner},
		{"forbid met", "f600", with(base, func(r *Rule) { r.Forbid = 0o077 }), nil, nil},
		{"forbid broken", "f640", with(base, func(r *Rule) { r.Forbid = 0o077 }), nil, ErrMode},
		{"forbid setuid", "setuid", with(base, func(r *Rule) { r.Forbid = fs.ModeSetuid }), nil, ErrMode},
		{"exact met", "f600", with(base, func(r *Rule) { r.Exact = 0o600 }), nil, nil},
		{"exact broken", "f640", with(base, func(r *Rule) { r.Exact = 0o600 }), nil, ErrMode},
		{"exact lower", "f400", with(base, func(r *Rule) { r.Exact = 0o600 }), nil, ErrMode},
		{"exact setuid", "setuid", with(base, func(r *Rule) { r.Exact = 0o600 }), nil, ErrMode},
		{"one link met", "f600", with(base, func(r *Rule) { r.OneLink = true }), nil, nil},
		{"one link broken", "linked", with(base, func(r *Rule) { r.OneLink = true }), nil, ErrLinks},
		{"size at the cap", "f600", with(base, func(r *Rule) { r.MaxSize = 10 }), nil, nil},
		{"size over the cap", "f600", with(base, func(r *Rule) { r.MaxSize = 9 }), nil, ErrSize},
		{"missing", "none", base, nil, ErrExamine},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.hooks != nil {
				safefiletest.Set(t, *tc.hooks)
			}
			err := open(t, r, tc.file, tc.rule)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
	// A file of root, opened as a normal user, has another owner.
	etc, etcErr := os.OpenRoot("/etc")
	if etcErr == nil {
		defer etc.Close()
	}
	rootOwned := []struct {
		name  string
		owner Owner
		want  error
	}{
		{"root file, self", OwnerSelf, ErrOwner},
		{"root file, self or root", OwnerSelfOrRoot, nil},
		{"root file, any owner", OwnerAny, nil},
	}
	for _, tc := range rootOwned {
		t.Run(tc.name, func(t *testing.T) {
			if os.Geteuid() == 0 {
				t.Skip("the file is the own file of root")
			}
			if etcErr != nil {
				t.Skip("no /etc:", etcErr)
			}
			err := open(t, etc, "passwd", with(base, func(r *Rule) { r.Owner = tc.owner }))
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
	err := open(t, r, "none", base)
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing file: %v does not hold fs.ErrNotExist", err)
	}
	if err.Error() != ErrExamine.Error() {
		t.Errorf("error text = %q, want the fixed text", err)
	}
}

func TestTS23_ZeroRuleRefused(t *testing.T) {
	r, dir := root(t)
	file(t, dir, "f", 0o600)
	bad := []Rule{
		{},
		{Type: Regular},
		{Owner: OwnerSelf},
		{Type: 3, Owner: OwnerSelf},
		{Type: Regular, Owner: 4},
		{Type: Regular, Owner: OwnerSelf, MaxSize: -1},
		{Type: Regular, Owner: OwnerSelf, Forbid: fs.ModeDir},
		{Type: Regular, Owner: OwnerSelf, Exact: fs.ModeSymlink},
	}
	for _, rule := range bad {
		if err := open(t, r, "f", rule); !errors.Is(err, ErrRule) {
			t.Errorf("rule %+v: err = %v, want ErrRule", rule, err)
		}
	}
	if _, _, err := Open(nil, "f", base); !errors.Is(err, ErrRule) {
		t.Errorf("nil root: err = %v, want ErrRule", err)
	}
}

func TestTS23_Identity(t *testing.T) {
	_, dir := root(t)
	file(t, dir, "f", 0o600)
	fi, err := os.Stat(filepath.Join(dir, "f"))
	if err != nil {
		t.Fatal(err)
	}
	id, ok := Identity(fi)
	if !ok || id.Ino == 0 {
		t.Errorf("Identity = %+v, %v", id, ok)
	}
}

// neverOpened fails the test when Open reaches the open of a refused name.
func neverOpened(t *testing.T) {
	t.Helper()
	hook := func(string) { t.Error("Open ran a hook after the open check") }
	safefiletest.Set(t, safefiletest.Hooks{AfterCheck: hook, AfterOpen: hook})
}

func TestTS23_DirAtRegularNameNeverOpened(t *testing.T) {
	r, dir := root(t)
	if err := os.Mkdir(filepath.Join(dir, "d"), 0o700); err != nil {
		t.Fatal(err)
	}
	neverOpened(t)
	if err := open(t, r, "d", base); !errors.Is(err, ErrType) {
		t.Errorf("err = %v, want ErrType", err)
	}
}

func TestTS23_FIFOAtNameNeverOpened(t *testing.T) {
	r, dir := root(t)
	if err := syscall.Mkfifo(filepath.Join(dir, "p"), 0o600); err != nil {
		t.Fatal(err)
	}
	neverOpened(t)
	// The call must not run the open, so it needs no reader or writer.
	if err := timed(t, r, "p", base); !errors.Is(err, ErrType) {
		t.Errorf("err = %v, want ErrType", err)
	}
}

func TestTS23_DeviceRefused(t *testing.T) {
	dev, err := os.OpenRoot("/dev")
	if err != nil {
		t.Skip("no /dev:", err)
	}
	defer dev.Close()
	neverOpened(t)
	if err := timed(t, dev, "null", base); !errors.Is(err, ErrType) {
		t.Errorf("err = %v, want ErrType", err)
	}
}

func TestTS23_SocketRefused(t *testing.T) {
	r, dir := root(t)
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Skip("no socket:", err)
	}
	defer syscall.Close(fd)
	if err := syscall.Bind(fd, &syscall.SockaddrUnix{Name: filepath.Join(dir, "s")}); err != nil {
		t.Skip("no bind:", err)
	}
	neverOpened(t)
	if err := timed(t, r, "s", base); !errors.Is(err, ErrType) {
		t.Errorf("err = %v, want ErrType", err)
	}
}

func TestTS23_SymlinkAtNameRefused(t *testing.T) {
	r, dir := root(t)
	file(t, dir, "f", 0o600)
	if err := os.Symlink("f", filepath.Join(dir, "l")); err != nil {
		t.Fatal(err)
	}
	if err := open(t, r, "l", base); !errors.Is(err, ErrSymlink) {
		t.Errorf("err = %v, want ErrSymlink", err)
	}
}

// swapAfterCheck runs swap once, between the check and the open.
func swapAfterCheck(t *testing.T, swap func(p string)) {
	t.Helper()
	var once atomic.Bool
	safefiletest.Set(t, safefiletest.Hooks{AfterCheck: func(name string) {
		if once.CompareAndSwap(false, true) {
			swap(name)
		}
	}})
}

func TestTS23_FIFOSwapAfterCheckNoBlock(t *testing.T) {
	r, dir := root(t)
	file(t, dir, "f", 0o600)
	p := filepath.Join(dir, "f")
	swapAfterCheck(t, func(string) {
		// Both files exist at once, so the inode of the FIFO is new.
		q := filepath.Join(dir, "q")
		if err := syscall.Mkfifo(q, 0o600); err != nil {
			t.Error(err)
		}
		if err := os.Rename(q, p); err != nil {
			t.Error(err)
		}
	})
	if err := timed(t, r, "f", base); !errors.Is(err, ErrChanged) {
		t.Errorf("err = %v, want ErrChanged", err)
	}
}

func TestTS23_SymlinkSwapAfterCheck(t *testing.T) {
	r, dir := root(t)
	file(t, dir, "f", 0o600)
	file(t, dir, "target", 0o600)
	p := filepath.Join(dir, "f")
	swapAfterCheck(t, func(string) {
		q := filepath.Join(dir, "q")
		if err := os.Symlink("target", q); err != nil {
			t.Error(err)
		}
		if err := os.Rename(q, p); err != nil {
			t.Error(err)
		}
	})
	if err := open(t, r, "f", base); !errors.Is(err, ErrChanged) {
		t.Errorf("err = %v, want ErrChanged", err)
	}
}

func TestTS23_SymlinkOutOfRootSwapAfterCheck(t *testing.T) {
	r, dir := root(t)
	file(t, dir, "f", 0o600)
	outside := t.TempDir()
	file(t, outside, "target", 0o600)
	p := filepath.Join(dir, "f")
	swapAfterCheck(t, func(string) {
		q := filepath.Join(dir, "q")
		if err := os.Symlink(filepath.Join(outside, "target"), q); err != nil {
			t.Error(err)
		}
		if err := os.Rename(q, p); err != nil {
			t.Error(err)
		}
	})
	if err := open(t, r, "f", base); !errors.Is(err, ErrOpen) {
		t.Errorf("err = %v, want ErrOpen", err)
	}
}

// A link to the checked file opens the checked file, and the rule runs on it.
func TestTS23_SymlinkToCheckedFileOpens(t *testing.T) {
	r, dir := root(t)
	file(t, dir, "f", 0o600)
	p := filepath.Join(dir, "f")
	orig, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	swapAfterCheck(t, func(string) {
		if err := os.Rename(p, filepath.Join(dir, "b")); err != nil {
			t.Error(err)
		}
		if err := os.Symlink("b", p); err != nil {
			t.Error(err)
		}
	})
	f, fi, err := Open(r, "f", base)
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	defer f.Close()
	if !os.SameFile(orig, fi) {
		t.Error("Open did not give the checked file")
	}
}

func TestTS23_NameOnePart(t *testing.T) {
	r, dir := root(t)
	file(t, dir, "f", 0o600)
	if err := os.Mkdir(filepath.Join(dir, "d"), 0o700); err != nil {
		t.Fatal(err)
	}
	file(t, filepath.Join(dir, "d"), "f", 0o600)
	if err := os.Symlink("d", filepath.Join(dir, "a")); err != nil {
		t.Fatal(err)
	}
	noHook := func(string) { t.Error("a hook ran for a refused name") }
	safefiletest.Set(t, safefiletest.Hooks{
		BeforeCheck: noHook, AfterCheck: noHook, AfterOpen: noHook,
	})
	for _, name := range []string{"", "a/f", "d/f", "/f", "f/"} {
		if err := open(t, r, name, base); !errors.Is(err, ErrName) {
			t.Errorf("name %q: err = %v, want ErrName", name, err)
		}
	}
}

func TestTS23_NameDotDotExamined(t *testing.T) {
	r, _ := root(t)
	if err := open(t, r, "..", Rule{Type: Dir, Owner: OwnerAny}); !errors.Is(err, ErrExamine) {
		t.Errorf("err = %v, want ErrExamine", err)
	}
}

func TestTS23_FileSwapAfterCheck(t *testing.T) {
	r, dir := root(t)
	file(t, dir, "f", 0o600)
	file(t, dir, "other", 0o600)
	swapAfterCheck(t, func(string) {
		if err := os.Rename(filepath.Join(dir, "other"), filepath.Join(dir, "f")); err != nil {
			t.Error(err)
		}
	})
	if err := open(t, r, "f", base); !errors.Is(err, ErrChanged) {
		t.Errorf("err = %v, want ErrChanged", err)
	}
}

func TestTS23_RulesOnOpenFile(t *testing.T) {
	r, dir := root(t)
	file(t, dir, "f", 0o600)
	var once atomic.Bool
	safefiletest.Set(t, safefiletest.Hooks{AfterOpen: func(string) {
		if once.CompareAndSwap(false, true) {
			if err := os.Chmod(filepath.Join(dir, "f"), 0o660); err != nil {
				t.Error(err)
			}
		}
	}})
	rule := base
	rule.Forbid = 0o077
	if err := open(t, r, "f", rule); !errors.Is(err, ErrMode) {
		t.Errorf("err = %v, want ErrMode", err)
	}
}

// chmodAfterOpen sets the AfterOpen hook to change the mode of p to m.
func chmodAfterOpen(t *testing.T, p string, m fs.FileMode) {
	t.Helper()
	safefiletest.Set(t, safefiletest.Hooks{AfterOpen: func(string) {
		if err := os.Chmod(p, m); err != nil {
			t.Error(err)
		}
	}})
}

// A refused Open or OpenPath closes the file that it opened. The test does not
// run the garbage collector. But a finalizer can close a leaked file before the
// second count. Then the test does not see the leak.
func TestTS23_RefusedOpenClosesTheFile(t *testing.T) {
	r, dir := root(t)
	file(t, dir, "f", 0o600)
	p := filepath.Join(dir, "f")
	rule := base
	rule.Forbid = 0o077
	chmodAfterOpen(t, p, 0o660)
	before := openFDs(t)
	if f, _, err := Open(r, "f", rule); !errors.Is(err, ErrMode) || f != nil {
		t.Errorf("Open: %v, %v, want ErrMode", f, err)
	}
	if after := openFDs(t); after != before {
		t.Errorf("Open: open files: %d before, %d after", before, after)
	}
	if err := os.Chmod(p, 0o600); err != nil {
		t.Fatal(err)
	}
	if f, _, err := OpenPath(p, rule); !errors.Is(err, ErrMode) || f != nil {
		t.Errorf("OpenPath: %v, %v, want ErrMode", f, err)
	}
	if after := openFDs(t); after != before {
		t.Errorf("OpenPath: open files: %d before, %d after", before, after)
	}
}

// Open and OpenPath give the FileInfo of the open file after the hook. They
// do not give the FileInfo of the check.
func TestTS23_ReturnedFileInfoIsOfTheOpenFile(t *testing.T) {
	r, dir := root(t)
	file(t, dir, "f", 0o600)
	p := filepath.Join(dir, "f")
	chmodAfterOpen(t, p, 0o640)
	f, fi, err := Open(r, "f", base)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if got := fi.Mode().Perm(); got != 0o640 {
		t.Errorf("Open: mode %o, want 640", got)
	}
	if err := os.Chmod(p, 0o600); err != nil {
		t.Fatal(err)
	}
	f, fi, err = OpenPath(p, base)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if got := fi.Mode().Perm(); got != 0o640 {
		t.Errorf("OpenPath: mode %o, want 640", got)
	}
}

// A hook cannot turn a refusal into a pass.
func TestTS23_HookCannotGrant(t *testing.T) {
	r, dir := root(t)
	file(t, dir, "f640", 0o640)
	if err := os.Mkdir(filepath.Join(dir, "d"), 0o700); err != nil {
		t.Fatal(err)
	}
	nop := func(string) {}
	safefiletest.Set(t, safefiletest.Hooks{
		BeforeCheck: nop, AfterCheck: nop, AfterOpen: nop,
		OtherOwner: func(seam.FileID) bool { return false },
	})
	mode := base
	mode.Exact = 0o600
	if err := open(t, r, "f640", mode); !errors.Is(err, ErrMode) {
		t.Errorf("mode: err = %v, want ErrMode", err)
	}
	if err := open(t, r, "d", base); !errors.Is(err, ErrType) {
		t.Errorf("type: err = %v, want ErrType", err)
	}
	if err := open(t, r, "f640", Rule{}); !errors.Is(err, ErrRule) {
		t.Errorf("rule: err = %v, want ErrRule", err)
	}
}

func TestTS23_HookCannotGrantOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to give a file to another owner")
	}
	r, dir := root(t)
	file(t, dir, "f", 0o600)
	if err := os.Chown(filepath.Join(dir, "f"), 12345, 12345); err != nil {
		t.Fatal(err)
	}
	safefiletest.Set(t, safefiletest.Hooks{
		OtherOwner: func(seam.FileID) bool { return false },
	})
	for _, o := range []Owner{OwnerSelf, OwnerSelfOrRoot} {
		rule := base
		rule.Owner = o
		if err := open(t, r, "f", rule); !errors.Is(err, ErrOwner) {
			t.Errorf("owner %d: err = %v, want ErrOwner", o, err)
		}
	}
}

func TestTS23_SetRestores(t *testing.T) {
	t.Run("sub", func(t *testing.T) {
		safefiletest.Set(t, safefiletest.Hooks{})
		if seam.Current() == nil {
			t.Error("no hook set is active after Set")
		}
	})
	if seam.Current() != nil {
		t.Error("the hook set is still active after the test")
	}
}

func TestTS23_SecondSetFails(t *testing.T) {
	safefiletest.Set(t, safefiletest.Hooks{})
	first := seam.Current()
	f := &fakeT{}
	// Fatalf of fakeT returns, so Set must not install after the failure.
	safefiletest.Set(f, safefiletest.Hooks{})
	if f.msg == "" {
		t.Error("a second Set did not fail the test")
	}
	if seam.Current() != first {
		t.Error("a second Set replaced the first hook set")
	}
	if len(f.cleanups) != 0 {
		t.Error("a failed Set registered a cleanup")
	}
}
