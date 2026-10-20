//go:build unix

package safefile

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/cybagard/cyba-phantom/internal/safefile/internal/seam"
	"github.com/cybagard/cyba-phantom/internal/safefile/safefiletest"
)

var base = Rule{Type: Regular, Owner: OwnerSelf}

// fakeT records a failure and ends the goroutine, as t.Fatalf does.
type fakeT struct {
	testing.TB
	msg atomic.Value
}

func (f *fakeT) Helper() {}

func (f *fakeT) Fatalf(format string, args ...any) {
	f.msg.Store(fmt.Sprintf(format, args...))
	runtime.Goexit()
}

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
		{"regular is a dir", "d", base, nil, ErrType},
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
			if tc.want == nil && err != nil || !errors.Is(err, tc.want) {
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

func TestTS23_FIFOAtNameNeverOpened(t *testing.T) {
	r, dir := root(t)
	if err := syscall.Mkfifo(filepath.Join(dir, "p"), 0o600); err != nil {
		t.Fatal(err)
	}
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
	f := &fakeT{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		safefiletest.Set(f, safefiletest.Hooks{})
	}()
	<-done
	if msg, _ := f.msg.Load().(string); msg == "" {
		t.Error("a second Set did not fail the test")
	}
}
