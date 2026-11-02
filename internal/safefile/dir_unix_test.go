//go:build unix && !aix && !solaris

package safefile

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/cybagard/cyba-phantom/internal/safefile/safefiletest"
)

var dirRule = Rule{Type: Dir, Owner: OwnerSelf, Forbid: 0o077}

// tree makes the directories a/b/c below dir with the mode 0700.
func tree(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, "a", "b", "c"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{".", "a", "a/b", "a/b/c"} {
		if err := os.Chmod(filepath.Join(dir, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
}

func TestTS23_OpenRootWalk(t *testing.T) {
	r, dir := root(t)
	tree(t, dir)
	put(t, filepath.Join(dir, "a", "b", "c"), "f", "0123456789")
	sub, err := OpenRoot(r, "a/b/c", dirRule)
	if err != nil {
		t.Fatal(err)
	}
	defer sub.Close()
	got, err := ReadFile(sub, "f", capRule)
	if err != nil || string(got) != "0123456789" {
		t.Errorf("read below the walk: %q, %v", got, err)
	}
	one, err := OpenRoot(r, "a", dirRule)
	if err != nil {
		t.Fatalf("one part: %v", err)
	}
	one.Close()
}

func TestTS23_OpenRootNameRules(t *testing.T) {
	r, dir := root(t)
	tree(t, dir)
	noHook := func(string) { t.Error("a hook ran for a refused name") }
	safefiletest.Set(t, safefiletest.Hooks{BeforeCheck: noHook, AfterCheck: noHook})
	for _, name := range []string{
		"", "/", "/a", "a/", "a//b", ".", "..", "a/.", "a/..", "../a", "./a",
	} {
		if _, err := OpenRoot(r, name, dirRule); !errors.Is(err, ErrName) {
			t.Errorf("OpenRoot %q: err = %v, want ErrName", name, err)
		}
		if err := CheckParents(r, name, dirRule); !errors.Is(err, ErrName) {
			t.Errorf("CheckParents %q: err = %v, want ErrName", name, err)
		}
	}
}

func TestTS23_OpenRootRuleRefused(t *testing.T) {
	r, dir := root(t)
	tree(t, dir)
	for _, rule := range []Rule{{}, base, {Type: Dir}} {
		if _, err := OpenRoot(r, "a", rule); !errors.Is(err, ErrRule) {
			t.Errorf("OpenRoot rule %+v: err = %v, want ErrRule", rule, err)
		}
		if err := CheckParents(r, "a/b", rule); !errors.Is(err, ErrRule) {
			t.Errorf("CheckParents rule %+v: err = %v, want ErrRule", rule, err)
		}
	}
	if _, err := OpenRoot(nil, "a", dirRule); !errors.Is(err, ErrRule) {
		t.Errorf("nil root: err = %v, want ErrRule", err)
	}
	if err := CheckParents(nil, "a/b", dirRule); !errors.Is(err, ErrRule) {
		t.Errorf("CheckParents nil root: err = %v, want ErrRule", err)
	}
}

func TestTS23_OpenRootLinkAtEachPart(t *testing.T) {
	for _, tc := range []struct{ name, link, target string }{
		{"first part", "a", "real"},
		{"middle part", "a/b", "../real"},
		{"last part", "a/b/c", "../../real"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, dir := root(t)
			tree(t, dir)
			if err := os.Mkdir(filepath.Join(dir, "real"), 0o700); err != nil {
				t.Fatal(err)
			}
			link := filepath.Join(dir, tc.link)
			if err := os.RemoveAll(link); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(tc.target, link); err != nil {
				t.Fatal(err)
			}
			if _, err := OpenRoot(r, "a/b/c", dirRule); !errors.Is(err, ErrSymlink) {
				t.Errorf("err = %v, want ErrSymlink", err)
			}
		})
	}
}

func TestTS23_OpenRootSwapAfterCheck(t *testing.T) {
	r, dir := root(t)
	tree(t, dir)
	swapAfterCheck(t, func(part string) {
		// The new directory has a new inode, because the old one still exists.
		q := filepath.Join(dir, "q")
		if err := os.Mkdir(q, 0o700); err != nil {
			t.Error(err)
		}
		p := filepath.Join(dir, part)
		if err := os.Rename(p, filepath.Join(dir, "old")); err != nil {
			t.Error(err)
		}
		if err := os.Rename(q, p); err != nil {
			t.Error(err)
		}
	})
	if _, err := OpenRoot(r, "a", dirRule); !errors.Is(err, ErrChanged) {
		t.Errorf("err = %v, want ErrChanged", err)
	}
}

func TestTS23_OpenRootLinkSwapAfterCheck(t *testing.T) {
	r, dir := root(t)
	tree(t, dir)
	swapAfterCheck(t, func(part string) {
		p := filepath.Join(dir, part)
		if err := os.Rename(p, filepath.Join(dir, "old")); err != nil {
			t.Error(err)
		}
		// A link to the checked directory would open it. Use another one.
		if err := os.Mkdir(filepath.Join(dir, "other"), 0o700); err != nil {
			t.Error(err)
		}
		if err := os.Symlink("other", p); err != nil {
			t.Error(err)
		}
	})
	if _, err := OpenRoot(r, "a", dirRule); !errors.Is(err, ErrChanged) {
		t.Errorf("err = %v, want ErrChanged", err)
	}
}

func TestTS23_OpenRootWholeRule(t *testing.T) {
	r, dir := root(t)
	tree(t, dir)
	if err := os.Chmod(filepath.Join(dir, "a", "b"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenRoot(r, "a/b/c", dirRule); !errors.Is(err, ErrMode) {
		t.Errorf("bad mode: err = %v, want ErrMode", err)
	}
	other := safefiletest.Hooks{OtherOwner: func(id FileID) bool { return true }}
	safefiletest.Set(t, other)
	if _, err := OpenRoot(r, "a", Rule{Type: Dir, Owner: OwnerSelf}); !errors.Is(err, ErrOwner) {
		t.Errorf("other owner: err = %v, want ErrOwner", err)
	}
}

func TestTS23_OpenRootMissingAndFile(t *testing.T) {
	r, dir := root(t)
	tree(t, dir)
	put(t, dir, "f", "x")
	if _, err := OpenRoot(r, "a/none/c", dirRule); !errors.Is(err, ErrExamine) {
		t.Errorf("missing: err = %v, want ErrExamine", err)
	}
	if _, err := OpenRoot(r, "f", dirRule); !errors.Is(err, ErrType) {
		t.Errorf("file: err = %v, want ErrType", err)
	}
}

func TestTS23_OpenRootClosesRoots(t *testing.T) {
	r, dir := root(t)
	tree(t, dir)
	before := openFDs(t)
	sub, err := OpenRoot(r, "a/b/c", dirRule)
	if err != nil {
		t.Fatal(err)
	}
	if during := openFDs(t); during != before+1 {
		t.Errorf("open files after the walk: %d, want %d", during, before+1)
	}
	sub.Close()
	if _, err := OpenRoot(r, "a/none", dirRule); err == nil {
		t.Fatal("no error for a missing directory")
	}
	if after := openFDs(t); after != before {
		t.Errorf("open files: %d before, %d after", before, after)
	}
	// The rule refuses a directory after OpenRoot opened it.
	if err := os.Chmod(filepath.Join(dir, "a", "b"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenRoot(r, "a/b/c", dirRule); !errors.Is(err, ErrMode) {
		t.Fatalf("bad mode: err = %v, want ErrMode", err)
	}
	if after := openFDs(t); after != before {
		t.Errorf("open files after a rule error: %d before, %d after", before, after)
	}
}

func mkFIFO(q string) error { return syscall.Mkfifo(q, 0o600) }
func mkDir(q string) error  { return os.Mkdir(q, 0o700) }

// swapPart replaces the part of a/b/c, once, at AfterCheck or at AfterOpen.
// mk makes the new file. It has a new inode, because the old directory
// moves to "old" and still exists.
func swapPart(t *testing.T, dir, part string, afterOpen bool, mk func(string) error) {
	t.Helper()
	paths := map[string]string{"a": "a", "b": "a/b", "c": "a/b/c"}
	swap := func(name string) {
		if name != part {
			return
		}
		q, p := filepath.Join(dir, "q"), filepath.Join(dir, paths[name])
		if err := mk(q); err != nil {
			t.Error(err)
		}
		if err := os.Rename(p, filepath.Join(dir, "old")); err != nil {
			t.Error(err)
		}
		if err := os.Rename(q, p); err != nil {
			t.Error(err)
		}
	}
	h := safefiletest.Hooks{AfterCheck: swap}
	if afterOpen {
		h = safefiletest.Hooks{AfterOpen: swap}
	}
	safefiletest.Set(t, h)
}

// timedRoot runs OpenRoot, closes the root and fails the test when it takes 2 s
// or more.
func timedRoot(t *testing.T, r *os.Root, name string) error {
	t.Helper()
	type result struct {
		sub *os.Root
		err error
	}
	done := make(chan result, 1)
	go func() {
		sub, err := OpenRoot(r, name, dirRule)
		done <- result{sub, err}
	}()
	select {
	case res := <-done:
		if res.sub != nil {
			res.sub.Close()
		}
		return res.err
	case <-time.After(2 * time.Second):
		t.Fatal("OpenRoot did not return before the deadline")
		return nil
	}
}

// A FIFO has no directory type, so the first open refuses it with ENOTDIR
// before it can block. That gives ErrType.
func TestTS23_OpenRootFIFOSwapAfterCheckNoBlock(t *testing.T) {
	for _, part := range []string{"a", "b", "c"} {
		t.Run(part, func(t *testing.T) {
			r, dir := root(t)
			tree(t, dir)
			swapPart(t, dir, part, false, mkFIFO)
			if err := timedRoot(t, r, "a/b/c"); !errors.Is(err, ErrType) {
				t.Errorf("err = %v, want ErrType", err)
			}
		})
	}
}

// The link stays in the root and points to a FIFO next to the part. The first
// open follows it and refuses the FIFO with ENOTDIR, so it does not block.
func TestTS23_OpenRootFIFOLinkSwapAfterCheckNoBlock(t *testing.T) {
	r, dir := root(t)
	tree(t, dir)
	if err := mkFIFO(filepath.Join(dir, "p")); err != nil {
		t.Fatal(err)
	}
	swapPart(t, dir, "a", false, func(q string) error {
		return os.Symlink("p", q)
	})
	if err := timedRoot(t, r, "a/b/c"); !errors.Is(err, ErrType) {
		t.Errorf("err = %v, want ErrType", err)
	}
}

// The swap comes after the first open. The descriptor is of the checked
// directory, so only the compare of the root with the Lstat result refuses.
func TestTS23_OpenRootSwapAfterOpen(t *testing.T) {
	for _, part := range []string{"a", "b", "c"} {
		t.Run(part, func(t *testing.T) {
			r, dir := root(t)
			tree(t, dir)
			swapPart(t, dir, part, true, mkDir)
			if err := timedRoot(t, r, "a/b/c"); !errors.Is(err, ErrChanged) {
				t.Errorf("err = %v, want ErrChanged", err)
			}
		})
	}
}

// The swap comes after the check. It is undone after the first open. The root
// open then gets the checked directory. So the compare of the first descriptor
// with the Lstat result is what refuses.
func TestTS23_OpenRootFirstCompareRefuses(t *testing.T) {
	r, dir := root(t)
	tree(t, dir)
	p, old := filepath.Join(dir, "a"), filepath.Join(dir, "old")
	safefiletest.Set(t, safefiletest.Hooks{
		AfterCheck: func(string) {
			if err := os.Rename(p, old); err != nil {
				t.Error(err)
			}
			if err := os.Mkdir(p, 0o700); err != nil {
				t.Error(err)
			}
		},
		AfterOpen: func(string) {
			if err := os.Rename(p, filepath.Join(dir, "new")); err != nil {
				t.Error(err)
			}
			if err := os.Rename(old, p); err != nil {
				t.Error(err)
			}
		},
	})
	if err := timedRoot(t, r, "a"); !errors.Is(err, ErrChanged) {
		t.Errorf("err = %v, want ErrChanged", err)
	}
}

func TestTS23_OpenRootSwapClosesDescriptors(t *testing.T) {
	for _, tc := range []struct {
		name      string
		afterOpen bool
		mk        func(string) error
		want      error
	}{
		{"fifo after check", false, mkFIFO, ErrType},
		{"directory after check", false, mkDir, ErrChanged},
		{"directory after open", true, mkDir, ErrChanged},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, dir := root(t)
			tree(t, dir)
			swapPart(t, dir, "b", tc.afterOpen, tc.mk)
			before := openFDs(t)
			if err := timedRoot(t, r, "a/b/c"); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if after := openFDs(t); after != before {
				t.Errorf("open files: %d before, %d after", before, after)
			}
		})
	}
}

func TestTS23_CheckParents(t *testing.T) {
	r, dir := root(t)
	tree(t, dir)
	if err := CheckParents(r, "a/b/c/f", dirRule); err != nil {
		t.Errorf("pass: %v", err)
	}
	if err := CheckParents(r, "f", dirRule); err != nil {
		t.Errorf("pass, name in the root: %v", err)
	}
	// The last part is not a parent, so CheckParents does not check it.
	if err := CheckParents(r, "a/missing", dirRule); err != nil {
		t.Errorf("last part: %v", err)
	}

	if err := os.Chmod(filepath.Join(dir, "a", "b"), 0o770); err != nil {
		t.Fatal(err)
	}
	if err := CheckParents(r, "a/b/c/f", dirRule); !errors.Is(err, ErrMode) {
		t.Errorf("bad mode: err = %v, want ErrMode", err)
	}
	if err := CheckParents(r, "a/b", dirRule); err != nil {
		t.Errorf("a parent only: %v", err)
	}
	if err := os.Chmod(filepath.Join(dir, "a", "b"), 0o700); err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(dir, 0o770); err != nil {
		t.Fatal(err)
	}
	if err := CheckParents(r, "a/f", dirRule); !errors.Is(err, ErrMode) {
		t.Errorf("bad mode of the root: err = %v, want ErrMode", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := CheckParents(r, "a/none/c/f", dirRule); !errors.Is(err, ErrExamine) ||
		!errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing parent: err = %v", err)
	}
	put(t, dir, "file", "x")
	if err := CheckParents(r, "file/x", dirRule); !errors.Is(err, ErrType) {
		t.Errorf("file as parent: err = %v, want ErrType", err)
	}

	if err := os.Rename(filepath.Join(dir, "a", "b"), filepath.Join(dir, "real")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../real", filepath.Join(dir, "a", "b")); err != nil {
		t.Fatal(err)
	}
	if err := CheckParents(r, "a/b/c/f", dirRule); !errors.Is(err, ErrSymlink) {
		t.Errorf("parent link: err = %v, want ErrSymlink", err)
	}
}
