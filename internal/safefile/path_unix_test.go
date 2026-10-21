//go:build unix && !aix && !solaris

package safefile

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/cybagard/cyba-phantom/internal/safefile/safefiletest"
)

var (
	followRule = Rule{Type: Regular, Owner: OwnerSelf, FollowEnd: true}
	parentRule = Rule{Type: Dir, Owner: OwnerSelfOrRoot, Forbid: 0o022}
)

// link makes the symlink name with the target.
func link(t *testing.T, target, name string) {
	t.Helper()
	if err := os.Symlink(target, name); err != nil {
		t.Fatal(err)
	}
}

// fifo makes a FIFO.
func fifo(t *testing.T, name string) {
	t.Helper()
	if err := syscall.Mkfifo(name, 0o600); err != nil {
		t.Fatal(err)
	}
}

// openWithin runs OpenPath and fails the test when it takes more than 2 s.
func openWithin(t *testing.T, path string, r Rule) error {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		f, _, err := OpenPath(path, r)
		if f != nil {
			f.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		return err
	case <-time.After(2 * time.Second):
		t.Fatal("OpenPath blocked")
		return nil
	}
}

func TestTS23_OpenPathFollowEnd(t *testing.T) {
	dir := t.TempDir()
	reg := put(t, dir, "reg", "0123456789")
	link(t, reg, filepath.Join(dir, "toreg"))
	fifo(t, filepath.Join(dir, "p"))
	link(t, filepath.Join(dir, "p"), filepath.Join(dir, "tofifo"))
	link(t, "/dev/null", filepath.Join(dir, "todev"))
	link(t, dir, filepath.Join(dir, "todir"))
	var checked int
	safefiletest.Set(t, safefiletest.Hooks{AfterCheck: func(string) { checked++ }})

	f, fi, err := OpenPath(filepath.Join(dir, "toreg"), followRule)
	if err != nil {
		t.Fatalf("FollowEnd link to a regular file: %v", err)
	}
	got, _ := io.ReadAll(f)
	f.Close()
	if string(got) != "0123456789" || !fi.Mode().IsRegular() {
		t.Errorf("read %q, mode %v", got, fi.Mode())
	}
	if checked != 1 {
		t.Fatalf("AfterCheck ran %d times, want 1", checked)
	}
	for _, n := range []string{"tofifo", "todev", "todir", "p"} {
		if err := openWithin(t, filepath.Join(dir, n), followRule); !errors.Is(err, ErrType) {
			t.Errorf("FollowEnd %s: err = %v, want ErrType", n, err)
		}
	}
	for _, n := range []string{"toreg", "tofifo", "todev", "todir"} {
		if err := openWithin(t, filepath.Join(dir, n), base); !errors.Is(err, ErrSymlink) {
			t.Errorf("no FollowEnd %s: err = %v, want ErrSymlink", n, err)
		}
	}
	if checked != 1 {
		t.Errorf("AfterCheck ran %d times, a refused file reached the open", checked)
	}
	if err := openWithin(t, reg, base); err != nil {
		t.Errorf("no FollowEnd regular file: %v", err)
	}
	if err := openWithin(t, filepath.Join(dir, "none"), followRule); !errors.Is(err, ErrExamine) {
		t.Errorf("missing file: err = %v, want ErrExamine", err)
	}
	for _, p := range []string{"", "reg", "./reg"} {
		if err := openWithin(t, p, followRule); !errors.Is(err, ErrName) {
			t.Errorf("path %q: err = %v, want ErrName", p, err)
		}
	}
	if err := openWithin(t, reg, Rule{}); !errors.Is(err, ErrRule) {
		t.Errorf("zero rule: err = %v, want ErrRule", err)
	}
	err = openWithin(t, filepath.Join(dir, "tofifo"), followRule)
	noLeak(t, err, dir)
}

func TestTS23_OpenPathSwap(t *testing.T) {
	dir := t.TempDir()
	a := put(t, dir, "a", "aaaa")
	b := put(t, dir, "b", "bbbb")
	fifo(t, filepath.Join(dir, "p"))
	ln := filepath.Join(dir, "ln")
	link(t, a, ln)
	relink := func(target string) func() {
		return func() {
			tmp := filepath.Join(dir, "tmp")
			_ = os.Remove(tmp)
			link(t, target, tmp)
			if err := os.Rename(tmp, ln); err != nil {
				t.Error(err)
			}
		}
	}
	for _, c := range []struct {
		name   string
		path   string
		rule   Rule
		action func()
	}{
		{"follow, link to a file", ln, followRule, relink(b)},
		{"follow, link to a FIFO", ln, followRule, relink(filepath.Join(dir, "p"))},
		{"no follow, file over name", a, base, func() {
			if err := os.Rename(b, a); err != nil {
				t.Error(err)
			}
		}},
		{"no follow, FIFO over name", b, base, func() {
			if err := os.Rename(filepath.Join(dir, "p"), b); err != nil {
				t.Error(err)
			}
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			safefiletest.Set(t, safefiletest.Hooks{AfterCheck: func(string) { c.action() }})
			err := openWithin(t, c.path, c.rule)
			if !errors.Is(err, ErrChanged) {
				t.Errorf("err = %v, want ErrChanged", err)
			}
			noLeak(t, err, dir)
		})
		// Restore the files for the next case.
		_ = os.Remove(a)
		_ = os.Remove(b)
		_ = os.Remove(ln)
		_ = os.Remove(filepath.Join(dir, "p"))
		put(t, dir, "a", "aaaa")
		put(t, dir, "b", "bbbb")
		link(t, a, ln)
		fifo(t, filepath.Join(dir, "p"))
	}
}

// mkdir makes a directory with the exact mode m.
func mkdir(t *testing.T, path string, m fs.FileMode) string {
	t.Helper()
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, m); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestTS23_PathParents(t *testing.T) {
	// The test tree is below the package directory. Each parent up to "/"
	// is then closed for write.
	wd, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	top, err := os.MkdirTemp(wd, "parents")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(top) })
	mkdir(t, top, 0o755)
	ok := mkdir(t, filepath.Join(top, "ok"), 0o755)
	put(t, ok, "f", "x")
	if err := os.Chmod(filepath.Join(ok, "f"), 0o666); err != nil {
		t.Fatal(err)
	}
	bad := map[string]fs.FileMode{
		"group": 0o775, "other": 0o757, "sticky": 0o1777, "wide": 0o777,
	}
	for n, m := range bad {
		d := mkdir(t, filepath.Join(top, n), m)
		put(t, d, "f", "x")
		link(t, filepath.Join(d, "f"), filepath.Join(ok, "to-"+n))
		link(t, d, filepath.Join(ok, "dir-"+n))
		link(t, filepath.Join(ok, "f"), filepath.Join(d, "in-"+n))
		link(t, "../"+n+"/f", filepath.Join(ok, "rel-"+n))
	}
	link(t, ok, filepath.Join(top, "okdir"))
	link(t, "loop", filepath.Join(ok, "loop"))

	pass := []string{
		filepath.Join(ok, "f"), // the file has mode 0666
		filepath.Join(top, "okdir", "f"),
		ok + "/../ok//f",
		filepath.Join(top, "group"), // the last part is not checked
	}
	for _, p := range pass {
		if err := CheckPathParents(p, parentRule); err != nil {
			t.Errorf("%s: %v", p, err)
		}
	}
	for n := range bad {
		for _, p := range []string{
			filepath.Join(top, n, "f"),
			filepath.Join(top, n, "in-"+n),
			filepath.Join(ok, "to-"+n),
			filepath.Join(ok, "dir-"+n, "f"),
			filepath.Join(ok, "rel-"+n),
			filepath.Join(top, "okdir", "to-"+n),
		} {
			if err := CheckPathParents(p, parentRule); !errors.Is(err, ErrMode) {
				t.Errorf("%s: err = %v, want ErrMode", filepath.Base(p), err)
			}
		}
	}

	self, err := os.Stat(ok)
	if err != nil {
		t.Fatal(err)
	}
	okID, _ := Identity(self)
	rootInfo, err := os.Stat("/")
	if err != nil {
		t.Fatal(err)
	}
	rootID, _ := Identity(rootInfo)
	for _, id := range []FileID{okID, rootID} {
		t.Run("other owner", func(t *testing.T) {
			safefiletest.Set(t, safefiletest.Hooks{
				OtherOwner: func(x FileID) bool { return x == id },
			})
			err := CheckPathParents(filepath.Join(ok, "f"), parentRule)
			if !errors.Is(err, ErrOwner) {
				t.Errorf("id %v: err = %v, want ErrOwner", id, err)
			}
		})
	}

	// Directories that the walk reaches only through a symlink.
	holder := mkdir(t, filepath.Join(top, "holder"), 0o755)
	tgt := mkdir(t, filepath.Join(top, "tgt"), 0o755)
	put(t, tgt, "f", "x")
	link(t, filepath.Join(ok, "f"), filepath.Join(holder, "lnk"))
	link(t, "../holder/lnk", filepath.Join(ok, "chain"))
	link(t, tgt, filepath.Join(ok, "tdir"))
	for _, c := range []struct{ name, dir, path string }{
		{"holder of a link", holder, filepath.Join(top, "okdir", "chain")},
		{"directory of a target", tgt, filepath.Join(ok, "tdir", "f")},
	} {
		t.Run(c.name, func(t *testing.T) {
			if err := CheckPathParents(c.path, parentRule); err != nil {
				t.Fatalf("without the hook: %v", err)
			}
			fi, err := os.Stat(c.dir)
			if err != nil {
				t.Fatal(err)
			}
			id, _ := Identity(fi)
			safefiletest.Set(t, safefiletest.Hooks{
				OtherOwner: func(x FileID) bool { return x == id },
			})
			if err := CheckPathParents(c.path, parentRule); !errors.Is(err, ErrOwner) {
				t.Errorf("err = %v, want ErrOwner", err)
			}
		})
	}

	for _, c := range []struct {
		path string
		rule Rule
		want error
	}{
		{filepath.Join(ok, "none"), parentRule, fs.ErrNotExist},
		{filepath.Join(top, "none", "f"), parentRule, fs.ErrNotExist},
		{filepath.Join(ok, "f", "x"), parentRule, ErrType},
		{filepath.Join(ok, "loop"), parentRule, ErrSymlink},
		{"ok/f", parentRule, ErrName},
		{"", parentRule, ErrName},
		{filepath.Join(ok, "f"), Rule{}, ErrRule},
		{filepath.Join(ok, "f"), Rule{Type: Regular, Owner: OwnerSelf}, ErrRule},
	} {
		err := CheckPathParents(c.path, c.rule)
		if !errors.Is(err, c.want) {
			t.Errorf("%q: err = %v, want %v", c.path, err, c.want)
		}
		noLeak(t, err, top)
	}
}
