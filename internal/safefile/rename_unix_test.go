//go:build unix && !aix && !solaris

package safefile

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cybagard/cyba-phantom/internal/safefile/safefiletest"
)

// renameDir makes a directory with the files a and b, and opens it as a root.
func renameDir(t *testing.T) (string, *os.Root) {
	t.Helper()
	dir := t.TempDir()
	for _, n := range []string{"a", "b"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("data-"+n), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	return dir, root
}

func readOf(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		return "missing"
	}
	return string(b)
}

// T-S-38: Rename renames one name to another name in the root.
func TestTS38_RenameRenames(t *testing.T) {
	dir, root := renameDir(t)
	if err := Rename(root, "a", "b"); err != nil {
		t.Fatal(err)
	}
	if got := readOf(t, filepath.Join(dir, "b")); got != "data-a" {
		t.Errorf("b holds %q", got)
	}
	if got := readOf(t, filepath.Join(dir, "a")); got != "missing" {
		t.Errorf("a holds %q", got)
	}
}

// T-S-38: a nil root gives ErrRule. A bad name gives ErrName and no rename.
func TestTS38_RenameRefusesArguments(t *testing.T) {
	dir, root := renameDir(t)
	if err := Rename(nil, "a", "b"); !errors.Is(err, ErrRule) {
		t.Errorf("nil root: %v", err)
	}
	var steps []string
	safefiletest.Set(t, safefiletest.Hooks{Step: func(step, name string) error {
		steps = append(steps, step+" "+name)
		return nil
	}})
	bad := []string{"", ".", "..", "x/y", "/a", "a/", "../a", "./a"}
	for _, n := range bad {
		for _, pair := range [][2]string{{n, "b"}, {"a", n}} {
			if err := Rename(root, pair[0], pair[1]); !errors.Is(err, ErrName) {
				t.Errorf("%q to %q: %v", pair[0], pair[1], err)
			}
		}
	}
	if len(steps) != 0 {
		t.Errorf("steps ran: %v", steps)
	}
	if readOf(t, filepath.Join(dir, "a")) != "data-a" || readOf(t, filepath.Join(dir, "b")) != "data-b" {
		t.Error("a file changed")
	}
}

// T-S-38: Rename runs one rename step with the name from. A hook error fails
// the step and renames nothing.
func TestTS38_RenameRunsStep(t *testing.T) {
	dir, root := renameDir(t)
	boom := errors.New("injected")
	var steps []string
	safefiletest.Set(t, safefiletest.Hooks{Step: func(step, name string) error {
		steps = append(steps, step+" "+name)
		return boom
	}})
	err := Rename(root, "a", "b")
	if want := "rename a"; len(steps) != 1 || steps[0] != want {
		t.Errorf("steps %v, want %q", steps, want)
	}
	var we *WriteError
	if !errors.As(err, &we) || we.Step != ErrRename || !errors.Is(err, boom) || !errors.Is(err, ErrMayBeRenamed) {
		t.Errorf("error %v", err)
	}
	if readOf(t, filepath.Join(dir, "a")) != "data-a" || readOf(t, filepath.Join(dir, "b")) != "data-b" {
		t.Error("the failed step renamed")
	}
}

// T-S-38: a crash at the step returns Crash and renames nothing.
func TestTS38_RenameCrash(t *testing.T) {
	dir, root := renameDir(t)
	safefiletest.Set(t, safefiletest.Hooks{Step: func(string, string) error { return safefiletest.Crash }})
	err := Rename(root, "a", "b")
	if !errors.Is(err, safefiletest.Crash) {
		t.Errorf("error %v", err)
	}
	var we *WriteError
	if errors.As(err, &we) {
		t.Error("a crash is a write error")
	}
	if readOf(t, filepath.Join(dir, "a")) != "data-a" || readOf(t, filepath.Join(dir, "b")) != "data-b" {
		t.Error("the crash renamed")
	}
}

// T-S-38: a failed rename is a write error with the step ErrRename. It holds
// the system error and no path.
func TestTS38_RenameErrorHoldsNoPath(t *testing.T) {
	dir, root := renameDir(t)
	err := Rename(root, "missing", "b")
	var we *WriteError
	if !errors.As(err, &we) || we.Step != ErrRename {
		t.Fatalf("error %v", err)
	}
	if !errors.Is(err, fs.ErrNotExist) || !errors.Is(err, ErrMayBeRenamed) {
		t.Errorf("error %v lacks the cause or ErrMayBeRenamed", err)
	}
	var le *os.LinkError
	var pe *fs.PathError
	if errors.As(err, &le) || errors.As(err, &pe) || strings.Contains(err.Error(), dir) || strings.Contains(err.Error(), "missing") {
		t.Errorf("error %q holds a path", err)
	}
}

// T-S-38: Rename replaces a link at the final name and does not follow it.
func TestTS38_RenameReplacesLink(t *testing.T) {
	dir, root := renameDir(t)
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "b")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "b")); err != nil {
		t.Fatal(err)
	}
	if err := Rename(root, "a", "b"); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(filepath.Join(dir, "b"))
	if err != nil || fi.Mode()&fs.ModeSymlink != 0 || readOf(t, filepath.Join(dir, "b")) != "data-a" {
		t.Errorf("b is %v, %v", fi, err)
	}
	if got := readOf(t, outside); got != "keep" {
		t.Errorf("the target holds %q", got)
	}
}

// T-S-38: Rename does not sync the directory.
func TestTS38_RenameDoesNotSyncDirectory(t *testing.T) {
	_, root := renameDir(t)
	var steps []string
	safefiletest.Set(t, safefiletest.Hooks{Step: func(step, _ string) error {
		steps = append(steps, step)
		return nil
	}})
	if err := Rename(root, "a", "b"); err != nil || len(steps) != 1 || steps[0] != "rename" {
		t.Errorf("error %v, steps %v", err, steps)
	}
}
