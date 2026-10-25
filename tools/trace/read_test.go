package main

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadCappedSizeCap(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f")
	writeFile(t, dir, "f", strings.Repeat("a", maxFileBytes))
	got, err := readCapped(path)
	if err != nil || len(got) != maxFileBytes {
		t.Fatalf("file at the cap: %d bytes, err %v", len(got), err)
	}
	writeFile(t, dir, "f", strings.Repeat("a", maxFileBytes+1))
	if _, err := readCapped(path); !errors.Is(err, errTooLarge) {
		t.Errorf("file over the cap: err %v, want errTooLarge", err)
	}
}

func TestReadCappedOverCapSpecFileIsFinding(t *testing.T) {
	dir := newSpec(t)
	writeFile(t, dir, "07-test-plan.md", strings.Repeat("a", maxFileBytes+1))
	wantFinding(t, dir, "07-test-plan.md: exceeds the 1048576 byte cap")
}

func TestReadCappedRelativePath(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "f", "text\n")
	t.Chdir(dir)
	got, err := readCapped("f")
	if err != nil || string(got) != "text\n" {
		t.Errorf("relative path: %q, err %v", got, err)
	}
}

func TestReadCappedMissingFile(t *testing.T) {
	_, err := readCapped(filepath.Join(t.TempDir(), "absent"))
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing file: err %v, want ErrNotExist", err)
	}
	if readFinding("x", err) != "" {
		t.Error("a missing file is not a finding")
	}
}

func TestReadCappedDirectoryAndSymlink(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "real", "x")
	if err := os.Symlink(filepath.Join(dir, "real"), filepath.Join(dir, "link")); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	for _, name := range []string{"link", "."} {
		if _, err := readCapped(filepath.Join(dir, name)); !errors.Is(err, errNotRegular) {
			t.Errorf("%s: err %v, want errNotRegular", name, err)
		}
	}
}

func TestCheckSpecDir(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "file", "x")
	if err := checkSpecDir(dir); err != nil {
		t.Errorf("directory: %v", err)
	}
	t.Chdir(dir)
	if err := os.Mkdir("sub", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := checkSpecDir("sub"); err != nil {
		t.Errorf("relative directory: %v", err)
	}
	if err := os.Symlink("sub", "link"); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	for _, name := range []string{"file", "link"} {
		err := checkSpecDir(name)
		want := name + ": spec dir must be a directory, not a symlink or file"
		if err == nil || err.Error() != want {
			t.Errorf("%s: err %v, want %q", name, err, want)
		}
	}
	err := checkSpecDir("absent")
	if !errors.Is(err, fs.ErrNotExist) || strings.Contains(err.Error(), "must be a directory") {
		t.Fatalf("missing directory: err %v", err)
	}
	if !strings.HasPrefix(err.Error(), "absent: ") {
		t.Errorf("missing directory: %q does not start with the name", err)
	}
}

// A file that grows or shrinks between the open and the read is refused.
func TestTS23FileChangedDuringReadIsRefused(t *testing.T) {
	for name, change := range map[string]func(path string) error{
		"grow": func(path string) error {
			f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
			if err != nil {
				return err
			}
			_, err = f.WriteString("more\n")
			return errors.Join(err, f.Close())
		},
		"shrink": func(path string) error { return os.Truncate(path, 2) },
	} {
		dir := t.TempDir()
		writeFile(t, dir, "f", "some text\n")
		path := filepath.Join(dir, "f")
		setBeforeRead(t, func() {
			if err := change(path); err != nil {
				t.Error(err)
			}
		})
		_, err := readCapped(path)
		if !errors.Is(err, errNotRegular) {
			t.Errorf("%s: err %v, want errNotRegular", name, err)
		}
		if got := readFinding("x", err); got != "x: not a regular file" {
			t.Errorf("%s: finding %q", name, got)
		}
	}
}

func TestTS23GrowPastCapDuringReadIsTooLarge(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "f", strings.Repeat("a", maxFileBytes))
	path := filepath.Join(dir, "f")
	setBeforeRead(t, func() {
		if err := os.WriteFile(path, bytes.Repeat([]byte("a"), maxFileBytes+1), 0o644); err != nil {
			t.Error(err)
		}
	})
	_, err := readCapped(path)
	if !errors.Is(err, errTooLarge) {
		t.Errorf("err %v, want errTooLarge", err)
	}
}

// setBeforeRead sets the test hook of readCapped. The test cleanup removes it.
func setBeforeRead(t testing.TB, hook func()) {
	t.Helper()
	beforeRead = hook
	t.Cleanup(func() { beforeRead = nil })
}

// symlinkedCwd makes the tree below and returns the paths. The tree is
// base/r/repo/spec (a directory), base/r/repo/spec/f.md (a file), and
// base/h/L, a symlink to base/r/repo. Only link is a symlink.
func symlinkedCwd(t *testing.T) (base, link string) {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	spec := filepath.Join(base, "r", "repo", "spec")
	if err := os.MkdirAll(spec, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(base, "h"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, spec, "f.md", "text\n")
	link = filepath.Join(base, "h", "L")
	if err := os.Symlink(filepath.Join(base, "r", "repo"), link); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	return base, link
}

// The working directory was entered through a symlink: $PWD names the link.
// A relative path starts at the real directory, as in the kernel.
func TestRelativePathInSymlinkedWorkingDirectory(t *testing.T) {
	_, link := symlinkedCwd(t)
	t.Chdir(link)
	if got, err := readCapped("spec/f.md"); err != nil || string(got) != "text\n" {
		t.Errorf("readCapped: %q, err %v", got, err)
	}
	for _, dir := range []string{".", "spec"} {
		if err := checkSpecDir(dir); err != nil {
			t.Errorf("checkSpecDir(%q): %v", dir, err)
		}
	}
}

// A ".." after a symlinked working directory names the parent of the real
// directory, not the parent of the link.
func TestDotDotAfterSymlinkedWorkingDirectory(t *testing.T) {
	base, link := symlinkedCwd(t)
	t.Chdir(link)
	if err := checkSpecDir("../repo/spec"); err != nil {
		t.Errorf("checkSpecDir: %v", err)
	}
	if got, err := readCapped("../repo/spec/f.md"); err != nil || string(got) != "text\n" {
		t.Errorf("readCapped: %q, err %v", got, err)
	}
	if got, err := absPath("../x"); err != nil || got != filepath.Join(base, "r", "x") {
		t.Errorf("absPath: %q, err %v", got, err)
	}
}

// absPath resolves a ".." after a symlink in the argument on disk. It does
// not resolve a symlink at any other part of a relative path.
func TestDotDotAfterSymlinkInPath(t *testing.T) {
	base, _ := symlinkedCwd(t)
	h := filepath.Join(base, "h")
	writeFile(t, h, "spec", "a file, not the spec directory")
	t.Chdir(h)
	if err := checkSpecDir("L/../repo/spec"); err != nil {
		t.Errorf("checkSpecDir: %v", err)
	}
	for path, want := range map[string]string{
		"L/..":           filepath.Join(base, "r"),
		"L/../":          filepath.Join(base, "r"),
		"L/../repo/spec": filepath.Join(base, "r", "repo", "spec"),
		"L/./..":         filepath.Join(base, "r"),
		"L/../../h/L":    filepath.Join(base, "h", "L"),
		"../h/L":         filepath.Join(base, "h", "L"),
		"spec":           filepath.Join(h, "spec"),
		"L/spec":         filepath.Join(h, "L", "spec"), // L stays a link
		".":              h,
		h + "/L/../repo": filepath.Join(h, "repo"), // text clean only
	} {
		if got, err := absPath(path); err != nil || got != want {
			t.Errorf("absPath(%q) = %q, err %v, want %q", path, got, err, want)
		}
	}
	if _, err := absPath("absent/../spec"); err == nil {
		t.Error("absPath of a missing directory with ..: want an error")
	}
	if got, err := absPath("/a/../b/"); err != nil || got != "/b" {
		t.Errorf("absolute path: %q, err %v", got, err)
	}
}

// The last named part of the argument is never resolved. A trailing "/"
// or "/." does not change that, with or without a ".." before it.
func TestCheckSpecDirLastNamedPartIsNotResolved(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"spec", "a"} {
		if err := os.Mkdir(filepath.Join(dir, name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("spec", filepath.Join(dir, "slink")); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	t.Chdir(dir)
	for _, name := range []string{"slink/", "slink/.", "a/../slink/", "a/../slink/."} {
		err := checkSpecDir(name)
		want := name + ": spec dir must be a directory, not a symlink or file"
		if err == nil || err.Error() != want {
			t.Errorf("%s: err %v, want %q", name, err, want)
		}
	}
	for _, name := range []string{"spec/", "spec/.", ".", "a/../spec"} {
		if err := checkSpecDir(name); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// An error from absPath starts with the argument, like the other errors
// of checkSpecDir.
func TestCheckSpecDirAbsPathErrorsCarryTheName(t *testing.T) {
	t.Chdir(t.TempDir())
	if _, err := absPath(""); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("absPath of an empty path: err %v, want ErrNotExist", err)
	}
	for name, want := range map[string]string{
		"":                  ": no such file or directory",
		"absent/../spec":    "absent/../spec: ",
		"absent/../spec///": "absent/../spec///: ",
	} {
		err := checkSpecDir(name)
		if err == nil || !errors.Is(err, fs.ErrNotExist) || !strings.HasPrefix(err.Error(), want) {
			t.Errorf("checkSpecDir(%q): err %v, want the prefix %q and ErrNotExist", name, err, want)
		}
	}
}
