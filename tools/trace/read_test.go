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
		if err == nil || !strings.Contains(err.Error(), "spec dir must be a directory") {
			t.Errorf("%s: err %v", name, err)
		}
	}
	err := checkSpecDir("absent")
	if !errors.Is(err, fs.ErrNotExist) || strings.Contains(err.Error(), "must be a directory") {
		t.Errorf("missing directory: err %v", err)
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
		beforeRead = func() {
			if err := change(path); err != nil {
				t.Error(err)
			}
		}
		_, err := readCapped(path)
		beforeRead = nil
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
	beforeRead = func() {
		if err := os.WriteFile(path, bytes.Repeat([]byte("a"), maxFileBytes+1), 0o644); err != nil {
			t.Error(err)
		}
	}
	_, err := readCapped(path)
	beforeRead = nil
	if !errors.Is(err, errTooLarge) {
		t.Errorf("err %v, want errTooLarge", err)
	}
}
