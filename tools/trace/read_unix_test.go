//go:build unix && !aix && !solaris

package main

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/cybagard/cyba-phantom/internal/safefile/safefiletest"
)

func TestTS23FIFOSpecFileIsFinding(t *testing.T) {
	dir := newSpec(t)
	path := filepath.Join(dir, "07-test-plan.md")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skip("mkfifo:", err)
	}
	wantFinding(t, dir, "07-test-plan.md: not a regular file")
	if _, err := readCapped(path); !errors.Is(err, errNotRegular) {
		t.Errorf("readCapped: err %v, want errNotRegular", err)
	}
}

// A file replaced between the check and the open gives the same finding.
func TestTS23SwapAfterCheckIsNotRegular(t *testing.T) {
	for _, kind := range []string{"file", "fifo"} {
		t.Run(kind, func(t *testing.T) { swapAfterCheck(t, kind) })
	}
}

func swapAfterCheck(t *testing.T, kind string) {
	dir := t.TempDir()
	writeFile(t, dir, "f", "old\n")
	writeFile(t, dir, "other", "new\n")
	swapped := false
	safefiletest.Set(t, safefiletest.Hooks{AfterCheck: func(name string) {
		swapped = true
		if kind == "file" {
			if err := os.Rename(filepath.Join(dir, "other"), name); err != nil {
				t.Error(err)
			}
			return
		}
		if err := os.Remove(name); err != nil {
			t.Error(err)
		}
		if err := syscall.Mkfifo(name, 0o600); err != nil {
			t.Error(err)
		}
	}})
	_, err := readCapped(filepath.Join(dir, "f"))
	if !swapped {
		t.Fatal("the hook did not run")
	}
	if got := readFinding("f", err); got != "f: not a regular file" {
		t.Errorf("finding %q, err %v", got, err)
	}
}

// openFDs counts the open file descriptors of this process.
func openFDs(t *testing.T) int {
	t.Helper()
	ents, err := os.ReadDir("/dev/fd")
	if err != nil {
		t.Skip("no /dev/fd:", err)
	}
	return len(ents)
}

func TestReadCappedAndCheckSpecDirCloseTheirFiles(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "f", "x")
	before := openFDs(t)
	for i := 0; i < 5; i++ {
		if _, err := readCapped(filepath.Join(dir, "f")); err != nil {
			t.Fatal(err)
		}
		if err := checkSpecDir(dir); err != nil {
			t.Fatal(err)
		}
	}
	if after := openFDs(t); after != before {
		t.Errorf("open descriptors: %d before, %d after", before, after)
	}
}

// The rule has no owner, mode or link-count check. A spec file may have
// another owner, be group-writable, or have a second link.
func TestReadCappedAppliesNoOwnerModeOrLinkRule(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f")
	writeFile(t, dir, "f", "x")
	if err := os.Chmod(path, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(path, filepath.Join(dir, "second")); err != nil {
		t.Skip("hard links unavailable:", err)
	}
	if _, err := readCapped(path); err != nil {
		t.Errorf("mode 0777 with two links: %v", err)
	}
	st, err := os.Stat("/etc/passwd")
	if err != nil || os.Getuid() == 0 {
		t.Skip("no foreign-owned file to read")
	}
	if owner, ok := st.Sys().(*syscall.Stat_t); !ok || int(owner.Uid) == os.Getuid() {
		t.Skip("/etc/passwd has the same owner")
	}
	if _, err := readCapped("/etc/passwd"); err != nil {
		t.Errorf("file of another owner: %v", err)
	}
}
