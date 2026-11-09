package main

import (
	"syscall"
	"testing"
)

// tmpfsMagic is the filesystem type number of tmpfs in statfs(2).
const tmpfsMagic = 0x01021994

// requireTmpfs stops the test if dir is not on a memory filesystem. A missing
// directory or another type is an error, so a run cannot skip the check.
func requireTmpfs(t *testing.T, dir string) {
	t.Helper()
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		t.Fatalf("the memory filesystem %s is missing; the 250 ms test needs it", dir)
	}
	if int64(st.Type) != tmpfsMagic {
		t.Fatalf("%s is not a tmpfs; the 250 ms test needs a memory filesystem", dir)
	}
}
