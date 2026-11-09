//go:build !linux

package main

import "testing"

// requireTmpfs skips the test. Only Linux has the memory filesystem that the
// 250 ms test needs.
func requireTmpfs(t *testing.T, _ string) {
	t.Helper()
	t.Skip("the 250 ms test needs a tmpfs state directory; only Linux has /dev/shm")
}
