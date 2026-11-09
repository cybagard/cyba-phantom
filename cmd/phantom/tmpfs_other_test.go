//go:build !linux

package main

import "testing"

// requireTmpfs skips the test. The check runs only on Linux. On other systems
// the test skips.
func requireTmpfs(t *testing.T, _ string) {
	t.Helper()
	t.Skip("the 250 ms test needs a tmpfs state directory; it runs only on Linux")
}
