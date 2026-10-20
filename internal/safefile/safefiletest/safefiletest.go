// Package safefiletest lets a test set the hooks of package safefile.
package safefiletest

import (
	"testing"

	"github.com/cybagard/cyba-phantom/internal/safefile/internal/seam"
)

// Hooks is the set of test hooks of package safefile.
type Hooks = seam.Hooks

// Set installs h for t and removes it in t.Cleanup. It fails t when the
// binary is not a test binary or when a set is already active.
func Set(t testing.TB, h Hooks) {
	t.Helper()
	if !testing.Testing() {
		t.Fatalf("safefiletest: hooks are for test binaries only")
	}
	if !seam.Install(&h) {
		t.Fatalf("safefiletest: a hook set is already active")
	}
	t.Cleanup(func() { seam.Remove(&h) })
}
