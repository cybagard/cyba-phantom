//go:build unix

package store

import (
	"os"
	"path/filepath"
	"testing"
)

// T-U-18: the real disk space reads the size of the database file and the space
// of its file system through the state root. A file that is not there fails.
func TestTU18SystemDiskSpace(t *testing.T) {
	root, state, _ := newState(t)
	if err := os.WriteFile(filepath.Join(state, "events.db"), make([]byte, 5000), 0o600); err != nil {
		t.Fatal(err)
	}
	size, fsSize, free, ok := systemDiskSpace(root, "events.db")
	if !ok || size != 5000 || fsSize == 0 || free > fsSize {
		t.Fatalf("size %d, file system %d, free %d, ok %v", size, fsSize, free, ok)
	}
	if _, _, _, ok := systemDiskSpace(root, "missing.db"); ok {
		t.Fatal("a missing file gave a size")
	}
}
