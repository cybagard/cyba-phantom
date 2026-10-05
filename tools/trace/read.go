// Read: safe input handling for spec files. Spec content and file names
// are PR-controlled, so the tool reads only regular files under a size
// cap, and a finding names a file only if the tool itself knows the name.

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
)

var (
	// errNotRegular rejects symlinks, devices, FIFOs, and directories.
	errNotRegular = errors.New("not a regular file")
	// errTooLarge rejects a file over maxFileBytes.
	errTooLarge = errors.New("over the size cap")
)

// knownSpecFiles are the only file names a finding prints. Every other
// name is PR-controlled text and shows as a short hash.
var knownSpecFiles = map[string]bool{
	"01-prd.md": true, "07-test-plan.md": true, "08-traceability.md": true,
	"README.md": true, "constitution-table.md": true, "manifest.json": true,
}

// readCapped reads a regular file of at most maxFileBytes. It does not
// follow symlinks: the file it opens must be the file it checked, and the
// open does not block on a FIFO swapped in between.
func readCapped(path string) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() {
		return nil, errNotRegular
	}
	f, err := openNoBlock(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	after, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !after.Mode().IsRegular() || !os.SameFile(before, after) {
		return nil, errNotRegular // replaced between the check and the open
	}
	data, err := io.ReadAll(io.LimitReader(f, maxFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxFileBytes {
		return nil, errTooLarge
	}
	return data, nil
}

// readFinding turns a rejected read into a finding. It returns "" for
// any other error, which the caller handles.
func readFinding(name string, err error) string {
	switch {
	case errors.Is(err, errNotRegular):
		return fmt.Sprintf("%s: not a regular file", name)
	case errors.Is(err, errTooLarge):
		return fmt.Sprintf("%s: exceeds the %d byte cap", name, maxFileBytes)
	}
	return ""
}

// checkSpecDir requires specDir to be a real directory, not a symlink.
func checkSpecDir(specDir string) error {
	fi, err := os.Lstat(specDir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return errors.New(specDir + ": spec dir must be a directory, not a symlink or file")
	}
	return nil
}

// printableName returns a known spec file name as is. Any other name
// shows as "unlisted file <hash>": a finding never carries PR text.
func printableName(name string) string {
	if knownSpecFiles[name] {
		return name
	}
	sum := sha256.Sum256([]byte(name))
	return "unlisted file " + hex.EncodeToString(sum[:4])
}
