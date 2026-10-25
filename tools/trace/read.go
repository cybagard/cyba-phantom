// Read: safe input handling for spec files. Spec content and file names
// are PR-controlled, so the tool reads only regular files under a size
// cap, and a finding names a file only if the tool itself knows the name.

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/cybagard/cyba-phantom/internal/safefile"
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
	"01-prd.md": true, "04-interfaces.md": true, "07-test-plan.md": true, "08-traceability.md": true,
	"README.md": true, "constitution-table.md": true, "manifest.json": true,
}

var (
	// fileRule is the rule for a spec file or a source file. It needs a
	// regular file of at most maxFileBytes. Owner and mode do not matter.
	fileRule = safefile.Rule{Type: safefile.Regular, Owner: safefile.OwnerAny, MaxSize: maxFileBytes}
	// dirRule is the rule for the spec directory and the tree root.
	dirRule = safefile.Rule{Type: safefile.Dir, Owner: safefile.OwnerAny}
)

// beforeRead is nil in production. A test sets it to change a file between
// the open and the read.
var beforeRead func()

// readCapped reads a regular file of at most maxFileBytes. It does not
// follow symlinks. The file it opens must be the file it checked. The open
// does not block on a FIFO swapped in between. A file that changes size
// during the read is refused.
func readCapped(path string) ([]byte, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	f, fi, err := safefile.OpenPath(abs, fileRule)
	if err != nil {
		return nil, readError(err)
	}
	defer f.Close()
	if beforeRead != nil {
		beforeRead()
	}
	data, err := safefile.ReadAll(f, fi, fileRule)
	if err != nil {
		return nil, readError(err)
	}
	return data, nil
}

// readError maps a safefile refusal to the errors that readFinding knows.
// Any other error stays as it is.
func readError(err error) error {
	switch {
	case errors.Is(err, safefile.ErrSymlink),
		errors.Is(err, safefile.ErrType),
		errors.Is(err, safefile.ErrChanged):
		return errNotRegular
	case errors.Is(err, safefile.ErrSize):
		return errTooLarge
	}
	return err
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
	abs, err := filepath.Abs(specDir)
	if err != nil {
		return err
	}
	f, _, err := safefile.OpenPath(abs, dirRule)
	switch {
	case errors.Is(err, safefile.ErrSymlink), errors.Is(err, safefile.ErrType):
		return errors.New(specDir + ": spec dir must be a directory, not a symlink or file")
	case err != nil:
		return fmt.Errorf("%s: %w", specDir, err)
	}
	return f.Close()
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
