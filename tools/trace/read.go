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
	"strings"
	"syscall"

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

// beforeRead is nil in production. A test sets it, through setBeforeRead,
// to change a file between the open and the read.
var beforeRead func()

// absPath makes path absolute. A relative path starts at the working
// directory of the kernel: syscall.Getwd does not read $PWD. The function
// resolves a ".." after a name on disk, so a symlink before it counts. It
// removes each trailing "/" and "/." part, and then it does not resolve
// the last part. A final ".." resolves the name before it. An absolute
// path is only cleaned. An empty path is an error.
func absPath(path string) (string, error) {
	if path == "" {
		return "", syscall.ENOENT
	}
	if filepath.IsAbs(path) {
		return filepath.Clean(path), nil
	}
	wd, err := syscall.Getwd()
	if err != nil {
		return "", err
	}
	path = trimDirSuffix(path)
	if !hasInnerDotDot(path) {
		return filepath.Join(wd, path), nil
	}
	dir, last := filepath.Split(wd + string(filepath.Separator) + path)
	dir, err = filepath.EvalSymlinks(dir)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, last), nil
}

// trimDirSuffix removes each "/" and "/." part at the end of a relative
// path. A path of dots only, such as ".", stays as it is.
func trimDirSuffix(path string) string {
	for {
		switch {
		case len(path) > 1 && strings.HasSuffix(path, "/"):
			path = path[:len(path)-1]
		case strings.HasSuffix(path, "/."):
			path = path[:len(path)-2]
		default:
			return path
		}
	}
}

// hasInnerDotDot reports whether path has a ".." after a name.
func hasInnerDotDot(path string) bool {
	named := false
	for _, part := range strings.Split(filepath.ToSlash(path), "/") {
		switch part {
		case "", ".":
		case "..":
			if named {
				return true
			}
		default:
			named = true
		}
	}
	return false
}

// readCapped reads a regular file of at most maxFileBytes. It does not
// follow a symlink at the last part. The file it opens must be the file it
// checked. The open does not block on a FIFO swapped in between. It
// refuses a file that changes size during the read.
func readCapped(path string) ([]byte, error) {
	abs, err := absPath(path)
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

// checkSpecDir requires specDir to name a real directory. It refuses a
// symlink at the last part, also with a trailing "/" or "/.". A final ".."
// resolves the part before it. In an absolute path, it does not resolve a
// ".." after a symlink: it only cleans the path.
func checkSpecDir(specDir string) error {
	abs, err := absPath(specDir)
	if err != nil {
		return fmt.Errorf("%s: %w", specDir, err)
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
