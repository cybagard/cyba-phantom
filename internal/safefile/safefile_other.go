//go:build !unix

package safefile

import (
	"io/fs"
	"os"
)

// Open fails closed: this system has no checked open.
func Open(root *os.Root, name string, r Rule) (*os.File, fs.FileInfo, error) {
	return nil, nil, fail(ErrUnsupported, nil)
}

// ReadAll fails closed: this system has no checked read.
func ReadAll(f *os.File, fi fs.FileInfo, r Rule) ([]byte, error) {
	return nil, fail(ErrUnsupported, nil)
}

// ReadFile fails closed: this system has no checked read.
func ReadFile(root *os.Root, name string, r Rule) ([]byte, error) {
	return nil, fail(ErrUnsupported, nil)
}

// Check fails closed: this system has no checked Lstat.
func Check(root *os.Root, name string, r Rule) (fs.FileInfo, error) {
	return nil, fail(ErrUnsupported, nil)
}

// OpenRoot fails closed: this system has no checked walk.
func OpenRoot(root *os.Root, name string, dir Rule) (*os.Root, error) {
	return nil, fail(ErrUnsupported, nil)
}

// CheckParents fails closed: this system has no checked walk.
func CheckParents(root *os.Root, name string, dir Rule) error {
	return fail(ErrUnsupported, nil)
}

// OpenPath fails closed: this system has no checked open.
func OpenPath(path string, r Rule) (*os.File, fs.FileInfo, error) {
	return nil, nil, fail(ErrUnsupported, nil)
}

// CheckPathParents fails closed: this system has no checked walk.
func CheckPathParents(path string, dir Rule) error {
	return fail(ErrUnsupported, nil)
}

// Identity gives false: this system has no device and inode.
func Identity(fi fs.FileInfo) (FileID, bool) { return FileID{}, false }
