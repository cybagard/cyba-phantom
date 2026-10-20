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

// Identity gives false: this system has no device and inode.
func Identity(fi fs.FileInfo) (FileID, bool) { return FileID{}, false }
