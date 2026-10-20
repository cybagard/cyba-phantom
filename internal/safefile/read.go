//go:build unix

package safefile

import (
	"io"
	"io/fs"
	"math"
	"os"
	"strings"

	"github.com/cybagard/cyba-phantom/internal/safefile/internal/seam"
)

// hooks gives the active test hooks, or an empty set on the production path.
func hooks() *seam.Hooks {
	if h := seam.Current(); h != nil {
		return h
	}
	return &seam.Hooks{}
}

// readable is true for a rule that ReadAll accepts. The rule must be valid,
// for a regular file, and have a size cap.
func readable(r Rule) bool {
	return r.valid() && r.Type == Regular && r.MaxSize > 0
}

// ReadAll reads the open file f from the start of the file. The file f must be
// the open file of fi, and Open gave fi. ReadAll reads at most MaxSize + 1
// bytes. A file with more than MaxSize bytes gives ErrSize. A byte count that
// is not the size in fi gives ErrChanged. A file f that is not the file of fi
// gives ErrChanged. A file f that is not a regular file gives ErrType. A nil f
// or fi, or a rule that is not readable, gives ErrRule. A stat or read error
// gives ErrExamine. The caller closes f.
func ReadAll(f *os.File, fi fs.FileInfo, r Rule) ([]byte, error) {
	if f == nil || fi == nil || !readable(r) {
		return nil, fail(ErrRule, nil)
	}
	st, err := f.Stat()
	switch {
	case err != nil:
		return nil, fail(ErrExamine, err)
	case !st.Mode().IsRegular():
		return nil, fail(ErrType, nil)
	case !os.SameFile(st, fi):
		return nil, fail(ErrChanged, nil)
	}
	limit := r.MaxSize
	if limit < math.MaxInt64 {
		limit++
	}
	b, err := io.ReadAll(io.NewSectionReader(f, 0, limit))
	switch {
	case err != nil:
		return nil, fail(ErrExamine, err)
	case int64(len(b)) > r.MaxSize:
		return nil, fail(ErrSize, nil)
	case int64(len(b)) != fi.Size():
		return nil, fail(ErrChanged, nil)
	}
	return b, nil
}

// ReadFile opens name below root with Open, reads it with ReadAll, and closes
// it. It gives the errors of both.
func ReadFile(root *os.Root, name string, r Rule) ([]byte, error) {
	if !readable(r) {
		return nil, fail(ErrRule, nil)
	}
	f, fi, err := Open(root, name, r)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ReadAll(f, fi, r)
}

// Check applies the rule to name below root. It gives the Lstat result. It
// opens nothing, so a FIFO or a device at the name cannot block it. The name
// and the rule follow the same limits as for Open. The type rule and the whole
// rule run on the Lstat result. A symlink at the name gives ErrSymlink.
func Check(root *os.Root, name string, r Rule) (fs.FileInfo, error) {
	if root == nil || !r.valid() {
		return nil, fail(ErrRule, nil)
	}
	if name == "" || strings.Contains(name, "/") {
		return nil, fail(ErrName, nil)
	}
	li, err := root.Lstat(name)
	if err != nil {
		return nil, fail(ErrExamine, err)
	}
	if err := checkOpen(li, r, hooks()); err != nil {
		return nil, err
	}
	return li, nil
}
