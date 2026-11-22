//go:build unix

package safefile

import "os"

// Rename renames the file from to the name to, in the directory of root. Each
// name is one name in that directory. An empty name, ".", "..", or a name with
// a slash gives ErrName, and nothing is renamed. A nil root gives ErrRule. A
// link at the name to is replaced. Rename never follows it.
//
// Rename runs one Step "rename" with the name from, then root.Rename. Each
// error other than seam.Crash is a *WriteError with the step ErrRename and no
// path, so it matches ErrMayBeRenamed. A hook error fails the step, and nothing
// is renamed. seam.Crash returns at once, and nothing is renamed. Rename does
// not sync the directory. The caller calls SyncDir.
func Rename(root *os.Root, from, to string) error {
	if root == nil {
		return fail(ErrRule, nil)
	}
	for _, name := range []string{from, to} {
		if ps, ok := parts(name); !ok || len(ps) != 1 {
			return fail(ErrName, nil)
		}
	}
	return runStep(hooks(), "rename", from, false, func() error {
		return root.Rename(from, to)
	})
}
