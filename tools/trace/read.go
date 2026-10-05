// Read: safe input handling for spec files. Spec content and file names
// are PR-controlled, so the tool reads only regular files under a size
// cap and prints only names that pass an allow-list.

package main

import (
	"errors"
	"io"
	"os"
	"regexp"
)

var (
	// errNotRegular rejects symlinks, devices, FIFOs, and directories.
	errNotRegular = errors.New("not a regular file")
	// errTooLarge rejects a file over maxFileBytes.
	errTooLarge = errors.New("over the size cap")

	// printableNameRE is the allow-list for a file name in a finding.
	printableNameRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
	// syncDateRE is the only accepted form of the manifest sync date.
	syncDateRE = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
)

// readCapped reads a regular file of at most maxFileBytes. It does not
// follow symlinks: the file it opens must be the file it checked.
func readCapped(path string) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() {
		return nil, errNotRegular
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	after, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(before, after) {
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

// printableName returns name if it passes the allow-list, else a fixed
// placeholder. Findings never carry a name that could hold prose.
func printableName(name string) string {
	if printableNameRE.MatchString(name) {
		return name
	}
	return "<file name not shown: outside [A-Za-z0-9._-]{1,64}>"
}
