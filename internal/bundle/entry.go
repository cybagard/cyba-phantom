package bundle

import (
	"archive/tar"
	"path/filepath"
	"slices"
	"strings"
)

// The name rules of an entry (SEC-23).
const (
	maxNameParts = 8
	maxPartBytes = 64
	manifestName = "manifest.json"
)

// topLevelDirs are the first name parts that an entry may have, besides the
// manifest file.
var topLevelDirs = []string{"vhosts", "traps", "fp", "score", "secrets"}

// checkEntry checks the header that Next of archive/tar returns. It returns
// the key that two entries must not share, or ErrArchiveInvalid.
//
// Next has applied the GNU long name and long link headers and the PAX path
// record to the header, and it has mapped type NUL to a regular file, or to a
// directory when the name ends in a slash. checkEntry checks that final form.
// The checks, in this order:
//   - the type is a regular file or a directory;
//   - the link name is empty;
//   - each PAX record is a path, a size or an mtime record;
//   - the name is local and has 1 to 8 parts. Each part has 1 to 64 bytes of
//     A-Z a-z 0-9 . _ - and is not "." or "..". A directory loses one trailing
//     slash first, so that a file with a trailing slash has an empty part;
//   - the first part is a top-level directory, or the name is the manifest
//     file. A directory has no manifest form.
//
// The key is the name in lower case, which is ASCII after the checks. A file
// and a directory share it when they differ only in case or in the trailing
// slash.
func checkEntry(hdr *tar.Header) (string, error) {
	isDir := hdr.Typeflag == tar.TypeDir
	if !isDir && hdr.Typeflag != tar.TypeReg {
		return "", ErrArchiveInvalid
	}
	if hdr.Linkname != "" {
		return "", ErrArchiveInvalid
	}
	for key := range hdr.PAXRecords {
		switch key {
		case "path", "size", "mtime":
		default:
			return "", ErrArchiveInvalid
		}
	}
	name := hdr.Name
	if isDir {
		name = strings.TrimSuffix(name, "/")
	}
	if !filepath.IsLocal(name) {
		return "", ErrArchiveInvalid
	}
	parts := strings.Split(name, "/")
	if len(parts) > maxNameParts {
		return "", ErrArchiveInvalid
	}
	for _, p := range parts {
		if !validPart(p) {
			return "", ErrArchiveInvalid
		}
	}
	if !isDir && len(parts) == 1 {
		if name != manifestName {
			return "", ErrArchiveInvalid
		}
	} else if !slices.Contains(topLevelDirs, parts[0]) {
		return "", ErrArchiveInvalid
	}
	return strings.ToLower(name), nil
}

// validPart reports whether p has 1 to 64 bytes of A-Z a-z 0-9 . _ - and is
// not "." or "..".
func validPart(p string) bool {
	if p == "" || len(p) > maxPartBytes || p == "." || p == ".." {
		return false
	}
	for i := 0; i < len(p); i++ {
		c := p[i]
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		case c == '.', c == '_', c == '-':
		default:
			return false
		}
	}
	return true
}
