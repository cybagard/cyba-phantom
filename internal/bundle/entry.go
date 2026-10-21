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
// Next maps type NUL to a regular file, or to a directory when the name ends
// in a slash. rawFormOK refuses the raw type byte NUL, so ReadArchive accepts
// only the raw types '0' and '5'. The checks, in this order:
//   - the format is ustar. A PAX header, a GNU header and a STAR header give
//     another format, so they fail here. A PAX header, a GNU long name header
//     and a GNU long link header fail in ReadArchive first. They fail the
//     limit maxKept or the byte count;
//   - the type is a regular file or a directory;
//   - the link name is empty;
//   - the name is local and has 1 to 8 parts. Each part has 1 to 64 bytes of
//     A-Z a-z 0-9 . _ - and is not "." or "..". A directory name loses one
//     trailing slash first. A file name keeps it, so its last part is empty;
//   - the first part is a top-level directory, or the name is the manifest
//     file. A directory cannot have the name manifest.json.
//
// The key is the name in lower case, which is ASCII after the checks. A file
// and a directory share it when they differ only in case or in the trailing
// slash.
func checkEntry(hdr *tar.Header) (string, error) {
	if hdr.Format != tar.FormatUSTAR {
		return "", ErrArchiveInvalid
	}
	isDir := hdr.Typeflag == tar.TypeDir
	if !isDir && hdr.Typeflag != tar.TypeReg {
		return "", ErrArchiveInvalid
	}
	if hdr.Linkname != "" {
		return "", ErrArchiveInvalid
	}
	name := hdr.Name
	if isDir {
		name = strings.TrimSuffix(name, "/")
	}
	if !filepath.IsLocal(name) {
		return "", ErrArchiveInvalid
	}
	parts := strings.SplitN(name, "/", maxNameParts+1)
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

// tree holds the keys that the entries so far give. A regular file must not be
// the parent of another entry. The archive can hold the child before or after
// the file, and it can omit the directory entries between them.
type tree struct {
	files   map[string]bool
	parents map[string]bool
}

// add records the entry with this key. It reports false when the entry and an
// earlier entry are a file and its child. A directory is a parent only.
func (t *tree) add(key string, isDir bool) bool {
	if !isDir && t.parents[key] {
		return false
	}
	for i := range len(key) {
		if key[i] != '/' {
			continue
		}
		if t.files[key[:i]] {
			return false
		}
		t.parents[key[:i]] = true
	}
	if !isDir {
		t.files[key] = true
	}
	return true
}

// validPart reports whether p has 1 to 64 bytes of A-Z a-z 0-9 . _ - and is
// not "." or "..".
func validPart(p string) bool {
	if p == "" || len(p) > maxPartBytes || p == "." || p == ".." {
		return false
	}
	for i := range len(p) {
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

// blockBytes is the size of one tar block.
const blockBytes = 512

// ustarSizeOK reports whether the size field of the header block b has the
// canonical form. tar.Writer, GNU tar and Python write 11 octal digits and one
// NUL.
func ustarSizeOK(b []byte) bool {
	f := b[124:136]
	for _, c := range f[:11] {
		if c < '0' || c > '7' {
			return false
		}
	}
	return f[11] == 0
}

// chksumOK reports whether the checksum field of the header block b has the
// form that tar.Writer, GNU tar and Python write: 6 octal digits, one NUL and
// one space. archive/tar checks the value of the field.
func chksumOK(b []byte) bool {
	f := b[148:156]
	for _, c := range f[:6] {
		if c < '0' || c > '7' {
			return false
		}
	}
	return f[6] == 0 && f[7] == ' '
}

// rawFormOK checks the header block b of an entry. It runs only after the byte
// count of ReadArchive has passed, so b is the last block that Next read. The
// checks:
//   - the type byte is '0' (file) or '5' (directory). The three writers write
//     these bytes. Type NUL is refused in every form, because Python reads it
//     as a file when a ustar prefix is present;
//   - the checksum field has the form of chksumOK;
//   - the size field has the canonical form.
func rawFormOK(b []byte) bool {
	if t := b[156]; t != tar.TypeReg && t != tar.TypeDir {
		return false
	}
	return chksumOK(b) && ustarSizeOK(b)
}
