package bundle

import (
	"archive/tar"
	"path/filepath"
	"slices"
	"strconv"
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
// in a slash. Next also applies a PAX path record to the name. checkEntry
// checks that final form. The checks, in this order:
//   - the format is ustar or PAX. A GNU header and a STAR header give another
//     format, so they fail here. A GNU long name or long link header fails the
//     byte count of ReadArchive first;
//   - the type is a regular file or a directory;
//   - the link name is empty;
//   - each PAX record is a path, a size or an mtime record;
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
	if hdr.Format != tar.FormatUSTAR && hdr.Format != tar.FormatPAX {
		return "", ErrArchiveInvalid
	}
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

// headerBytes returns the number of decoded bytes that one Next call reads for
// an entry with one header block and at most one PAX header. prevPad is the
// padding of the previous entry. A PAX header adds one block and the padded
// records in canonical form.
func headerBytes(prevPad int64, hdr *tar.Header) int64 {
	n := prevPad + blockBytes
	if len(hdr.PAXRecords) == 0 {
		return n
	}
	var records int64
	for k, v := range hdr.PAXRecords {
		records += int64(paxRecordLen(k, v))
	}
	return n + blockBytes + (records+blockBytes-1)/blockBytes*blockBytes
}

// paxRecordLen returns the length of the PAX record "<n> <key>=<value>\n" in
// canonical form. The decimal number n is the length of the whole line, with
// no leading zero.
func paxRecordLen(key, value string) int {
	rest := len(key) + len(value) + 3
	n := rest + len(strconv.Itoa(rest))
	if m := rest + len(strconv.Itoa(n)); m != n {
		n = m
	}
	return n
}
