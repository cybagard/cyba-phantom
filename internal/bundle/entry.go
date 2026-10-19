package bundle

import (
	"archive/tar"
	"bytes"
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
// in a slash. rawFormOK refuses the raw type byte NUL, so ReadArchive accepts
// only the raw types '0' and '5'. Next also applies a PAX path record to the
// name. checkEntry checks that final form. The checks, in this order:
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
	for key, value := range hdr.PAXRecords {
		switch key {
		case "path", "size", "mtime":
		default:
			return "", ErrArchiveInvalid
		}
		// Next ignores a record with an empty value. Python reads an empty path
		// as the name and an empty size as 0. GNU tar fails on an empty mtime or
		// size.
		if value == "" {
			return "", ErrArchiveInvalid
		}
		if key == "mtime" && !paxTimeOK(value) {
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

// paxTimeOK reports whether v has the form of a PAX mtime value: an optional
// "-", one or more digits, and optionally "." and one or more digits. GNU tar
// fails on a value with a plus sign.
func paxTimeOK(v string) bool {
	v = strings.TrimPrefix(v, "-")
	whole, frac, dot := strings.Cut(v, ".")
	return digits(whole) && (!dot || digits(frac))
}

// digits reports whether s has one or more bytes, all of them 0-9.
func digits(s string) bool {
	if s == "" {
		return false
	}
	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
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

// headerBytes returns the number of decoded bytes that one Next call reads for
// an entry with one header block and at most one PAX header. prevPad is the
// padding of the previous entry. A PAX header adds one block and the padded
// records in canonical form.
func headerBytes(prevPad int64, hdr *tar.Header) int64 {
	n := prevPad + blockBytes
	if len(hdr.PAXRecords) == 0 {
		return n
	}
	return n + blockBytes + (paxBytes(hdr)+blockBytes-1)/blockBytes*blockBytes
}

// paxBytes returns the sum of the canonical lengths of the PAX records.
func paxBytes(hdr *tar.Header) int64 {
	var records int64
	for k, v := range hdr.PAXRecords {
		records += int64(paxRecordLen(k, v))
	}
	return records
}

// maxCut is the length of the ustar name field. A reader that does not read
// PAX records sees only the first maxCut bytes of a longer PAX path.
const maxCut = 100

// ustarSeenKey returns the key of the name that a reader without PAX support
// sees: the cut of a long PAX path, or else the final name. The key has the
// form of the key that checkEntry returns: lower case, with one trailing slash
// removed from the cut or from the name.
func ustarSeenKey(hdr *tar.Header) string {
	name := hdr.Name
	if p := hdr.PAXRecords["path"]; len(p) > maxCut {
		name = p[:maxCut]
	}
	return strings.ToLower(strings.TrimSuffix(name, "/"))
}

// ustarSize returns the value of the size field of the header block b. The
// field must have the form that tar.Writer, GNU tar and Python write: 11 octal
// digits and one NUL.
func ustarSize(b []byte) (int64, bool) {
	f := b[124:136]
	var n int64
	for _, c := range f[:11] {
		if c < '0' || c > '7' {
			return 0, false
		}
		n = n*8 + int64(c-'0')
	}
	if f[11] != 0 {
		return 0, false
	}
	return n, true
}

// zeroed reports whether b holds only zero bytes.
func zeroed(b []byte) bool { return len(bytes.TrimLeft(b, "\x00")) == 0 }

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

// rawFormOK checks the bytes k that the Next call of hdr read. It runs only
// after the byte count of headerBytes has passed. The layout of k is then
// fixed: the padding of the previous entry, a PAX header with its records when
// hdr has PAX records, and the header block of the entry. The checks:
//   - the type byte of the entry is '0' (file) or '5' (directory). The three
//     writers write these bytes. Type NUL is refused in every form, because
//     Python reads it as a file when a PAX header or a ustar prefix is present;
//   - the checksum field of each header block has the form of chksumOK;
//   - the size field of each header block has the canonical form;
//   - the size of the PAX header is the sum of the canonical record lengths,
//     and the bytes after the records are zero. A repeated key or a record
//     length with a leading zero makes the sum smaller;
//   - a PAX size record has decimal digits only, with no sign and no leading
//     zero, and its value is the value of the size field of the entry;
//   - with a PAX path record, the prefix field is zero and the name field is
//     the path, or the first 100 bytes of it, with NUL padding.
func rawFormOK(k []byte, pad int64, hdr *tar.Header) bool {
	entry := k[len(k)-blockBytes:]
	if t := entry[156]; t != tar.TypeReg && t != tar.TypeDir {
		return false
	}
	if !chksumOK(entry) {
		return false
	}
	size, ok := ustarSize(entry)
	if !ok {
		return false
	}
	if len(hdr.PAXRecords) > 0 {
		x := k[pad : pad+blockBytes]
		if !chksumOK(x) {
			return false
		}
		recs := k[pad+blockBytes : len(k)-blockBytes]
		// A size field in another form gives 0, which is not the sum.
		n, _ := ustarSize(x)
		if n != paxBytes(hdr) || !zeroed(recs[n:]) {
			return false
		}
	}
	if s, ok := hdr.PAXRecords["size"]; ok {
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil || strconv.FormatInt(n, 10) != s || n != size {
			return false
		}
	}
	if p, ok := hdr.PAXRecords["path"]; ok {
		p = p[:min(len(p), maxCut)]
		return zeroed(entry[345:500]) && string(entry[:len(p)]) == p && zeroed(entry[len(p):maxCut])
	}
	return true
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
