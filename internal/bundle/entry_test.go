package bundle

import (
	"archive/tar"
	"bytes"
	"fmt"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// rawArchive makes the gzip bytes of the tar parts, with the end blocks.
func rawArchive(parts ...[]byte) []byte {
	return gz(append(bytes.Join(parts, nil), zeros(1024)...))
}

// rawFile makes the header and the data of a regular file.
func rawFile(name, data string) []byte {
	return append(rawHdr(name, tar.TypeReg, int64(len(data))), padded([]byte(data))...)
}

// rawLinkHdr makes a header with a link name, for the hard link case.
func rawLinkHdr(name string, typ byte, link string) []byte {
	h := rawHdr(name, typ, 0)
	copy(h[157:], link)
	return withSum(h)
}

// withMagic sets the magic and version field of the header block h.
func withMagic(h []byte, magic string) []byte {
	copy(h[257:265], magic)
	return withSum(h)
}

// withPrefix sets the ustar prefix field of the header block h.
func withPrefix(h []byte, prefix string) []byte {
	copy(h[345:500], prefix)
	return withSum(h)
}

// longHdr makes a GNU 'L' (long name) or 'K' (long link) header with its
// text. It has the GNU magic, as GNU tar writes it.
func longHdr(typ byte, text string) []byte {
	h := withMagic(rawHdr("long-header", typ, int64(len(text)+1)), "ustar  \x00")
	return append(h, padded([]byte(text+"\x00"))...)
}

// paxRecZeros makes a PAX record whose length field has leading zeros, so
// that the field is wider than the canonical form.
func paxRecZeros(key, value string) string {
	rest := " " + key + "=" + value + "\n"
	return fmt.Sprintf("%04d%s", len(rest)+4, rest)
}

// fullBlockMtime returns an mtime value so that a path record for path and
// the mtime record together fill exactly one block in canonical form.
func fullBlockMtime(path string) string {
	for d := 0; d < blockBytes; d++ {
		v := "1700000000." + strings.Repeat("1", d)
		if len(paxRec("path", path))+len(paxRec("mtime", v)) == blockBytes {
			return v
		}
	}
	panic("no mtime value fills one block")
}

// starHdr makes a STAR header with a prefix of 131 bytes, base-256 times and
// the STAR trailer. The ustar prefix field of the same block has 155 bytes.
func starHdr() []byte {
	h := rawHdr("manifest.json", tar.TypeReg, 1)
	copy(h[345:476], "traps/"+strings.Repeat("a", 60)+"/"+strings.Repeat("b", 64))
	times := []byte{0xff, 0xff, 0xff, 0xff, 0x80, '/', '.', '.', '/', '.', '.', '/'}
	copy(h[476:488], times)
	copy(h[488:500], times)
	copy(h[508:512], "tar\x00")
	return append(withSum(h), padded([]byte("S"))...)
}

// ustarTwinOfStar makes the block of starHdr with the ustar form: no trailer
// and zero times, so that the prefix field ends after 131 bytes.
func ustarTwinOfStar() []byte {
	h := starHdr()[:blockBytes]
	clear(h[476:500])
	clear(h[508:512])
	return append(withSum(h), padded([]byte("S"))...)
}

// globalHdr makes a PAX global header with the records.
func globalHdr(recs ...string) []byte {
	body := strings.Join(recs, "")
	return append(rawHdr("pax-global-header", tar.TypeXGlobalHeader, int64(len(body))), padded([]byte(body))...)
}

// entryCase is a refused archive and its passing twin. The twin changes the
// refused property, so that the bad archive fails from its own rule. The type
// cases use a regular file with the same name as the twin. The case "directory
// named like the manifest" also removes the trailing slash. A nil twin means
// that the refused form has no accepted form. The bundle archive has no PAX
// header, so most forms with a PAX header have a nil twin. Two have a ustar
// twin. They are "PAX header with no records" and "PAX path of a name that
// does not fit the ustar fields".
type entryCase struct {
	name      string
	bad, twin []byte
}

// longName makes a name of the given number of parts below traps, each part
// of partLen bytes.
func longName(parts, partLen int) string {
	p := strings.Repeat("a", partLen)
	return "traps/" + strings.Repeat(p+"/", parts-2) + p
}

// entryCases returns the refused entry forms. Most forms with a PAX header
// have a nil twin, and two have a ustar twin, as entryCase says. A few other
// forms have a nil twin.
func entryCases() []entryCase {
	const p = "traps/a"
	reg := func(names ...string) []byte {
		var ents []ent
		for _, n := range names {
			ents = append(ents, ent{name: n, data: []byte("x")})
		}
		return build(ents...)
	}
	typed := func(typ byte) []byte { return build(ent{name: p, typ: typ}) }
	dir := func(name string) ent { return ent{name: name, typ: tar.TypeDir} }
	file := func(name string) ent { return ent{name: name, data: []byte("x")} }
	same := reg(p)
	// The name has 460 bytes, so no ustar split fits. The twin has a name of
	// 110 bytes with a split.
	long := longName(8, 64)
	const mtime = "1700000000"
	return append([]entryCase{
		{"symlink", typed(tar.TypeSymlink), same},
		{"symlink with an empty link name", rawArchive(rawHdr(p, tar.TypeSymlink, 0)), same},
		{"hard link", rawArchive(rawLinkHdr(p, tar.TypeLink, "traps/b")), same},
		{"hard link with an empty link name", rawArchive(rawHdr(p, tar.TypeLink, 0)), same},
		// Only the link name differs from the twin, so only the link-name check
		// can refuse the bad archive.
		{"regular file with a link name",
			rawArchive(rawLinkHdr(p, tar.TypeReg, "traps/b")),
			rawArchive(rawHdr(p, tar.TypeReg, 0))},
		{"character device", typed(tar.TypeChar), same},
		{"block device", typed(tar.TypeBlock), same},
		{"FIFO", typed(tar.TypeFifo), same},
		{"PAX global header", rawArchive(globalHdr(paxRec("mtime", mtime)), rawFile(p, "x")), nil},
		{"unknown PAX record", rawArchive(paxHdr(paxRec("comment", mtime)), rawFile(p, "x")), nil},
		{"GNU long link before a regular file",
			rawArchive(longHdr(tar.TypeGNULongLink, "traps/b"), rawFile(p, "x")), same},
		// A name over the ustar fields comes only through a PAX path record
		// or a GNU long name. The twin has a split name.
		{"GNU long name",
			rawArchive(longHdr(tar.TypeGNULongName, long), rawFile("traps/x", "x")),
			build(ent{name: longName(8, 14), data: []byte("x")})},
		{"PAX path of a name that does not fit the ustar fields",
			rawArchive(pathEntry(noSplit)), build(ent{name: split131, data: []byte("x")})},
		{"PAX path and GNU long name",
			rawArchive(paxHdr(paxRec("path", "../../evil")), longHdr(tar.TypeGNULongName, "traps/fromL"),
				rawFile("traps/ustar", "x")), nil},
		{"GNU header with a prefix",
			rawArchive(rawFile(manifestName, "x"),
				withMagic(withPrefix(rawHdr(manifestName, tar.TypeReg, 1), "traps"), "ustar  \x00"), padded([]byte("B"))),
			rawArchive(rawFile(manifestName, "x"),
				withPrefix(rawHdr(manifestName, tar.TypeReg, 1), "traps"), padded([]byte("B")))},
		// The header has no prefix, so its format is GNU and not unknown. Only the
		// magic differs from the twin, so only the format check can refuse it.
		{"header with the GNU magic",
			rawArchive(withMagic(rawHdr("traps/g", tar.TypeReg, 1), "ustar  \x00"), padded([]byte("x"))),
			rawArchive(rawHdr("traps/g", tar.TypeReg, 1), padded([]byte("x")))},
		// The header has no magic, which is the v7 form. Only the magic differs
		// from the twin.
		{"header with no magic",
			rawArchive(withMagic(rawHdr("traps/v", tar.TypeReg, 1), string(make([]byte, 8))), padded([]byte("x"))),
			rawArchive(rawHdr("traps/v", tar.TypeReg, 1), padded([]byte("x")))},
		{"STAR header", rawArchive(rawFile(manifestName, "x"), starHdr()),
			rawArchive(rawFile(manifestName, "x"), ustarTwinOfStar())},
		{"two PAX headers before one entry",
			rawArchive(paxHdr(paxRec("path", p)), paxHdr(paxRec("mtime", "1")), rawFile(p, "x")), nil},
		{"PAX header with a repeated key",
			rawArchive(paxHdr(paxRec("path", strings.Repeat("a", 600)), paxRec("path", p)), rawFile(p, "x")), nil},
		{"PAX header with no records",
			rawArchive(rawHdr("PaxHeaders/x", tar.TypeXHeader, 0), rawFile(p, "x")), same},
		{"PAX record with a non-minimal length",
			rawArchive(paxHdr(paxRecZeros("path", p), paxRec("mtime", fullBlockMtime(p))), rawFile(p, "x")), nil},
		{"absolute name", reg("/traps/a"), same},
		{"name with ..", reg("traps/../a"), reg("traps/..a/a")},
		{"part outside the set", reg("traps/a b"), reg("traps/a_b")},
		// tar.Writer cannot write a non-ASCII name in the USTAR format.
		{"part with a non-ASCII byte", rawArchive(rawFile("traps/é", "x")), reg("traps/e")},
		{"part with a backslash", reg(`traps/a\b`), reg("traps/a_b")},
		{"part over 64 bytes", reg("traps/" + strings.Repeat("a", 65)), reg("traps/" + strings.Repeat("a", 64))},
		{"more than 8 parts", reg("traps/a/b/c/d/e/f/g/h"), reg("traps/a/b/c/d/e/f/g")},
		{"PAX path with 9 parts", rawArchive(pathEntry(longName(9, 12))), nil},
		{"unknown top-level name", reg("other/a"), same},
		{"regular file with one part", reg("traps"), build(dir("traps"))},
		{"directory named like the manifest", build(dir("manifest.json/")), reg("manifest.json")},
		{"two names that differ only in case", reg("traps/A", "traps/a"), reg("traps/A", "traps/b")},
		{"./a form", reg("./traps/a"), same},
		{"regular file with a trailing slash", rawArchive(rawFile("traps/a/", "x")), same},
		{"empty part", reg("traps//a"), same},
		{"directory and file with the same name",
			build(dir("traps/a/"), file(p)), build(dir("traps/a/"), file("traps/b"))},
		{"raw directory header and regular file with the same name",
			rawArchive(rawHdr("traps/a/", tar.TypeDir, 0), rawFile(p, "x")),
			rawArchive(rawHdr("traps/a/", tar.TypeDir, 0), rawFile("traps/b", "x"))},
		{"regular file and raw directory header with the same name",
			rawArchive(rawFile(p, "x"), rawHdr("traps/a/", tar.TypeDir, 0)),
			rawArchive(rawFile(p, "x"), rawHdr("traps/b/", tar.TypeDir, 0))},
		// A regular file is not the parent of another entry. The twins keep the
		// name prefix, but they end the prefix before the slash.
		{"file, then a child", reg(p, "traps/a/b"), reg(p, "traps/ab")},
		{"child, then the file", reg("traps/a/b", p), reg("traps/ab", p)},
		{"file, then a grandchild with no parent directory", reg(p, "traps/a/b/c"), reg(p, "traps/ab/c")},
		{"grandchild, then the file with no parent directory", reg("traps/a/b/c", p), reg("traps/ab/c", p)},
		{"file, then a child that differs in case", reg("traps/A", "traps/a/b"), reg("traps/A", "traps/ab")},
		{"file, then a directory below it", build(file(p), dir("traps/a/d/")), build(file(p), dir("traps/ab/d/"))},
		{"directory below a file, then the file", build(dir("traps/a/d/"), file(p)), build(dir("traps/ab/d/"), file(p))},
	}, rawFormCases()...)
}

// maxCut is the length of the ustar name field. posixMtime is a time value
// with a fraction, as GNU tar and Python write it.
const (
	maxCut     = 100
	posixMtime = "1700000000.123456789"
)

// gnuTimes returns the three time records that GNU tar writes: mtime, atime
// and ctime.
func gnuTimes() []string {
	return []string{paxRec("mtime", posixMtime), paxRec("atime", posixMtime), paxRec("ctime", posixMtime)}
}

// gnuPaxHdr makes the PAX header that GNU tar writes before an entry.
func gnuPaxHdr() []byte { return paxHdr(gnuTimes()...) }

// Two names need more than 100 bytes. noSplit has 251 bytes and no slash that
// gives a ustar split. split131 has 131 bytes and a split.
var (
	noSplit  = "traps/" + strings.Repeat("a", 245)
	split131 = "traps/" + strings.Repeat("a", 64) + "/" + strings.Repeat("b", 60)
)

// pathEntry makes a regular file with a PAX header that holds a path record
// and the other records. The ustar name field holds the path, or its first 100
// bytes, as tar.Writer writes it.
func pathEntry(path string, recs ...string) []byte {
	x := paxHdr(append([]string{paxRec("path", path)}, recs...)...)
	return append(x, rawFile(path[:min(len(path), maxCut)], "x")...)
}

// withField sets the bytes of the header block h from off on.
func withField(h []byte, off int, v string) []byte {
	copy(h[off:], v)
	return withSum(h)
}

// withChksumForm writes the checksum of the header block h in the form of the
// format. The format has one %o verb for the value, which is the sum with the
// checksum field as spaces.
func withChksumForm(h []byte, format string) []byte {
	copy(h[148:156], "        ")
	sum := 0
	for _, c := range h {
		sum += int(c)
	}
	copy(h[148:156], fmt.Sprintf(format, sum))
	return h
}

// paxHdrTail makes a PAX header whose size field covers the records only. The
// tail follows the records in the padding of the block.
func paxHdrTail(tail string, recs ...string) []byte {
	body := strings.Join(recs, "")
	return append(rawHdr("PaxHeaders/x", tar.TypeXHeader, int64(len(body))), padded([]byte(body+tail))...)
}

// rawFormCases returns the refused forms of the raw header bytes, each with a
// twin that differs in that form only.
func rawFormCases() []entryCase {
	const p = "traps/a"
	long := longName(8, 64)
	// upperLong has upper case letters in its first 100 bytes.
	upperLong := "traps/" + strings.ToUpper(long[6:])
	// The first 100 bytes of slashCut end in a slash. A directory with these
	// bytes as its name has the same key as the cut.
	slashCut := "traps/" + strings.Repeat("a", 64) + "/" + strings.Repeat("b", 28) + "/" + strings.Repeat("c", 64)
	hidden := rawHdr("traps/hid", tar.TypeReg, 0)
	// withHidden makes a file of 512 bytes with the header h. The data is the
	// header of another entry, that a reader with another size does not skip.
	withHidden := func(h []byte) []byte { return append(h, hidden...) }
	size := rawHdr(p, tar.TypeReg, 512)
	nulSize := fmt.Sprintf("\x00%010o\x00", 512)
	good := paxRec("path", "traps/good")
	xNul := paxHdr(good)
	withField(xNul[:blockBytes], 124, fmt.Sprintf("\x00%010o\x00", len(good)))
	sizeForm := func(field string) []byte {
		return rawArchive(withField(rawHdr(p, tar.TypeReg, 1), 124, field), padded([]byte("x")))
	}
	hiddenLink := rawLinkHdr("traps/link", tar.TypeSymlink, "/etc/passwd")
	// secondFile makes the file traps/b with the checksum field in the form of
	// the format, after the file traps/a.
	secondFile := func(format string) []byte {
		h := withChksumForm(rawHdr("traps/b", tar.TypeReg, 1), format)
		return append(rawFile(p, "x"), append(h, padded([]byte("x"))...)...)
	}
	// xSum makes the PAX header of traps/b with the checksum field in the form
	// of the format, after the file traps/a. The entry follows the header.
	xSum := func(format string) []byte {
		x := paxHdr(paxRec("path", "traps/b"))
		withChksumForm(x[:blockBytes], format)
		return append(rawFile(p, "x"), append(x, rawFile("traps/b", "x")...)...)
	}
	const nulSum = "\x00%06o\x00"
	return []entryCase{
		// The raw type byte is '0' or '5' in the twins. The three writers write
		// these bytes.
		{"type NUL regular file", rawArchive(rawHdr("traps/n", 0, 1), padded([]byte("x"))),
			rawArchive(rawFile("traps/n", "x"))},
		{"type NUL directory", rawArchive(rawHdr("traps/d/", 0, 0)), rawArchive(rawHdr("traps/d/", tar.TypeDir, 0))},
		{"type NUL directory behind a PAX mtime record",
			rawArchive(paxHdr(paxRec("mtime", "1")), rawHdr("traps/d/", 0, 0)), nil},
		{"type NUL directory behind a PAX path record",
			rawArchive(paxHdr(paxRec("path", "traps/d/")), rawHdr("traps/d/", 0, 0)), nil},
		{"type NUL with a prefix and an empty name field",
			rawArchive(withPrefix(rawHdr("", 0, 0), "traps/d")),
			rawArchive(withPrefix(rawHdr("", tar.TypeDir, 0), "traps/d"))},
		{"checksum field with a leading NUL in the second entry", rawArchive(secondFile(nulSum)),
			rawArchive(rawFile(p, "x"), rawFile("traps/b", "x"))},
		{"checksum field with a leading NUL in a PAX header that is not the first header", rawArchive(xSum(nulSum)), nil},
		{"checksum field with a leading space", rawArchive(secondFile(" %06o\x00")),
			rawArchive(rawFile(p, "x"), rawFile("traps/b", "x"))},
		// The next three forms each break one part of chksumOK: the digit loop,
		// the NUL at byte 6 and the space at byte 7. archive/tar trims a space
		// and a NUL from the field, so it reads the right value from each form.
		// The twin of each is the canonical form.
		{"checksum field with a space and 5 digits", rawArchive(secondFile(" %05o\x00 ")),
			rawArchive(rawFile(p, "x"), rawFile("traps/b", "x"))},
		{"checksum field with two NUL bytes at the end", rawArchive(secondFile("%06o\x00\x00")),
			rawArchive(rawFile(p, "x"), rawFile("traps/b", "x"))},
		{"checksum field with two spaces at the end", rawArchive(secondFile("%06o  ")),
			rawArchive(rawFile(p, "x"), rawFile("traps/b", "x"))},
		{"PAX mtime record with a plus sign", rawArchive(paxHdr(paxRec("mtime", "+1")), rawFile(p, "x")), nil},
		// rawFormOK is not the only rule that refuses this form. Next gives the
		// format unknown for a size field that has no NUL at the end, so the
		// format check refuses it first.
		{"size field with a trailing space", sizeForm("00000000001 "), rawArchive(rawFile(p, "x"))},
		{"size field with a leading NUL", rawArchive(withHidden(withField(slices.Clone(size), 124, nulSize))),
			rawArchive(withHidden(size))},
		{"size field of the PAX header with a leading NUL", rawArchive(xNul, rawFile("traps/good", "x")), nil},
		{"size field with a leading space", sizeForm(fmt.Sprintf(" %010o\x00", 1)), rawArchive(rawFile(p, "x"))},
		// The next two forms are not isolated to rawFormOK. Next refuses the
		// non-octal byte with a header error. Next accepts the base-256 form
		// (size 1) with the format unknown, so the format check refuses it.
		{"size field with a non-octal byte", sizeForm("0000000001" + "8" + "\x00"), rawArchive(rawFile(p, "x"))},
		{"size field in base-256 form", sizeForm("\x80" + strings.Repeat("\x00", 10) + "\x01"), rawArchive(rawFile(p, "x"))},
		{"PAX size record with a plus sign", rawArchive(paxHdr(paxRec("size", "+1")), rawFile(p, "x")), nil},
		{"size field with fewer digits", sizeForm("1" + strings.Repeat("\x00", 11)), rawArchive(rawFile(p, "x"))},
		{"PAX path in the padding of the PAX header",
			rawArchive(paxHdrTail(paxRec("path", "../../evil"), good), rawFile("traps/good", "x")), nil},
		{"PAX path of the manifest in the padding of the PAX header",
			rawArchive(rawFile(manifestName, "x"), paxHdrTail(paxRec("path", manifestName), good), rawFile("traps/good", "B")), nil},
		{"PAX size in the padding of the PAX header",
			rawArchive(paxHdrTail(paxRec("size", "0"), good), rawHdr("traps/good", tar.TypeReg, 512), hiddenLink), nil},
		{"PAX header with a repeated key in one block",
			rawArchive(paxHdr(paxRec("path", p), paxRec("path", p)), rawFile(p, "x")), nil},
		{"PAX record length with a leading zero in one block",
			rawArchive(paxHdr(paxRecZeros("path", p)), rawFile(p, "x")), nil},
		{"PAX path record with an empty value", rawArchive(paxHdr(paxRec("path", "")), rawFile(p, "x")), nil},
		{"PAX mtime record at the int64 minimum with a fraction",
			rawArchive(paxHdr(paxRec("mtime", "-9223372036854775808.5")), rawFile(p, "x")), nil},
		{"PAX mtime record with 19 digits",
			rawArchive(paxHdr(paxRec("mtime", "1000000000000000000")), rawFile(p, "x")), nil},
		{"PAX mtime record with a dot and no fraction", rawArchive(paxHdr(paxRec("mtime", "1.")), rawFile(p, "x")), nil},
		{"PAX mtime record with an empty value", rawArchive(paxHdr(paxRec("mtime", "")), rawFile(p, "x")), nil},
		{"PAX size record with an empty value", rawArchive(paxHdr(paxRec("size", "")), withHidden(size)), nil},
		{"PAX size record and ustar size field that differ",
			rawArchive(paxHdr(paxRec("size", "0")), withHidden(size)), nil},
		{"PAX size record with a leading zero", rawArchive(paxHdr(paxRec("size", "0512")), withHidden(size)), nil},
		{"PAX path over the ustar name ../x",
			rawArchive(paxHdr(paxRec("path", "traps/p")), rawFile("../x", "x")), nil},
		{"PAX path that starts the ustar name",
			rawArchive(paxHdr(paxRec("path", "traps/p")), rawFile("traps/pq", "x")), nil},
		{"PAX path with a ustar prefix",
			rawArchive(paxHdr(paxRec("path", "traps/p")), withPrefix(rawHdr("traps/p", tar.TypeReg, 1), "traps"), padded([]byte("x"))), nil},
		{"PAX path over 100 bytes with another ustar name",
			rawArchive(paxHdr(paxRec("path", long)), rawFile("traps/x", "x")), nil},
		{"long name with the cut of another file", rawArchive(rawFile(long[:maxCut], "x"), pathEntry(long)), nil},
		{"long name with a cut that ends in a slash and a file",
			rawArchive(rawFile(slashCut[:maxCut-1], "x"), pathEntry(slashCut)), nil},
		{"long name with a cut that differs from a file only in case",
			rawArchive(pathEntry(upperLong), rawFile(strings.ToLower(upperLong[:maxCut]), "x")), nil},
		{"long name with a cut that ends in a slash and a directory",
			rawArchive(rawHdr(slashCut[:maxCut], tar.TypeDir, 0), pathEntry(slashCut)), nil},
		// Python 3.13 (PAX_FORMAT) writes an mtime record before each entry.
		// For a name of 131 bytes, it writes a path record and an mtime record.
		{"PAX header with one mtime record before each entry",
			rawArchive(paxHdr(paxRec("mtime", posixMtime)), rawFile("traps/a", "x"),
				paxHdr(paxRec("mtime", posixMtime)), rawFile("traps/b", "x")), nil},
		{"PAX header with a path record and an mtime record for a name of 131 bytes",
			rawArchive(pathEntry(split131, paxRec("mtime", posixMtime))), nil},
		// GNU tar 1.35 (--format=posix) writes mtime, atime and ctime records
		// before each entry. For a name of 131 bytes, it adds a path record.
		{"PAX header with mtime, atime and ctime records before each entry",
			rawArchive(gnuPaxHdr(), rawFile("traps/a", "x"), gnuPaxHdr(), rawFile("traps/b", "x")), nil},
		{"PAX header with path, mtime, atime and ctime records for a name of 131 bytes",
			rawArchive(pathEntry(split131, gnuTimes()...)), nil},
		{"no end blocks", gz(rawFile(p, "x")), rawArchive(rawFile(p, "x"))},
		{"one end block", gz(append(rawFile(p, "x"), zeros(blockBytes)...)), rawArchive(rawFile(p, "x"))},
	}
}

// passCase is an archive that ReadArchive accepts, with the names of its
// regular files.
type passCase struct {
	name  string
	b     []byte
	names []string
}

// entryPassCases returns the accepted entry forms, each with the names that
// ReadArchive gives.
func entryPassCases() []passCase {
	return []passCase{
		// The name has 131 bytes. tar.Writer splits it at a slash. The parts go
		// into the prefix field and the name field (TestTS19WriterUstarOnly).
		{"name of 131 bytes split into the prefix and name fields",
			build(ent{name: split131, data: []byte("x")}), []string{split131}},
		// The directory name and the file names are over 100 bytes. Each has a
		// split.
		{"directory of 135 bytes and two files with a split name", deepDirArchive(), deepDirFiles()},
		// The files traps/a and traps/ab share a prefix, but neither is the
		// parent of the other.
		{"file and a file whose name starts with it",
			build(ent{name: "traps/a", data: []byte("x")}, ent{name: "traps/ab", data: []byte("x")}),
			[]string{"traps/a", "traps/ab"}},
		{"directory and a file below it",
			build(ent{name: "traps/a/", typ: tar.TypeDir}, ent{name: "traps/a/b", data: []byte("x")}),
			[]string{"traps/a/b"}},
		// The file of 1 byte leaves padding. The directory has none, so the next
		// header must not count the padding of the file before the directory.
		{"file, directory, file",
			build(ent{name: "traps/a", data: []byte("x")}, ent{name: "traps/d/", typ: tar.TypeDir},
				ent{name: "traps/b", data: []byte("x")}),
			[]string{"traps/a", "traps/b"}},
		{"directory and file below vhosts",
			build(ent{name: "vhosts/", typ: tar.TypeDir}, ent{name: "vhosts/a", data: []byte("x")}),
			[]string{"vhosts/a"}},
		{"manifest and every top-level directory",
			build(ent{name: "manifest.json", data: []byte("x")},
				ent{name: "fp/a", data: []byte("x")}, ent{name: "score/a", data: []byte("x")},
				ent{name: "secrets/a", data: []byte("x")}, ent{name: "vhosts/h/a", data: []byte("x")},
				ent{name: "traps/a", data: []byte("x")}),
			[]string{"fp/a", "manifest.json", "score/a", "secrets/a", "traps/a", "vhosts/h/a"}},
	}
}

// deepDir is a directory name of 135 bytes: traps and two parts of 64 bytes.
var deepDir = "traps/" + strings.Repeat("a", 64) + "/" + strings.Repeat("b", 64)

// deepDirEnts returns the entries of deepDirArchive: the directory and two
// files in it.
func deepDirEnts() []ent {
	return []ent{
		{name: deepDir, typ: tar.TypeDir},
		{name: deepDir + "/f1", data: []byte("x")},
		{name: deepDir + "/f2", data: []byte("x")},
	}
}

// deepDirArchive makes the archive of deepDirEnts with tar.Writer.
func deepDirArchive() []byte { return build(deepDirEnts()...) }

// deepDirFiles returns the sorted names of the files of deepDirArchive.
func deepDirFiles() []string { return []string{deepDir + "/f1", deepDir + "/f2"} }

// T-S-19: tar.Writer with the format USTAR gives an error from WriteHeader. The
// name has 251 bytes and no fitting slash. The writer writes no header bytes.
// It gives no error for a name of 131 bytes with a fitting split. Each entry of
// deepDirArchive has a ustar header with no PAX record.
func TestTS19WriterUstarOnly(t *testing.T) {
	for _, c := range []struct {
		name string
		want bool
	}{{noSplit, false}, {split131, true}} {
		var buf bytes.Buffer
		err := tar.NewWriter(&buf).WriteHeader(&tar.Header{Name: c.name, Typeflag: tar.TypeReg, Format: tar.FormatUSTAR})
		if (err == nil) != c.want || (err != nil && buf.Len() != 0) {
			t.Errorf("name of %d bytes: error %v, %d bytes written; want no error %v", len(c.name), err, buf.Len(), c.want)
		}
	}
	if len(deepDir) != 135 {
		t.Fatalf("directory of %d bytes; want 135", len(deepDir))
	}
	tr := tar.NewReader(bytes.NewReader(buildTar(deepDirEnts()...)))
	for i := range 3 {
		if hdr, err := tr.Next(); err != nil || hdr.Format != tar.FormatUSTAR || len(hdr.Name) <= maxCut {
			t.Errorf("entry %d: error %v, header %+v; want USTAR and a name over %d bytes", i, err, hdr, maxCut)
		}
	}
}

// T-S-19: each PAX 'x' header gives ErrArchiveInvalid. This includes a header
// with only a size record, only an mtime record, a path record or no record. A
// PAX 'g' header stays refused.
func TestTS19PAXHeaderIsRefused(t *testing.T) {
	const p = "traps/a"
	for _, c := range []struct {
		name string
		b    []byte
	}{
		{"size record only", rawArchive(paxHdr(paxRec("size", "1")), rawFile(p, "x"))},
		{"mtime record only", rawArchive(paxHdr(paxRec("mtime", "1")), rawFile(p, "x"))},
		{"path record", rawArchive(paxHdr(paxRec("path", p)), rawFile(p, "x"))},
		{"no record", rawArchive(rawHdr("PaxHeaders/x", tar.TypeXHeader, 0), rawFile(p, "x"))},
		{"global header", rawArchive(globalHdr(paxRec("mtime", "1")), rawFile(p, "x"))},
	} {
		if a, err := ReadArchive(c.b); a != nil || err != ErrArchiveInvalid {
			t.Errorf("%s: archive %v, error %v", c.name, a != nil, err)
		}
	}
}

// entryPassing returns the accepted entry forms as fixtures.
func entryPassing() []fixture {
	var fs []fixture
	for _, c := range entryPassCases() {
		fs = append(fs, fixture{c.name, c.b})
	}
	return fs
}

// T-S-19: each refused entry form gives the one error. ReadArchive accepts
// the twin of each form that has one.
func TestTS19EntryRules(t *testing.T) {
	for _, c := range entryCases() {
		t.Run(c.name, func(t *testing.T) {
			if a, err := ReadArchive(c.bad); a != nil || err != ErrArchiveInvalid {
				t.Errorf("refused archive: archive %v, len %d, error %v", a != nil, lenOf(a), err)
			}
			if c.twin == nil {
				return
			}
			if _, err := ReadArchive(c.twin); err != nil {
				t.Errorf("twin: %v", err)
			}
		})
	}
}

// T-S-19: ReadArchive accepts the twin of a ustar prefix header and gives both
// names of the archive.
func TestTS19UstarPrefixTwinNames(t *testing.T) {
	for _, c := range entryCases() {
		if c.name != "GNU header with a prefix" {
			continue
		}
		a, err := ReadArchive(c.twin)
		if err != nil {
			t.Fatal(err)
		}
		if want := []string{manifestName, "traps/" + manifestName}; !slices.Equal(a.Names(), want) {
			t.Errorf("names %q; want %q", a.Names(), want)
		}
	}
}

// T-S-19: checkEntry accepts a header with the format USTAR. It refuses the
// same header with the format PAX or GNU.
func TestTS19CheckEntryFormat(t *testing.T) {
	for _, c := range []struct {
		format tar.Format
		ok     bool
	}{{tar.FormatUSTAR, true}, {tar.FormatPAX, false}, {tar.FormatGNU, false}} {
		hdr := &tar.Header{Name: "traps/a", Typeflag: tar.TypeReg, Format: c.format}
		if _, err := checkEntry(hdr); (err == nil) != c.ok {
			t.Errorf("format %v: error %v; want no error %v", c.format, err, c.ok)
		}
	}
}

// nameAllocBound is the most that checkEntry may allocate for a name with
// 500 000 parts. A split in at most 9 parts needs 144 bytes. A split in every
// part needs about 8 MiB.
const nameAllocBound = 64 << 10

// T-S-19: the name check of a name with very many parts allocates a small,
// fixed amount, because it splits the name in at most 9 parts.
func TestTS19NameWithManyPartsAllocatesLittle(t *testing.T) {
	hdr := &tar.Header{
		Name:     "traps/" + strings.Repeat("a/", 500_000) + "a",
		Typeflag: tar.TypeReg,
		Format:   tar.FormatUSTAR,
	}
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	_, err := checkEntry(hdr)
	runtime.ReadMemStats(&after)
	if err != ErrArchiveInvalid {
		t.Fatalf("error %v", err)
	}
	grown := after.TotalAlloc - before.TotalAlloc
	t.Logf("allocated %d bytes, bound %d bytes", grown, nameAllocBound)
	if grown > nameAllocBound {
		t.Errorf("allocated %d bytes, bound %d bytes", grown, nameAllocBound)
	}
}

// T-S-19: the accepted forms give the final names. Next joins the ustar prefix
// field and the name field. A directory gives no name. It holds no file.
func TestTS19EntryNamesAccepted(t *testing.T) {
	for _, c := range entryPassCases() {
		t.Run(c.name, func(t *testing.T) {
			a, err := ReadArchive(c.b)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(a.Names(), c.names) {
				t.Errorf("names %q; want %q", a.Names(), c.names)
			}
		})
	}
}
