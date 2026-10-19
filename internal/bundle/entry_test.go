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
		if paxRecordLen("path", path)+paxRecordLen("mtime", v) == blockBytes {
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
// that the refused form has no accepted form.
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

// entryCases returns the refused entry forms. Each has a twin, except the case
// "PAX path and GNU long name".
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
	long := longName(8, 14)
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
		{"PAX global header",
			rawArchive(globalHdr(paxRec("mtime", mtime)), rawFile(p, "x")),
			rawArchive(paxHdr(paxRec("mtime", mtime)), rawFile(p, "x"))},
		{"unknown PAX record",
			rawArchive(paxHdr(paxRec("comment", mtime)), rawFile(p, "x")),
			rawArchive(paxHdr(paxRec("mtime", mtime)), rawFile(p, "x"))},
		{"GNU long link before a regular file",
			rawArchive(longHdr(tar.TypeGNULongLink, "traps/b"), rawFile(p, "x")), same},
		{"GNU long name",
			rawArchive(longHdr(tar.TypeGNULongName, long), rawFile("traps/x", "x")),
			rawArchive(pathEntry(long))},
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
			rawArchive(paxHdr(paxRec("path", p)), paxHdr(paxRec("mtime", "1")), rawFile(p, "x")),
			rawArchive(pathEntry(p, paxRec("mtime", "1")))},
		// The first path record is long, so the repeated key adds a block.
		{"PAX header with a repeated key",
			rawArchive(paxHdr(paxRec("path", strings.Repeat("a", 600)), paxRec("path", p)), rawFile(p, "x")),
			rawArchive(pathEntry(p))},
		{"PAX header with no records",
			rawArchive(rawHdr("PaxHeaders/x", tar.TypeXHeader, 0), rawFile(p, "x")), same},
		// The canonical records fill one block, so the extra zeros add a block.
		{"PAX record with a non-minimal length",
			rawArchive(paxHdr(paxRecZeros("path", p), paxRec("mtime", fullBlockMtime(p))), rawFile(p, "x")),
			rawArchive(pathEntry(p, paxRec("mtime", fullBlockMtime(p))))},
		{"absolute name", reg("/traps/a"), same},
		{"name with ..", reg("traps/../a"), reg("traps/..a/a")},
		{"part outside the set", reg("traps/a b"), reg("traps/a_b")},
		{"part with a non-ASCII byte", reg("traps/é"), reg("traps/e")},
		{"part with a backslash", reg(`traps/a\b`), reg("traps/a_b")},
		{"part over 64 bytes", reg("traps/" + strings.Repeat("a", 65)), reg("traps/" + strings.Repeat("a", 64))},
		{"more than 8 parts", reg("traps/a/b/c/d/e/f/g/h"), reg("traps/a/b/c/d/e/f/g")},
		{"PAX path with 9 parts",
			rawArchive(pathEntry(longName(9, 12))),
			rawArchive(pathEntry(longName(8, 12)))},
		{"unknown top-level name", reg("other/a"), same},
		{"regular file with one part", reg("traps"), build(dir("traps"))},
		{"directory named like the manifest", build(dir("manifest.json/")), reg("manifest.json")},
		{"two names that differ only in case", reg("traps/A", "traps/a"), reg("traps/A", "traps/b")},
		{"./a form", reg("./traps/a"), same},
		{"regular file with a trailing slash", rawArchive(rawFile("traps/a/", "x")), same},
		{"empty part", reg("traps//a"), same},
		{"directory and file with the same name",
			build(dir("traps/a/"), file(p)), build(dir("traps/a/"), file("traps/b"))},
		{"type NUL directory and regular file with the same name",
			rawArchive(rawHdr("traps/a/", 0, 0), rawFile(p, "x")),
			rawArchive(rawHdr("traps/a/", 0, 0), rawFile("traps/b", "x"))},
		{"regular file and type NUL directory with the same name",
			rawArchive(rawFile(p, "x"), rawHdr("traps/a/", 0, 0)),
			rawArchive(rawFile(p, "x"), rawHdr("traps/b/", 0, 0))},
	}, rawFormCases()...)
}

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
	// tail has the 100-byte cut of long. other has another cut.
	other := "traps/b" + long[7:]
	tail := long[:len(long)-1] + "b"
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
	return []entryCase{
		{"size field with a leading NUL", rawArchive(withHidden(withField(slices.Clone(size), 124, nulSize))),
			rawArchive(withHidden(size))},
		{"size field of the PAX header with a leading NUL", rawArchive(xNul, rawFile("traps/good", "x")),
			rawArchive(pathEntry("traps/good"))},
		{"size field with a leading space", sizeForm(fmt.Sprintf(" %010o\x00", 1)), rawArchive(rawFile(p, "x"))},
		// The next two forms are not isolated to rawFormOK. Next refuses the
		// non-octal byte with a header error. Next accepts the base-256 form
		// (size 1) with the format unknown, so the format check refuses it.
		{"size field with a non-octal byte", sizeForm("0000000001" + "8" + "\x00"), rawArchive(rawFile(p, "x"))},
		{"size field in base-256 form", sizeForm("\x80" + strings.Repeat("\x00", 10) + "\x01"), rawArchive(rawFile(p, "x"))},
		{"PAX size record with a plus sign",
			rawArchive(paxHdr(paxRec("size", "+1")), rawFile(p, "x")), rawArchive(paxHdr(paxRec("size", "1")), rawFile(p, "x"))},
		{"size field with fewer digits", sizeForm("1" + strings.Repeat("\x00", 11)), rawArchive(rawFile(p, "x"))},
		{"PAX path in the padding of the PAX header",
			rawArchive(paxHdrTail(paxRec("path", "../../evil"), good), rawFile("traps/good", "x")),
			rawArchive(paxHdrTail("", good), rawFile("traps/good", "x"))},
		{"PAX path of the manifest in the padding of the PAX header",
			rawArchive(rawFile(manifestName, "x"), paxHdrTail(paxRec("path", manifestName), good), rawFile("traps/good", "B")),
			rawArchive(rawFile(manifestName, "x"), paxHdrTail("", good), rawFile("traps/good", "B"))},
		{"PAX size in the padding of the PAX header",
			rawArchive(paxHdrTail(paxRec("size", "0"), good), rawHdr("traps/good", tar.TypeReg, 512), hiddenLink),
			rawArchive(paxHdrTail("", good), rawHdr("traps/good", tar.TypeReg, 512), hiddenLink)},
		{"PAX header with a repeated key in one block",
			rawArchive(paxHdr(paxRec("path", p), paxRec("path", p)), rawFile(p, "x")), rawArchive(pathEntry(p))},
		{"PAX record length with a leading zero in one block",
			rawArchive(paxHdr(paxRecZeros("path", p)), rawFile(p, "x")), rawArchive(pathEntry(p))},
		{"PAX path record with an empty value",
			rawArchive(paxHdr(paxRec("path", "")), rawFile(p, "x")), rawArchive(pathEntry(p))},
		{"PAX mtime record with an empty value",
			rawArchive(paxHdr(paxRec("mtime", "")), rawFile(p, "x")),
			rawArchive(paxHdr(paxRec("mtime", "1")), rawFile(p, "x"))},
		{"PAX size record with an empty value",
			rawArchive(paxHdr(paxRec("size", "")), withHidden(size)), rawArchive(paxHdr(paxRec("size", "512")), withHidden(size))},
		{"PAX size record and ustar size field that differ",
			rawArchive(paxHdr(paxRec("size", "0")), withHidden(size)), rawArchive(paxHdr(paxRec("size", "512")), withHidden(size))},
		{"PAX size record with a leading zero",
			rawArchive(paxHdr(paxRec("size", "0512")), withHidden(size)), rawArchive(paxHdr(paxRec("size", "512")), withHidden(size))},
		{"PAX path over the ustar name ../x",
			rawArchive(paxHdr(paxRec("path", "traps/p")), rawFile("../x", "x")), rawArchive(pathEntry("traps/p"))},
		{"PAX path that starts the ustar name",
			rawArchive(paxHdr(paxRec("path", "traps/p")), rawFile("traps/pq", "x")), rawArchive(pathEntry("traps/p"))},
		{"PAX path with a ustar prefix",
			rawArchive(paxHdr(paxRec("path", "traps/p")), withPrefix(rawHdr("traps/p", tar.TypeReg, 1), "traps"), padded([]byte("x"))),
			rawArchive(pathEntry("traps/p"))},
		{"PAX path over 100 bytes with another ustar name",
			rawArchive(paxHdr(paxRec("path", long)), rawFile("traps/x", "x")), rawArchive(pathEntry(long))},
		{"two long names with the same cut", rawArchive(pathEntry(long), pathEntry(tail)),
			rawArchive(pathEntry(long), pathEntry(other))},
		{"long name with the cut of another file", rawArchive(rawFile(long[:maxCut], "x"), pathEntry(long)),
			rawArchive(rawFile(other[:maxCut], "x"), pathEntry(long))},
		{"long name with a cut that ends in a slash and a directory",
			rawArchive(rawHdr(slashCut[:maxCut], tar.TypeDir, 0), pathEntry(slashCut)),
			rawArchive(rawHdr("traps/d", tar.TypeDir, 0), pathEntry(slashCut))},
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
	// The last part has 64 bytes, so no ustar prefix and name split fits the
	// name, and tar.Writer writes a PAX path record.
	long := longName(8, 64)
	// The canonical records have 101 and 412 bytes. Together they have 513
	// bytes, so they fill two blocks. A record of 101 bytes is a length that a
	// guess of the length field gets wrong by one.
	path101 := "traps/" + strings.Repeat("a", 64) + "/" + strings.Repeat("a", 20)
	mtime412 := "1700000000." + strings.Repeat("1", 390)
	if len(paxRec("path", path101)) != 101 || len(paxRec("mtime", mtime412)) != 412 {
		panic("the PAX records of the fixture do not have 101 and 412 bytes")
	}
	return []passCase{
		{"PAX path over 100 bytes, written by tar.Writer", build(ent{name: long, data: []byte("x")}), []string{long}},
		{"PAX path record", rawArchive(pathEntry("traps/p")), []string{"traps/p"}},
		{"PAX path and mtime records",
			rawArchive(pathEntry("traps/p", paxRec("mtime", "1700000000.5"))), []string{"traps/p"}},
		{"PAX records of 513 bytes with a record of 101 bytes",
			rawArchive(pathEntry(path101, paxRec("mtime", mtime412))), []string{path101}},
		// The file of 1 byte leaves padding. The directory has none, so the next
		// header must not count the padding of the file before the directory.
		{"file, directory, file",
			build(ent{name: "traps/a", data: []byte("x")}, ent{name: "traps/d/", typ: tar.TypeDir},
				ent{name: "traps/b", data: []byte("x")}),
			[]string{"traps/a", "traps/b"}},
		{"type NUL regular file",
			rawArchive(append(rawHdr("traps/n", 0, 1), padded([]byte("x"))...)), []string{"traps/n"}},
		{"type NUL directory", rawArchive(rawHdr("traps/d/", 0, 0)), []string{}},
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

// T-S-19: paxRecordLen gives the length of the record that paxRec makes, for
// value lengths from 0 to 1200. This covers the points where the length field
// gains a digit.
func TestTS19PAXRecordLen(t *testing.T) {
	for _, key := range []string{"path", "size", "mtime", "a"} {
		for n := 0; n <= 1200; n++ {
			value := strings.Repeat("v", n)
			if got, want := paxRecordLen(key, value), len(paxRec(key, value)); got != want {
				t.Fatalf("key %q, value of %d bytes: paxRecordLen %d; record has %d bytes", key, n, got, want)
			}
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
		Format:   tar.FormatPAX,
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

// T-S-19: tar.Writer writes a PAX header for the long name of the pass case.
// The case then pins the byte count of the PAX header against the real writer.
func TestTS19WriterWritesPAXForLongName(t *testing.T) {
	tr := tar.NewReader(bytes.NewReader(buildTar(ent{name: longName(8, 64), data: []byte("x")})))
	hdr, err := tr.Next()
	if err != nil {
		t.Fatal(err)
	}
	if hdr.Format != tar.FormatPAX || len(hdr.PAXRecords) != 1 {
		t.Errorf("format %v, %d PAX records; want PAX and 1", hdr.Format, len(hdr.PAXRecords))
	}
}

// T-S-19: the accepted forms give the final names. Next applies a PAX path
// record. A directory gives no name, because it holds no file.
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
