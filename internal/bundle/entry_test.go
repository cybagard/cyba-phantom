package bundle

import (
	"archive/tar"
	"bytes"
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

// longHdr makes a GNU 'L' (long name) or 'K' (long link) header with its
// text. Next applies it to the entry that follows.
func longHdr(typ byte, text string) []byte {
	return append(rawHdr("long-header", typ, int64(len(text)+1)), padded([]byte(text+"\x00"))...)
}

// globalHdr makes a PAX global header with the records.
func globalHdr(recs ...string) []byte {
	body := strings.Join(recs, "")
	return append(rawHdr("pax-global-header", tar.TypeXGlobalHeader, int64(len(body))), padded([]byte(body))...)
}

// entryCase is a refused archive and its passing twin. The twin changes only
// the refused property, so that the bad archive fails from its own rule.
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
	const mtime = "1700000000"
	return []entryCase{
		{"symlink", typed(tar.TypeSymlink), same},
		{"hard link", rawArchive(rawLinkHdr(p, tar.TypeLink, "traps/b")), same},
		{"character device", typed(tar.TypeChar), same},
		{"block device", typed(tar.TypeBlock), same},
		{"FIFO", typed(tar.TypeFifo), same},
		{"PAX global header",
			rawArchive(globalHdr(paxRec("mtime", mtime)), rawFile(p, "x")),
			rawArchive(paxHdr(paxRec("mtime", mtime)), rawFile(p, "x"))},
		{"unknown PAX record",
			rawArchive(paxHdr(paxRec("comment", "x")), rawFile(p, "x")),
			rawArchive(paxHdr(paxRec("mtime", mtime)), rawFile(p, "x"))},
		{"GNU long link before a regular file",
			rawArchive(longHdr(tar.TypeGNULongLink, "traps/b"), rawFile(p, "x")), same},
		{"absolute name", reg("/traps/a"), same},
		{"name with ..", reg("traps/../traps/a"), reg("traps/..a")},
		{"part outside the set", reg("traps/a b"), reg("traps/a_b")},
		{"part with a non-ASCII byte", reg("traps/é"), reg("traps/e")},
		{"part with a backslash", reg(`traps/a\b`), reg("traps/a_b")},
		{"part over 64 bytes", reg("traps/" + strings.Repeat("a", 65)), reg("traps/" + strings.Repeat("a", 64))},
		{"more than 8 parts", reg("traps/a/b/c/d/e/f/g/h"), reg("traps/a/b/c/d/e/f/g")},
		{"GNU long name with 9 parts",
			rawArchive(longHdr(tar.TypeGNULongName, longName(9, 12)), rawFile("traps/x", "x")),
			rawArchive(longHdr(tar.TypeGNULongName, longName(8, 14)), rawFile("traps/x", "x"))},
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
	}
}

// passCase is an archive that ReadArchive accepts, with the names of its
// regular files.
type passCase struct {
	name  string
	b     []byte
	names []string
}

func entryPassCases() []passCase {
	long := longName(8, 14)
	return []passCase{
		{"GNU long name, valid name over 100 bytes",
			rawArchive(longHdr(tar.TypeGNULongName, long), rawFile("traps/x", "x")), []string{long}},
		{"PAX path record",
			rawArchive(paxHdr(paxRec("path", "traps/p")), rawFile("traps/x", "x")), []string{"traps/p"}},
		{"PAX path and mtime records",
			rawArchive(paxHdr(paxRec("path", "traps/p"), paxRec("mtime", "1700000000.5")), rawFile("traps/x", "x")),
			[]string{"traps/p"}},
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

func entryPassing() []fixture {
	var fs []fixture
	for _, c := range entryPassCases() {
		fs = append(fs, fixture{c.name, c.b})
	}
	return fs
}

// T-S-19: each refused entry form gives the one error, and the same archive
// with only the refused property changed is accepted.
func TestTS19EntryRules(t *testing.T) {
	for _, c := range entryCases() {
		t.Run(c.name, func(t *testing.T) {
			if a, err := ReadArchive(c.bad); a != nil || err != ErrArchiveInvalid {
				t.Errorf("refused archive: archive %v, len %d, error %v", a != nil, lenOf(a), err)
			}
			if _, err := ReadArchive(c.twin); err != nil {
				t.Errorf("twin: %v", err)
			}
		})
	}
}

// T-S-19: the accepted forms give the final names. Next applies a GNU long
// name and a PAX path record, and a directory is not an entry of the files.
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
