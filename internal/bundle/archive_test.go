package bundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"go/parser"
	"go/token"
	"io"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// Marker text for the tests that check the error text. The marker text is
// test text and holds no bundle content.
const (
	markerName = "marker-name-7f3a"
	markerData = "marker-data-91c2"
	// markerPath is a permitted name that holds the marker text.
	markerPath = "traps/" + markerName
)

// ent is one tar entry of a fixture. typ 0 (the zero value) means tar.TypeReg.
type ent struct {
	name string
	typ  byte
	data []byte
}

// buildTar makes the tar bytes of the entries, with the end blocks. It panics
// on an error, so that a fixture never depends on the testing.TB of a caller.
func buildTar(ents ...ent) []byte {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range ents {
		if e.typ == 0 {
			e.typ = tar.TypeReg
		}
		h := &tar.Header{Name: e.name, Typeflag: e.typ, Mode: 0o644, Format: tar.FormatUSTAR}
		switch e.typ {
		case tar.TypeReg:
			h.Size = int64(len(e.data))
		case tar.TypeSymlink:
			h.Linkname = "target"
		}
		if err := tw.WriteHeader(h); err != nil {
			panic(err)
		}
		if _, err := tw.Write(e.data); err != nil {
			panic(err)
		}
	}
	if err := tw.Close(); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func gz(b []byte) []byte {
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.BestSpeed)
	if err != nil {
		panic(err)
	}
	if _, err := zw.Write(b); err != nil {
		panic(err)
	}
	if err := zw.Close(); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func build(ents ...ent) []byte { return gz(buildTar(ents...)) }

func zeros(n int) []byte { return make([]byte, n) }

// T-S-19: with keep set, capReader keeps maxKept bytes without an error. A
// read that asks for more gets the bytes up to maxKept. The next read gives
// ErrArchiveInvalid and passes no byte. The test asserts that kept never holds
// more than maxKept bytes.
func TestTS19CapReaderKeepsAtMostMaxKept(t *testing.T) {
	cr := &capReader{r: bytes.NewReader(zeros(maxKept + 1)), keep: true}
	buf := make([]byte, 4096)
	if n, err := cr.Read(buf); err != nil || n != maxKept || len(cr.kept) != maxKept {
		t.Errorf("first read: %d bytes, error %v, kept %d; want %d bytes and no error", n, err, len(cr.kept), maxKept)
	}
	if n, err := cr.Read(buf); err != ErrArchiveInvalid || n != 0 || len(cr.kept) != maxKept {
		t.Errorf("second read: %d bytes, error %v, kept %d; want 0 bytes and ErrArchiveInvalid", n, err, len(cr.kept))
	}
	if n, err := cr.Read(nil); err != nil || n != 0 {
		t.Errorf("empty read: %d bytes, error %v", n, err)
	}
	// With keep unset, the reader keeps nothing and has no cap of this kind.
	free := &capReader{r: bytes.NewReader(zeros(maxKept + 1))}
	if _, err := io.Copy(io.Discard, free); err != nil || len(free.kept) != 0 {
		t.Errorf("keep unset: error %v, kept %d", err, len(free.kept))
	}
}

// T-S-19: a PAX 'x' header with one small record comes before an entry. Next
// of archive/tar gives an error, on a capReader with keep set. ReadArchive
// does not need its byte count for this. The kept bytes stay within maxKept.
func TestTS19PAXHeaderWithSmallRecordFailsInNext(t *testing.T) {
	tb := append(paxHdr(paxRec("mtime", "1")), rawHdr(markerPath, tar.TypeReg, 0)...)
	cr := &capReader{r: bytes.NewReader(append(tb, zeros(1024)...)), keep: true}
	hdr, err := tar.NewReader(cr).Next()
	if err == nil || hdr != nil {
		t.Errorf("Next gave header %v and error %v; want an error", hdr != nil, err)
	}
	if len(cr.kept) > maxKept {
		t.Errorf("kept %d bytes, at most %d", len(cr.kept), maxKept)
	}
}

// rawHdr makes one ustar header block. The Writer of archive/tar cannot make
// the headers that some fixtures need (a GNU.sparse. PAX record, a directory
// with a size, a header that claims data that is not there).
func rawHdr(name string, typ byte, size int64) []byte {
	b := make([]byte, 512)
	copy(b, name)
	copy(b[100:], "0000644\x00")
	copy(b[124:], fmt.Sprintf("%011o\x00", size))
	b[156] = typ
	copy(b[257:], "ustar\x0000")
	return withSum(b)
}

// withSum writes the checksum of the header block b into b.
func withSum(b []byte) []byte {
	copy(b[148:156], "        ")
	sum := 0
	for _, c := range b {
		sum += int(c)
	}
	copy(b[148:], fmt.Sprintf("%06o\x00 ", sum))
	return b
}

// padded fills b with zero bytes up to a multiple of the 512-byte block size.
func padded(b []byte) []byte {
	return append(b, zeros((512-len(b)%512)%512)...)
}

// paxRec makes one PAX record. The length field counts its own digits.
func paxRec(key, value string) string {
	n := len(key) + len(value) + 3
	for {
		s := strconv.Itoa(n) + " " + key + "=" + value + "\n"
		if len(s) == n {
			return s
		}
		n = len(s)
	}
}

// paxHdr makes a PAX 'x' header with the records, that applies to the next entry.
func paxHdr(recs ...string) []byte {
	body := strings.Join(recs, "")
	return append(rawHdr("PaxHeaders/x", tar.TypeXHeader, int64(len(body))), padded([]byte(body))...)
}

// sparseTar makes n regular entries, each with PAX sparse records (format
// 0.1), a logical size of MaxEntryBytes and no data in the stream.
func sparseTar(n int) []byte {
	var tb []byte
	for i := range n {
		name := "traps/s" + strconv.Itoa(i)
		tb = append(tb, paxHdr(
			paxRec("GNU.sparse.major", "0"),
			paxRec("GNU.sparse.minor", "1"),
			paxRec("GNU.sparse.name", name),
			paxRec("GNU.sparse.realsize", strconv.Itoa(MaxEntryBytes)),
			paxRec("GNU.sparse.numblocks", "1"),
			paxRec("GNU.sparse.map", "0,0"))...)
		tb = append(tb, rawHdr(name, tar.TypeReg, 0)...)
	}
	return append(tb, zeros(1024)...)
}

// sparseTar00 makes one regular entry with PAX sparse records (format 0.0),
// a logical size of MaxEntryBytes and one byte of data.
func sparseTar00() []byte {
	tb := paxHdr(
		paxRec("GNU.sparse.size", strconv.Itoa(MaxEntryBytes)),
		paxRec("GNU.sparse.numblocks", "1"),
		paxRec("GNU.sparse.offset", strconv.Itoa(MaxEntryBytes-1)),
		paxRec("GNU.sparse.numbytes", "1"),
		paxRec("GNU.sparse.map", strconv.Itoa(MaxEntryBytes-1)+",1"))
	tb = append(tb, rawHdr("traps/s0", tar.TypeReg, 1)...)
	tb = append(tb, padded([]byte("z"))...)
	return append(tb, zeros(1024)...)
}

// sparseOldTar makes one old GNU sparse entry (type 'S') with a real size of
// MaxEntryBytes.
func sparseOldTar() []byte {
	h := rawHdr("traps/s0", tar.TypeGNUSparse, 0)
	copy(h[257:], "ustar  \x00")
	copy(h[483:], fmt.Sprintf("%011o\x00", MaxEntryBytes))
	return append(withSum(h), zeros(1024)...)
}

// dirWithSize makes a directory header with a size. Its data is the header of
// a regular file and the data block of that file.
func dirWithSize() []byte {
	inner := append(rawHdr("traps/hidden", tar.TypeReg, 1), padded([]byte("h"))...)
	tb := append(rawHdr("traps/d/", tar.TypeDir, int64(len(inner))), inner...)
	return append(tb, zeros(1024)...)
}

// many makes n entries with distinct names: directories and empty files.
func many(n int) []ent {
	ents := make([]ent, n)
	for i := range ents {
		ents[i] = ent{name: "traps/e" + strconv.Itoa(i)}
		if i%2 == 0 {
			ents[i].typ = tar.TypeDir
		}
	}
	return ents
}

// validArchive makes the valid archive of the tests: a directory, a trap file
// and the manifest.
func validArchive() []byte {
	return build(
		ent{name: "traps/", typ: tar.TypeDir},
		ent{name: "traps/trap-fixture-1", data: []byte(markerData)},
		ent{name: "manifest.json", data: []byte(`{"version":"2026.01.01-1"}`)})
}

// sparse1x0 makes one regular entry with PAX sparse records (format 1.0), a
// logical size of MaxEntryBytes and the map in the data.
func sparse1x0() []byte {
	data := padded([]byte("1\n0\n1\n"))
	tb := paxHdr(
		paxRec("GNU.sparse.major", "1"),
		paxRec("GNU.sparse.minor", "0"),
		paxRec("GNU.sparse.name", "traps/s0"),
		paxRec("GNU.sparse.realsize", strconv.Itoa(MaxEntryBytes)))
	tb = append(tb, rawHdr("traps/s0", tar.TypeReg, int64(len(data))+1)...)
	tb = append(tb, data...)
	tb = append(tb, padded([]byte("z"))...)
	return append(tb, zeros(1024)...)
}

// longMtimeTar makes n empty regular entries. Each entry follows a PAX header
// with an mtime record of about 500 KiB. Next ignores the digits after the
// first nine of the fraction. ReadArchive refuses the first PAX header.
func longMtimeTar(n int) []byte {
	long := "1700000000." + strings.Repeat("1", 500<<10)
	var tb []byte
	for i := range n {
		tb = append(tb, paxHdr(paxRec("mtime", long))...)
		tb = append(tb, rawHdr(markerPath+strconv.Itoa(i), tar.TypeReg, 0)...)
	}
	return append(tb, zeros(1024)...)
}

// lenOf gives the length of a, or -1 for no archive. A failure message uses
// it, so that the message does not print the whole archive.
func lenOf(a *Archive) int {
	if a == nil {
		return -1
	}
	return a.Len()
}

type fixture struct {
	name string
	b    []byte
}

var (
	fixOnce    sync.Once
	failing    []fixture
	passing    []fixture
	validBytes []byte
)

// fixtures returns the failing and the passing archives, made once. The
// failing names and data hold the marker text where the case allows it.
func fixtures() (fail, pass []fixture) {
	fixOnce.Do(func() {
		file := func(n int) ent { return ent{name: markerPath, data: zeros(n)} }
		validBytes = validArchive()
		tarValid := buildTar(ent{name: markerPath, data: []byte(markerData)})
		flipped := slices.Clone(validBytes)
		flipped[len(flipped)-8] ^= 0xff
		dir := ent{name: markerPath, typ: tar.TypeDir}
		regular := ent{name: markerPath, data: []byte(markerData)}
		passing = []fixture{
			{"valid", validBytes},
			{"1024 entries", build(many(1024)...)},
			{"entry of 4 MiB", build(file(MaxEntryBytes))},
			{"data under the cap", build(file(3<<20), ent{name: "traps/b", data: zeros(3 << 20)})},
			{"zero bytes after the tar end", gz(append(slices.Clone(tarValid), zeros(4<<20)...))},
			{"decoded bytes at the cap", gz(append(slices.Clone(tarValid), zeros(MaxDecodedBytes-len(tarValid))...))},
		}
		failing = []fixture{
			{"data over the cap", build(file(3<<20), ent{name: "traps/b", data: zeros(3 << 20)}, ent{name: "traps/c", data: zeros(3 << 20)})},
			{"PAX headers with an mtime record of 500 KiB, 10 entries", gz(longMtimeTar(10))},
			{"1025 entries", build(many(1025)...)},
			{"entry over 4 MiB", build(file(MaxEntryBytes + 1))},
			{"non-zero byte after the tar end", gz(append(slices.Clone(tarValid), 'x'))},
			{"zero bytes after the tar end over the cap", gz(append(slices.Clone(tarValid), zeros(MaxDecodedBytes)...))},
			{"decoded bytes one past the cap", gz(append(slices.Clone(tarValid), zeros(MaxDecodedBytes+1-len(tarValid))...))},
			{"data that is not valid after the gzip stream", append(slices.Clone(validBytes), markerData...)},
			{"zero byte after the gzip stream", append(slices.Clone(validBytes), 0)},
			{"bad tar header", gz(bytes.Repeat([]byte(markerData), 64))},
			{"truncated stream", validBytes[:len(validBytes)-5]},
			{"bad checksum", flipped},
			{"not gzip", []byte(markerData)},
			{"empty input", nil},
			{"same name twice", build(regular, ent{name: markerPath, data: []byte("b")})},
			{"directory twice", build(dir, dir)},
			{"directory and file with the same name", build(dir, regular)},
			{"file and directory with the same name", build(regular, dir)},
			{"directory with a size", gz(dirWithSize())},
			{"sparse entry, format 0.1", gz(sparseTar(1))},
			{"sparse entry, format 0.0", gz(sparseTar00())},
			{"sparse entry, format 1.0", gz(sparse1x0())},
			{"sparse entry, old GNU type", gz(sparseOldTar())},
			{"sparse bomb of 16 entries", gz(sparseTar(16))},
		}
		for _, c := range entryCases() {
			failing = append(failing, fixture{c.name, c.bad})
			if c.twin != nil {
				passing = append(passing, fixture{"twin of " + c.name, c.twin})
			}
		}
		passing = append(passing, entryPassing()...)
	})
	return failing, passing
}

// T-S-19: a valid archive gives the sorted names and the bytes of the files.
func TestTS19ValidArchive(t *testing.T) {
	a, err := ReadArchive(validArchive())
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"manifest.json", "traps/trap-fixture-1"}; !slices.Equal(a.Names(), want) || a.Len() != 2 {
		t.Errorf("names %q, len %d; want %q", a.Names(), a.Len(), want)
	}
	if b, ok := a.File("manifest.json"); !ok || string(b) != `{"version":"2026.01.01-1"}` {
		t.Errorf("manifest.json: %q, %v", b, ok)
	}
	if _, ok := a.File("traps/"); ok {
		t.Error("a directory is an entry")
	}
	a.Names()[0] = "changed"
	if a.Names()[0] != "manifest.json" {
		t.Error("Names does not return a copy")
	}
}

// T-S-19: the caps accept the values at the cap.
func TestTS19AtTheCapsPasses(t *testing.T) {
	_, pass := fixtures()
	for _, f := range pass {
		if _, err := ReadArchive(f.b); err != nil {
			t.Errorf("%s: %v", f.name, err)
		}
	}
}

// T-S-19: each failure gives the one error value, and its text holds no input.
func TestTS19ArchiveInvalid(t *testing.T) {
	fail, _ := fixtures()
	for _, f := range fail {
		a, err := ReadArchive(f.b)
		if a != nil || err != ErrArchiveInvalid {
			t.Errorf("%s: archive %v, len %d, error %v", f.name, a != nil, lenOf(a), err)
			continue
		}
		if err.Error() != "bundle: archive_invalid" || strings.Contains(err.Error(), "marker") {
			t.Errorf("%s: error text %q", f.name, err.Error())
		}
	}
}

// T-S-19: a sparse entry gives an error. Each case holds one entry of 4 MiB,
// so the sum of the entry sizes does not refuse it. The format check refuses
// the PAX forms (0.0, 0.1 and 1.0). It also refuses the old GNU 'S' case,
// because its header has the GNU magic.
func TestTS19SparseEntryIsRefused(t *testing.T) {
	for name, tb := range map[string][]byte{
		"PAX format 0.1":   sparseTar(1),
		"PAX format 0.0":   sparseTar00(),
		"PAX format 1.0":   sparse1x0(),
		"old GNU type 'S'": sparseOldTar(),
	} {
		if a, err := ReadArchive(gz(tb)); a != nil || err != ErrArchiveInvalid {
			t.Errorf("%s: archive %v, len %d, error %v", name, a != nil, lenOf(a), err)
		}
	}
}

// allocated returns the bytes that ReadArchive allocates for b, and its error.
// runtime.GC runs first. TotalAlloc is the sum of all allocations, so it is an
// upper bound of the peak heap.
func allocated(b []byte) (uint64, error) {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	_, err := ReadArchive(b)
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc, err
}

// heapBound is the most that ReadArchive may allocate for the bomb: the two
// entries (7 MiB) plus a margin. TotalAlloc is an upper bound of the peak heap,
// so the peak heap is below it. The sum of the entry sizes is 7 MiB, so the
// decoded-byte cap is the check that fires, in the zero bytes after the tar
// end. A reader without that cap accepts the archive, and the error check
// fails.
const heapBound = 24 << 20

// T-S-19: a stream that decodes to more than 70 MiB, with 64 MiB of zero bytes
// after the tar end, gives an error. ReadArchive refuses it with the
// decoded-byte cap, and the allocation stays below the bound.
func TestTS19AllocationOfDecodedBytesBomb(t *testing.T) {
	bomb := gz(append(buildTar(
		ent{name: "traps/a", data: zeros(3584 << 10)},
		ent{name: "traps/b", data: zeros(3584 << 10)}), zeros(64<<20)...))
	grown, err := allocated(bomb)
	if err != ErrArchiveInvalid {
		t.Fatalf("error %v", err)
	}
	t.Logf("allocated %d bytes, bound %d bytes", grown, heapBound)
	if grown > heapBound {
		t.Errorf("allocated %d bytes, bound %d bytes", grown, heapBound)
	}
}

// sizesBound is the most that ReadArchive may allocate when the entry sizes
// pass the budget: two buffers that fill the budget, plus a margin. A reader
// that makes the buffer of the third entry first needs about 12 MiB.
const sizesBound = 10 << 20

// T-S-19: ReadArchive refuses a header that claims more than the rest of the
// budget before it makes the buffer of the entry.
func TestTS19EntrySizesPastBudget(t *testing.T) {
	tb := buildTar(
		ent{name: "traps/a", data: zeros(MaxEntryBytes)},
		ent{name: "traps/b", data: zeros(MaxEntryBytes - 2<<10)})
	tb = append(tb[:len(tb)-1024], rawHdr("traps/c", tar.TypeReg, MaxEntryBytes)...)
	if len(tb) > MaxDecodedBytes {
		t.Fatalf("fixture decodes to %d bytes", len(tb))
	}
	grown, err := allocated(gz(tb))
	if err != ErrArchiveInvalid {
		t.Fatalf("error %v", err)
	}
	t.Logf("allocated %d bytes, bound %d bytes", grown, sizesBound)
	if grown > sizesBound {
		t.Errorf("allocated %d bytes, bound %d bytes", grown, sizesBound)
	}
}

// recordsBound is the most that ReadArchive may allocate for a PAX header with
// records of about 1 MiB. It is the gzip reader and a margin. A reader that
// keeps the records needs over 1 MiB.
const recordsBound = 256 << 10

// T-S-19: a PAX 'x' header with an mtime record of about 1 MiB is refused
// before ReadArchive keeps its records. maxKept is the most that one Next call
// reads: padding of 511 bytes, and the two end blocks.
func TestTS19PAXHeaderWithLargeRecordsIsRefusedEarly(t *testing.T) {
	if maxKept != blockBytes-1+2*blockBytes {
		t.Errorf("maxKept %d; want %d", maxKept, blockBytes-1+2*blockBytes)
	}
	mtime := "1700000000." + strings.Repeat("1", 1<<20-200)
	tb := append(paxHdr(paxRec("mtime", mtime)), rawHdr(markerPath, tar.TypeReg, 0)...)
	grown, err := allocated(gz(append(tb, zeros(1024)...)))
	if err != ErrArchiveInvalid {
		t.Fatalf("error %v", err)
	}
	t.Logf("allocated %d bytes, bound %d bytes", grown, recordsBound)
	if grown > recordsBound {
		t.Errorf("allocated %d bytes, bound %d bytes", grown, recordsBound)
	}
}

// T-S-19: ReadArchive makes no file and no directory.
func TestTS19NoFileIsMade(t *testing.T) {
	fail, pass := fixtures()
	t.Chdir(t.TempDir())
	for _, f := range append(fail, pass...) {
		ReadArchive(f.b)
	}
	if names, err := os.ReadDir("."); err != nil || len(names) != 0 {
		t.Errorf("directory holds %d entries, error %v", len(names), err)
	}
}

// T-S-19: archive.go does not import os (or a path to the file system).
func TestTS19NoFileImports(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "archive.go", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	for _, imp := range f.Imports {
		switch imp.Path.Value {
		case `"os"`, `"path/filepath"`, `"io/fs"`, `"io/ioutil"`:
			t.Errorf("archive.go imports %s", imp.Path.Value)
		}
	}
}
