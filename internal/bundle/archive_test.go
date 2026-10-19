package bundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"go/parser"
	"go/token"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// Marker text for the tests that check the error text. It is stale text only.
const (
	markerName = "marker-name-7f3a"
	markerData = "marker-data-91c2"
)

// ent is one tar entry of a fixture. typ 0 means a regular file.
type ent struct {
	name string
	typ  byte
	data []byte
	pax  map[string]string
}

// buildTar makes the tar bytes of the entries, with the end blocks.
func buildTar(t testing.TB, ents ...ent) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range ents {
		if e.typ == 0 {
			e.typ = tar.TypeReg
		}
		h := &tar.Header{Name: e.name, Typeflag: e.typ, Mode: 0o644, PAXRecords: e.pax}
		switch e.typ {
		case tar.TypeReg:
			h.Size = int64(len(e.data))
		case tar.TypeSymlink:
			h.Linkname = "target"
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(e.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func gz(t testing.TB, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.BestSpeed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := zw.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func build(t testing.TB, ents ...ent) []byte { return gz(t, buildTar(t, ents...)) }

func zeros(n int) []byte { return make([]byte, n) }

// many makes n entries with distinct names: directories and empty files.
func many(n int) []ent {
	ents := make([]ent, n)
	for i := range ents {
		ents[i] = ent{name: "e" + strconv.Itoa(i)}
		if i%2 == 0 {
			ents[i].typ = tar.TypeDir
		}
	}
	return ents
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
func fixtures(t testing.TB) (fail, pass []fixture) {
	t.Helper()
	fixOnce.Do(func() {
		file := func(n int) ent { return ent{name: markerName, data: zeros(n)} }
		validBytes = build(t,
			ent{name: "traps/", typ: tar.TypeDir},
			ent{name: "traps/trap-fixture-1", data: []byte(markerData)},
			ent{name: "manifest.json", data: []byte(`{"version":"2026.01.01-1"}`)})
		tarValid := buildTar(t, ent{name: markerName, data: []byte(markerData)})
		flipped := slices.Clone(validBytes)
		flipped[len(flipped)-8] ^= 0xff
		bigPax := map[string]string{"comment": strings.Repeat("x", 500<<10)}
		var headers []ent
		for i := range 20 {
			headers = append(headers, ent{name: markerName + strconv.Itoa(i), pax: bigPax})
		}
		passing = []fixture{
			{"valid", validBytes},
			{"1024 entries", build(t, many(1024)...)},
			{"entry of 4 MiB", build(t, file(MaxEntryBytes))},
			{"data under the cap", build(t, file(3<<20), ent{name: "b", data: zeros(3 << 20)})},
			{"headers under the cap", build(t, headers[:10]...)},
			{"zero bytes after the tar end", gz(t, append(slices.Clone(tarValid), zeros(4<<20)...))},
		}
		failing = []fixture{
			{"data over the cap", build(t, file(3<<20), ent{name: "b", data: zeros(3 << 20)}, ent{name: "c", data: zeros(3 << 20)})},
			{"headers over the cap", build(t, headers...)},
			{"1025 entries", build(t, many(1025)...)},
			{"entry over 4 MiB", build(t, file(MaxEntryBytes+1))},
			{"non-zero byte after the tar end", gz(t, append(slices.Clone(tarValid), 'x'))},
			{"zero bytes after the tar end over the cap", gz(t, append(slices.Clone(tarValid), zeros(MaxDecodedBytes)...))},
			{"junk after the gzip stream", append(slices.Clone(validBytes), markerData...)},
			{"zero byte after the gzip stream", append(slices.Clone(validBytes), 0)},
			{"bad tar header", gz(t, bytes.Repeat([]byte(markerData), 64))},
			{"truncated stream", validBytes[:len(validBytes)-5]},
			{"bad checksum", flipped},
			{"not gzip", []byte(markerData)},
			{"empty input", nil},
			{"symlink", build(t, ent{name: markerName, typ: tar.TypeSymlink})},
			{"fifo", build(t, ent{name: markerName, typ: tar.TypeFifo})},
			{"same name twice", build(t, ent{name: markerName, data: []byte("a")}, ent{name: markerName, data: []byte("b")})},
		}
	})
	return failing, passing
}

// T-S-19: a valid archive gives the sorted names and the bytes of the files.
func TestTS19ValidArchive(t *testing.T) {
	a, err := ReadArchive(build(t,
		ent{name: "traps/", typ: tar.TypeDir},
		ent{name: "traps/trap-fixture-1", data: []byte("trap-fixture-1")},
		ent{name: "manifest.json", data: []byte(`{"version":"2026.01.01-1"}`)}))
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
	_, pass := fixtures(t)
	for _, f := range pass {
		if _, err := ReadArchive(f.b); err != nil {
			t.Errorf("%s: %v", f.name, err)
		}
	}
}

// T-S-19: each failure gives the one error value, and its text holds no input.
func TestTS19ArchiveInvalid(t *testing.T) {
	fail, _ := fixtures(t)
	for _, f := range fail {
		a, err := ReadArchive(f.b)
		if a != nil || err != ErrArchiveInvalid {
			t.Errorf("%s: got %v, %v", f.name, a, err)
			continue
		}
		if err.Error() != "bundle: archive_invalid" || strings.Contains(err.Error(), "marker") {
			t.Errorf("%s: error text %q", f.name, err.Error())
		}
	}
}

// heapBound is the most that ReadArchive may allocate for the bomb: the cap
// (8 MiB) plus the entry that crosses it (3.5 MiB) plus slack. A reader with
// the entry cap only reads 70 MiB, so it fails this bound.
const heapBound = 24 << 20

// T-S-19: a stream that decodes to 70 MiB, in entries below the entry cap, is
// refused before the memory grows past the bound.
func TestTS19HeapOfDecodedBytesBomb(t *testing.T) {
	ents := make([]ent, 20)
	for i := range ents {
		ents[i] = ent{name: "e" + strconv.Itoa(i), data: zeros(3584 << 10)}
	}
	bomb := build(t, ents...)
	ents = nil
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	_, err := ReadArchive(bomb)
	runtime.ReadMemStats(&after)
	if err != ErrArchiveInvalid {
		t.Fatalf("error %v", err)
	}
	grown := after.TotalAlloc - before.TotalAlloc
	t.Logf("allocated %d bytes, bound %d bytes", grown, heapBound)
	if grown > heapBound {
		t.Errorf("allocated %d bytes, bound %d bytes", grown, heapBound)
	}
}

// T-S-19: ReadArchive makes no file and no directory.
func TestTS19NoFileIsMade(t *testing.T) {
	fail, pass := fixtures(t)
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
