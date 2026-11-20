package reference

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/cybagard/cyba-phantom/internal/bundle"
)

// archiveEntry is a file of an archive: the name with "/" and the bytes.
type archiveEntry struct {
	name string
	data []byte
}

// treeEntries reads each regular file below dir, in the walk order of
// bundle-sign pack. The name is the path below dir with "/".
func treeEntries(dir string) ([]archiveEntry, error) {
	root := os.DirFS(dir)
	var out []archiveEntry
	err := fs.WalkDir(root, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("%s is not a regular file", p)
		}
		b, err := fs.ReadFile(root, p)
		out = append(out, archiveEntry{p, b})
		return err
	})
	return out, err
}

// packEntries makes an archive as bundle-sign pack does. It is a gzip stream
// of a tar. The headers are USTAR with mode 0644 and no mtime. The order of
// the entries is the order of the files.
func packEntries(files []archiveEntry) ([]byte, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for _, f := range files {
		hdr := &tar.Header{Name: f.name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(f.data)), Format: tar.FormatUSTAR}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, err
		}
		if _, err := tw.Write(f.data); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// archiveEntries reads the entries of an archive after the decompress. An entry
// that is not a regular file, and a name that repeats, are errors.
func archiveEntries(arch []byte) ([]archiveEntry, error) {
	zr, err := gzip.NewReader(bytes.NewReader(arch))
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(zr)
	var out []archiveEntry
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		if hdr.Typeflag != tar.TypeReg {
			return nil, fmt.Errorf("entry %q is not a regular file", hdr.Name)
		}
		if slices.ContainsFunc(out, func(e archiveEntry) bool { return e.name == hdr.Name }) {
			return nil, fmt.Errorf("entry %q repeats", hdr.Name)
		}
		b, err := io.ReadAll(tr)
		if err != nil {
			return nil, err
		}
		out = append(out, archiveEntry{hdr.Name, b})
	}
}

// archiveEqualsTree compares the entries of the archive arch with the files
// below dir. The names must be the same. The bytes of each file must be the
// same. The archive must have no other entry. The error names each difference.
// It is nil when the archive and the tree are equal. It takes the archive as
// bytes and the tree as a directory. So a test can run it on a committed
// archive file.
func archiveEqualsTree(arch []byte, dir string) error {
	got, err := archiveEntries(arch)
	if err != nil {
		return fmt.Errorf("archive: %w", err)
	}
	want, err := treeEntries(dir)
	if err != nil {
		return fmt.Errorf("tree: %w", err)
	}
	var diffs []string
	inTree := map[string]bool{}
	for _, w := range want {
		inTree[w.name] = true
		i := slices.IndexFunc(got, func(e archiveEntry) bool { return e.name == w.name })
		switch {
		case i < 0:
			diffs = append(diffs, "missing entry "+w.name)
		case !bytes.Equal(got[i].data, w.data):
			diffs = append(diffs, "changed bytes in "+w.name)
		}
	}
	for _, g := range got {
		if !inTree[g.name] {
			diffs = append(diffs, "extra entry "+g.name)
		}
	}
	if len(diffs) > 0 {
		return errors.New(strings.Join(diffs, "; "))
	}
	return nil
}

// TestTU29_ArchiveEntriesEqualTree checks that the archive of the source tree
// has the same entries as the tree (T-U-29, SEC-42). The test packs src/ as
// bundle-sign pack does. The reader of the engine accepts the archive. After
// the decompress, the entries have the names and the bytes of the files of
// src/, and no other entry. Three test copies each have a fault: one extra
// entry, one missing entry, or one changed byte. The compare finds each. The
// error names the entry.
func TestTU29_ArchiveEntriesEqualTree(t *testing.T) {
	const src = "src"
	files, err := treeEntries(src)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) < 3 {
		t.Fatalf("the tree has %d files; want at least the manifest, the seed and a trap file", len(files))
	}
	arch, err := packEntries(files)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bundle.ReadArchive(arch); err != nil {
		t.Fatalf("the reader of the engine refuses the archive: %v", err)
	}
	if err := archiveEqualsTree(arch, src); err != nil {
		t.Fatalf("archive of the tree: %v", err)
	}

	changed := slices.Clone(files)
	changed[1] = archiveEntry{files[1].name, slices.Clone(files[1].data)}
	changed[1].data[0] ^= 1
	copies := []struct {
		name  string
		files []archiveEntry
		want  string
	}{
		{"extra entry", append(slices.Clone(files), archiveEntry{"extra.txt", []byte("x")}), "extra entry extra.txt"},
		{"missing entry", slices.Delete(slices.Clone(files), 1, 2), "missing entry " + files[1].name},
		{"changed byte", changed, "changed bytes in " + files[1].name},
	}
	for _, c := range copies {
		t.Run(c.name, func(t *testing.T) {
			bad, err := packEntries(c.files)
			if err != nil {
				t.Fatal(err)
			}
			err = archiveEqualsTree(bad, src)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("compare: error %v; want one with %q", err, c.want)
			}
		})
	}
}
