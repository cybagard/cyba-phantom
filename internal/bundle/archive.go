// Package bundle reads a bundle archive (SEC-23, FR-02). The archive is a tar
// stream that gzip compresses. The package treats the archive as untrusted
// input. It reads the archive from memory and keeps each entry in memory. It
// makes no file and no directory for an entry, and it does not import os. The
// package also parses the manifest of a bundle and checks it (manifest.go).
//
// The errors of this package are fixed values. They hold no input bytes. The
// package does not wrap an error from another package and does not return
// one, because the text of that error can hold input bytes. Callers test
// errors with errors.Is.
package bundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"slices"
	"strings"
)

// The caps of an archive, in bytes or in entries. MaxDecodedBytes counts the
// output of the gzip reader. It includes the tar headers, the padding and the
// zero bytes after the end of the tar.
const (
	MaxDecodedBytes = 8 << 20
	MaxEntries      = 1024
	MaxEntryBytes   = 4 << 20
)

// ErrArchiveInvalid is the one error of ReadArchive. Every failure gives
// exactly this value.
var ErrArchiveInvalid = errors.New("bundle: archive_invalid")

// Archive holds the regular files of an archive, with the sorted names.
type Archive struct {
	files map[string][]byte
	names []string
}

// Names returns a copy of the sorted entry names.
func (a *Archive) Names() []string { return slices.Clone(a.names) }

// File returns the bytes of the entry with this name. The caller must not
// change the bytes.
func (a *Archive) File(name string) ([]byte, bool) {
	b, ok := a.files[name]
	return b, ok
}

// Len returns the number of entries in the archive.
func (a *Archive) Len() int { return len(a.files) }

// capReader reads from r and gives ErrArchiveInvalid when it has read more
// than MaxDecodedBytes. It never asks r for more than one byte past the cap.
type capReader struct {
	r io.Reader
	n int64
	// While keep is set, the reader appends the bytes that it passes to kept.
	// Before an append that would pass maxKept, Read gives ErrArchiveInvalid.
	// So kept never holds more than maxKept bytes.
	keep bool
	kept []byte
}

// maxKept is the most bytes that ReadArchive accepts from one Next call. A
// Next call that reads an entry reads the padding of the previous entry. That
// is at most 511 bytes. It also reads one header block. A Next call that reads
// the tar end reads that padding and the two end blocks. The header block and
// the end blocks are never in the same call. A call that reads more than
// maxKept bytes gives ErrArchiveInvalid. So ReadArchive refuses a PAX header
// with large records before it keeps them.
const maxKept = blockBytes - 1 + 2*blockBytes

func (c *capReader) Read(p []byte) (int, error) {
	if c.n > MaxDecodedBytes {
		return 0, ErrArchiveInvalid
	}
	if room := MaxDecodedBytes - c.n + 1; int64(len(p)) > room {
		p = p[:room]
	}
	n, err := c.r.Read(p)
	c.n += int64(n)
	if c.n > MaxDecodedBytes {
		return n, ErrArchiveInvalid
	}
	if c.keep {
		if len(c.kept)+n > maxKept {
			return n, ErrArchiveInvalid
		}
		c.kept = append(c.kept, p[:n]...)
	}
	return n, err
}

// ReadArchive reads the archive in b. The archive has the USTAR form only.
// Each entry has one header block, and no meta header before it. The type byte
// of an entry is '0' (regular file) or '5' (directory). ReadArchive refuses
// type NUL.
//
// ReadArchive checks the header bytes of each entry. It then checks the header
// format, the type, the link name, the name and the top-level name. The byte
// count refuses a PAX header, a GNU long name header and a GNU long link
// header. It also refuses sparse format 1.0. Next reads their data as extra
// bytes. The format check refuses a PAX header, a GNU header and a STAR
// header. Next gives a sparse entry its logical size. The hole bytes do not
// pass through the decoded-byte count. A directory has no data and no effect,
// but it counts toward MaxEntries.
//
// ReadArchive keeps the bytes that each Next call reads and checks their form
// (rawFormOK). The tar end is the padding of the last entry and exactly two
// zero blocks.
//
// ReadArchive also refuses:
//   - two entries, files and directories together, whose names are equal or
//     differ only in case or in a trailing slash;
//   - a regular file that is the parent of another entry, as a file traps/a
//     and an entry traps/a/b. The order does not matter. The directory
//     entries between them can be absent. Case does not count (tree);
//   - a directory with a size;
//   - an archive where the sum of the regular entry sizes passes
//     MaxDecodedBytes.
//
// After the end of the tar, only zero bytes can follow until the end of the
// gzip data. ReadArchive reads further gzip members as the standard library
// reads them, and each further member must hold only zero bytes. Every
// failure gives ErrArchiveInvalid. The function does not keep b, and it opens
// no file.
func ReadArchive(b []byte) (*Archive, error) {
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, ErrArchiveInvalid
	}
	defer zr.Close()
	cr := &capReader{r: zr}
	tr := tar.NewReader(cr)
	files := make(map[string][]byte)
	seen := make(map[string]bool)
	layout := &tree{files: make(map[string]bool), parents: make(map[string]bool)}
	var sizes, prevPad int64
	for n := 0; ; n++ {
		cr.kept, cr.keep = cr.kept[:0], true
		hdr, err := tr.Next()
		cr.keep = false
		if err == io.EOF {
			// The end is the padding of the last entry and two zero blocks.
			if int64(len(cr.kept)) != prevPad+2*blockBytes {
				return nil, ErrArchiveInvalid
			}
			break
		}
		if err != nil || n >= MaxEntries {
			return nil, ErrArchiveInvalid
		}
		// Next skips a meta header and leaves no trace of it. Another tar
		// implementation can take a name from that header. So the bytes that
		// this Next call read must be the padding of the previous entry and
		// one header block. This needs archive/tar to read the header block
		// exactly, with no read-ahead, from a source that is not an
		// io.Seeker. The capReader is such a source. If a Go change adds a
		// buffer, every archive fails. The tests that use tar.Writer show it.
		if int64(len(cr.kept)) != prevPad+blockBytes {
			return nil, ErrArchiveInvalid
		}
		prevPad = 0
		if hdr.Typeflag == tar.TypeReg {
			prevPad = (blockBytes - hdr.Size%blockBytes) % blockBytes
		}
		key, err := checkEntry(hdr)
		if err != nil || !rawFormOK(cr.kept[len(cr.kept)-blockBytes:]) {
			return nil, ErrArchiveInvalid
		}
		isDir := hdr.Typeflag == tar.TypeDir
		if seen[key] || !layout.add(key, isDir) {
			return nil, ErrArchiveInvalid
		}
		seen[key] = true
		if isDir {
			if hdr.Size != 0 {
				return nil, ErrArchiveInvalid
			}
			continue
		}
		if hdr.Size > MaxEntryBytes {
			return nil, ErrArchiveInvalid
		}
		// The sum of the sizes bounds the memory of the entries, also when
		// the reader makes more bytes than the stream holds.
		sizes += hdr.Size
		if sizes > MaxDecodedBytes {
			return nil, ErrArchiveInvalid
		}
		// The size is within the cap, so the buffer has the right size at
		// once. The limit reader is a second bound on the read.
		data := make([]byte, hdr.Size)
		if _, err := io.ReadFull(io.LimitReader(tr, MaxEntryBytes+1), data); err != nil {
			return nil, ErrArchiveInvalid
		}
		files[strings.Clone(hdr.Name)] = data
	}
	rest := make([]byte, 4096)
	for {
		n, err := cr.Read(rest)
		if bytes.Count(rest[:n], []byte{0}) != n {
			return nil, ErrArchiveInvalid
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, ErrArchiveInvalid
		}
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	slices.Sort(names)
	return &Archive{files: files, names: names}, nil
}
