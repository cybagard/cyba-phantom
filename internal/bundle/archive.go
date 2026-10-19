// Package bundle reads a bundle archive (SEC-23, FR-02). The archive is a tar
// stream that gzip compresses. The package treats the archive as untrusted
// input. It reads the archive from memory and keeps each entry in memory. It
// makes no file and no directory for an entry, and it does not import os.
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
// output of the gzip reader. It includes the tar headers, the PAX records,
// the padding and the zero bytes after the end of the tar.
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
	// ReadArchive sets keep for one Next call, so kept holds at most maxKept
	// bytes: the padding of the previous entry, two header blocks, the PAX data
	// that archive/tar caps at 1 MiB, and the end blocks.
	keep bool
	kept []byte
}

// maxKept is the most bytes that the Next call of one entry can read.
const maxKept = 3*blockBytes + 1<<20

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

// ReadArchive reads the archive in b. Each entry has one header block. It can
// have one PAX 'x' header before it, and no other meta header. Type NUL is a
// regular file, or a directory when the name ends in a slash.
//
// ReadArchive checks the header bytes of each entry. It then checks the header
// format, the type, the link name, the PAX records, the name and the top-level
// name. The byte count refuses a GNU long name or long link header, because
// Next reads its data as extra bytes. It also refuses sparse format 1.0, for
// the same reason. The format check refuses a GNU header and a STAR header.
// The check of the PAX records refuses a GNU.sparse. record. Next gives a
// sparse entry its logical size, and the hole bytes do not pass through the
// decoded-byte count. A directory has no data and no effect, but it counts
// toward MaxEntries.
//
// ReadArchive keeps the bytes that each Next call reads and checks their form
// (rawFormOK). The tar end is the padding of the last entry and exactly two
// zero blocks.
//
// ReadArchive also refuses:
//   - two entries, files and directories together, whose names are equal or
//     differ only in case or in a trailing slash;
//   - two entries whose names are equal in the same way for a reader that does
//     not read PAX records (ustarSeenKey);
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
	seenUstar := make(map[string]bool)
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
		// Next keeps only the last PAX 'x' header and leaves no trace of an
		// earlier one. Another tar implementation can take its name from that
		// header. So the bytes that this Next call read must match the bytes of
		// one header. This needs archive/tar to read the header blocks and the
		// PAX data exactly, with no read-ahead, from a source that is not an
		// io.Seeker. The capReader is such a source. If a Go change adds a
		// buffer, every archive fails, and the tests that use tar.Writer show it.
		if int64(len(cr.kept)) != headerBytes(prevPad, hdr) {
			return nil, ErrArchiveInvalid
		}
		padBefore := prevPad
		prevPad = 0
		if hdr.Typeflag == tar.TypeReg {
			prevPad = (blockBytes - hdr.Size%blockBytes) % blockBytes
		}
		key, err := checkEntry(hdr)
		if err != nil || !rawFormOK(cr.kept, padBefore, hdr) {
			return nil, ErrArchiveInvalid
		}
		ustarKey := ustarSeenKey(hdr)
		if seen[key] || seenUstar[ustarKey] {
			return nil, ErrArchiveInvalid
		}
		// Only the files map outlives ReadArchive. The clones of the keys let
		// the seen maps hold no PAX buffer, so the peak heap in the loop stays
		// small.
		seen[strings.Clone(key)] = true
		seenUstar[strings.Clone(ustarKey)] = true
		if hdr.Typeflag == tar.TypeDir {
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
