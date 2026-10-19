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
}

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
	return n, err
}

// ReadArchive reads the archive in b. The Next function of archive/tar reads
// the PAX 'x' headers and the GNU 'L' and 'K' headers itself and applies them
// to the next entry. It reads type NUL as a regular file or a directory.
// ReadArchive checks each header that Next returns with checkEntry: the type,
// the link name, the PAX records, the name and the top-level name. A header
// with a GNU.sparse. PAX record fails there, because Next gives such an entry
// its logical size, and the hole bytes do not pass through the decoded-byte
// count. A directory has no data and no effect, but it counts toward
// MaxEntries.
//
// ReadArchive also refuses:
//   - two entries, files and directories together, whose names are equal or
//     differ only in case or in a trailing slash;
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
	var sizes int64
	for n := 0; ; n++ {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil || n >= MaxEntries {
			return nil, ErrArchiveInvalid
		}
		key, err := checkEntry(hdr)
		if err != nil || seen[key] {
			return nil, ErrArchiveInvalid
		}
		// A name from a PAX path record points into the PAX buffer. The
		// clone lets the maps keep the name without that buffer.
		seen[strings.Clone(key)] = true
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
