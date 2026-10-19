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

// ReadArchive reads the archive in b. It accepts regular files (type 0) and
// directories (type 5). A directory has no effect, but it counts toward
// MaxEntries. After the end of the tar, only zero bytes can follow, and the
// gzip stream must end. Every failure gives ErrArchiveInvalid. The function
// does not keep b, and it opens no file.
func ReadArchive(b []byte) (*Archive, error) {
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, ErrArchiveInvalid
	}
	defer zr.Close()
	cr := &capReader{r: zr}
	tr := tar.NewReader(cr)
	files := make(map[string][]byte)
	for n := 0; ; n++ {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil || n >= MaxEntries {
			return nil, ErrArchiveInvalid
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
		case tar.TypeReg:
			if _, dup := files[hdr.Name]; dup || hdr.Size > MaxEntryBytes {
				return nil, ErrArchiveInvalid
			}
			// The size is within the cap, so the buffer has the right size at
			// once. The limit reader is a second bound on the read.
			data := make([]byte, hdr.Size)
			if _, err := io.ReadFull(io.LimitReader(tr, MaxEntryBytes+1), data); err != nil {
				return nil, ErrArchiveInvalid
			}
			files[hdr.Name] = data
		default:
			return nil, ErrArchiveInvalid
		}
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
