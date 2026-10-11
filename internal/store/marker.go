package store

import (
	"errors"
	"io/fs"
	"os"
)

// markerName is the stop marker: an empty file in the state directory. Only the
// operator removes it.
const markerName = "writer.stop"

const (
	ruleMarkerExists = "stop marker exists"
	ruleMarkerRead   = "stop marker cannot be examined"
)

// checkMarker refuses a start while the marker exists. Lstat does not follow a
// link, so a symlink, a directory, or any other type is a marker. An error that
// is not "does not exist" also refuses the start.
func checkMarker(root *os.Root) error {
	switch _, err := root.Lstat(markerName); {
	case err == nil:
		return fail(writerName, ruleMarkerExists)
	case !errors.Is(err, fs.ErrNotExist):
		return fail(writerName, ruleMarkerRead)
	}
	return nil
}

// makeMarker makes the marker if it is absent. A marker that exists is a
// success. When it makes the file, it calls fsync on the file. It always calls
// fsync on the directory. A nil root is an error.
func makeMarker(root *os.Root) error {
	if root == nil {
		return errors.New("no state directory")
	}
	f, err := root.OpenFile(markerName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err == nil {
		err = f.Sync()
		if e := f.Close(); err == nil {
			err = e
		}
	} else if errors.Is(err, fs.ErrExist) {
		err = nil
	}
	if err != nil {
		return err
	}
	d, err := root.Open(".")
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// ensureMarker makes the marker once. If it fails, it logs one line, and the
// next call tries again. A failure keeps the stop in memory only.
func (w *Writer) ensureMarker() {
	if w.markerMade.Load() {
		return
	}
	if makeMarker(w.rec.State) != nil {
		if w.markerLogged.CompareAndSwap(false, true) {
			w.log.Error("store writer cannot make the stop marker", "name", markerName)
		}
		return
	}
	w.markerMade.Store(true)
}
