package store

import (
	"errors"
	"os"
	"syscall"
)

const (
	// pauseAt and resumeAt are the use limits of the disk guard (SEC-40). The
	// writer pauses at pauseAt or more. It writes again below resumeAt. A use
	// between the two keeps the state.
	pauseAt  = 0.90
	resumeAt = 0.85
)

// DiskGuard measures the use of the file systems of the state directory and of
// the log directory (SEC-40). It holds one open descriptor for each directory.
// A measure calls Fstatfs on these descriptors and does no path lookup. A
// guard is safe for concurrent use until Close.
type DiskGuard struct {
	dirs    []*os.File
	measure func(*os.File) (float64, error) // fdUse; a test sets another
}

// OpenDiskGuard opens the state directory and the directory tlogDir through
// root. tlogDir is relative to root. The caller closes the guard with Close.
func OpenDiskGuard(root *os.Root, tlogDir string) (*DiskGuard, error) {
	g := &DiskGuard{measure: fdUse}
	for _, name := range []string{".", tlogDir} {
		f, err := root.Open(name)
		if err != nil {
			g.Close()
			return nil, err
		}
		g.dirs = append(g.dirs, f)
	}
	return g, nil
}

// Close closes the descriptors. A measure after Close gives an error.
func (g *DiskGuard) Close() error {
	var errs []error
	for _, f := range g.dirs {
		errs = append(errs, f.Close())
	}
	return errors.Join(errs...)
}

// Use returns the highest value, between 0 and 1, of the block use and the
// inode use. It reads both directories. The block use is the used blocks
// over the used blocks plus the blocks that a normal user can take.
// The inode use counts only when the file system has inodes.
func (g *DiskGuard) Use() (float64, error) {
	var top float64
	for _, f := range g.dirs {
		u, err := g.measure(f)
		if err != nil {
			return 0, err
		}
		top = max(top, u)
	}
	return top, nil
}

// fdUse reads the use of the file system of f. It uses only fields that Linux
// and the other Unix systems have.
func fdUse(f *os.File) (use float64, err error) {
	c, err := f.SyscallConn()
	if err != nil {
		return 0, err
	}
	var st syscall.Statfs_t
	var serr error
	if err := c.Control(func(fd uintptr) { serr = syscall.Fstatfs(int(fd), &st) }); err != nil {
		return 0, err
	}
	if serr != nil {
		return 0, serr
	}
	return fsUse(uint64(st.Blocks), uint64(st.Bfree), uint64(st.Bavail), uint64(st.Files), uint64(st.Ffree)), nil
}

// fsUse is the higher of the block use and the inode use. A file system with
// no blocks, or with no inode count, adds no value for that part.
func fsUse(blocks, bfree, bavail, files, ffree uint64) float64 {
	var top float64
	if used := blocks - min(bfree, blocks); used+bavail > 0 {
		top = float64(used) / float64(used+bavail)
	}
	if files > 0 {
		top = max(top, float64(files-min(ffree, files))/float64(files))
	}
	return top
}

// SetDiskGuard makes the writer pause at 90 % use and write again below 85 %.
// While paused, the writer writes no event row and calls no appender. It
// drops the events of both lanes with a count. The pause is not a stop.
// Healthy and Err do not change, and no stop marker is made. A retention run
// still runs. The caller calls SetDiskGuard one time, before Run. A writer
// with no guard never pauses.
func (w *Writer) SetDiskGuard(g *DiskGuard) {
	if g != nil {
		w.disk = g.Use
	}
}

// Paused tells if the writer is in the pause of the disk guard. It is safe to
// call from any goroutine.
func (w *Writer) Paused() bool { return w.paused.Load() }

// DiskCheckErrors returns the number of disk use checks that failed. It is safe
// to call from any goroutine.
func (w *Writer) DiskCheckErrors() uint64 { return w.diskErrors.Load() }

// diskPaused measures the use and gives the pause state. A failed measure keeps
// the last state, counts the error, and logs the first one with a fixed text.
func (w *Writer) diskPaused() bool {
	if w.disk == nil {
		return false
	}
	use, err := w.disk()
	if err != nil {
		w.diskErrors.Add(1)
		if w.diskErrLogged.CompareAndSwap(false, true) {
			w.log.Error("store writer disk check failed")
		}
		return w.paused.Load()
	}
	switch paused := w.paused.Load(); {
	case !paused && use >= pauseAt:
		w.paused.Store(true)
		w.log.Warn("store writer paused: disk use is high")
	case paused && use < resumeAt:
		w.paused.Store(false)
		w.log.Info("store writer resumed: disk use is low")
	}
	return w.paused.Load()
}
