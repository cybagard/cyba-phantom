//go:build linux

package store

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"unsafe"

	"github.com/cybagard/cyba-phantom/internal/safefile"
	"github.com/cybagard/cyba-phantom/internal/safefile/safefiletest"
)

// fdsOf counts the descriptors of the process that point to path. It reads
// /proc/self/fd.
func fdsOf(t *testing.T, path string) int {
	t.Helper()
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range ents {
		if to, err := os.Readlink("/proc/self/fd/" + e.Name()); err == nil && to == path {
			n++
		}
	}
	return n
}

// watchOpens watches path for opens, from now on. The returned function reads
// the queue without blocking and returns the number of open events it found.
// It also watches the closes, but it does not count them. The kernel joins
// equal events in a row that are not read yet. Without the close events, open,
// close, open would give one open event. A close between two opens keeps them
// apart. An open and a close keep the count of descriptors. They still leave an
// event here.
func watchOpens(t *testing.T, path string) func() int {
	t.Helper()
	fd, err := syscall.InotifyInit1(syscall.IN_NONBLOCK | syscall.IN_CLOEXEC)
	if err != nil {
		t.Fatalf("inotify: %v", err)
	}
	t.Cleanup(func() { syscall.Close(fd) })
	if _, err := syscall.InotifyAddWatch(fd, path, syscall.IN_OPEN|syscall.IN_CLOSE_NOWRITE|syscall.IN_CLOSE_WRITE); err != nil {
		t.Fatal(err)
	}
	return func() int {
		t.Helper()
		buf := make([]byte, 4096)
		n, err := syscall.Read(fd, buf)
		if err == syscall.EAGAIN {
			return 0
		}
		if err != nil {
			t.Fatal(err)
		}
		events := 0
		for off := 0; off+syscall.SizeofInotifyEvent <= n; {
			ev := (*syscall.InotifyEvent)(unsafe.Pointer(&buf[off]))
			if ev.Mask&syscall.IN_OPEN != 0 {
				events++
			}
			off += syscall.SizeofInotifyEvent + int(ev.Len)
		}
		return events
	}
}

// T-S-15: the checks of a connection open no descriptor of the database file.
// The close of any such descriptor would drop the locks of SQLite. The count of
// descriptors that point to the file is the same before and after the checks.
// Also, a watch on the file sees no open during the checks. An open that is
// closed again would keep the count. This holds also for a file below a parent
// directory.
func TestTS15ChecksOpenNoDescriptorOfDatabase(t *testing.T) {
	for _, rel := range []string{"events.db", "data/events.db"} {
		t.Run(rel, func(t *testing.T) {
			f := newFixture(t)
			if err := os.Mkdir(filepath.Join(f.state, "data"), 0o700); err != nil {
				t.Fatal(err)
			}
			held := holdHook(t)
			db := mustOpen(t, f.root, rel)
			defer db.Close()
			fi, err := (*held).Stat()
			if err != nil {
				t.Fatal(err)
			}
			id, _ := safefile.Identity(fi)
			path := filepath.Join(f.state, filepath.FromSlash(rel))
			c := &connector{root: f.root, rel: rel, want: path, id: id, held: *held}
			safefiletest.Set(t, safefiletest.Hooks{AfterCheck: func(name string) {
				if name == "events.db" {
					t.Error("a check opened the database file")
				}
			}})
			before := fdsOf(t, path)
			opens := watchOpens(t, path)
			if err := c.check(); err != nil {
				t.Fatal(err)
			}
			if after := fdsOf(t, path); before == 0 || after != before {
				t.Fatalf("%d descriptors of the database file before the checks, %d after", before, after)
			}
			if n := opens(); n != 0 {
				t.Fatalf("%d opens of the database file during the checks", n)
			}
		})
	}
}

// T-S-15: the file checks of Open open the database file one time only. That
// open is the one that Open holds for the life of the pool. The watch is read
// in the hook that gets the held descriptor. So it counts the earlier opens.
func TestTS15OpenChecksOpenTheDatabaseOnce(t *testing.T) {
	for _, rel := range []string{"events.db", "data/events.db"} {
		t.Run(rel, func(t *testing.T) {
			f := newFixture(t)
			if err := os.Mkdir(filepath.Join(f.state, "data"), 0o700); err != nil {
				t.Fatal(err)
			}
			mustOpen(t, f.root, rel).Close()
			opens := watchOpens(t, filepath.Join(f.state, filepath.FromSlash(rel)))
			n := -1
			held := holdHook(t)
			inner := onHeld
			setHook(t, &onHeld, func(h *os.File) { inner(h); n = opens() })
			setHook(t, &afterVerify, func() { opens() })
			db := mustOpen(t, f.root, rel)
			defer db.Close()
			if *held == nil || n != 1 {
				t.Fatalf("%d opens of the database file up to the held open, want 1", n)
			}
			if n := opens(); n != 0 {
				t.Fatalf("%d opens of the database file after the first connection", n)
			}
		})
	}
}

// T-S-15: when Open of a new file gets the held descriptor, one descriptor of
// the process points to the database file. Open has closed the descriptor that
// made the file. SQLite has not opened the file yet.
func TestTS15NewFileHasOneDescriptorAtHeldOpen(t *testing.T) {
	root, state, _ := newState(t)
	n := -1
	setHook(t, &onHeld, func(*os.File) { n = fdsOf(t, filepath.Join(state, "events.db")) })
	mustOpen(t, root, "events.db").Close()
	if n != 1 {
		t.Fatalf("%d descriptors of the new database file, want 1", n)
	}
}
