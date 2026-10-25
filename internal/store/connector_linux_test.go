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
// open is the one that Open holds for the life of the pool. For an existing
// file, the watch is read in the hook that gets the held descriptor. It counts
// the earlier opens. For a new file, the watch starts in that hook. A hook
// reads the watch again right after the driver opens the first connection. So
// the opens of the driver are not counted. After Open returns, the watch counts
// 0 opens: no later check of Open opens the file.
func TestTS15OpenChecksOpenTheDatabaseOnce(t *testing.T) {
	rows := []struct {
		name, rel string
		exists    bool
		wantHeld  int // the opens up to the hook that gets the held descriptor
	}{
		{"events.db", "events.db", true, 1},
		{"data/events.db", "data/events.db", true, 1},
		{"new file", "events.db", false, 0},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			root, state, _ := newState(t)
			if err := os.Mkdir(filepath.Join(state, "data"), 0o700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(state, filepath.FromSlash(r.rel))
			var opens func() int
			if r.exists {
				mustOpen(t, root, r.rel).Close()
				opens = watchOpens(t, path)
			}
			n := -1
			held := holdHook(t)
			inner := onHeld
			setHook(t, &onHeld, func(h *os.File) {
				inner(h)
				if opens == nil {
					opens = watchOpens(t, path)
				}
				n = opens()
			})
			setHook(t, &afterDriverOpen, func() { opens() })
			db := mustOpen(t, root, r.rel)
			defer db.Close()
			if *held == nil || n != r.wantHeld {
				t.Fatalf("%d opens of the database file up to the held open, want %d", n, r.wantHeld)
			}
			if n := opens(); n != 0 {
				t.Fatalf("%d opens of the database file after the first connection", n)
			}
		})
	}
}

// T-S-15: Open of a new file gets the held descriptor. At that time, one
// descriptor of the process points to the database file. Open has closed the
// descriptor that made the file. SQLite has not opened the file yet.
func TestTS15NewFileHasOneDescriptorAtHeldOpen(t *testing.T) {
	root, state, _ := newState(t)
	n := -1
	setHook(t, &onHeld, func(*os.File) { n = fdsOf(t, filepath.Join(state, "events.db")) })
	mustOpen(t, root, "events.db").Close()
	if n != 1 {
		t.Fatalf("%d descriptors of the new database file, want 1", n)
	}
}

// T-S-15: a refused open of a new file leaves no descriptor. The hook swaps
// the made file for another file. Open refuses, and the process holds no
// descriptor of either file. When refuse runs, the create descriptor of the
// made file is still open.
func TestTS15RefusedNewFileLeavesNoDescriptor(t *testing.T) {
	root, state, _ := newState(t)
	file := filepath.Join(state, "events.db")
	swapMadeFile(t, file)
	made := -1
	setHook(t, &beforeRefuse, func() { made = fdsOf(t, file+".moved") })
	db, err := Open(root, "events.db", Options{})
	if db != nil {
		db.Close()
	}
	if err == nil {
		t.Fatal("Open worked with a swapped file")
	}
	if made != 1 {
		t.Fatalf("%d descriptors of the made file when refuse runs, want 1", made)
	}
	for _, p := range []string{file, file + ".moved"} {
		if n := fdsOf(t, p); n != 0 {
			t.Fatalf("%d descriptors of %s after the refusal, want 0", n, filepath.Base(p))
		}
	}
}
