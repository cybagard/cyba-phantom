package tlog

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/note"
)

var spoolTargets = []string{"https://a.test/put", "https://b.test/put"}

// fakeSender records the sizes for each target. failAt makes one size fail for
// a target until the test clears it.
type fakeSender struct {
	got    map[string][]uint64
	failAt map[string]uint64
}

func (f *fakeSender) Send(target string, size uint64, _ []byte) error {
	if n, ok := f.failAt[target]; ok && n == size {
		return errors.New("target down")
	}
	f.got[target] = append(f.got[target], size)
	return nil
}

func newFake() *fakeSender {
	return &fakeSender{got: map[string][]uint64{}, failAt: map[string]uint64{}}
}

type spoolEnv struct {
	*Spool
	dir      string
	signer   note.Signer
	verifier note.Verifier
	logs     *bytes.Buffer
}

func newSpool(t *testing.T) *spoolEnv {
	t.Helper()
	root, dir := newState(t)
	signer, verifier := noteKeys(t, testOrigin, 1)
	log, buf := testLogger()
	sp, err := OpenSpool(root, log, testOrigin, verifier, spoolTargets)
	must(t, err)
	return &spoolEnv{sp, dir, signer, verifier, buf}
}

// add signs and stores a note of the given size.
func (e *spoolEnv) add(t *testing.T, size uint64) {
	t.Helper()
	msg, err := SignCheckpoint(e.signer, size, testRoot())
	must(t, err)
	must(t, e.Add(size, msg))
}

// files lists the sizes of the notes on disk.
func (e *spoolEnv) files(t *testing.T) []uint64 {
	t.Helper()
	sizes, err := e.sizes()
	must(t, err)
	return sizes
}

// T-I-09: each note is checkpoints/<size>.note with mode 0600 in a 0700
// directory, and no temporary file stays, even after a crash left one.
func TestTI09_SpoolFiles(t *testing.T) {
	e := newSpool(t)
	must(t, os.WriteFile(filepath.Join(e.dir, spoolDir, "7.note.tmp"), []byte("left by a crash"), 0o600))
	e.add(t, 7)
	want, err := SignCheckpoint(e.signer, 7, testRoot())
	must(t, err)
	got, err := os.ReadFile(filepath.Join(e.dir, "checkpoints", "7.note"))
	must(t, err)
	if !bytes.Equal(got, want) {
		t.Fatal("note on disk differs from the signed note")
	}
	for path, mode := range map[string]os.FileMode{"checkpoints": 0o700, "checkpoints/7.note": 0o600} {
		if fi, err := os.Stat(filepath.Join(e.dir, path)); err != nil || fi.Mode().Perm() != mode {
			t.Fatalf("%s: mode %v, err %v, want %v", path, fi.Mode().Perm(), err, mode)
		}
	}
	entries, err := os.ReadDir(filepath.Join(e.dir, "checkpoints"))
	must(t, err)
	if len(entries) != 1 {
		t.Fatalf("spool has %d entries, want only 7.note", len(entries))
	}
}

// T-I-09: for each target the notes come out in increasing size after the
// cursor; the cursor moves only on success; a target that fails does not stop the
// other target; the cursor file is checkpoints/target-<16 hex of SHA-256>.
func TestTI09_OrderAndCursor(t *testing.T) {
	e := newSpool(t)
	for _, size := range []uint64{4, 2, 5, 1, 3} { // not in order
		e.add(t, size)
	}
	f := newFake()
	f.failAt[spoolTargets[0]] = 3
	if err := e.Publish(0, f); err == nil {
		t.Fatal("Publish hid the error of the sender")
	}
	must(t, e.Publish(1, f))
	if !slices.Equal(f.got[spoolTargets[0]], []uint64{1, 2}) || !slices.Equal(f.got[spoolTargets[1]], []uint64{1, 2, 3, 4, 5}) {
		t.Fatalf("sent = %v", f.got)
	}
	b, err := os.ReadFile(filepath.Join(e.dir, e.cursorName(0)))
	must(t, err)
	if string(b) != "2" || !strings.HasPrefix(e.cursorName(0), "checkpoints/target-") || len(e.cursorName(0)) != len("checkpoints/target-")+16 {
		t.Fatalf("cursor file %q has %q, want 2", e.cursorName(0), b)
	}
	if want := []uint64{3, 4, 5}; !slices.Equal(e.files(t), want) {
		t.Fatalf("notes on disk = %v, want %v (2 and 1 published by every target)", e.files(t), want)
	}

	delete(f.failAt, spoolTargets[0])
	must(t, e.Publish(0, f))
	must(t, e.Publish(0, f)) // nothing new: never a size <= cursor
	if !slices.Equal(f.got[spoolTargets[0]], []uint64{1, 2, 3, 4, 5}) {
		t.Fatalf("target 0 sent = %v", f.got[spoolTargets[0]])
	}
	if !slices.Equal(e.files(t), []uint64{5}) {
		t.Fatalf("notes on disk = %v, want only the newest", e.files(t))
	}
}

// T-I-09: the spool holds at most 1025 notes. The oldest note goes first and
// counts as skipped for each target below its size, with one log line each hour.
func TestTI09_Bound(t *testing.T) {
	e := newSpool(t)
	e.add(t, 1)
	e.add(t, 2)
	must(t, e.Publish(0, newFake())) // target 0 has 1 and 2; target 1 has nothing
	for size := uint64(3); size <= 1030; size++ {
		must(t, e.Add(size, []byte("x"))) // Add does not verify
	}
	sizes := e.files(t)
	if len(sizes) != maxSpoolNotes || sizes[0] != 6 || sizes[len(sizes)-1] != 1030 {
		t.Fatalf("spool has %d notes from %d to %d", len(sizes), sizes[0], sizes[len(sizes)-1])
	}
	if st := e.Stats(); !slices.Equal(st.Skipped, []uint64{3, 5}) { // sizes 3,4,5 and 1..5
		t.Fatalf("skipped = %v", st.Skipped)
	}
	if n := strings.Count(e.logs.String(), "notes were skipped"); n != 2 {
		t.Fatalf("%d summary lines, want one for each target:\n%s", n, e.logs)
	}
	if strings.Contains(e.logs.String(), "a.test") {
		t.Fatal("log has a target URL")
	}
	e.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	must(t, e.Add(1031, []byte("x")))
	if n := strings.Count(e.logs.String(), "notes were skipped"); n != 4 {
		t.Fatalf("%d summary lines after one hour, want 4", n)
	}
}

// T-I-09: a cursor file that cannot be read does not stop the bound. Add
// does not fail, the spool keeps at most 1025 notes, and each dropped note is
// skipped for that target. That target gets an error from Publish. The other
// target publishes.
func TestTI09_BadCursorKeepsBound(t *testing.T) {
	e := newSpool(t)
	must(t, os.WriteFile(filepath.Join(e.dir, e.cursorName(0)), []byte("x"), 0o600))
	const last = maxSpoolNotes + 5
	for size := uint64(1); size <= last; size++ {
		e.add(t, size)
	}
	if sizes := e.files(t); len(sizes) != maxSpoolNotes || sizes[0] != 6 {
		t.Fatalf("spool has %d notes from %d", len(sizes), sizes[0])
	}
	if st := e.Stats(); !slices.Equal(st.Skipped, []uint64{5, 5}) {
		t.Fatalf("skipped = %v", st.Skipped)
	}
	f := newFake()
	if err := e.Publish(0, f); err == nil || !strings.Contains(err.Error(), "canonical decimal") || len(f.got) != 0 {
		t.Fatalf("Publish(0): err %v, sent %v", err, f.got)
	}
	must(t, e.Publish(1, f))
	if got := f.got[spoolTargets[1]]; len(got) != maxSpoolNotes || got[len(got)-1] != last {
		t.Fatalf("target 1 got %d notes", len(got))
	}
}

// T-I-09: a cursor file larger than 1 KiB gives an error with the file name and
// the rule.
func TestTI09_BigCursorError(t *testing.T) {
	e := newSpool(t)
	e.add(t, 1)
	must(t, os.WriteFile(filepath.Join(e.dir, e.cursorName(0)), bytes.Repeat([]byte("1"), 2*maxNoteSize), 0o600))
	err := e.Publish(0, newFake())
	if err == nil || !strings.Contains(err.Error(), e.cursorName(0)) || !strings.Contains(err.Error(), "1 KiB") || strings.Contains(err.Error(), "bad note") {
		t.Fatalf("Publish error = %v", err)
	}
}

// T-I-09: an entry at the oldest note name that cannot be deleted does not stop
// the trim. The notes that can be deleted stay within the bound.
func TestTI09_UndeletableOldest(t *testing.T) {
	e := newSpool(t)
	dir := filepath.Join(e.dir, e.noteFile(1))
	must(t, os.Mkdir(dir, 0o700))
	must(t, os.WriteFile(filepath.Join(dir, "x"), nil, 0o600))
	for size := uint64(2); size <= 1030; size++ {
		must(t, e.Add(size, []byte("x")))
	}
	notes := 0
	entries, err := os.ReadDir(filepath.Join(e.dir, spoolDir))
	must(t, err)
	for _, entry := range entries {
		if entry.Type().IsRegular() && strings.HasSuffix(entry.Name(), noteSuffix) {
			notes++
		}
	}
	if notes != maxSpoolNotes {
		t.Fatalf("%d regular notes on disk, want %d", notes, maxSpoolNotes)
	}
}

// T-S-13: an entry at a note name that is not a regular file (a directory, a
// FIFO, a symlink) is not given to the sender. It is deleted and counted. If it
// cannot be deleted, it is counted. The targets continue with the next notes, and
// Publish returns an error that names the file and the rule.
func TestTS13_NonRegularNote(t *testing.T) {
	for name, make := range map[string]func(t *testing.T, path string){
		"directory": func(t *testing.T, path string) { must(t, os.Mkdir(path, 0o700)) },
		"fifo":      func(t *testing.T, path string) { must(t, syscall.Mkfifo(path, 0o600)) },
		"directory-not-empty": func(t *testing.T, path string) {
			must(t, os.Mkdir(path, 0o700))
			must(t, os.WriteFile(filepath.Join(path, "x"), nil, 0o600))
		},
	} {
		t.Run(name, func(t *testing.T) {
			e := newSpool(t)
			e.add(t, 1)
			path := filepath.Join(e.dir, e.noteFile(2))
			make(t, path)
			e.add(t, 3)
			f := newFake()
			kept := name == "directory-not-empty"
			err0, err1 := e.Publish(0, f), e.Publish(1, f)
			if err0 == nil || !strings.Contains(err0.Error(), "2.note") || !strings.Contains(err0.Error(), "regular file") {
				t.Fatalf("Publish(0) error = %v, want the file and the rule", err0)
			}
			if (err1 != nil) != kept { // a deleted entry gives an error only one time
				t.Fatalf("Publish(1) error = %v, entry kept = %v", err1, kept)
			}
			for _, target := range spoolTargets {
				if !slices.Equal(f.got[target], []uint64{1, 3}) {
					t.Fatalf("sent = %v", f.got)
				}
			}
			_, err := os.Lstat(path)
			if kept == errors.Is(err, os.ErrNotExist) {
				t.Fatalf("entry kept = %v, want %v (err %v)", !errors.Is(err, os.ErrNotExist), kept, err)
			}
			if st := e.Stats(); st.Rejected == 0 {
				t.Fatal("entry not counted")
			}
		})
	}
}

// T-I-09: an entry that is not a regular file and cannot be deleted never
// counts as the newest note. The newest regular note stays on disk.
func TestTI09_NewestRegularNoteStays(t *testing.T) {
	e := newSpool(t)
	e.add(t, 1)
	e.add(t, 2)
	f := newFake()
	must(t, e.Publish(0, f))
	must(t, e.Publish(1, f))
	dir := filepath.Join(e.dir, e.noteFile(3))
	must(t, os.Mkdir(dir, 0o700))
	must(t, os.WriteFile(filepath.Join(dir, "x"), nil, 0o600))
	for range 4 {
		if err := e.Publish(0, f); err == nil {
			t.Fatal("Publish hid the entry that is not a regular file")
		}
	}
	if got := e.files(t); !slices.Equal(got, []uint64{2, 3}) {
		t.Fatalf("notes on disk = %v, want 2 (regular) and 3 (directory)", got)
	}
	if fi, err := os.Lstat(filepath.Join(e.dir, e.noteFile(2))); err != nil || !fi.Mode().IsRegular() {
		t.Fatalf("note 2: %v, %v", fi, err)
	}
}

// T-S-13: a regular note that cannot be opened (mode 0000) is a bad note. It is
// not sent and it is deleted. Publish continues with the next notes and returns
// an error that names the file and the rule.
func TestTS13_UnreadableNote(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can open a file with mode 0000")
	}
	e := newSpool(t)
	for size := uint64(1); size <= 3; size++ {
		e.add(t, size)
	}
	must(t, os.Chmod(filepath.Join(e.dir, e.noteFile(2)), 0))
	f := newFake()
	for i, target := range spoolTargets {
		err := e.Publish(i, f)
		if i == 0 && (err == nil || !strings.Contains(err.Error(), "2.note") || !strings.Contains(err.Error(), "cannot be opened")) {
			t.Fatalf("Publish(0) error = %v, want the file and the rule", err)
		}
		if !slices.Equal(f.got[target], []uint64{1, 3}) {
			t.Fatalf("sent = %v", f.got)
		}
	}
	if _, err := os.Lstat(filepath.Join(e.dir, e.noteFile(2))); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unreadable note stays: %v", err)
	}
	if st := e.Stats(); st.Rejected != 1 {
		t.Fatalf("rejected = %d, want 1", st.Rejected)
	}
}

// T-S-13: a note that does not parse or verify is not given to the sender. It
// is deleted and counted. The good notes still go out in order.
func TestTS13_BadNotesAreNotSent(t *testing.T) {
	e := newSpool(t)
	otherSigner, _ := noteKeys(t, testOrigin, 2) // same origin, other key
	wrongOrigin, _ := noteKeys(t, "agent-canary/other", 1)
	bad := func(size uint64, s note.Signer, signedSize uint64) {
		msg, err := SignCheckpoint(s, signedSize, testRoot())
		must(t, err)
		must(t, e.Add(size, msg))
	}
	e.add(t, 1)
	bad(2, otherSigner, 2)
	bad(3, wrongOrigin, 3)
	bad(4, e.signer, 9) // valid note under the name of another size
	must(t, e.Add(5, []byte("not a note")))
	must(t, e.Add(6, bytes.Repeat([]byte("x"), 2*maxNoteSize)))
	e.add(t, 7)
	f := newFake()
	must(t, e.Publish(0, f))
	if !slices.Equal(f.got[spoolTargets[0]], []uint64{1, 7}) {
		t.Fatalf("sent = %v", f.got)
	}
	if st := e.Stats(); st.Rejected != 5 {
		t.Fatalf("rejected = %d, want 5", st.Rejected)
	}
	if got := e.files(t); !slices.Equal(got, []uint64{1, 7}) { // target 1 has not published
		t.Fatalf("notes on disk = %v", got)
	}
}

// T-S-13: a spool path (directory, note, or cursor) that is a symlink out of
// the state directory is an error. The outside file is not read or changed.
func TestTS13_SymlinkOut(t *testing.T) {
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret")
	const content = "outside"
	check := func(t *testing.T) {
		t.Helper()
		if b, err := os.ReadFile(secret); err != nil || string(b) != content {
			t.Fatalf("outside file changed: %q, %v", b, err)
		}
	}
	reset := func(t *testing.T) { must(t, os.WriteFile(secret, []byte(content), 0o600)) }

	t.Run("directory", func(t *testing.T) {
		reset(t)
		root, dir := newState(t)
		mustSymlink(t, outside, filepath.Join(dir, "checkpoints"))
		_, verifier := noteKeys(t, testOrigin, 1)
		if _, err := OpenSpool(root, nil, testOrigin, verifier, spoolTargets); err == nil {
			t.Fatal("OpenSpool followed a directory symlink")
		}
		if entries, _ := os.ReadDir(outside); len(entries) != 1 {
			t.Fatalf("outside directory has %d entries", len(entries))
		}
		check(t)
	})
	t.Run("note", func(t *testing.T) {
		reset(t)
		e := newSpool(t)
		mustSymlink(t, secret, filepath.Join(e.dir, e.noteFile(3)))
		f := newFake()
		// The link is a bad note: deleted, not read, not sent, and an error.
		if err := e.Publish(0, f); err == nil || !strings.Contains(err.Error(), "3.note") || !strings.Contains(err.Error(), "symlink") {
			t.Fatalf("Publish error = %v, want the file and the rule", err)
		}
		if len(f.got) != 0 || e.Stats().Rejected != 1 {
			t.Fatalf("sent %v, rejected %d", f.got, e.Stats().Rejected)
		}
		check(t)
		mustSymlink(t, secret, filepath.Join(e.dir, e.noteFile(3)))
		e.add(t, 3) // a write replaces the link and does not follow it
		check(t)
		must(t, e.Publish(0, f))
	})
	t.Run("cursor", func(t *testing.T) {
		reset(t)
		e := newSpool(t)
		e.add(t, 3)
		mustSymlink(t, secret, filepath.Join(e.dir, e.cursorName(0)))
		f := newFake()
		if err := e.Publish(0, f); err == nil || len(f.got) != 0 {
			t.Fatalf("Publish: err %v, sent %v", err, f.got)
		}
		check(t)
	})
}

func (e *spoolEnv) noteFile(size uint64) string {
	return "checkpoints/" + strconv.FormatUint(size, 10) + ".note"
}
