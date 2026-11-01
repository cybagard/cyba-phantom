package tlog

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/note"

	"github.com/cybagard/cyba-phantom/internal/safefile"
	"github.com/cybagard/cyba-phantom/internal/safefile/safefiletest"
)

var spoolTargets = []string{"https://a.test/put", "https://b.test/put"}

// overfull is the newest size of a spool that gets 5 notes more than the bound.
const overfull = maxSpoolNotes + 5

var errTargetDown = errors.New("target down")

// fakeSender records the sizes for each target. failAt makes one size fail for
// a target until the test clears it.
type fakeSender struct {
	got    map[string][]uint64
	failAt map[string]uint64
}

func (f *fakeSender) Send(target string, size uint64, _ []byte) error {
	if n, ok := f.failAt[target]; ok && n == size {
		return errTargetDown
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
	// The on-disk name is fixed. Keep the literal, so that a change of spoolDir
	// fails this test.
	const onDisk = "checkpoints"
	got, err := os.ReadFile(filepath.Join(e.dir, onDisk, "7.note"))
	must(t, err)
	if !bytes.Equal(got, want) {
		t.Fatal("note on disk differs from the signed note")
	}
	for path, mode := range map[string]os.FileMode{onDisk: 0o700, onDisk + "/7.note": 0o600} {
		if fi, err := os.Stat(filepath.Join(e.dir, path)); err != nil || fi.Mode().Perm() != mode {
			t.Fatalf("%s: mode %v, err %v, want %v", path, fi.Mode().Perm(), err, mode)
		}
	}
	entries, err := os.ReadDir(filepath.Join(e.dir, onDisk))
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
	// The cursor name is fixed on disk. Keep the literal, so that a change of
	// cursorPrefix fails this test. A rename loses the cursors of every target
	// at an upgrade.
	const onDiskCursor = "checkpoints/target-"
	// The test computes the name itself: 16 lowercase hex of the SHA-256 of
	// the target URL.
	sum := sha256.Sum256([]byte(spoolTargets[0]))
	name := onDiskCursor + hex.EncodeToString(sum[:8])
	b, err := os.ReadFile(filepath.Join(e.dir, name))
	must(t, err)
	if string(b) != "2" || e.cursorName(0) != name {
		t.Fatalf("cursor file %q has %q, want 2 (cursorName %q)", name, b, e.cursorName(0))
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
	for size := uint64(3); size <= overfull; size++ {
		must(t, e.Add(size, []byte("x"))) // Add does not verify
	}
	sizes := e.files(t)
	if len(sizes) != maxSpoolNotes || sizes[0] != 6 || sizes[len(sizes)-1] != overfull {
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

// T-I-09: a cursor file that cannot be read does not keep the spool above the
// bound. Add does not fail and the spool keeps at most 1025 notes. Each
// dropped note counts as skipped for that target. That target gets an error
// from Publish. The other target publishes.
func TestTI09_BadCursorKeepsBound(t *testing.T) {
	e := newSpool(t)
	must(t, os.WriteFile(filepath.Join(e.dir, e.cursorName(0)), []byte("x"), 0o600))
	for size := uint64(1); size <= overfull; size++ {
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
	if got := f.got[spoolTargets[1]]; len(got) != maxSpoolNotes || got[len(got)-1] != overfull {
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
	for size := uint64(2); size <= overfull; size++ {
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
	if n := strings.Count(e.logs.String(), "cannot delete an entry"); n != 1 {
		t.Fatalf("%d warning lines for the entry, want 1 for all the calls of Add:\n%s", n, e.logs)
	}
}

// T-I-09: an entry that cannot be deleted is counted and logged one time, not
// for each Publish call and target. When it can be deleted later, it is not
// counted again. The spool forgets it when it is gone.
func TestTI09_StuckEntryCountsOnce(t *testing.T) {
	e := newSpool(t)
	e.add(t, 1)
	dir := filepath.Join(e.dir, e.noteFile(2))
	must(t, os.MkdirAll(filepath.Join(dir, "x"), 0o700))
	f := newFake()
	for _, i := range []int{0, 1, 0, 1} {
		if err := e.Publish(i, f); err == nil {
			t.Fatal("Publish hid the entry that is not a regular file")
		}
	}
	if n := strings.Count(e.logs.String(), "cannot delete a note that must not be sent"); n != 1 || e.Stats().Rejected != 1 {
		t.Fatalf("%d warning lines, rejected %d, want 1 and 1:\n%s", n, e.Stats().Rejected, e.logs)
	}
	if !strings.Contains(e.logs.String(), "name=checkpoints/2.note") || strings.Contains(e.logs.String(), "deleted a note") {
		t.Fatalf("the line has no name, or says deleted:\n%s", e.logs)
	}
	must(t, os.Remove(filepath.Join(dir, "x")))
	if err := e.Publish(0, f); err == nil {
		t.Fatal("Publish hid the entry that is not a regular file")
	}
	if _, err := os.Lstat(dir); !errors.Is(err, os.ErrNotExist) || e.Stats().Rejected != 1 || len(e.stuck) != 0 {
		t.Fatalf("entry: %v, rejected %d, stuck %v, want deleted, 1, none", err, e.Stats().Rejected, e.stuck)
	}
}

// downSender is a Sender that always fails.
type downSender struct{}

func (downSender) Send(string, uint64, []byte) error { return errors.New("target down") }

// fill writes the signed notes from..to with no fsync. Thus the test fills
// the spool quickly.
func (e *spoolEnv) fill(t *testing.T, from, to uint64) {
	t.Helper()
	for size := from; size <= to; size++ {
		msg, err := SignCheckpoint(e.signer, size, testRoot())
		must(t, err)
		must(t, os.WriteFile(filepath.Join(e.dir, e.noteFile(size)), msg, 0o600))
	}
}

// T-I-09: an entry that cannot be deleted gets one Warn line and one Rejected
// count. This holds if Publish and Add both meet it, in each order.
func TestTI09_StuckEntryOneLineForAllPaths(t *testing.T) {
	e := newSpool(t)
	stick := func(size uint64) {
		must(t, os.MkdirAll(filepath.Join(e.dir, e.noteFile(size), "x"), 0o700))
	}
	publish := func() {
		t.Helper()
		for range 3 { // each target meets the stuck entry more than once
			for i := range spoolTargets {
				if err := e.Publish(i, downSender{}); err == nil {
					t.Fatal("Publish hid the error")
				}
			}
		}
	}
	stick(1) // Publish meets it first
	publish()
	stick(2) // Add meets it first
	e.fill(t, 3, maxSpoolNotes+1)
	for size := uint64(maxSpoolNotes + 2); size <= maxSpoolNotes+4; size++ {
		e.add(t, size)
	}
	publish()
	logs := e.logs.String()
	lines := strings.Count(logs, "cannot delete an entry") + strings.Count(logs, "cannot delete a note that must not be sent")
	if lines != 2 || e.Stats().Rejected != 2 || len(e.stuck) != 2 {
		t.Fatalf("%d lines, rejected %d, stuck %v, want 2, 2, 2 entries:\n%s", lines, e.Stats().Rejected, e.stuck, logs)
	}
	if !strings.Contains(logs, "cannot delete a note that must not be sent\" name=checkpoints/1.note") || !strings.Contains(logs, "cannot delete an entry\" size=2") {
		t.Fatalf("a line has no entry name:\n%s", logs)
	}
}

// T-I-09: the spool forgets an entry that cannot be deleted when a listing
// shows it gone. A new entry with that name gets a log line again.
func TestTI09_ForgetsStuckEntryThatIsGone(t *testing.T) {
	e := newSpool(t)
	dir := filepath.Join(e.dir, e.noteFile(1))
	stick := func() { must(t, os.MkdirAll(filepath.Join(dir, "x"), 0o700)) }
	stick()
	e.fill(t, 2, maxSpoolNotes+1)
	e.add(t, maxSpoolNotes+2) // the full spool meets the entry
	if len(e.stuck) != 1 || strings.Count(e.logs.String(), "cannot delete an entry") != 1 {
		t.Fatalf("stuck %v, log:\n%s", e.stuck, e.logs)
	}
	must(t, os.RemoveAll(dir))
	e.files(t)
	if len(e.stuck) != 0 {
		t.Fatalf("stuck %v after a listing, want none", e.stuck)
	}
	stick()
	e.add(t, maxSpoolNotes+3)
	if n := strings.Count(e.logs.String(), "cannot delete an entry"); n != 2 {
		t.Fatalf("%d lines for the new entry, want 2 in all:\n%s", n, e.logs)
	}
}

// T-S-13: if the sweep at open cannot list checkpoints/, OpenSpool still
// succeeds and writes one log line with no path.
func TestTS13_OpenLogsSweepListingError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can list a directory with mode 0300")
	}
	e := newSpool(t)
	dir := filepath.Join(e.dir, spoolDir)
	must(t, os.Chmod(dir, 0o300))
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	log, buf := testLogger()
	_, err := OpenSpool(e.root, log, testOrigin, e.verifier, spoolTargets)
	must(t, err)
	if n := strings.Count(buf.String(), "cannot list"); n != 1 || strings.Contains(buf.String(), e.dir) {
		t.Fatalf("%d lines, want 1 with no path:\n%s", n, buf)
	}
}

// T-I-09: the spool lists all names when there are more names than one step.
func TestTI09_ListsInSteps(t *testing.T) {
	e := newSpool(t)
	const count = 2*listStep + 1
	want := make([]uint64, 0, count)
	for size := uint64(1); size <= count; size++ {
		must(t, os.WriteFile(filepath.Join(e.dir, e.noteFile(size)), nil, 0o600))
		want = append(want, size)
	}
	if got := e.files(t); !slices.Equal(got, want) {
		t.Fatalf("listed %d sizes, want %d", len(got), count)
	}
}

// T-I-09: the full spool deletes an entry that is not a regular file (a
// directory, a FIFO, a symlink). It is not a skipped note. A regular note is a
// skipped note.
// An entry that is gone before drop runs does not stop it.
func TestTI09_DropCountsOnlyNotes(t *testing.T) {
	e := newSpool(t)
	drop := func(size uint64) {
		t.Helper()
		e.mu.Lock() // Add holds the lock for drop
		defer e.mu.Unlock()
		must(t, e.drop(size))
	}
	for i, create := range []func(path string){
		func(path string) { must(t, os.Mkdir(path, 0o700)) },
		func(path string) { must(t, syscall.Mkfifo(path, 0o600)) },
		func(path string) { mustSymlink(t, filepath.Join(e.dir, "target"), path) },
	} {
		path := filepath.Join(e.dir, e.noteFile(uint64(i+1)))
		create(path)
		drop(uint64(i + 1))
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("entry %d stays: %v", i+1, err)
		}
		if st := e.Stats(); !slices.Equal(st.Skipped, []uint64{0, 0}) {
			t.Fatalf("skipped = %v after entry %d, want none", st.Skipped, i+1)
		}
	}
	e.add(t, 4)
	drop(4)
	if st := e.Stats(); !slices.Equal(st.Skipped, []uint64{1, 1}) {
		t.Fatalf("skipped = %v after a note, want 1 for each target", st.Skipped)
	}
	drop(5) // no entry
}

// T-S-13: a note name with a decimal above uint64 is never a size. The spool
// deletes it and counts it one time. No target gets it.
func TestTS13_BigDecimalNameIsRejected(t *testing.T) {
	e := newSpool(t)
	e.add(t, 1)
	big := filepath.Join(e.dir, spoolDir, "99999999999999999999"+noteSuffix)
	must(t, os.WriteFile(big, []byte("x"), 0o600))
	f := newFake()
	for i := range spoolTargets {
		must(t, e.Publish(i, f))
	}
	if _, err := os.Lstat(big); !errors.Is(err, os.ErrNotExist) || e.Stats().Rejected != 1 {
		t.Fatalf("entry: %v, rejected %d, want deleted and 1", err, e.Stats().Rejected)
	}
	for _, target := range spoolTargets {
		if !slices.Equal(f.got[target], []uint64{1}) {
			t.Fatalf("sent = %v", f.got)
		}
	}
	must(t, os.WriteFile(big, []byte("x"), 0o600)) // a new entry counts again
	e.files(t)
	if e.Stats().Rejected != 2 {
		t.Fatalf("rejected = %d, want 2", e.Stats().Rejected)
	}
	// The names at the edge of 32 and 64 bits are sizes. The decimal after the
	// largest uint64 is not a size.
	const largest = 1<<64 - 1
	for _, size := range []uint64{1 << 32, largest} {
		must(t, os.WriteFile(filepath.Join(e.dir, e.noteFile(size)), []byte("x"), 0o600))
	}
	over := filepath.Join(e.dir, spoolDir, "18446744073709551616"+noteSuffix)
	must(t, os.WriteFile(over, []byte("x"), 0o600))
	if got := e.files(t); !slices.Equal(got, []uint64{1, 1 << 32, largest}) {
		t.Fatalf("listed %v, want 1, 4294967296 and the largest uint64", got)
	}
	if _, err := os.Lstat(over); !errors.Is(err, os.ErrNotExist) || e.Stats().Rejected != 3 {
		t.Fatalf("entry above uint64: %v, rejected %d, want deleted and 3", err, e.Stats().Rejected)
	}
}

// T-S-13: OpenSpool deletes the temporary files that a crash left, for a note
// and for a cursor. The spool deletes the file with no new write of that name.
// A temporary entry that cannot be deleted stays and gets a log line. A name
// that does not end in .tmp stays.
func TestTS13_OpenDeletesLeftoverTempFiles(t *testing.T) {
	e := newSpool(t)
	e.add(t, 5) // a signed note: the sweep keeps it
	const cursor = cursorPrefix + "0123456789abcdef"
	kept := []string{"5.note", cursor, "5.note.tmpx"}
	left := []string{"5.note.tmp", cursor + ".tmp"}
	for _, name := range append(left, kept[1:]...) {
		must(t, os.WriteFile(filepath.Join(e.dir, spoolDir, name), []byte("x"), 0o600))
	}
	stays := filepath.Join(e.dir, spoolDir, "9.note.tmp")
	must(t, os.MkdirAll(filepath.Join(stays, "x"), 0o700))
	log, buf := testLogger()
	_, err := OpenSpool(e.root, log, testOrigin, e.verifier, spoolTargets)
	must(t, err)
	for _, name := range left {
		if _, err := os.Lstat(filepath.Join(e.dir, spoolDir, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s stays: %v", name, err)
		}
	}
	for _, name := range kept {
		if _, err := os.Lstat(filepath.Join(e.dir, spoolDir, name)); err != nil {
			t.Fatalf("%s is not a temporary file, but the sweep removed it: %v", name, err)
		}
	}
	if _, err := os.Lstat(stays); err != nil || !strings.Contains(buf.String(), "9.note.tmp") {
		t.Fatalf("entry: %v, log %q, want it kept and one log line", err, buf)
	}
}

// T-S-13: an entry at a note name that is not a regular file (a directory, a
// FIFO, a symlink) is not given to the sender. It is deleted and counted. If it
// cannot be deleted, it is counted. The targets continue with the next notes, and
// Publish returns an error that names the file and the rule.
func TestTS13_NonRegularNote(t *testing.T) {
	for name, create := range map[string]func(t *testing.T, path string){
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
			create(t, path)
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
	for range 2 { // call 2 meets the directory again and keeps note 2
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

// T-S-13: a regular note that fails to open with EACCES (mode 0000) is a bad
// note. It is not sent and it is deleted. Publish continues with the next notes
// and returns an error that names the file and the rule.
func TestTS13_UnreadableNote(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can open a file with mode 0000")
	}
	e := newSpool(t)
	for size := uint64(1); size <= 3; size++ {
		e.add(t, size)
	}
	must(t, os.Chmod(filepath.Join(e.dir, e.noteFile(2)), 0))
	opens := 0
	safefiletest.Set(t, safefiletest.Hooks{AfterCheck: func(name string) {
		if name == "2.note" {
			opens++
		}
	}})
	f := newFake()
	defer func() {
		// The first Publish deletes the note. Its cause needs no second open.
		if opens != 1 {
			t.Errorf("%d opens of the note, want 1", opens)
		}
	}()
	for i, target := range spoolTargets {
		err := e.Publish(i, f)
		if i == 0 && (err == nil || !strings.Contains(err.Error(), "2.note") || !strings.Contains(err.Error(), "cannot be opened") || !errors.Is(err, syscall.EACCES)) {
			t.Fatalf("Publish(0) error = %v, want the file, the rule, and EACCES", err)
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

// T-S-13: an open error that is not a property of the note is not a bad note. A
// swap between the check and the open stands for it. Publish keeps the note,
// does not count it, stops, and returns an error that names the file and the rule.
func TestTS13_OpenErrorIsNotABadNote(t *testing.T) {
	e := newSpool(t)
	for size := uint64(1); size <= 3; size++ {
		e.add(t, size)
	}
	path := filepath.Join(e.dir, e.noteFile(2))
	safefiletest.Set(t, safefiletest.Hooks{AfterCheck: func(name string) {
		if name == "2.note" {
			must(t, os.WriteFile(path+".swap", nil, 0o600))
			must(t, os.Rename(path+".swap", path))
		}
	}})
	f := newFake()
	err := e.Publish(0, f)
	if err == nil || !strings.Contains(err.Error(), "2.note") || !strings.Contains(err.Error(), "changed between") {
		t.Fatalf("Publish error = %v, want the file and the rule", err)
	}
	if !slices.Equal(f.got[spoolTargets[0]], []uint64{1}) || !slices.Equal(e.files(t), []uint64{1, 2, 3}) || e.Stats().Rejected != 0 {
		t.Fatalf("sent %v, on disk %v, rejected %d", f.got, e.files(t), e.Stats().Rejected)
	}
}

// failAtNote2 sets faultAt to return err at step for note 2 only.
func failAtNote2(t *testing.T, step string, err error) {
	faultAt = func(s, name string) error {
		if s == step && name == noteName(2) {
			return err
		}
		return nil
	}
	t.Cleanup(func() { faultAt = nil })
}

// T-S-13: some errors to examine, open, or read a note are not a property of
// the note (EMFILE, EPERM, EIO). Then the note is not bad. Publish keeps it. It
// does not count it or send it. It stops for the target and returns an error
// that names the file and the rule. EACCES is a property of the note only when
// the spool opens it.
func TestTS13_ErrorNotOfTheNoteKeepsIt(t *testing.T) {
	for _, c := range []struct {
		name, step, rule string
		err              error
	}{
		{"open-emfile", "open", "cannot be opened", syscall.EMFILE},
		{"open-eperm", "open", "cannot be opened", syscall.EPERM},
		{"examine-eio", "examine", "cannot be examined", syscall.EIO},
		{"read-eio", "read", "cannot be read", syscall.EIO},
		{"examine-eacces", "examine", "cannot be examined", syscall.EACCES},
		{"read-eacces", "read", "cannot be read", syscall.EACCES},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newSpool(t)
			for size := uint64(1); size <= 3; size++ {
				e.add(t, size)
			}
			failAtNote2(t, c.step, c.err)
			f := newFake()
			err := e.Publish(0, f)
			if err == nil || !strings.Contains(err.Error(), "2.note") || !strings.Contains(err.Error(), c.rule) {
				t.Fatalf("Publish error = %v, want the file and the rule", err)
			}
			if !slices.Equal(f.got[spoolTargets[0]], []uint64{1}) || !slices.Equal(e.files(t), []uint64{1, 2, 3}) || e.Stats().Rejected != 0 {
				t.Fatalf("sent %v, on disk %v, rejected %d", f.got, e.files(t), e.Stats().Rejected)
			}
		})
	}
}

// T-S-13: Publish returns the errors of the bad notes together with a later
// error. The later error comes from Send, from the cursor read in next, or
// from the cursor read in advance. errors.Is finds errBadNote and the error of
// the sender. For the cursor errors the test matches the text. The cursor read
// does not keep the cause.
func TestTS13_EntryErrorJoinsLaterError(t *testing.T) {
	// Notes 1 and 2 are bad entries. Publish tries to send note 3. Note 4
	// is not reached.
	setup := func(t *testing.T) *spoolEnv {
		e := newSpool(t)
		must(t, os.Mkdir(filepath.Join(e.dir, e.noteFile(1)), 0o700))
		must(t, os.Mkdir(filepath.Join(e.dir, e.noteFile(2)), 0o700))
		e.add(t, 3)
		e.add(t, 4)
		return e
	}
	check := func(t *testing.T, e *spoolEnv, err error, later string) {
		t.Helper()
		if !errors.Is(err, errBadNote) || err == nil || !strings.Contains(err.Error(), "1.note") ||
			!strings.Contains(err.Error(), "2.note") || !strings.Contains(err.Error(), later) {
			t.Fatalf("Publish error = %v, want both entry errors and %q", err, later)
		}
		if e.Stats().Rejected != 2 {
			t.Fatalf("rejected = %d, want 2", e.Stats().Rejected)
		}
	}
	t.Run("send", func(t *testing.T) {
		e := setup(t)
		f := newFake()
		f.failAt[spoolTargets[0]] = 3
		err := e.Publish(0, f)
		if !errors.Is(err, errTargetDown) {
			t.Fatalf("Publish error = %v, want the error of the sender", err)
		}
		check(t, e, err, "target down")
	})
	// Calls that examine the cursor of target 0, in order: the first next,
	// advance, and the second next. Advance runs after the send of note 3.
	for _, c := range []struct {
		name string
		call int
	}{{"advance", 2}, {"next", 3}} {
		t.Run(c.name, func(t *testing.T) {
			e := setup(t)
			calls := 0
			faultAt = func(step, name string) error {
				if step == "examine" && name == e.cursorName(0) {
					if calls++; calls == c.call {
						return syscall.EIO
					}
				}
				return nil
			}
			t.Cleanup(func() { faultAt = nil })
			f := newFake()
			check(t, e, e.Publish(0, f), "cannot be examined")
			if !slices.Equal(f.got[spoolTargets[0]], []uint64{3}) {
				t.Fatalf("sent %v, want only note 3", f.got)
			}
		})
	}
}

// T-S-13: a note that goes before Publish can open it is not a bad note.
// Publish does not count it. It stops for the target and returns an error that
// says the note is gone before it is read.
func TestTS13_NoteGoneAfterLstat(t *testing.T) {
	e := newSpool(t)
	for size := uint64(1); size <= 3; size++ {
		e.add(t, size)
	}
	safefiletest.Set(t, safefiletest.Hooks{AfterCheck: func(name string) {
		if name == "2.note" {
			must(t, os.Remove(filepath.Join(e.dir, e.noteFile(2))))
		}
	}})
	f := newFake()
	err := e.Publish(0, f)
	if err == nil || !strings.Contains(err.Error(), "2.note") || !strings.Contains(err.Error(), "is gone before it is read") || strings.Contains(err.Error(), "cannot be opened") {
		t.Fatalf("Publish error = %v, want the file and the rule", err)
	}
	if !slices.Equal(f.got[spoolTargets[0]], []uint64{1}) || !slices.Equal(e.files(t), []uint64{1, 3}) || e.Stats().Rejected != 0 {
		t.Fatalf("sent %v, on disk %v, rejected %d", f.got, e.files(t), e.Stats().Rejected)
	}
}

// T-S-13: a fault of checkpoints/ between the cursor read and the note read is
// not a property of the note. An in-root symlink in its place and a mode 0 each
// stop Publish with an error that names the note. Publish sends nothing,
// counts no bad note, and deletes no note.
func TestTS13_SpoolDirFaultKeepsNotes(t *testing.T) {
	for _, tc := range []struct {
		name  string
		fault func(t *testing.T, dir string) (notes string)
		cause error
	}{
		{"symlink", func(t *testing.T, dir string) string {
			must(t, os.Rename(filepath.Join(dir, spoolDir), filepath.Join(dir, spoolDir+".real")))
			mustSymlink(t, spoolDir+".real", filepath.Join(dir, spoolDir))
			return spoolDir + ".real"
		}, safefile.ErrSymlink},
		{"mode 0", func(t *testing.T, dir string) string {
			if os.Geteuid() == 0 {
				t.Skip("root can open a directory with mode 0")
			}
			p := filepath.Join(dir, spoolDir)
			t.Cleanup(func() { _ = os.Chmod(p, 0o700) })
			must(t, os.Chmod(p, 0))
			return spoolDir
		}, syscall.EACCES},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newSpool(t)
			e.add(t, 1)
			e.add(t, 2)
			var notes string
			opens := 0
			safefiletest.Set(t, safefiletest.Hooks{BeforeCheck: func(name string) {
				// The first open is for the cursor, the second for note 1.
				if name == spoolDir {
					if opens++; opens == 2 {
						notes = tc.fault(t, e.dir)
					}
				}
			}})
			f := newFake()
			err := e.Publish(0, f)
			if err == nil || !strings.Contains(err.Error(), "1.note: cannot be read") || strings.Contains(err.Error(), "regular file") || errors.Is(err, errBadNote) || errors.As(err, new(entryError)) {
				t.Fatalf("Publish error = %v, want an error for 1.note that is not a bad note", err)
			}
			if !errors.Is(err, tc.cause) {
				t.Errorf("Publish error = %v, want the cause %v", err, tc.cause)
			}
			if len(f.got) != 0 || e.Stats().Rejected != 0 {
				t.Errorf("sent %v, rejected %d; want nothing", f.got, e.Stats().Rejected)
			}
			must(t, os.Chmod(filepath.Join(e.dir, notes), 0o700))
			for size := uint64(1); size <= 2; size++ {
				if _, err := os.Lstat(filepath.Join(e.dir, notes, path.Base(e.noteFile(size)))); err != nil {
					t.Errorf("note %d: %v; want it kept", size, err)
				}
			}
		})
	}
}

// T-S-13: a note or a cursor of maxNoteSize bytes is read. One of
// maxNoteSize + 1 bytes is too large, and the read refuses it.
func TestTS13_NoteSizeLimit(t *testing.T) {
	e := newSpool(t)
	for _, name := range []string{noteName(5), e.cursorName(0)} {
		must(t, os.WriteFile(filepath.Join(e.dir, name), bytes.Repeat([]byte("x"), maxNoteSize), 0o600))
		if b, err := e.readFile(name); err != nil || len(b) != maxNoteSize {
			t.Errorf("%s at the limit: %d bytes, %v; want the bytes", name, len(b), err)
		}
		must(t, os.WriteFile(filepath.Join(e.dir, name), bytes.Repeat([]byte("x"), maxNoteSize+1), 0o600))
		if _, err := e.readFile(name); !errors.Is(err, safefile.ErrSize) || !strings.Contains(err.Error(), "must not be larger than 1 KiB") {
			t.Errorf("%s above the limit: %v; want the size error", name, err)
		}
	}
}

// T-S-13: a FIFO renamed over a note after the check is a changed file, and
// Publish refuses it. Publish does not block. The note is kept.
func TestTS13_NoteFifoSwapAfterCheck(t *testing.T) {
	e := newSpool(t)
	for size := uint64(1); size <= 2; size++ {
		e.add(t, size)
	}
	fifo := filepath.Join(e.dir, "swap.fifo")
	mustFifo(t, fifo)
	safefiletest.Set(t, safefiletest.Hooks{AfterCheck: func(name string) {
		if name == "2.note" {
			must(t, os.Rename(fifo, filepath.Join(e.dir, e.noteFile(2))))
		}
	}})
	err := within(t, func() error { return e.Publish(0, newFake()) })
	if err == nil || !errors.Is(err, safefile.ErrChanged) || !strings.Contains(err.Error(), "2.note") || !strings.Contains(err.Error(), "changed between") {
		t.Errorf("Publish error = %v, want the changed-file error for 2.note", err)
	}
	if _, err := os.Lstat(filepath.Join(e.dir, e.noteFile(2))); err != nil {
		t.Errorf("note 2 after Publish: %v; want it kept", err)
	}
}

// T-S-13: Publish counts and deletes a note that is too large and an entry that
// is not a regular file. A note that grows after the check is a bad note and
// gives no error. An unreadable large note and a self-loop symlink swapped in
// after the check each give an entry error. The next good note is sent.
func TestTS13_NoteSizeAndSwapRows(t *testing.T) {
	for _, tc := range []struct {
		name    string
		prepare func(t *testing.T, e *spoolEnv) func(name string)
		wantErr func(err error) bool
	}{
		{"grows after the check", func(t *testing.T, e *spoolEnv) func(string) {
			return func(name string) {
				if name != "2.note" {
					return
				}
				f, err := os.OpenFile(filepath.Join(e.dir, e.noteFile(2)), os.O_APPEND|os.O_WRONLY, 0)
				must(t, err)
				_, err = f.Write(bytes.Repeat([]byte("x"), maxNoteSize))
				must(t, err)
				must(t, f.Close())
			}
		}, func(err error) bool { return err == nil }},
		{"large with mode 0", func(t *testing.T, e *spoolEnv) func(string) {
			if os.Geteuid() == 0 {
				t.Skip("root can open a file with mode 0000")
			}
			p := filepath.Join(e.dir, e.noteFile(2))
			must(t, os.WriteFile(p, bytes.Repeat([]byte("x"), maxNoteSize+1), 0o600))
			must(t, os.Chmod(p, 0))
			return nil
		}, func(err error) bool { return errors.Is(err, syscall.EACCES) }},
		{"self-loop symlink swapped in", func(t *testing.T, e *spoolEnv) func(string) {
			return func(name string) {
				if name != "2.note" {
					return
				}
				tmp := filepath.Join(e.dir, spoolDir, "loop")
				must(t, os.Symlink(name, tmp))
				must(t, os.Rename(tmp, filepath.Join(e.dir, e.noteFile(2))))
			}
		}, func(err error) bool {
			return err != nil && strings.Contains(err.Error(), "must be a regular file and not a symlink")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newSpool(t)
			for size := uint64(1); size <= 3; size++ {
				e.add(t, size)
			}
			hook := tc.prepare(t, e)
			safefiletest.Set(t, safefiletest.Hooks{AfterCheck: hook})
			f := newFake()
			err := within(t, func() error { return e.Publish(0, f) })
			if !tc.wantErr(err) {
				t.Errorf("Publish error = %v", err)
			}
			if !slices.Equal(f.got[spoolTargets[0]], []uint64{1, 3}) || !slices.Equal(e.files(t), []uint64{1, 3}) || e.Stats().Rejected != 1 {
				t.Errorf("sent %v, on disk %v, rejected %d", f.got, e.files(t), e.Stats().Rejected)
			}
		})
	}
}

// T-S-13: a note that does not parse or verify is not given to the sender. It
// is deleted and counted. The good notes are still sent in order.
func TestTS13_BadNotesAreNotSent(t *testing.T) {
	e := newSpool(t)
	otherSigner, _ := noteKeys(t, testOrigin, 2) // same origin, other key
	wrongOrigin, _ := noteKeys(t, "phantom/other", 1)
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
	logs := e.logs.String()
	if n := strings.Count(logs, "deleted a note that must not be sent"); n != 5 || strings.Contains(logs, "cannot delete") || !strings.Contains(logs, "name=checkpoints/2.note") {
		t.Fatalf("%d lines for deleted notes, want 5 with a name and no line for a stuck entry:\n%s", n, logs)
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
		mustSymlink(t, outside, filepath.Join(dir, spoolDir))
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

func (e *spoolEnv) noteFile(size uint64) string { return noteName(size) }

// gateSender is a Sender for tests with several goroutines. Send tells the test
// that it is entered. It then waits for release (a nil release does not wait),
// and records the size.
type gateSender struct {
	mu      sync.Mutex
	sent    map[string][]uint64
	entered chan uint64
	release chan struct{}
	onSend  func(target string, size uint64)
}

func newGate(block bool) *gateSender {
	g := &gateSender{sent: map[string][]uint64{}, entered: make(chan uint64, 16)}
	if block {
		g.release = make(chan struct{})
	}
	return g
}

func (g *gateSender) Send(target string, size uint64, _ []byte) error {
	if g.onSend != nil {
		g.onSend(target, size)
	}
	g.entered <- size
	if g.release != nil {
		<-g.release
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.sent[target] = append(g.sent[target], size)
	return nil
}

func (g *gateSender) got(target string) []uint64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return slices.Clone(g.sent[target])
}

func (g *gateSender) waitEntered(t *testing.T) {
	t.Helper()
	select {
	case <-g.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("Send was not entered")
	}
}

// publishAsync runs Publish for target 0 in a goroutine and returns its result.
func (e *spoolEnv) publishAsync(send Sender) <-chan error {
	done := make(chan error, 1)
	go func() { done <- e.Publish(0, send) }()
	return done
}

// T-S-13: Add returns while a Publish waits in Send.
func TestTS13AddDoesNotWaitForSend(t *testing.T) {
	e := newSpool(t)
	e.add(t, 1)
	msg2, err := SignCheckpoint(e.signer, 2, testRoot())
	must(t, err)
	g := newGate(true)
	done := e.publishAsync(g)
	g.waitEntered(t)
	added := make(chan error, 1)
	go func() { added <- e.Add(2, msg2) }()
	select {
	case err := <-added:
		must(t, err)
	case <-time.After(time.Second):
		t.Fatal("Add waited for Send")
	}
	close(g.release)
	must(t, <-done)
	if got := g.got(spoolTargets[0]); !slices.Equal(got, []uint64{1}) {
		t.Fatalf("sent = %v, want 1 only: size 2 is above the limit of the call", got)
	}
	must(t, e.Publish(0, g))
	if got := g.got(spoolTargets[0]); !slices.Equal(got, []uint64{1, 2}) {
		t.Fatalf("sent after the second call = %v", got)
	}
}

// T-S-13: a failed Send leaves the cursor, and the next Publish starts with the
// same size.
func TestTS13FailedSendKeepsCursor(t *testing.T) {
	e := newSpool(t)
	e.add(t, 3)
	f := newFake()
	must(t, e.Publish(0, f))
	e.add(t, 4)
	f.failAt[spoolTargets[0]] = 4
	if err := e.Publish(0, f); err == nil {
		t.Fatal("Publish hid the error of the sender")
	}
	if b, err := os.ReadFile(filepath.Join(e.dir, e.cursorName(0))); err != nil || string(b) != "3" {
		t.Fatalf("cursor = %q, err %v, want 3", b, err)
	}
	delete(f.failAt, spoolTargets[0])
	must(t, e.Publish(0, f))
	if got := f.got[spoolTargets[0]]; !slices.Equal(got, []uint64{3, 4}) {
		t.Fatalf("sent = %v", got)
	}
}

// T-S-13: a second Publish for one target returns immediately while the first
// one sends. No size is sent two times, also not after the cursor moved.
func TestTS13SecondPublishSendsNothing(t *testing.T) {
	e := newSpool(t)
	for _, size := range []uint64{1, 2, 3} {
		e.add(t, size)
	}
	g := newGate(true)
	done := e.publishAsync(g)
	g.waitEntered(t)
	second := make(chan error, 1)
	go func() { second <- e.Publish(0, g) }()
	select {
	case err := <-second:
		if err == nil {
			close(g.release)
			t.Fatal("the second Publish returned no error")
		}
	case <-time.After(time.Second):
		close(g.release)
		t.Fatal("the second Publish did not return")
	}
	close(g.release)
	must(t, <-done)
	must(t, e.Publish(0, g))
	if got := g.got(spoolTargets[0]); !slices.Equal(got, []uint64{1, 2, 3}) {
		t.Fatalf("sent = %v, want each size one time", got)
	}
	if got := len(g.entered); got != 2 { // sizes 2 and 3; the test read size 1
		t.Fatalf("Send was entered %d more times, want 2", got)
	}
}

// T-S-13: if the cursor changes during Send, Publish does not write it.
func TestTS13CursorChangeIsAnError(t *testing.T) {
	e := newSpool(t)
	e.add(t, 1)
	g := newGate(false)
	g.onSend = func(string, uint64) {
		must(t, os.WriteFile(filepath.Join(e.dir, e.cursorName(0)), []byte("9"), 0o600))
	}
	err := e.Publish(0, g)
	if err == nil || !strings.Contains(err.Error(), e.cursorName(0)) {
		t.Fatalf("error = %v, want one that names the cursor file", err)
	}
	if b, err := os.ReadFile(filepath.Join(e.dir, e.cursorName(0))); err != nil || string(b) != "9" {
		t.Fatalf("cursor = %q, err %v, want the value of the sender", b, err)
	}
}

// T-S-13: the sizes for one target increase, also when Add adds notes during
// Send. The first call sends only the note of its first listing. The second call
// sends the notes that Add added, in order. No size is sent two times.
func TestTS13SizesIncreaseWhileAddRuns(t *testing.T) {
	e := newSpool(t)
	e.add(t, 1)
	g := newGate(false)
	g.onSend = func(_ string, size uint64) {
		if size == 1 {
			e.add(t, 3)
			e.add(t, 2)
		}
	}
	must(t, e.Publish(0, g))
	if got := g.got(spoolTargets[0]); !slices.Equal(got, []uint64{1}) {
		t.Fatalf("sent after the first call = %v, want 1 only", got)
	}
	must(t, e.Publish(0, g))
	got := g.got(spoolTargets[0])
	if !slices.Equal(got, []uint64{1, 2, 3}) {
		t.Fatalf("sent after the second call = %v, want 1 2 3", got)
	}
	if len(slices.Compact(slices.Clone(got))) != len(got) {
		t.Fatalf("a size was sent two times: %v", got)
	}
}

// T-S-13: one Publish call ends after the notes of its first listing, also when
// Add adds a new note during each Send. The next call sends the new notes.
func TestTS13PublishEndsAtTheFirstListing(t *testing.T) {
	e := newSpool(t)
	e.add(t, 1)
	e.add(t, 2)
	g := newGate(false)
	g.onSend = func(_ string, size uint64) {
		if size < 100 {
			e.add(t, size+100)
		}
	}
	must(t, e.Publish(0, g))
	if got := g.got(spoolTargets[0]); !slices.Equal(got, []uint64{1, 2}) {
		t.Fatalf("sent = %v, want the notes of the first listing only", got)
	}
	must(t, e.Publish(0, g))
	if got := g.got(spoolTargets[0]); !slices.Equal(got, []uint64{1, 2, 101, 102}) {
		t.Fatalf("sent after the second call = %v", got)
	}
}

// T-S-13: Publish with a target index that is not in the spool returns an error
// and does not leave the lock held.
func TestTS13BadTargetIndexIsAnError(t *testing.T) {
	e := newSpool(t)
	e.add(t, 1)
	for _, i := range []int{-1, len(spoolTargets)} {
		if err := e.Publish(i, newFake()); err == nil {
			t.Fatalf("Publish(%d) returned no error", i)
		}
	}
	msg, err := SignCheckpoint(e.signer, 2, testRoot())
	must(t, err)
	added := make(chan error, 1)
	go func() { added <- e.Add(2, msg) }()
	select {
	case err := <-added:
		must(t, err)
	case <-time.After(time.Second):
		t.Fatal("Add waited after a bad target index")
	}
}

// panicSender is a Sender whose Send panics.
type panicSender struct{}

func (panicSender) Send(string, uint64, []byte) error { panic("send panic") }

// T-S-13: after a panic in Send, the flag of the target is reset. A new Publish
// for the target sends the note, and Add does not block.
func TestTS13FlagResetsAfterPanicInSend(t *testing.T) {
	e := newSpool(t)
	e.add(t, 1)
	func() {
		defer func() {
			if recover() == nil {
				t.Error("Send did not panic")
			}
		}()
		_ = e.Publish(0, panicSender{})
	}()
	msg, err := SignCheckpoint(e.signer, 2, testRoot())
	must(t, err)
	added := make(chan error, 1)
	go func() { added <- e.Add(2, msg) }()
	select {
	case err := <-added:
		must(t, err)
	case <-time.After(time.Second):
		t.Fatal("Add waited after a panic in Send")
	}
	f := newFake()
	must(t, e.Publish(0, f))
	if got := f.got[spoolTargets[0]]; !slices.Equal(got, []uint64{1, 2}) {
		t.Fatalf("sent = %v, want 1 2", got)
	}
}
