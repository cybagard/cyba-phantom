package verify

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/note"

	"github.com/cybagard/cyba-phantom/internal/safefile"
	"github.com/cybagard/cyba-phantom/internal/safefile/safefiletest"
	"github.com/cybagard/cyba-phantom/internal/testutil"
)

// snapshot lists a directory: each name, with the bytes of a file or the target
// of a symlink. Two equal snapshots mean that nothing changed, and that no
// temporary file is left.
func snapshot(t *testing.T, dir string) string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, e := range entries {
		p := filepath.Join(dir, e.Name())
		switch {
		case e.Type()&os.ModeSymlink != 0:
			target, _ := os.Readlink(p)
			fmt.Fprintf(&b, "%s -> %s\n", e.Name(), target)
		case e.IsDir():
			fmt.Fprintf(&b, "%s/\n", e.Name())
		default:
			data, _ := os.ReadFile(p)
			fmt.Fprintf(&b, "%s: %q\n", e.Name(), data)
		}
	}
	return b.String()
}

// T-S-14: first use, update, and no write for a smaller or equal size.
func TestTS14_StateUpdate(t *testing.T) {
	s, text := newKey(t, origin)
	v, _ := ParseKey([]byte(text))
	l, _ := realLog(t, 20)
	cp := func(size int64) []byte { return checkpointAt(t, l, s, size) }
	dir := filepath.Join(t.TempDir(), "a", "b") // the directory does not exist
	file := filepath.Join(dir, StateFileName(v))

	st, err := LoadState(dir, v, StateOptions{})
	if err != nil || st.Bytes() != nil {
		t.Fatalf("first use: %v, %q", err, st.Bytes())
	}
	if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("the directory: %v, %v", fi, err)
	}
	steps := []struct {
		size int64
		want StateChange
		file int64 // the size in the file after the step
	}{
		{5, StateFirstUse, 5}, {10, StateUpdated, 10}, {10, StateUnchanged, 10}, {5, StateUnchanged, 10},
	}
	for _, step := range steps {
		got, err := st.Update(cp(step.size))
		if err != nil || got != step.want {
			t.Fatalf("size %d: %v, %v, want %v", step.size, got, err, step.want)
		}
		if b, _ := os.ReadFile(file); !bytes.Equal(b, cp(step.file)) {
			t.Errorf("size %d: the file holds another note", step.size)
		}
		if fi, err := os.Stat(file); err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("size %d: the file mode: %v, %v", step.size, fi, err)
		}
		if got := snapshot(t, dir); strings.Count(got, "\n") != 1 {
			t.Errorf("size %d: the directory holds more than the state:\n%s", step.size, got)
		}
	}
	st.Close()
	// A Load in a new object sees the file. The first state holds the lock until
	// the test closes it, so this load comes after the close.
	again, err := LoadState(dir, v, StateOptions{})
	if err != nil {
		t.Fatalf("load after close: %v", err)
	}
	defer again.Close()
	if !bytes.Equal(again.Bytes(), cp(10)) {
		t.Error("load after close: the state holds another note")
	}
}

// T-S-14: two runs on one state directory, each with its own load, never leave
// the state at the smaller size. A run holds the lock from the load until it
// closes the state, so the second run loads the state that the first one wrote.
func TestTS14_ConcurrentRuns(t *testing.T) {
	s, text := newKey(t, origin)
	v, _ := ParseKey([]byte(text))
	l, _ := realLog(t, 15)
	cp5, cp10, cp15 := checkpointAt(t, l, s, 5), checkpointAt(t, l, s, 10), checkpointAt(t, l, s, 15)
	for pair := 0; pair < 100; pair++ {
		dir := filepath.Join(t.TempDir(), "state")
		first, err := LoadState(dir, v, StateOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := first.Update(cp5); err != nil {
			t.Fatal(err)
		}
		first.Close()

		start := make(chan struct{})
		var wg sync.WaitGroup
		for _, latest := range [][]byte{cp15, cp10} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				st, err := LoadState(dir, v, StateOptions{})
				if err != nil {
					t.Errorf("pair %d: load: %v", pair, err)
					return
				}
				defer st.Close()
				if _, err := st.Update(latest); err != nil {
					t.Errorf("pair %d: update: %v", pair, err)
				}
			}()
		}
		close(start)
		wg.Wait()
		if got, _ := os.ReadFile(filepath.Join(dir, StateFileName(v))); !bytes.Equal(got, cp15) {
			t.Fatalf("pair %d: the state file does not hold the size 15 note", pair)
		}
	}
}

// loadResult is the result of a LoadState call in a goroutine.
type loadResult struct {
	st  *State
	err error
}

// loadAsync loads the state in a goroutine. The channel gets the state and the
// error.
func loadAsync(dir string, v note.Verifier) <-chan loadResult {
	done := make(chan loadResult, 1)
	go func() {
		st, err := LoadState(dir, v, StateOptions{})
		done <- loadResult{st, err}
	}()
	return done
}

// closeLoaded reports the error of a load and closes the state.
func closeLoaded(t *testing.T, r loadResult) {
	t.Helper()
	if r.err != nil {
		t.Errorf("load: %v", r.err)
	}
	if r.st != nil {
		r.st.Close()
	}
}

// T-S-14: a second load on the same directory waits until the first run
// closes its state.
func TestTS14_LoadWaitsForClose(t *testing.T) {
	_, text := newKey(t, origin)
	v, _ := ParseKey([]byte(text))
	dir := filepath.Join(t.TempDir(), "state")
	first, err := LoadState(dir, v, StateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	done := loadAsync(dir, v)
	select {
	case <-done:
		t.Fatal("the second load returned while the first state was open")
	case <-time.After(200 * time.Millisecond):
	}
	first.Close()
	select {
	case r := <-done:
		closeLoaded(t, r)
	case <-time.After(5 * time.Second):
		t.Fatal("the second load did not return after the close")
	}
}

// The helper process of TestTS14_KilledRunReleasesLock. It takes the lock,
// prints one line, and waits until the test kills it.
func TestTS14_LockHelper(t *testing.T) {
	dir := os.Getenv("VERIFY_LOCK_TEST_DIR")
	if dir == "" {
		t.Skip("helper process only")
	}
	v, err := ParseKey([]byte(os.Getenv("VERIFY_LOCK_TEST_KEY")))
	if err != nil {
		t.Fatal(err)
	}
	state, err := LoadState(dir, v, StateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("locked")
	// The state holds the locked directory file. Without a reference, the
	// garbage collector can run the finalizer of the file, which closes it and
	// frees the lock.
	for {
		runtime.KeepAlive(state)
		time.Sleep(time.Second)
	}
}

// T-S-14: the kernel releases the lock when the process ends. When the test
// kills a run, the run leaves no lock.
func TestTS14_KilledRunReleasesLock(t *testing.T) {
	_, text := newKey(t, origin)
	v, _ := ParseKey([]byte(text))
	dir := filepath.Join(t.TempDir(), "state")
	cmd := exec.Command(os.Args[0], "-test.run=^TestTS14_LockHelper$")
	cmd.Env = append(os.Environ(), "VERIFY_LOCK_TEST_DIR="+dir, "VERIFY_LOCK_TEST_KEY="+text)
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	if line, err := bufio.NewReader(out).ReadString('\n'); line != "locked\n" {
		cmd.Process.Kill()
		cmd.Wait()
		t.Fatalf("helper line %q, %v", line, err)
	}
	// The helper holds the lock, so a load in this process waits.
	done := loadAsync(dir, v)
	select {
	case r := <-done:
		closeLoaded(t, r)
		cmd.Process.Kill()
		cmd.Wait()
		t.Fatal("the load returned while the helper held the lock")
	case <-time.After(200 * time.Millisecond):
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	cmd.Wait()
	select {
	case r := <-done:
		closeLoaded(t, r)
	case <-time.After(5 * time.Second):
		t.Fatal("the load did not return after the test killed the helper")
	}
}

// T-S-14: a state that does not load is a fault. The file stays as it is.
func TestTS14_StateFaults(t *testing.T) {
	s, text := newKey(t, origin)
	v, _ := ParseKey([]byte(text))
	other, _ := newKey(t, origin) // same name, another key
	l, _ := realLog(t, 10)
	good := checkpointAt(t, l, s, 5)
	changed := bytes.Clone(good)
	changed[len(changed)-20] ^= 1
	outside := filepath.Join(t.TempDir(), "outside.note")
	if err := os.WriteFile(outside, good, 0o600); err != nil {
		t.Fatal(err)
	}
	for name, setup := range map[string]func(dir, file string) error{
		"changed byte":    func(_, file string) error { return os.WriteFile(file, changed, 0o600) },
		"another key":     func(_, file string) error { return os.WriteFile(file, checkpointAt(t, l, other, 5), 0o600) },
		"garbage":         func(_, file string) error { return os.WriteFile(file, []byte("contentmarker"), 0o600) },
		"past the cap":    func(_, file string) error { return os.WriteFile(file, bytes.Repeat(good, 20), 0o600) },
		"directory":       func(_, file string) error { return os.Mkdir(file, 0o700) },
		"symlink inside":  func(dir, file string) error { return symlinkTo(t, dir, good, file) },
		"symlink outside": func(_, file string) error { return os.Symlink(outside, file) },
	} {
		dir := filepath.Join(t.TempDir(), "pathmarker")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := setup(dir, filepath.Join(dir, StateFileName(v))); err != nil {
			t.Fatal(err)
		}
		before := snapshot(t, dir)
		_, err := LoadState(dir, v, StateOptions{})
		if err != ErrState {
			t.Errorf("%s: error %v, want ErrState", name, err)
		}
		if err != nil && (errors.Is(err, ErrSignature) || strings.Contains(err.Error(), "pathmarker")) {
			t.Errorf("%s: error text %q", name, err)
		}
		if after := snapshot(t, dir); after != before {
			t.Errorf("%s: the directory changed:\n%s\n%s", name, before, after)
		}
	}
	if b, _ := os.ReadFile(outside); !bytes.Equal(b, good) {
		t.Error("the file outside changed")
	}
}

// symlinkTo writes a valid note under another name in dir, and links file to it.
func symlinkTo(t *testing.T, dir string, data []byte, file string) error {
	if err := os.WriteFile(filepath.Join(dir, "valid.note"), data, 0o600); err != nil {
		return err
	}
	return os.Symlink("valid.note", file)
}

// T-S-14: if the state file changes between the load and the write, the write
// is refused. The new file stays and no temporary file is left.
func TestTS14_StateChangedDuringRun(t *testing.T) {
	s, text := newKey(t, origin)
	v, _ := ParseKey([]byte(text))
	l, _ := realLog(t, 20)
	cp := func(size int64) []byte { return checkpointAt(t, l, s, size) }
	for name, tc := range map[string]struct {
		first  bool // no state at load
		change func(file string) error
		want   string // the bytes in the file after the run, "" for none
		err    error  // the error of Update
	}{
		"state replaced":     {false, func(f string) error { return os.WriteFile(f, cp(7), 0o600) }, string(cp(7)), ErrStateChanged},
		"state removed":      {false, os.Remove, "", ErrStateChanged},
		"state made":         {true, func(f string) error { return os.WriteFile(f, cp(7), 0o600) }, string(cp(7)), ErrStateChanged},
		"state made, a link": {true, func(f string) error { return os.Symlink("x", f) }, "", ErrState},
	} {
		dir := t.TempDir()
		// t.TempDir makes the directory with the umask.
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		file := filepath.Join(dir, StateFileName(v))
		if !tc.first {
			if err := os.WriteFile(file, cp(5), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		st, err := LoadState(dir, v, StateOptions{})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if err := tc.change(file); err != nil {
			t.Fatal(err)
		}
		before := snapshot(t, dir)
		if _, err := st.Update(cp(10)); !errors.Is(err, tc.err) {
			t.Errorf("%s: error %v, want %v", name, err, tc.err)
		}
		if after := snapshot(t, dir); after != before {
			t.Errorf("%s: the directory changed:\n%s\n%s", name, before, after)
		}
		if tc.want != "" {
			if b, _ := os.ReadFile(file); string(b) != tc.want {
				t.Errorf("%s: the file was replaced", name)
			}
		}
		st.Close()
	}
}

// T-S-14: a note of size 0 with the empty root is consistent with itself. A
// note of size 0 with another root is a fork. The command uses this check for
// the first checkpoint, when there is no state.
func TestTS14_SizeZeroRoot(t *testing.T) {
	s, text := newKey(t, origin)
	v, _ := ParseKey([]byte(text))
	l, _ := realLog(t, 5)
	empty := checkpointAt(t, l, s, 0)
	other, err := note.Sign(&note.Note{Text: origin + "\n0\n" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)) + "\n"}, s)
	if err != nil {
		t.Fatal(err)
	}
	if err := Consistency(v, empty, empty, nil); err != nil {
		t.Errorf("empty root: %v", err)
	}
	if err := Consistency(v, other, other, nil); !errors.Is(err, ErrFork) {
		t.Errorf("another root: %v, want ErrFork", err)
	}
}

// T-S-14: the default directory.
func TestTS14_DefaultStateDir(t *testing.T) {
	for name, tc := range map[string]struct{ xdg, home, want string }{
		"absolute":       {"/x/state", "/h", "/x/state/phantom-verify"},
		"empty":          {"", "/h", "/h/.local/state/phantom-verify"},
		"relative":       {"rel/state", "/h", "/h/.local/state/phantom-verify"},
		"no home":        {"", "", ""},
		"relative, none": {"rel", "", ""},
	} {
		t.Setenv("XDG_STATE_HOME", tc.xdg)
		t.Setenv("HOME", tc.home)
		got, err := DefaultStateDir()
		if filepath.ToSlash(got) != tc.want || (tc.want == "") != (err == ErrState) {
			t.Errorf("%s: %q, %v", name, got, err)
		}
	}
}

// stateWithFile makes a state directory with mode 0700 that holds a valid state
// file with mode 0600. It returns the key, the directory, and the file.
func stateWithFile(t *testing.T) (note.Verifier, string, string) {
	t.Helper()
	s, text := newKey(t, origin)
	v, _ := ParseKey([]byte(text))
	l, _ := realLog(t, 10)
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, StateFileName(v))
	if err := os.WriteFile(file, checkpointAt(t, l, s, 5), 0o600); err != nil {
		t.Fatal(err)
	}
	return v, dir, file
}

// wantRefused checks that LoadState refuses dir with ErrState and that the
// directory does not change.
func wantRefused(t *testing.T, name, dir string, v note.Verifier) {
	t.Helper()
	before := snapshot(t, dir)
	st, err := LoadState(dir, v, StateOptions{})
	if !errors.Is(err, ErrState) || errors.Is(err, ErrStateLocked) {
		t.Errorf("%s: error %v, want ErrState", name, err)
	}
	if st != nil {
		st.Close()
	}
	if after := snapshot(t, dir); after != before {
		t.Errorf("%s: the directory changed:\n%s\n%s", name, before, after)
	}
}

// T-S-14: LoadState refuses a state directory with a group or other permission
// bit. The state file does not change.
func TestTS14_SharedDirectory(t *testing.T) {
	for _, mode := range []os.FileMode{0o755, 0o750, 0o701} {
		v, dir, file := stateWithFile(t)
		// Chmod, not Mkdir, so the umask does not change the mode.
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatal(err)
		}
		wantRefused(t, mode.String(), dir, v)
		if fi, err := os.Stat(file); err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("%v: the file mode: %v, %v", mode, fi, err)
		}
	}
}

// T-S-14: LoadState refuses a state file with a group or other permission bit.
func TestTS14_SharedFile(t *testing.T) {
	for _, mode := range []os.FileMode{0o640, 0o604} {
		v, dir, file := stateWithFile(t)
		if err := os.Chmod(file, mode); err != nil {
			t.Fatal(err)
		}
		wantRefused(t, mode.String(), dir, v)
		if fi, err := os.Stat(file); err != nil || fi.Mode().Perm() != mode {
			t.Errorf("%v: the file mode: %v, %v", mode, fi, err)
		}
	}
}

// T-S-14: LoadState refuses a state directory or a state file that another user
// owns.
func TestTS14_ForeignOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("os.Chown to another user needs root")
	}
	const other = 65534
	for _, target := range []string{"directory", "file"} {
		v, dir, file := stateWithFile(t)
		path := map[string]string{"directory": dir, "file": file}[target]
		if err := os.Chown(path, other, other); err != nil {
			t.Fatal(err)
		}
		wantRefused(t, target, dir, v)
	}
}

// T-S-14: a directory that LoadState makes has mode 0700 and loads again.
func TestTS14_MadeDirectoryLoadsAgain(t *testing.T) {
	_, text := newKey(t, origin)
	v, _ := ParseKey([]byte(text))
	dir := filepath.Join(t.TempDir(), "a", "state")
	for range 2 {
		st, err := LoadState(dir, v, StateOptions{})
		if err != nil {
			t.Fatal(err)
		}
		st.Close()
		if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != 0o700 {
			t.Fatalf("the directory: %v, %v", fi, err)
		}
	}
}

// T-S-14: if another run holds the lock, LoadState gives ErrStateLocked after
// the lock wait, and not much later. The state file does not change.
func TestTS14_LockWaitLimit(t *testing.T) {
	v, dir, file := stateWithFile(t)
	before, _ := os.ReadFile(file)
	// Another open file: its lock conflicts in one process.
	held, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	if err := syscall.Flock(int(held.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	const wait = 300 * time.Millisecond

	start := time.Now()
	st, err := LoadState(dir, v, StateOptions{LockWait: wait})
	elapsed := time.Since(start)
	if st != nil {
		st.Close()
	}
	if !errors.Is(err, ErrStateLocked) || !errors.Is(err, ErrState) {
		t.Errorf("error %v, want ErrStateLocked and ErrState", err)
	}
	if elapsed < wait || elapsed > wait+2*time.Second {
		t.Errorf("LoadState returned after %v, limit %v", elapsed, wait)
	}
	if after, _ := os.ReadFile(file); !bytes.Equal(after, before) {
		t.Error("the state file changed")
	}
}

// T-S-14: StateFirstUse is not the zero value, which Update returns with an
// error.
func TestTS14_StateChangeNotZero(t *testing.T) {
	for name, c := range map[string]StateChange{"first use": StateFirstUse, "updated": StateUpdated, "unchanged": StateUnchanged} {
		if c == 0 {
			t.Errorf("%s is the zero value", name)
		}
	}
}

// T-S-14: if the sync of the directory fails after the rename, the new
// checkpoint is the state: in the object, and in the file. Update gives the
// change that it made and ErrStateSync, no temporary file is left, and a new
// load finds the new checkpoint.
func TestTS14_DirectorySyncFault(t *testing.T) {
	s, text := newKey(t, origin)
	v, _ := ParseKey([]byte(text))
	l, _ := realLog(t, 10)
	cp5, cp10 := checkpointAt(t, l, s, 5), checkpointAt(t, l, s, 10)
	for name, tc := range map[string]struct {
		old  []byte // the state before the run, nil for none
		want StateChange
	}{
		"updated":   {cp5, StateUpdated},
		"first use": {nil, StateFirstUse},
	} {
		dir := filepath.Join(t.TempDir(), "state")
		file := filepath.Join(dir, StateFileName(v))
		if tc.old != nil {
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(file, tc.old, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		failSync := StateOptions{DirSync: func(*os.File) error { return errors.New("sync failed") }}
		st, err := LoadState(dir, v, failSync)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		got, err := st.Update(cp10)
		if got != tc.want || err != ErrStateSync || !errors.Is(err, ErrState) {
			t.Errorf("%s: %v, %v, want %v and ErrStateSync", name, got, err, tc.want)
		}
		if !bytes.Equal(st.Bytes(), cp10) {
			t.Errorf("%s: Bytes does not hold the new checkpoint", name)
		}
		if b, _ := os.ReadFile(file); !bytes.Equal(b, cp10) {
			t.Errorf("%s: the file does not hold the new checkpoint", name)
		}
		if n := strings.Count(snapshot(t, dir), "\n"); n != 1 {
			t.Errorf("%s: the directory holds more than the state:\n%s", name, snapshot(t, dir))
		}
		st.Close()

		again, err := LoadState(dir, v, StateOptions{})
		if err != nil {
			t.Fatalf("%s: load after the fault: %v", name, err)
		}
		if !bytes.Equal(again.Bytes(), cp10) {
			t.Errorf("%s: the load after the fault holds another note", name)
		}
		again.Close()
	}
}

// T-S-14: a fault of flock, other than a lock that another run holds, gives
// ErrState, and not ErrStateLocked.
func TestTS14_LockFault(t *testing.T) {
	v, dir, _ := stateWithFile(t)
	testutil.Set(t, &flock, func(int, int) error { return syscall.EBADF })
	wantRefused(t, "flock fault", dir, v)
}

// swapForFifo makes a hook that runs after the check of the state file. It
// replaces the file with a FIFO. The returned counter holds the swaps.
func swapForFifo(t *testing.T, file string) *int {
	t.Helper()
	swaps := new(int)
	safefiletest.Set(t, safefiletest.Hooks{AfterCheck: func(name string) {
		if name != filepath.Base(file) {
			return
		}
		*swaps++
		if err := os.Remove(file); err != nil {
			t.Error(err)
		}
		if err := syscall.Mkfifo(file, 0o600); err != nil {
			t.Error(err)
		}
	}})
	return swaps
}

// boundedCall runs f in a goroutine and fails the test if f blocks for 10
// seconds.
func boundedCall(t *testing.T, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		f()
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the call blocked")
	}
}

// wantOnlyFifo checks that the directory holds one entry, the FIFO of the swap.
func wantOnlyFifo(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 || entries[0].Type()&os.ModeNamedPipe == 0 {
		t.Errorf("the directory: %v, %v", entries, err)
	}
}

// T-S-14: a FIFO that replaces the state file after the check does not block
// LoadState. LoadState gives ErrState.
func TestTS14_FifoAfterCheck(t *testing.T) {
	v, dir, file := stateWithFile(t)
	swaps := swapForFifo(t, file)
	var err error
	boundedCall(t, func() {
		var st *State
		if st, err = LoadState(dir, v, StateOptions{}); st != nil {
			st.Close()
		}
	})
	if err != ErrState || *swaps != 1 {
		t.Errorf("error %v after %d swaps, want ErrState after 1", err, *swaps)
	}
	wantOnlyFifo(t, dir)
}

// T-S-14: a FIFO that replaces the state file after the check of the second
// read does not block Update. Update gives ErrState and does not rename.
func TestTS14_FifoAfterCheckInUpdate(t *testing.T) {
	s, text := newKey(t, origin)
	v, _ := ParseKey([]byte(text))
	l, _ := realLog(t, 10)
	dir := filepath.Join(t.TempDir(), "state")
	file := filepath.Join(dir, StateFileName(v))
	st, err := LoadState(dir, v, StateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.Update(checkpointAt(t, l, s, 5)); err != nil {
		t.Fatal(err)
	}
	swaps := swapForFifo(t, file)
	boundedCall(t, func() { _, err = st.Update(checkpointAt(t, l, s, 10)) })
	if err != ErrState || *swaps != 1 {
		t.Errorf("error %v after %d swaps, want ErrState after 1", err, *swaps)
	}
	wantOnlyFifo(t, dir)
}

// T-S-14: LoadState refuses a state file with a second hard link. Both names
// keep their bytes.
func TestTS14_SecondLink(t *testing.T) {
	v, dir, file := stateWithFile(t)
	if err := os.Link(file, filepath.Join(dir, "second.note")); err != nil {
		t.Fatal(err)
	}
	wantRefused(t, "second link", dir, v)
}

// T-S-14: if the mode of the state file changes between the load and the
// write, Update gives ErrState, and not ErrStateChanged. Nothing changes.
func TestTS14_ModeChangedDuringRun(t *testing.T) {
	s, text := newKey(t, origin)
	v, _ := ParseKey([]byte(text))
	l, _ := realLog(t, 10)
	dir := filepath.Join(t.TempDir(), "state")
	file := filepath.Join(dir, StateFileName(v))
	st, err := LoadState(dir, v, StateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.Update(checkpointAt(t, l, s, 5)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(file, 0o644); err != nil {
		t.Fatal(err)
	}
	before := snapshot(t, dir)
	if _, err := st.Update(checkpointAt(t, l, s, 10)); err != ErrState {
		t.Errorf("error %v, want ErrState", err)
	}
	if after := snapshot(t, dir); after != before {
		t.Errorf("the directory changed:\n%s\n%s", before, after)
	}
	if fi, err := os.Stat(file); err != nil || fi.Mode().Perm() != 0o644 {
		t.Errorf("the file mode: %v, %v", fi, err)
	}
}

// T-S-14: the lock wait is 30 seconds when StateOptions.LockWait is zero.
func TestTS14_DefaultLockWait(t *testing.T) {
	if defaultLockWait != 30*time.Second {
		t.Errorf("defaultLockWait is %v, want 30s", defaultLockWait)
	}
}

// T-S-14: the owner rule runs on the open state directory. A hook that names
// the directory as owned by another user makes LoadState give ErrState.
func TestTS14_OwnerRuleOnOpenDirectory(t *testing.T) {
	v, dir, _ := stateWithFile(t)
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	id, ok := safefile.Identity(fi)
	if !ok {
		t.Fatal("no identity")
	}
	safefiletest.Set(t, safefiletest.Hooks{
		OtherOwner: func(got safefile.FileID) bool { return got == id },
	})
	wantRefused(t, "other owner", dir, v)
}

// T-S-14: the text of ErrStateLocked has the "verify:" prefix once. It still
// matches ErrState.
func TestTS14_LockedErrorText(t *testing.T) {
	if n := strings.Count(ErrStateLocked.Error(), "verify:"); n != 1 {
		t.Errorf("%q has the prefix %d times", ErrStateLocked, n)
	}
	if !errors.Is(ErrStateLocked, ErrState) {
		t.Error("ErrStateLocked does not match ErrState")
	}
}
