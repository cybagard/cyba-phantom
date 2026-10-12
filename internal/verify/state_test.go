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
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/note"
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

func stateName(v note.Verifier) string { return fmt.Sprintf("%08x.note", v.KeyHash()) }

// T-S-14: first use, update, and no write for a smaller or equal size.
func TestTS14_StateUpdate(t *testing.T) {
	s, text := newKey(t, origin)
	v, _ := ParseKey([]byte(text))
	l, _ := realLog(t, 20)
	cp := func(size int64) []byte { return checkpointAt(t, l, s, size) }
	dir := filepath.Join(t.TempDir(), "a", "b") // the directory does not exist
	file := filepath.Join(dir, stateName(v))

	st, err := LoadState(dir, v)
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
	again, err := LoadState(dir, v)
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
		first, err := LoadState(dir, v)
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
				st, err := LoadState(dir, v)
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
		if got, _ := os.ReadFile(filepath.Join(dir, stateName(v))); !bytes.Equal(got, cp15) {
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
		st, err := LoadState(dir, v)
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

// T-S-14: a second load on the same directory waits until the first state is
// closed.
func TestTS14_LoadWaitsForClose(t *testing.T) {
	_, text := newKey(t, origin)
	v, _ := ParseKey([]byte(text))
	dir := filepath.Join(t.TempDir(), "state")
	first, err := LoadState(dir, v)
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
	dir := os.Getenv("PHANTOM_TEST_LOCK_DIR")
	if dir == "" {
		t.Skip("helper process only")
	}
	v, err := ParseKey([]byte(os.Getenv("PHANTOM_TEST_LOCK_KEY")))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadState(dir, v); err != nil {
		t.Fatal(err)
	}
	fmt.Println("locked")
	select {}
}

// T-S-14: the kernel releases the lock when the process ends. A run that is
// killed leaves no lock.
func TestTS14_KilledRunReleasesLock(t *testing.T) {
	_, text := newKey(t, origin)
	v, _ := ParseKey([]byte(text))
	dir := filepath.Join(t.TempDir(), "state")
	cmd := exec.Command(os.Args[0], "-test.run=^TestTS14_LockHelper$")
	cmd.Env = append(os.Environ(), "PHANTOM_TEST_LOCK_DIR="+dir, "PHANTOM_TEST_LOCK_KEY="+text)
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
		if err := setup(dir, filepath.Join(dir, stateName(v))); err != nil {
			t.Fatal(err)
		}
		before := snapshot(t, dir)
		_, err := LoadState(dir, v)
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
		file := filepath.Join(dir, stateName(v))
		if !tc.first {
			if err := os.WriteFile(file, cp(5), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		st, err := LoadState(dir, v)
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
