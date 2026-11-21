package verify

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
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
		got, err := st.Update(checkpointOf(t, v, cp(step.size)))
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
		if _, err := first.Update(checkpointOf(t, v, cp5)); err != nil {
			t.Fatal(err)
		}
		first.Close()

		start := make(chan struct{})
		var wg sync.WaitGroup
		for _, latest := range []Checkpoint{checkpointOf(t, v, cp15), checkpointOf(t, v, cp10)} {
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
		if _, err := st.Update(checkpointOf(t, v, cp(10))); !errors.Is(err, tc.err) {
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

// T-S-14: Update takes a note of size 0 with the empty root as the first state.
// A note of size 0 with another root gives ErrFork, also when a state exists.
// The state file does not change.
func TestTS14_SizeZeroRoot(t *testing.T) {
	s, text := newKey(t, origin)
	v, _ := ParseKey([]byte(text))
	l, _ := realLog(t, 5)
	empty := checkpointOf(t, v, checkpointAt(t, l, s, 0))
	other, err := note.Sign(&note.Note{Text: origin + "\n0\n" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)) + "\n"}, s)
	if err != nil {
		t.Fatal(err)
	}
	bad := checkpointOf(t, v, other)
	for name, old := range map[string][]byte{"first use": nil, "with a state": checkpointAt(t, l, s, 5)} {
		dir := t.TempDir()
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if old != nil {
			if err := os.WriteFile(filepath.Join(dir, StateFileName(v)), old, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		st, err := LoadState(dir, v, StateOptions{})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		before := snapshot(t, dir)
		got, err := st.Update(bad)
		if got != 0 || err != ErrFork {
			t.Errorf("%s, another root: %v, %v, want 0 and ErrFork", name, got, err)
		}
		if after := snapshot(t, dir); after != before {
			t.Errorf("%s: the directory changed:\n%s\n%s", name, before, after)
		}
		st.Close()
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	st, err := LoadState(dir, v, StateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if got, err := st.Update(empty); got != StateFirstUse || err != nil {
		t.Errorf("empty root: %v, %v", got, err)
	}
}

// T-S-14: Update refuses the zero value, and a value of another origin, with
// ErrState. It writes nothing, and the state in the object stays as it was.
func TestTS14_UpdateRefusesValue(t *testing.T) {
	_, text := newKey(t, origin)
	v, _ := ParseKey([]byte(text))
	s2, text2 := newKey(t, origin+"-b")
	v2, _ := ParseKey([]byte(text2))
	l, _ := realLog(t, 10)
	for name, c := range map[string]Checkpoint{
		"zero value":   {},
		"other origin": checkpointOf(t, v2, checkpointAt(t, l, s2, 10)),
	} {
		dir := t.TempDir()
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		st, err := LoadState(dir, v, StateOptions{})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		before := snapshot(t, dir)
		if got, err := st.Update(c); got != 0 || err != ErrState {
			t.Errorf("%s: %v, %v, want 0 and ErrState", name, got, err)
		}
		if after := snapshot(t, dir); after != before {
			t.Errorf("%s: the directory changed:\n%s\n%s", name, before, after)
		}
		if _, ok := st.Checkpoint(); ok {
			t.Errorf("%s: the object holds a state", name)
		}
		st.Close()
	}
}

// relabeledSigner signs with a real key. It has the name and the key hash that
// a test chooses.
type relabeledSigner struct {
	note.Signer
	name string
	hash uint32
}

func (r relabeledSigner) Name() string    { return r.name }
func (r relabeledSigner) KeyHash() uint32 { return r.hash }

// relabeledVerifier verifies with a real key. It has the name and the key hash
// that a test chooses.
type relabeledVerifier struct {
	note.Verifier
	name string
	hash uint32
}

func (r relabeledVerifier) Name() string    { return r.name }
func (r relabeledVerifier) KeyHash() uint32 { return r.hash }

// relabeled returns a signer and a verifier of the key s with another name and
// another key hash.
func relabeled(t testing.TB, s note.Signer, text, name string, hash uint32) (note.Signer, note.Verifier) {
	t.Helper()
	v, err := ParseKey([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	return relabeledSigner{s, name, hash}, relabeledVerifier{v, name, hash}
}

// otherKey is a signer and a verifier that are not key A. The name is the name
// of key A, or another name.
type otherKey struct {
	label string
	s     note.Signer
	v     note.Verifier
}

// otherKeys returns the keys with the name of key A and another key hash: a
// real key, and a key with the key hash of A plus 1 or minus 1.
func otherKeys(t testing.TB, hashA uint32) []otherKey {
	t.Helper()
	sB, textB := newKey(t, origin)
	vB, _ := ParseKey([]byte(textB))
	sUp, vUp := relabeled(t, sB, textB, origin, hashA+1)
	sDown, vDown := relabeled(t, sB, textB, origin, hashA-1)
	return []otherKey{{"key B", sB, vB}, {"hash plus 1", sUp, vUp}, {"hash minus 1", sDown, vDown}}
}

// T-S-14: two checkpoints from two keys with one name are not one log. This
// holds also when the sizes and the roots are equal, and when one size is 0.
// Different sizes with a proof that verifies give ErrFork too.
func TestTS14_ConsistencyKeyHash(t *testing.T) {
	sA, textA := newKey(t, origin)
	vA, _ := ParseKey([]byte(textA))
	l, _ := realLog(t, 10)
	cpOfA := func(size int64) Checkpoint { return checkpointOf(t, vA, checkpointAt(t, l, sA, size)) }
	a0, a5, a10 := cpOfA(0), cpOfA(5), cpOfA(10)
	proofs := []ConsistencyProof{consProof(t, l, 5, 10)}
	wantErr(t, "key A with key A", Consistency(a5, a10, proofs), nil)
	for _, k := range otherKeys(t, vA.KeyHash()) {
		cpOfOther := func(size int64) Checkpoint { return checkpointOf(t, k.v, checkpointAt(t, l, k.s, size)) }
		o0, o5, o10 := cpOfOther(0), cpOfOther(5), cpOfOther(10)
		wantErr(t, k.label+": same size and root", Consistency(a10, o10, nil), ErrFork)
		wantErr(t, k.label+": same size and root, reverse", Consistency(o10, a10, nil), ErrFork)
		wantErr(t, k.label+": other size, proof verifies", Consistency(a5, o10, proofs), ErrFork)
		wantErr(t, k.label+": other size, reverse", Consistency(o10, a5, proofs), ErrFork)
		wantErr(t, k.label+": key A at 0, other at 10", Consistency(a0, o10, nil), ErrFork)
		wantErr(t, k.label+": other at 0, key A at 10", Consistency(o0, a10, nil), ErrFork)
		wantErr(t, k.label+": both at 0", Consistency(a0, o0, nil), ErrFork)
		wantErr(t, k.label+" with "+k.label, Consistency(o5, o10, proofs), nil)
	}
}

// T-S-14: a value with another name and the key hash of key A is not one log
// with a value of key A. Consistency gives ErrFork in both orders, also at size
// 0.
func TestTS14_ConsistencyOriginSameKeyHash(t *testing.T) {
	sA, textA := newKey(t, origin)
	vA, _ := ParseKey([]byte(textA))
	sB, textB := newKey(t, origin+"-b")
	sX, vX := relabeled(t, sB, textB, origin+"-b", vA.KeyHash())
	l, _ := realLog(t, 10)
	cpOfA := func(size int64) Checkpoint { return checkpointOf(t, vA, checkpointAt(t, l, sA, size)) }
	cpOfX := func(size int64) Checkpoint { return checkpointOf(t, vX, checkpointAt(t, l, sX, size)) }
	proofs := []ConsistencyProof{consProof(t, l, 5, 10)}
	wantErr(t, "same size and root", Consistency(cpOfA(10), cpOfX(10), nil), ErrFork)
	wantErr(t, "same size and root, reverse", Consistency(cpOfX(10), cpOfA(10), nil), ErrFork)
	wantErr(t, "other size, proof verifies", Consistency(cpOfA(5), cpOfX(10), proofs), ErrFork)
	wantErr(t, "other size, reverse", Consistency(cpOfX(10), cpOfA(5), proofs), ErrFork)
	wantErr(t, "size 0", Consistency(cpOfA(0), cpOfX(10), nil), ErrFork)
	wantErr(t, "size 0, reverse", Consistency(cpOfX(10), cpOfA(0), nil), ErrFork)
	wantErr(t, "value with itself", Consistency(cpOfX(5), cpOfX(10), proofs), nil)
}

// refuseUpdates checks that Update gives ErrState for each size of other, and
// writes nothing. It checks first use, and a state that holds noteA. The state
// has the name of key vA.
func refuseUpdates(t *testing.T, vA note.Verifier, noteA []byte, label string, other func(size int64) Checkpoint) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	st, err := LoadState(dir, vA, StateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	// First use: no state file. The refusal makes no file.
	empty := snapshot(t, dir)
	for _, size := range []int64{10, 0} {
		if got, err := st.Update(other(size)); got != 0 || err != ErrState {
			t.Errorf("%s, first use, size %d: %v, %v, want 0 and ErrState", label, size, got, err)
		}
		if after := snapshot(t, dir); after != empty {
			t.Errorf("%s, first use, size %d: the directory changed:\n%s", label, size, after)
		}
		if _, ok := st.Checkpoint(); ok {
			t.Errorf("%s, first use, size %d: the object holds a state", label, size)
		}
	}
	if _, err := st.Update(checkpointOf(t, vA, noteA)); err != nil {
		t.Fatal(err)
	}
	st.Close()
	st, err = LoadState(dir, vA, StateOptions{}) // a state that comes from the file
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	before := snapshot(t, dir)
	for _, size := range []int64{10, 5, 3, 0} {
		if got, err := st.Update(other(size)); got != 0 || err != ErrState {
			t.Errorf("%s, size %d: %v, %v, want 0 and ErrState", label, size, got, err)
		}
		if after := snapshot(t, dir); after != before {
			t.Errorf("%s, size %d: the directory changed:\n%s\n%s", label, size, before, after)
		}
		if c, ok := st.Checkpoint(); !ok || !bytes.Equal(c.Note(), noteA) {
			t.Errorf("%s, size %d: the object does not hold the old value", label, size)
		}
	}
}

// T-S-14: Update refuses a value from a key with the name of the state key and
// another key hash. This holds for a larger, an equal, a smaller and a zero
// size. It writes nothing, and the state in the object stays as it was.
func TestTS14_UpdateKeyHash(t *testing.T) {
	sA, textA := newKey(t, origin)
	vA, _ := ParseKey([]byte(textA))
	l, _ := realLog(t, 10)
	noteA := checkpointAt(t, l, sA, 5)
	for _, k := range otherKeys(t, vA.KeyHash()) {
		refuseUpdates(t, vA, noteA, k.label, func(size int64) Checkpoint {
			return checkpointOf(t, k.v, checkpointAt(t, l, k.s, size))
		})
	}
}

// T-S-14: Update refuses a value with another name and the key hash of the
// state key, with ErrState. It writes nothing.
func TestTS14_UpdateOriginSameKeyHash(t *testing.T) {
	sA, textA := newKey(t, origin)
	vA, _ := ParseKey([]byte(textA))
	sB, textB := newKey(t, origin+"-b")
	sX, vX := relabeled(t, sB, textB, origin+"-b", vA.KeyHash())
	l, _ := realLog(t, 10)
	refuseUpdates(t, vA, checkpointAt(t, l, sA, 5), "other name", func(size int64) Checkpoint {
		return checkpointOf(t, vX, checkpointAt(t, l, sX, size))
	})
}

// leftover makes a file in dir and returns its name.
func leftover(t *testing.T, dir, name string) string {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	return name
}

// T-S-14: LoadState removes each leftover temporary file of its key, and no
// other name. A symlink with the name is removed as a link: the target stays.
// More leftovers than one batch go too. A leftover that cannot go does not stop
// the load or the other removes.
func TestTS14_LeftoverTemporaryFiles(t *testing.T) {
	s, text := newKey(t, origin)
	v, _ := ParseKey([]byte(text))
	l, _ := realLog(t, 5)
	name := StateFileName(v)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	state := checkpointAt(t, l, s, 5)
	if err := os.WriteFile(filepath.Join(dir, name), state, 0o600); err != nil {
		t.Fatal(err)
	}
	digits := "0123456789abcdef"
	var gone []string
	for i := 0; i < 2*leftoverBatch+1; i++ {
		gone = append(gone, leftover(t, dir, fmt.Sprintf("%s.tmp-%016x", name, i)))
	}
	gone = append(gone, name+".tmp-"+digits)
	keep := []string{
		name + ".tmp-" + strings.ToUpper(digits),
		name + ".tmp-" + digits[:15],
		name + ".tmp-" + digits + "0",
		name + ".tmp-" + digits[:15] + "g",
		name + ".tmp-",
		name + ".tmp" + digits,
		name + ".tmp-" + digits + ".x",
		name + "x.tmp-" + digits,
		"x" + name + ".tmp-" + digits,
		"ffffffff.note.tmp-" + digits, // the temporary file of another key
		"other",
	}
	for _, k := range keep {
		leftover(t, dir, k)
	}
	target := leftover(t, dir, "target")
	link := name + ".tmp-" + "aaaaaaaaaaaaaaaa"
	if err := os.Symlink(target, filepath.Join(dir, link)); err != nil {
		t.Fatal(err)
	}
	gone = append(gone, link)
	stuck := name + ".tmp-" + "bbbbbbbbbbbbbbbb" // Remove fails: not empty
	if err := os.Mkdir(filepath.Join(dir, stuck), 0o700); err != nil {
		t.Fatal(err)
	}
	leftover(t, filepath.Join(dir, stuck), "inner")
	keep = append(keep, target, stuck)

	st, err := LoadState(dir, v, StateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	for _, g := range gone {
		if _, err := os.Lstat(filepath.Join(dir, g)); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s: not removed (%v)", g, err)
		}
	}
	for _, k := range append(keep, name) {
		if _, err := os.Lstat(filepath.Join(dir, k)); err != nil {
			t.Errorf("%s: %v", k, err)
		}
	}
	if b, err := os.ReadFile(filepath.Join(dir, target)); err != nil || string(b) != "x" {
		t.Errorf("the target of the link: %q, %v", b, err)
	}
	if !bytes.Equal(st.Bytes(), state) {
		t.Error("the state is not loaded")
	}
}

// T-S-14: the temporary name of a write is a leftover name. The next
// LoadState removes a file with that name.
func TestTS14_WriteNameIsLeftoverName(t *testing.T) {
	_, text := newKey(t, origin)
	v, _ := ParseKey([]byte(text))
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	st, err := LoadState(dir, v, StateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var made []string
	for i := 0; i < 8; i++ {
		tmp, err := st.tmpName()
		if err != nil {
			t.Fatal(err)
		}
		if !st.isLeftover(tmp) {
			t.Errorf("%q: not a leftover name", tmp)
		}
		made = append(made, leftover(t, dir, tmp))
	}
	st.Close()

	st, err = LoadState(dir, v, StateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	for _, m := range made {
		if _, err := os.Lstat(filepath.Join(dir, m)); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s: not removed (%v)", m, err)
		}
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
		got, err := st.Update(checkpointOf(t, v, cp10))
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

// swapAfterCheck makes a hook that runs swap after the check of the state file.
// The returned slice holds the name of each check after which swap ran.
func swapAfterCheck(t *testing.T, file string, swap func() error) *[]string {
	t.Helper()
	swapped := new([]string)
	safefiletest.Set(t, safefiletest.Hooks{AfterCheck: func(name string) {
		if name != filepath.Base(file) {
			return
		}
		*swapped = append(*swapped, name)
		if err := swap(); err != nil {
			t.Error(err)
		}
	}})
	return swapped
}

// stateSwap is a change of the state file after the check, and before the open.
type stateSwap struct {
	name string
	fifo bool // the swap leaves a FIFO at the name
	swap func(dir, file string) error
}

var stateSwaps = []stateSwap{
	{"FIFO", true, func(_, file string) error {
		if err := os.Remove(file); err != nil {
			return err
		}
		return syscall.Mkfifo(file, 0o600)
	}},
	{"file removed", false, func(_, file string) error { return os.Remove(file) }},
	{"dangling symlink", false, func(_, file string) error {
		if err := os.Remove(file); err != nil {
			return err
		}
		return os.Symlink("missing", file)
	}},
	{"symlink to another file", false, func(dir, file string) error {
		if err := os.WriteFile(filepath.Join(dir, "other.note"), []byte("other"), 0o600); err != nil {
			return err
		}
		if err := os.Remove(file); err != nil {
			return err
		}
		return os.Symlink("other.note", file)
	}},
	{"new inode", false, func(dir, file string) error {
		if err := os.Rename(file, filepath.Join(dir, "old.note")); err != nil {
			return err
		}
		return os.WriteFile(file, []byte("new"), 0o600)
	}},
}

// wantSwapRefused checks the result of a run in which a swap changed the state
// file after the check. The swap ran once, for the state file only. The run
// gave ErrState, left no temporary file, and did not write the note written.
func wantSwapRefused(t *testing.T, tc stateSwap, dir, file string, swapped []string, err error, written []byte) {
	t.Helper()
	if want := []string{filepath.Base(file)}; err != ErrState || !slices.Equal(swapped, want) {
		t.Errorf("error %v after swaps for %q, want ErrState after %q", err, swapped, want)
	}
	if tc.fifo {
		wantOnlyFifo(t, dir)
		return
	}
	entries, rerr := os.ReadDir(dir)
	if rerr != nil {
		t.Fatal(rerr)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Errorf("the temporary file %s is left", e.Name())
		}
	}
	if b, rerr := os.ReadFile(file); rerr == nil && written != nil && bytes.Equal(b, written) {
		t.Error("the state file holds the new note")
	}
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

// T-S-14: a swap of the state file after the check gives ErrState in LoadState.
// The swap is a FIFO, which does not block, or a removed file, a symlink, or a
// new file. The run writes nothing.
func TestTS14_SwapAfterCheck(t *testing.T) {
	for _, tc := range stateSwaps {
		t.Run(tc.name, func(t *testing.T) {
			v, dir, file := stateWithFile(t)
			swapped := swapAfterCheck(t, file, func() error { return tc.swap(dir, file) })
			var err error
			boundedCall(t, func() {
				var st *State
				if st, err = LoadState(dir, v, StateOptions{}); st != nil {
					st.Close()
				}
			})
			wantSwapRefused(t, tc, dir, file, *swapped, err, nil)
		})
	}
}

// T-S-14: the same swaps after the check of the second read give ErrState in
// Update. Update does not rename.
func TestTS14_SwapAfterCheckInUpdate(t *testing.T) {
	for _, tc := range stateSwaps {
		t.Run(tc.name, func(t *testing.T) {
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
			if _, err := st.Update(checkpointOf(t, v, checkpointAt(t, l, s, 5))); err != nil {
				t.Fatal(err)
			}
			swapped := swapAfterCheck(t, file, func() error { return tc.swap(dir, file) })
			latest := checkpointAt(t, l, s, 10)
			latestCp := checkpointOf(t, v, latest)
			boundedCall(t, func() { _, err = st.Update(latestCp) })
			wantSwapRefused(t, tc, dir, file, *swapped, err, latest)
		})
	}
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

// T-S-14: the mode of the state file changes between the load and the write.
// Then Update gives ErrState, not ErrStateChanged. Nothing changes.
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
	if _, err := st.Update(checkpointOf(t, v, checkpointAt(t, l, s, 5))); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(file, 0o644); err != nil {
		t.Fatal(err)
	}
	before := snapshot(t, dir)
	if _, err := st.Update(checkpointOf(t, v, checkpointAt(t, l, s, 10))); err != ErrState {
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

// otherOwnerOf sets an OtherOwner hook that is true only for the FileID of
// path.
func otherOwnerOf(t *testing.T, path string) {
	t.Helper()
	fi, err := os.Stat(path)
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
}

// T-S-14: an OtherOwner hook refuses the FileID of the state directory. Then
// LoadState gives ErrState.
func TestTS14_OwnerRuleOnOpenDirectory(t *testing.T) {
	v, dir, _ := stateWithFile(t)
	otherOwnerOf(t, dir)
	wantRefused(t, "other owner", dir, v)
}

// T-S-14: an OtherOwner hook refuses the FileID of the state file. Then
// LoadState gives ErrState, also when the run is not root.
func TestTS14_OwnerRuleOnStateFile(t *testing.T) {
	v, dir, file := stateWithFile(t)
	otherOwnerOf(t, file)
	wantRefused(t, "other owner", dir, v)
}

// T-S-14: a byte appended to the state file after the open gives ErrState. The
// hook runs before the fstat, so the parse of the note refuses the file.
func TestTS14_FileGrowsAfterOpen(t *testing.T) {
	v, dir, file := stateWithFile(t)
	safefiletest.Set(t, safefiletest.Hooks{AfterOpen: func(name string) {
		if name != filepath.Base(file) {
			return
		}
		f, err := os.OpenFile(file, os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			t.Error(err)
			return
		}
		if _, err := f.Write([]byte{'x'}); err != nil {
			t.Error(err)
		}
		f.Close()
	}})
	st, err := LoadState(dir, v, StateOptions{})
	if st != nil {
		st.Close()
	}
	if err != ErrState {
		t.Errorf("error %v, want ErrState", err)
	}
}

// T-S-14: each text of a state fault has the "verify:" prefix once, and each
// still matches ErrState.
func TestTS14_LockedErrorText(t *testing.T) {
	for name, err := range map[string]error{"locked": ErrStateLocked, "sync": ErrStateSync} {
		if n := strings.Count(err.Error(), "verify:"); n != 1 {
			t.Errorf("%s: %q has the prefix %d times", name, err, n)
		}
		if !errors.Is(err, ErrState) {
			t.Errorf("%s: does not match ErrState", name)
		}
	}
}
