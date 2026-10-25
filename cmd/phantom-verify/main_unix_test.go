//go:build linux || darwin

package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"testing"
	"time"

	"github.com/cybagard/cyba-phantom/internal/safefile/safefiletest"
)

// T-S-14: a state that fails the file rules gives exit 2 and a fixed message.
// The state directory does not change. A FIFO swapped in after the check does
// not block the command.
func TestTS14_StateUnsafe(t *testing.T) {
	s, keyText := testKey(t, origin)
	l, _ := testLog(t, 10, `{"n":%d}`)
	name := stateFile(t, keyText)
	const want = "phantom-verify: state fault: the state cannot be used\n"
	for label, tc := range map[string]struct {
		setup func(t *testing.T, dir, file string)
		fifo  bool // a FIFO replaces the file after the check
	}{
		"second link": {setup: func(t *testing.T, dir, file string) {
			if err := os.Link(file, filepath.Join(dir, "second.note")); err != nil {
				t.Fatal(err)
			}
		}},
		"directory mode 0755": {setup: func(t *testing.T, dir, _ string) {
			if err := os.Chmod(dir, 0o755); err != nil {
				t.Fatal(err)
			}
		}},
		"FIFO after the check": {fifo: true},
	} {
		t.Run(label, func(t *testing.T) {
			f := newFiles(t)
			dir := filepath.Join(f.dir, "state")
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(dir, name)
			if err := os.WriteFile(file, checkpointAt(t, l, s, 5), 0o600); err != nil {
				t.Fatal(err)
			}
			if tc.setup != nil {
				tc.setup(t, dir, file)
			}
			var before string // a FIFO would block the listing
			if !tc.fifo {
				before = stateSnap(t, dir)
			}
			var swapped []string // the name of each check after which the swap ran
			if tc.fifo {
				safefiletest.Set(t, safefiletest.Hooks{AfterCheck: func(n string) {
					if n != name {
						return
					}
					swapped = append(swapped, n)
					if err := os.Remove(file); err != nil {
						t.Error(err)
					}
					if err := syscall.Mkfifo(file, 0o600); err != nil {
						t.Error(err)
					}
				}})
			}
			key := f.write("key", []byte(keyText))
			cp := f.write("cp", checkpointAt(t, l, s, 10))
			t.Setenv("XDG_STATE_HOME", f.dir)
			type result struct {
				code           int
				stdout, stderr string
			}
			done := make(chan result, 1)
			go func() {
				var stdout, stderr bytes.Buffer
				code := run([]string{"--key", key, "--checkpoint", cp, "--state", dir}, &stdout, &stderr)
				done <- result{code, stdout.String(), stderr.String()}
			}()
			var r result
			select {
			case r = <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("the command blocked")
			}
			if r.code != 2 || r.stdout != "" || r.stderr != want {
				t.Errorf("exit %d, stdout %q, stderr %q", r.code, r.stdout, r.stderr)
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			if tc.fifo {
				if !slices.Equal(swapped, []string{name}) {
					t.Errorf("the swap ran after the checks of %q, want %q", swapped, name)
				}
				if len(entries) != 1 || entries[0].Type()&os.ModeNamedPipe == 0 {
					t.Errorf("the state directory: %v", entries)
				}
				return
			}
			if after := stateSnap(t, dir); after != before {
				t.Errorf("the state directory changed:\n%s\n%s", before, after)
			}
		})
	}
}

// T-S-14: the command closes the state, and so frees the lock, before it reads
// the event file. Run 1 blocks on a FIFO as event file. Run 2 on the same state
// directory must finish while run 1 still waits for the event.
func TestTS14_StateUnlockedBeforeEvent(t *testing.T) {
	s, keyText := testKey(t, origin)
	l, events := testLog(t, 10, `{"n":%d}`)
	f := newFiles(t)
	dir := filepath.Join(f.dir, "state")
	fifo := filepath.Join(f.dir, "event")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	// If the test fails early, run 1 still blocks until a reader opens the FIFO.
	// The test opens and closes the FIFO, so that the run can return.
	t.Cleanup(func() {
		if w, err := os.OpenFile(fifo, os.O_RDWR, 0); err == nil {
			w.Close()
		}
	})
	key := f.write("key", []byte(keyText))
	cp := f.write("cp", checkpointAt(t, l, s, 10))
	proof := f.write("proof", []byte(inclusionJSON(t, l, 3, 10)))
	// start runs the command in a goroutine. The channel gets "" or the fault.
	start := func(args ...string) <-chan string {
		done := make(chan string, 1)
		go func() {
			var stdout, stderr bytes.Buffer
			if code := run(args, &stdout, &stderr); code != 0 {
				done <- fmt.Sprintf("exit %d, stderr %q", code, stderr.String())
				return
			}
			done <- ""
		}()
		return done
	}
	first := start("--key", key, "--checkpoint", cp, "--state", dir, "--event", fifo, "--proof", proof)

	file := filepath.Join(dir, stateFile(t, keyText))
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if _, err := os.Stat(file); err == nil {
			break
		}
		select {
		case msg := <-first:
			t.Fatalf("run 1 finished before it wrote the state: %q", msg)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("run 1 did not write the state")
		}
	}

	second := start("--key", key, "--checkpoint", cp, "--state", dir)
	select {
	case msg := <-second:
		if msg != "" {
			t.Errorf("run 2: %s", msg)
		}
	case <-time.After(5 * time.Second):
		t.Error("run 2 did not finish while run 1 waited for the event file")
	}

	type opened struct {
		w   *os.File
		err error
	}
	open := make(chan opened, 1)
	go func() {
		w, err := os.OpenFile(fifo, os.O_WRONLY, 0)
		open <- opened{w, err}
	}()
	select {
	case o := <-open:
		if o.err != nil {
			t.Fatal(o.err)
		}
		_, werr := o.w.Write(events[3].Raw)
		if cerr := o.w.Close(); werr != nil || cerr != nil {
			t.Fatalf("write the event: %v, %v", werr, cerr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run 1 did not open the event file")
	}
	select {
	case msg := <-first:
		if msg != "" {
			t.Errorf("run 1: %s", msg)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run 1 did not finish")
	}
}
