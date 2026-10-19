//go:build linux || darwin

package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

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
