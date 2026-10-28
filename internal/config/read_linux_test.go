package config

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestTS10_NoOpenBeforeRefusal checks that the config file and the htpasswd
// file are refused as a FIFO before any open (T-S-10). An inotify watch on the
// FIFO sees each open. The test first opens the FIFO itself, to show that the
// watch sees an open.
func TestTS10_NoOpenBeforeRefusal(t *testing.T) {
	fifo := filepath.Join(pkgTempDir(t), "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	fd, err := syscall.InotifyInit1(syscall.IN_NONBLOCK | syscall.IN_CLOEXEC)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(fd)
	if _, err := syscall.InotifyAddWatch(fd, fifo, syscall.IN_OPEN); err != nil {
		t.Fatal(err)
	}
	// opened reports whether the watch has an open event.
	opened := func() bool {
		n, err := syscall.Read(fd, make([]byte, 4096))
		if errors.Is(err, syscall.EAGAIN) {
			return false
		}
		if err != nil {
			t.Fatal(err)
		}
		return n > 0
	}

	if _, err := ReadFile(fifo); err == nil || opened() {
		t.Errorf("ReadFile: error %v, or the FIFO was opened", err)
	}
	if got := checkHtpasswd(&loader{}, fifo); got != htpasswdNotFile || opened() {
		t.Errorf("checkHtpasswd: got %q, want %q, or the FIFO was opened", got, htpasswdNotFile)
	}

	f, err := os.OpenFile(fifo, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if !opened() {
		t.Error("the watch has no event for an open of the FIFO")
	}
}
