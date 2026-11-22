package main

import (
	"bytes"
	"context"
	"os"
	"testing"

	"github.com/cybagard/cyba-phantom/internal/event"
	"github.com/cybagard/cyba-phantom/internal/listener"
)

// closeBounded stops the certificate client before it closes the cache. The
// client writes to the cache until it stops.
func TestCloseBoundedStopsClientBeforeCacheCloses(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	cache, err := listener.Open(root, "cache")
	if err != nil {
		t.Fatal(err)
	}
	defer cache.Close()
	q, err := event.NewQueue(1, event.NewCounters())
	if err != nil {
		t.Fatal(err)
	}
	s := &storePart{
		q:         q,
		cancel:    func() {},
		stopSched: func() {},
	}
	var calls int
	var openAtStop bool
	stopClient := func() {
		calls++
		openAtStop = cache.Store(context.Background(), "probe", []byte("x")) == nil
	}
	var stderr bytes.Buffer
	if !closeBounded(&stderr, stopClient, cache, s) {
		t.Fatalf("close did not end in time; stderr %q", stderr.String())
	}
	if calls != 1 {
		t.Fatalf("the client stop step ran %d times, want 1", calls)
	}
	if !openAtStop {
		t.Error("the cache was closed before the client stopped")
	}
}
