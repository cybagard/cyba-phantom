package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"

	"github.com/cybagard/cyba-phantom/internal/listener"
)

// fenceWait is the time that the close of a cacheFence gets to wait for the
// operations in progress.
const fenceWait = 30 * time.Second

var errFenceClosed = errors.New("certificate cache fence is closed")

// cacheFence is a certmagic.Storage over the certificate cache. It counts the
// operations in progress. After close, it refuses each operation with
// errFenceClosed and does not call the cache. The os.Root of the cache only
// marks itself closed. An operation that passed its check can still make a
// file.
type cacheFence struct {
	mu     sync.Mutex
	next   certmagic.Storage
	closed bool
	busy   sync.WaitGroup // the operations in progress
}

func newCacheFence(next certmagic.Storage) *cacheFence { return &cacheFence{next: next} }

// do runs fn on the cache, or returns errFenceClosed after the close.
func (f *cacheFence) do(fn func(certmagic.Storage) error) error {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return errFenceClosed
	}
	f.busy.Add(1)
	next := f.next
	f.mu.Unlock()
	defer f.busy.Done()
	return fn(next)
}

// close refuses the later operations. Then it waits at most wait for the
// operations in progress. It can run more than once.
func (f *cacheFence) close(wait time.Duration) error {
	f.mu.Lock()
	f.closed = true
	f.mu.Unlock()
	idle := make(chan struct{})
	go func() { f.busy.Wait(); close(idle) }()
	select {
	case <-idle:
		return nil
	case <-time.After(wait):
		return fmt.Errorf("an operation on the certificate cache did not end in %v", wait)
	}
}

func (f *cacheFence) Lock(ctx context.Context, name string) error {
	return f.do(func(s certmagic.Storage) error { return s.Lock(ctx, name) })
}

func (f *cacheFence) Unlock(ctx context.Context, name string) error {
	return f.do(func(s certmagic.Storage) error { return s.Unlock(ctx, name) })
}

func (f *cacheFence) Store(ctx context.Context, key string, value []byte) error {
	return f.do(func(s certmagic.Storage) error { return s.Store(ctx, key, value) })
}

func (f *cacheFence) Load(ctx context.Context, key string) (v []byte, err error) {
	err = f.do(func(s certmagic.Storage) (e error) { v, e = s.Load(ctx, key); return })
	return v, err
}

func (f *cacheFence) Delete(ctx context.Context, key string) error {
	return f.do(func(s certmagic.Storage) error { return s.Delete(ctx, key) })
}

func (f *cacheFence) Exists(ctx context.Context, key string) (ok bool) {
	f.do(func(s certmagic.Storage) error { ok = s.Exists(ctx, key); return nil })
	return ok
}

func (f *cacheFence) List(ctx context.Context, path string, recursive bool) (keys []string, err error) {
	err = f.do(func(s certmagic.Storage) (e error) { keys, e = s.List(ctx, path, recursive); return })
	return keys, err
}

func (f *cacheFence) Stat(ctx context.Context, key string) (info certmagic.KeyInfo, err error) {
	err = f.do(func(s certmagic.Storage) (e error) { info, e = s.Stat(ctx, key); return })
	return info, err
}

// fenceCache puts a cacheFence over the certificate cache of the client that
// serve makes, until the test ends. The fence has one cache. When a test makes
// a second client, the first client also uses the cache of the second client.
// Its close runs in a cleanup: call
// fenceCache before the cleanup that waits for serve. Then the close runs after
// that wait and before the removal of the temporary directory. A test that
// wraps newACME itself sets its wrapper before the call.
func fenceCache(t *testing.T) {
	t.Helper()
	f := &cacheFence{}
	old := newACME
	newACME = func(ap listener.ACMEParams) (*listener.ACME, error) {
		f.mu.Lock()
		f.next, ap.Storage = ap.Storage, f
		f.mu.Unlock()
		return old(ap)
	}
	t.Cleanup(func() { newACME = old })
	t.Cleanup(func() {
		if err := f.close(fenceWait); err != nil {
			t.Error(err)
		}
	})
}

// countStore counts the calls that reach it. A Store call tells entered, then
// waits for release when release is set.
type countStore struct {
	calls   atomic.Int32
	stored  atomic.Bool // a Store call ran to its end
	entered chan struct{}
	release chan struct{}
}

func (c *countStore) Lock(context.Context, string) error   { c.calls.Add(1); return nil }
func (c *countStore) Unlock(context.Context, string) error { c.calls.Add(1); return nil }
func (c *countStore) Load(context.Context, string) ([]byte, error) {
	c.calls.Add(1)
	return nil, nil
}
func (c *countStore) Delete(context.Context, string) error { c.calls.Add(1); return nil }
func (c *countStore) Exists(context.Context, string) bool  { c.calls.Add(1); return true }
func (c *countStore) List(context.Context, string, bool) ([]string, error) {
	c.calls.Add(1)
	return nil, nil
}
func (c *countStore) Stat(context.Context, string) (certmagic.KeyInfo, error) {
	c.calls.Add(1)
	return certmagic.KeyInfo{}, nil
}

func (c *countStore) Store(context.Context, string, []byte) error {
	c.calls.Add(1)
	if c.release != nil {
		c.entered <- struct{}{}
		<-c.release
	}
	c.stored.Store(true)
	return nil
}

// TestTI03_FenceCloseWaitsForOperation holds one Store call in the cache. A
// close with a short wait must fail while the call is in progress. After the
// call returns, the close must work, and the call must have ended.
func TestTI03_FenceCloseWaitsForOperation(t *testing.T) {
	cs := &countStore{entered: make(chan struct{}, 1), release: make(chan struct{})}
	release := sync.OnceFunc(func() { close(cs.release) })
	t.Cleanup(release)
	f := newCacheFence(cs)
	stored := make(chan error, 1)
	go func() { stored <- f.Store(t.Context(), "k", []byte("v")) }()
	select {
	case <-cs.entered:
	case <-time.After(fenceWait):
		t.Fatalf("the Store call did not reach the cache in %v", fenceWait)
	}
	if err := f.close(10 * time.Millisecond); err == nil {
		t.Fatal("close returned with no error while an operation was in progress")
	}
	release()
	if err := f.close(fenceWait); err != nil {
		t.Fatal(err)
	}
	if !cs.stored.Load() {
		t.Error("close returned before the operation in progress returned")
	}
	if err := <-stored; err != nil {
		t.Errorf("the operation in progress: %v", err)
	}
}

// TestTI03_FenceRefusesAfterClose checks each operation after the close. It
// gives errFenceClosed and makes no call to the cache. A Store call to a cache
// on disk makes no file, and a Store call before the close makes one.
func TestTI03_FenceRefusesAfterClose(t *testing.T) {
	ctx := t.Context()
	cs := &countStore{}
	f := newCacheFence(cs)
	if err := f.close(fenceWait); err != nil {
		t.Fatal(err)
	}
	_, loadErr := f.Load(ctx, "k")
	_, listErr := f.List(ctx, "k", true)
	_, statErr := f.Stat(ctx, "k")
	for name, err := range map[string]error{
		"Lock": f.Lock(ctx, "k"), "Unlock": f.Unlock(ctx, "k"), "Store": f.Store(ctx, "k", nil),
		"Load": loadErr, "Delete": f.Delete(ctx, "k"), "List": listErr, "Stat": statErr,
	} {
		if !errors.Is(err, errFenceClosed) {
			t.Errorf("%s after the close: error %v, want %v", name, err, errFenceClosed)
		}
	}
	if f.Exists(ctx, "k") {
		t.Error("Exists after the close is true")
	}
	if n := cs.calls.Load(); n != 0 {
		t.Errorf("%d calls reached the cache after the close, want 0", n)
	}

	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	cache, err := listener.Open(root, "cache")
	if err != nil {
		t.Fatal(err)
	}
	defer cache.Close()
	onDisk := newCacheFence(cache)
	if err := onDisk.Store(ctx, "before", []byte("v")); err != nil {
		t.Fatalf("Store before the close: %v", err)
	}
	if err := onDisk.close(fenceWait); err != nil {
		t.Fatal(err)
	}
	if err := onDisk.Store(ctx, "after", []byte("v")); !errors.Is(err, errFenceClosed) {
		t.Errorf("Store after the close: error %v, want %v", err, errFenceClosed)
	}
	for key, want := range map[string]bool{"before": true, "after": false} {
		if _, err := os.Lstat(filepath.Join(dir, "cache", key)); (err == nil) != want {
			t.Errorf("file %q in the cache directory: error %v, want present %v", key, err, want)
		}
	}
}

// TestTI03_LaunchGivesTheClientTheFence checks that launchServe and
// launchViaServe put the fence over the cache of the client. After the cleanup
// of the launch ran, a Store call through the Storage of the client fails with
// errFenceClosed.
func TestTI03_LaunchGivesTheClientTheFence(t *testing.T) {
	var got certmagic.Storage
	oldNew := newACME
	t.Cleanup(func() { newACME = oldNew })
	newACME = func(ap listener.ACMEParams) (*listener.ACME, error) { got = ap.Storage; return oldNew(ap) }
	for _, name := range []string{"launchServe", "launchViaServe"} {
		got = nil
		t.Run(name, func(t *testing.T) {
			https, plain, ca := openListeners(t)
			cfg := serveCfg(t, https.Addr().String(), plain.Addr().String(), ca)
			if name == "launchServe" {
				launchServe(t, cfg, tempState(t, cfg), realDeps).waitStarted(t)
			} else {
				launchViaServe(t, cfg, content{}, tempState(t, cfg), nil).waitStarted(t)
			}
		})
		if _, ok := got.(*cacheFence); !ok {
			t.Fatalf("%s: the Storage of the client is %T, want *cacheFence", name, got)
		}
		if err := got.Store(t.Context(), "k", []byte("v")); !errors.Is(err, errFenceClosed) {
			t.Errorf("%s: Store after the cleanup: error %v, want %v", name, err, errFenceClosed)
		}
	}
}
