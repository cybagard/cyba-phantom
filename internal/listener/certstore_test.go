package listener

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const marker = "-----BEGIN EC PRIVATE KEY-----"

// newStore opens a cache in the directory acme/cache of a new state directory.
// It returns the store and the path of the state directory.
func newStore(t *testing.T) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	state, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { state.Close() })
	s, err := Open(state, "acme/cache")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, dir
}

func mustNil(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestTS16StoreLoadStatDeleteRoundTrip(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	key := "certificates/ca-dir/example.com/example.com.crt"
	mustNil(t, s.Store(ctx, key, []byte("one")))
	mustNil(t, s.Store(ctx, key, []byte("second")))
	b, err := s.Load(ctx, key)
	if err != nil || string(b) != "second" {
		t.Fatalf("Load = %q, %v", b, err)
	}
	fi, err := s.Stat(ctx, key)
	if err != nil || fi.Key != key || fi.Size != 6 || !fi.IsTerminal || time.Since(fi.Modified) > time.Minute {
		t.Fatalf("Stat = %+v, %v", fi, err)
	}
	if fi, err := s.Stat(ctx, "certificates/ca-dir"); err != nil || fi.IsTerminal {
		t.Fatalf("Stat of a directory key = %+v, %v", fi, err)
	}
	if !s.Exists(ctx, key) || !s.Exists(ctx, "certificates") {
		t.Fatal("Exists is false for a stored key or its directory")
	}
	mustNil(t, s.Delete(ctx, "certificates/ca-dir"))
	if s.Exists(ctx, key) {
		t.Fatal("Delete of a directory key left a key below it")
	}
}

func TestTS16StoresIntoNewSharedDirectoriesDoNotFail(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	var failed atomic.Int64
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				// Every goroutine makes the same new directories at the same time.
				key := fmt.Sprintf("d%d/e%d/k%d-%d", j%4, j/4, g, j)
				if err := s.Store(ctx, key, []byte("v")); err != nil {
					failed.Add(1)
					t.Errorf("Store: %v", err)
				}
			}
		}()
	}
	wg.Wait()
	if n := failed.Load(); n != 0 {
		t.Fatalf("%d of 1600 Store calls failed", n)
	}
	if b, err := s.Load(ctx, "d3/e49/k7-199"); err != nil || string(b) != "v" {
		t.Fatalf("Load = %q, %v", b, err)
	}
}

func TestTS16EndedContextGivesAnErrorWithTheContextIdentity(t *testing.T) {
	s, _ := newStore(t)
	mustNil(t, s.Store(context.Background(), "kd/key", []byte("v")))
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	expired, cancel2 := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel2()
	for _, tc := range []struct {
		name string
		ctx  context.Context
		want error
	}{
		{"canceled", canceled, context.Canceled},
		{"deadline", expired, context.DeadlineExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := tc.ctx
			check := func(op string, err error) {
				t.Helper()
				if !errors.Is(err, tc.want) {
					t.Errorf("%s: error %v does not wrap %v", op, err, tc.want)
				}
				var e *Error
				if !errors.As(err, &e) || e.Op != op || e.Rule != ruleStopped {
					t.Errorf("%s: error %#v is not an *Error with the operation and the rule", op, err)
				}
			}
			_, err := s.Load(ctx, "kd/key")
			check("load", err)
			check("store", s.Store(ctx, "kd/key", []byte("changed")))
			_, err = s.Stat(ctx, "kd/key")
			check("stat", err)
			_, err = s.List(ctx, "", true)
			check("list", err)
			check("delete", s.Delete(ctx, "kd/key"))
			check("lock", s.Lock(ctx, "name"))
			if s.Exists(ctx, "kd/key") {
				t.Error("Exists with an ended context is true")
			}
			// The failed calls changed nothing.
			if b, err := s.Load(context.Background(), "kd/key"); err != nil || string(b) != "v" {
				t.Errorf("Load = %q, %v", b, err)
			}
		})
	}
	// A Lock that waits for a held lock stops with the same error.
	bg := context.Background()
	mustNil(t, s.Lock(bg, "held"))
	wctx, wcancel := context.WithTimeout(bg, 20*time.Millisecond)
	defer wcancel()
	err := s.Lock(wctx, "held")
	var e *Error
	if !errors.Is(err, context.DeadlineExceeded) || !errors.As(err, &e) || e.Op != "lock" || e.Rule != ruleStopped {
		t.Errorf("Lock while the lock is held, context ends: %#v", err)
	}
}

func TestTS16MissingKeyKeepsTheNotExistIdentity(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	for _, key := range []string{"nokey", "no/dir/key"} {
		if _, err := s.Load(ctx, key); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("Load(%q) error = %v, want fs.ErrNotExist", key, err)
		}
		if _, err := s.Stat(ctx, key); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("Stat(%q) error = %v, want fs.ErrNotExist", key, err)
		}
		if s.Exists(ctx, key) {
			t.Errorf("Exists(%q) is true", key)
		}
		// certmagic.Storage: a Delete of a missing key is not an error.
		if err := s.Delete(ctx, key); err != nil {
			t.Errorf("Delete(%q) = %v, want nil", key, err)
		}
	}
	if _, err := s.List(ctx, "nokey", true); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("List of a missing prefix error = %v, want fs.ErrNotExist", err)
	}
	var e *Error
	_, err := s.Load(ctx, "nokey")
	if !errors.As(err, &e) || e.Op != "load" || e.Rule != ruleMissing {
		t.Errorf("error = %#v, want the operation and the fixed rule", err)
	}
}

func TestTS16BadKeysAreRefused(t *testing.T) {
	s, dir := newStore(t)
	ctx := context.Background()
	keys := []string{
		"", "/", "a//b", "..", ".", "a/../b", "a/./b", "../x", "a/", "/a", "a/b\x00",
		"a b", "a:b", "a\\b", "a*b", "ä", "a/b%2f", ".tmp-x",
		"1/2/3/4/5/6/7/8/9", strings.Repeat("a", 256),
	}
	for _, key := range keys {
		if err := s.Store(ctx, key, []byte("x")); err == nil {
			t.Errorf("Store(%q) = nil", key)
		}
		if _, err := s.Load(ctx, key); err == nil {
			t.Errorf("Load(%q) = nil", key)
		}
		if s.Exists(ctx, key) {
			t.Errorf("Exists(%q) is true", key)
		}
		if err := s.Delete(ctx, key); err == nil {
			t.Errorf("Delete(%q) = nil", key)
		}
	}
	// 8 parts and 255 bytes are the limit and work.
	for _, key := range []string{"1/2/3/4/5/6/7/8", strings.Repeat("a", 255), "A-z_0.9@h"} {
		mustNil(t, s.Store(ctx, key, []byte("x")))
	}
	if _, err := s.List(ctx, "a/..", false); err == nil {
		t.Error("List of a prefix with .. = nil")
	}
	if _, err := os.Lstat(filepath.Join(dir, "x")); err == nil {
		t.Error("a bad key made a file outside the cache directory")
	}
}

func TestTS16ListFollowsTheStorageContract(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	for _, k := range []string{"a/b/1", "a/b/2", "a/c", "d"} {
		mustNil(t, s.Store(ctx, k, nil))
	}
	for _, tc := range []struct {
		prefix    string
		recursive bool
		want      []string
	}{
		{"a", false, []string{"a/b", "a/c"}},
		{"a", true, []string{"a/b/1", "a/b/2", "a/c"}},
		{"", false, []string{"a", "d"}},
		{"", true, []string{"a/b/1", "a/b/2", "a/c", "d"}},
	} {
		got, err := s.List(ctx, tc.prefix, tc.recursive)
		slices.Sort(got)
		if err != nil || !slices.Equal(got, tc.want) {
			t.Errorf("List(%q, %v) = %v, %v; want %v", tc.prefix, tc.recursive, got, err, tc.want)
		}
	}
	if _, err := s.List(ctx, "d", false); err == nil {
		t.Error("List of a file = nil")
	}
}

func TestTS16ListIsBoundedByTheNameCount(t *testing.T) {
	s, dir := newStore(t)
	for i := 0; i <= maxList; i++ {
		mustNil(t, os.WriteFile(filepath.Join(dir, "acme/cache", fmt.Sprintf("k%d", i)), nil, 0o600))
	}
	_, err := s.List(context.Background(), "", false)
	if e := new(Error); !errors.As(err, &e) || e.Rule != ruleMany {
		t.Fatalf("List error = %v, want the name limit", err)
	}
}

func TestTS16ValueIsCappedAt64KiB(t *testing.T) {
	s, dir := newStore(t)
	ctx := context.Background()
	mustNil(t, s.Store(ctx, "ok", bytes.Repeat([]byte("x"), maxValue)))
	if b, err := s.Load(ctx, "ok"); err != nil || len(b) != maxValue {
		t.Fatalf("Load of a file at the cap = %d bytes, %v", len(b), err)
	}
	if err := s.Store(ctx, "big", make([]byte, maxValue+1)); err == nil {
		t.Error("Store above the cap = nil")
	}
	// A file that another writer made above the cap: Load refuses it.
	big := append([]byte(marker), bytes.Repeat([]byte("x"), 70<<10)...)
	mustNil(t, os.WriteFile(filepath.Join(dir, "acme/cache/big"), big, 0o600))
	b, err := s.Load(ctx, "big")
	if err == nil || b != nil || strings.Contains(err.Error(), marker) {
		t.Fatalf("Load of a 70 KiB file = %d bytes, %v", len(b), err)
	}
}

func TestTS16LockBlocksUntilUnlockAndHonorsContext(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	mustNil(t, s.Lock(ctx, "a"))
	mustNil(t, s.Lock(ctx, "b")) // another name does not block
	got := make(chan error, 1)
	go func() { got <- s.Lock(ctx, "a") }()
	select {
	case err := <-got:
		t.Fatalf("second Lock returned before Unlock: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	mustNil(t, s.Unlock(ctx, "a"))
	select {
	case err := <-got:
		mustNil(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("second Lock did not return after Unlock")
	}
	cctx, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancel()
	if err := s.Lock(cctx, "a"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Lock with an ended context = %v", err)
	}
	mustNil(t, s.Unlock(ctx, "a"))
	if err := s.Unlock(ctx, "a"); err == nil {
		t.Fatal("Unlock of a lock that is not held = nil")
	}
}
