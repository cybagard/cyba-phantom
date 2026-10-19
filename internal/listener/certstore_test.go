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

func mustNil(t testing.TB, err error) {
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

func TestTS16OpenRefusesABadCacheDirectoryPath(t *testing.T) {
	dir := t.TempDir()
	state, err := os.OpenRoot(dir)
	mustNil(t, err)
	defer state.Close()
	for _, p := range []string{"", ".", "/", "/acme", "acme/", "..", "../acme", "a//b", "a/../b", "a/./b"} {
		s, err := Open(state, p)
		if err == nil {
			s.Close()
		}
		var e *Error
		if !errors.As(err, &e) || e.Op != "open" || e.Rule != ruleCachePath {
			t.Errorf("Open(%q) error = %#v, want the operation open and the rule for the cache path", p, err)
		}
	}
	if names, err := os.ReadDir(dir); err != nil || len(names) != 0 {
		t.Errorf("a bad path made %d names in the state directory, %v", len(names), err)
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
	target := outside(t, dir)
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
	// A bad key must not make a name next to the cache directory (acme/x, which
	// is also acme/cache/../x) or in the state directory (x).
	for _, p := range []string{"x", "acme/x", "acme/cache/../x"} {
		if _, err := os.Lstat(filepath.Join(dir, p)); err == nil {
			t.Errorf("a bad key made %s outside the cache directory", p)
		}
	}
	for p, want := range map[string]string{".": "acme", "acme": "cache"} {
		if names, err := os.ReadDir(filepath.Join(dir, p)); err != nil || len(names) != 1 || names[0].Name() != want {
			t.Errorf("directory %s has the names %v, %v; want only %s", p, names, err, want)
		}
	}
	unchanged(t, target)
}

func TestTS16KeyPartOf256BytesGivesTheKeyRule(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	for _, key := range []string{strings.Repeat("a", 256), "kd/" + strings.Repeat("a", 256)} {
		wantError(t, s.Store(ctx, key, []byte("v")), "store", ruleKey)
		_, err := s.Load(ctx, key)
		wantError(t, err, "load", ruleKey)
		wantError(t, s.Delete(ctx, key), "delete", ruleKey)
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

// fill makes n empty key files with mode 0600 in the directory d of the cache.
func fill(t *testing.T, dir, d string, n int) {
	t.Helper()
	mustNil(t, os.MkdirAll(filepath.Join(dir, "acme/cache", d), 0o700))
	for i := 0; i < n; i++ {
		mustNil(t, os.WriteFile(filepath.Join(dir, "acme/cache", d, fmt.Sprintf("k%d", i)), nil, 0o600))
	}
}

func TestTS16ListHidesTemporaryFiles(t *testing.T) {
	s, dir := newStore(t)
	ctx := context.Background()
	cache := filepath.Join(dir, "acme/cache")
	for _, k := range []string{"r", "kd/k"} {
		mustNil(t, s.Store(ctx, k, []byte("v")))
	}
	for _, p := range []string{".tmp-a", "kd/.tmp-b"} {
		mustNil(t, os.WriteFile(filepath.Join(cache, p), []byte("v"), 0o600))
	}
	for _, tc := range []struct {
		prefix    string
		recursive bool
		want      []string
	}{
		{"", false, []string{"kd", "r"}},
		{"", true, []string{"kd/k", "r"}},
		{"kd", false, []string{"kd/k"}},
		{"kd", true, []string{"kd/k"}},
	} {
		got, err := s.List(ctx, tc.prefix, tc.recursive)
		slices.Sort(got)
		if err != nil || !slices.Equal(got, tc.want) {
			t.Errorf("List(%q, %v) = %v, %v; want %v", tc.prefix, tc.recursive, got, err, tc.want)
		}
	}
}

func TestTS16ListBoundCountsTheNamesOfAllDirectories(t *testing.T) {
	s, dir := newStore(t)
	ctx := context.Background()
	// Each directory is below the bound. Together they are above it.
	fill(t, dir, "d1", 2058)
	fill(t, dir, "d2", 2058)
	for _, d := range []string{"d1", "d2"} {
		if keys, err := s.List(ctx, d, true); err != nil || len(keys) != 2058 {
			t.Fatalf("List(%q) = %d keys, %v", d, len(keys), err)
		}
	}
	keys, err := s.List(ctx, "", true)
	if e := new(Error); !errors.As(err, &e) || e.Op != "list" || e.Rule != ruleMany || keys != nil {
		t.Fatalf("recursive List = %d keys, %v; want the name limit", len(keys), err)
	}
}

func TestTS16ListAcceptsExactlyTheMostNames(t *testing.T) {
	ctx := context.Background()
	t.Run("one directory", func(t *testing.T) {
		s, dir := newStore(t)
		fill(t, dir, ".", maxList)
		if keys, err := s.List(ctx, "", false); err != nil || len(keys) != maxList {
			t.Fatalf("List = %d keys, %v; want %d keys", len(keys), err, maxList)
		}
	})
	t.Run("two directories", func(t *testing.T) {
		s, dir := newStore(t)
		// The two directories count as 2 names.
		fill(t, dir, "d1", (maxList-2)/2)
		fill(t, dir, "d2", (maxList-2)/2)
		if keys, err := s.List(ctx, "", true); err != nil || len(keys) != maxList-2 {
			t.Fatalf("List = %d keys, %v; want %d keys", len(keys), err, maxList-2)
		}
	})
}

func TestTS16ValueIsCappedAt64KiB(t *testing.T) {
	s, dir := newStore(t)
	ctx := context.Background()
	target := outside(t, dir)
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
	unchanged(t, target)
}

// A hook does the rename of a Store at three fixed points of a Load, so the test
// does not depend on timing. At each point Load returns a whole value with no
// error:
//   - between the Lstat and the open: the new value, after a second try;
//   - after the open, before Stat: the old value of the open file, in one try;
//   - before the rename, when the temporary file is written: the old value (the
//     Load runs first, then the rename).
//
// After the Store returns, Load gives the new value.
func TestTS16LoadDuringStoreOfTheSameKeyGivesAWholeValue(t *testing.T) {
	ctx := context.Background()
	oldValue := bytes.Repeat([]byte("o"), 1500)
	newValue := bytes.Repeat([]byte("nm"), 2500)
	setup := func(t *testing.T) *Store {
		s, _ := newStore(t)
		mustNil(t, s.Store(ctx, "kd/key", oldValue))
		return s
	}
	load := func(t *testing.T, s *Store, want []byte) {
		t.Helper()
		if b, err := s.Load(ctx, "kd/key"); err != nil || !bytes.Equal(b, want) {
			t.Fatalf("Load = %d bytes, %v; want the %d bytes of the whole value", len(b), err, len(want))
		}
	}

	t.Run("rename between the Lstat and the open", func(t *testing.T) {
		s := setup(t)
		calls := 0
		betweenLstatAndOpen = func() {
			if calls++; calls == 1 {
				mustNil(t, s.Store(ctx, "kd/key", newValue))
			}
		}
		t.Cleanup(func() { betweenLstatAndOpen = nil })
		load(t, s, newValue)
		if calls != 2 {
			t.Errorf("the hook ran %d times, want 2", calls)
		}
	})

	t.Run("rename after the open, before Stat", func(t *testing.T) {
		s := setup(t)
		calls := 0
		betweenOpenAndStat = func() {
			if calls++; calls == 1 {
				mustNil(t, s.Store(ctx, "kd/key", newValue))
			}
		}
		t.Cleanup(func() { betweenOpenAndStat = nil })
		load(t, s, oldValue)
		if calls != 1 {
			t.Errorf("the hook ran %d times, want 1", calls)
		}
		load(t, s, newValue)
	})

	t.Run("temporary file written, not yet renamed", func(t *testing.T) {
		s := setup(t)
		realRename := renameFile
		t.Cleanup(func() { renameFile = realRename })
		calls := 0
		renameFile = func(r *os.Root, from, to string) error {
			if calls++; calls == 1 {
				load(t, s, oldValue)
			}
			return realRename(r, from, to)
		}
		mustNil(t, s.Store(ctx, "kd/key", newValue))
		if calls != 1 {
			t.Errorf("the rename ran %d times, want 1", calls)
		}
		load(t, s, newValue)
	})
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
	err := s.Unlock(ctx, "a")
	if err == nil {
		t.Fatal("Unlock of a lock that is not held = nil")
	}
	wantError(t, err, "unlock", ruleNotHeld)
}

// countTmp returns the number of names in the host directory p that start with
// tmpPrefix.
func countTmp(t *testing.T, p string) int {
	t.Helper()
	names, err := os.ReadDir(p)
	mustNil(t, err)
	n := 0
	for _, e := range names {
		if strings.HasPrefix(e.Name(), tmpPrefix) {
			n++
		}
	}
	return n
}

func TestTS16OpenRemovesLeftoverTemporaryFilesThroughTheRoot(t *testing.T) {
	ctx := context.Background()
	first, dir := newStore(t)
	mustNil(t, first.Store(ctx, "kd/real", []byte("v")))
	mustNil(t, first.Close())
	cache := filepath.Join(dir, "acme/cache")
	kd := filepath.Join(cache, "kd")
	mustNil(t, os.Mkdir(filepath.Join(kd, "sub"), 0o700))
	// More leftovers than List reads, in one key directory. A few more are in the
	// cache directory and in a directory below the key directory.
	for i := 0; i <= maxList; i++ {
		mustNil(t, os.WriteFile(filepath.Join(kd, fmt.Sprintf("%s%d", tmpPrefix, i)), nil, 0o600))
	}
	for i := 0; i < 3; i++ {
		mustNil(t, os.WriteFile(filepath.Join(cache, fmt.Sprintf("%sroot%d", tmpPrefix, i)), nil, 0o600))
	}
	mustNil(t, os.WriteFile(filepath.Join(kd, "sub", tmpPrefix+"deep"), nil, 0o600))
	// The names outside the cache directory: in the parent, outside the state
	// directory, and a symbolic link in the cache that names the outside file.
	target := outside(t, dir)
	parentTmp := filepath.Join(dir, "acme", tmpPrefix+"parent")
	outsideTmp := filepath.Join(filepath.Dir(dir), tmpPrefix+"outside-"+filepath.Base(dir))
	mustNil(t, os.WriteFile(parentTmp, []byte("parent"), 0o600))
	mustNil(t, os.WriteFile(outsideTmp, []byte("outside"), 0o600))
	mustNil(t, os.Symlink(outsideTmp, filepath.Join(cache, tmpPrefix+"link")))

	state, err := os.OpenRoot(dir)
	mustNil(t, err)
	defer state.Close()
	s, err := Open(state, "acme/cache")
	mustNil(t, err)
	defer s.Close()

	for _, p := range []string{cache, kd, filepath.Join(kd, "sub")} {
		if n := countTmp(t, p); n != 0 {
			t.Errorf("%d temporary names stay in %s", n, p)
		}
	}
	if b, err := s.Load(ctx, "kd/real"); err != nil || string(b) != "v" {
		t.Errorf("Load = %q, %v", b, err)
	}
	keys, err := s.List(ctx, "kd", false)
	slices.Sort(keys)
	if err != nil || !slices.Equal(keys, []string{"kd/real", "kd/sub"}) {
		t.Errorf("List = %v, %v", keys, err)
	}
	for p, want := range map[string]string{parentTmp: "parent", outsideTmp: "outside"} {
		if b, err := os.ReadFile(p); err != nil || string(b) != want {
			t.Errorf("%s holds %q, %v; want %q", p, b, err, want)
		}
	}
	unchanged(t, target)
}

func TestTS16LoadGivesTheChangedRuleForAKeyFileThatShrinksAfterTheOpen(t *testing.T) {
	s, dir := newStore(t)
	ctx := context.Background()
	mustNil(t, s.Store(ctx, "kd/key", bytes.Repeat([]byte("v"), 1500)))
	// The hook cuts the same file before Load calls Stat, so the open file has the
	// size 700 when Load reads it. Load must not return the 700 bytes.
	calls := 0
	betweenOpenAndStat = func() {
		calls++
		mustNil(t, os.Truncate(filepath.Join(dir, "acme/cache/kd/key"), 700))
	}
	t.Cleanup(func() { betweenOpenAndStat = nil })
	b, err := s.Load(ctx, "kd/key")
	wantError(t, err, "load", ruleChanged)
	if b != nil {
		t.Errorf("Load returned %d bytes with an error", len(b))
	}
	if calls != 1 {
		t.Errorf("the hook ran %d times, want 1: Load must not try again", calls)
	}
}

func TestTS16ListSkipsAChildDirectoryThatADeleteRemovesDuringTheList(t *testing.T) {
	s, dir := newStore(t)
	ctx := context.Background()
	for _, k := range []string{"d1/a", "d2/b", "d3/c"} {
		mustNil(t, s.Store(ctx, k, []byte("v")))
	}
	calls := 0
	beforeListChild = func(key string) {
		if key == "d2" {
			calls++
			mustNil(t, os.RemoveAll(filepath.Join(dir, "acme/cache/d2")))
		}
	}
	t.Cleanup(func() { beforeListChild = nil })
	keys, err := s.List(ctx, "", true)
	slices.Sort(keys)
	if err != nil || !slices.Equal(keys, []string{"d1/a", "d3/c"}) {
		t.Errorf("List = %v, %v; want the keys of the other directories", keys, err)
	}
	if calls != 1 {
		t.Errorf("the hook ran %d times, want 1", calls)
	}
	// A missing top prefix is still an error.
	if _, err := s.List(ctx, "d2", true); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("List of the missing prefix error = %v, want fs.ErrNotExist", err)
	}
}

func TestTS16StoreGivesTheFileRuleWhenADeleteRemovesTheKeyDirectory(t *testing.T) {
	s, dir := newStore(t)
	ctx := context.Background()
	mustNil(t, s.Store(ctx, "kd/key", []byte("old")))
	// The hook removes the key directory after the checks of Store and before the
	// rename. The rename then fails with ENOENT.
	realRename := renameFile
	t.Cleanup(func() { renameFile = realRename })
	renameFile = func(r *os.Root, from, to string) error {
		mustNil(t, os.RemoveAll(filepath.Join(dir, "acme/cache/kd")))
		return realRename(r, from, to)
	}
	err := s.Store(ctx, "kd/key", []byte("new"))
	wantError(t, err, "store", ruleIO)
	noMarker(t, err, "kd/key")
	if errors.Is(err, fs.ErrNotExist) {
		t.Errorf("error %v wraps fs.ErrNotExist", err)
	}
	cache := filepath.Join(dir, "acme/cache")
	if n := countTmp(t, cache); n != 0 {
		t.Errorf("%d temporary names stay in the cache directory", n)
	}
	if _, err := os.Lstat(filepath.Join(cache, "kd")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Lstat of the key directory = %v, want not exist", err)
	}
}
