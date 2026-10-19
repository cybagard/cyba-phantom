//go:build unix

package listener

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"
)

func TestTS16NewFilesAreMode0600AndNewDirectoriesMode0700(t *testing.T) {
	// Set the umask to 0, so that it does not hide a wrong mode in the code.
	old := syscall.Umask(0)
	defer syscall.Umask(old)
	s, dir := newStore(t)
	mustNil(t, s.Store(context.Background(), "certificates/ca/site/site.key", []byte("k")))
	cache := filepath.Join(dir, "acme/cache")
	mustNil(t, filepath.WalkDir(cache, func(p string, d fs.DirEntry, err error) error {
		if err != nil || p == cache {
			return err
		}
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		want := fs.FileMode(0o600)
		if fi.IsDir() {
			want = 0o700
		}
		if fi.Mode().Perm() != want {
			t.Errorf("%s has mode %o, want %o", p, fi.Mode().Perm(), want)
		}
		return nil
	}))
	if fi, err := os.Lstat(filepath.Join(dir, "acme")); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("parent of the cache directory: %v, %v", fi, err)
	}
	// A temporary file does not stay.
	if names, _ := os.ReadDir(filepath.Join(cache, "certificates/ca/site")); len(names) != 1 {
		t.Errorf("key directory has %d names, want 1", len(names))
	}
}

// A value is durable in this order: write of a temporary file in the directory
// of the key, fsync of the file, rename, then fsync of the key directory and of
// each directory above it up to the cache directory.
func TestTS16WriteOrderIsTempFsyncRenameDirectoryFsync(t *testing.T) {
	s, dir := newStore(t)
	ctx := context.Background()
	cache := filepath.Join(dir, "acme/cache")
	const key = "kd/ca/key"
	mustNil(t, s.Store(ctx, key, []byte("old")))
	keyDir := filepath.Join(cache, "kd/ca")
	final := filepath.Join(cache, key)
	holds := func(p, v string) bool {
		b, err := os.ReadFile(p)
		return err == nil && string(b) == v
	}
	// tmpFile returns the temporary file in the key directory, if there is one.
	tmpFile := func() (string, bool) {
		names, _ := os.ReadDir(keyDir)
		for _, n := range names {
			if strings.HasPrefix(n.Name(), tmpPrefix) {
				return filepath.Join(keyDir, n.Name()), true
			}
		}
		return "", false
	}
	var steps []string
	oldSync, oldDir, oldRename := syncFile, syncDirFile, renameFile
	t.Cleanup(func() { syncFile, syncDirFile, renameFile = oldSync, oldDir, oldRename })
	syncFile = func(f *os.File) error {
		tmp, ok := tmpFile()
		if !ok || !holds(tmp, "new") || !holds(final, "old") {
			t.Error("file sync: the temporary file lacks the value, or the key has it already")
		} else if fi, err := f.Stat(); err != nil {
			t.Error(err)
		} else if ti, err := os.Stat(tmp); err != nil || !os.SameFile(fi, ti) {
			t.Error("file sync: the file is not the temporary file")
		}
		steps = append(steps, "sync file")
		return oldSync(f)
	}
	renameFile = func(r *os.Root, from, to string) error {
		tmp, ok := tmpFile()
		if !ok || filepath.Dir(from) != "kd/ca" || !strings.HasPrefix(filepath.Base(from), tmpPrefix) ||
			filepath.Base(tmp) != filepath.Base(from) || to != key || !holds(tmp, "new") || !holds(final, "old") {
			t.Errorf("rename %s to %s: wrong names or state", from, to)
		}
		steps = append(steps, "rename")
		return oldRename(r, from, to)
	}
	syncDirFile = func(f *os.File) error {
		if _, ok := tmpFile(); ok || !holds(final, "new") {
			t.Error("directory sync: the temporary file is there, or the key lacks the value")
		}
		fi, err := f.Stat()
		mustNil(t, err)
		step := "sync of an unknown directory"
		for _, d := range []string{"kd/ca", "kd", "."} {
			if di, err := os.Stat(filepath.Join(cache, d)); err == nil && os.SameFile(di, fi) {
				step = "sync dir " + d
				break
			}
		}
		steps = append(steps, step)
		return oldDir(f)
	}
	mustNil(t, s.Store(ctx, key, []byte("new")))
	want := []string{"sync file", "rename", "sync dir kd/ca", "sync dir kd", "sync dir ."}
	if !slices.Equal(steps, want) {
		t.Errorf("steps = %q, want %q", steps, want)
	}
	if !holds(final, "new") {
		t.Error("the key does not hold the new value")
	}
}

// failText is the text of a failure that a seam returns. It holds a path, so a
// test can see that Store does not copy the text of an inner error.
const failText = "/private/path/to/disk: EIO"

// seamError fails unless err is an *Error with the operation store and the rule
// for a file that cannot be accessed, and its text holds no path and no key.
func seamError(t *testing.T, err error, key string) {
	t.Helper()
	wantError(t, err, "store", ruleIO)
	noMarker(t, err, key)
	if err != nil && (strings.Contains(err.Error(), "private") || strings.Contains(err.Error(), "EIO")) {
		t.Errorf("error text %q holds the text of the inner error", err)
	}
}

func TestTS16FailedRenameLeavesNoTemporaryFileAndGivesAnError(t *testing.T) {
	s, dir := newStore(t)
	const key = "kd/ca/key"
	mustNil(t, s.Store(context.Background(), key, []byte("old")))
	old := renameFile
	t.Cleanup(func() { renameFile = old })
	renameFile = func(*os.Root, string, string) error { return errors.New(failText) }
	seamError(t, s.Store(context.Background(), key, []byte("new")), key)
	names, err := os.ReadDir(filepath.Join(dir, "acme/cache/kd/ca"))
	if err != nil || len(names) != 1 || names[0].Name() != "key" {
		t.Errorf("key directory has the names %v, %v; want only key", names, err)
	}
	if b, err := os.ReadFile(filepath.Join(dir, "acme/cache", key)); err != nil || string(b) != "old" {
		t.Errorf("the key holds %q, %v; want old", b, err)
	}
}

func TestTS16FailedFileSyncFailsStore(t *testing.T) {
	s, dir := newStore(t)
	const key = "kd/ca/key"
	mustNil(t, s.Store(context.Background(), key, []byte("old")))
	old := syncFile
	t.Cleanup(func() { syncFile = old })
	syncFile = func(*os.File) error { return errors.New(failText) }
	seamError(t, s.Store(context.Background(), key, []byte("new")), key)
	if b, err := os.ReadFile(filepath.Join(dir, "acme/cache", key)); err != nil || string(b) != "old" {
		t.Errorf("the key holds %q, %v; want old", b, err)
	}
	if names, err := os.ReadDir(filepath.Join(dir, "acme/cache/kd/ca")); err != nil || len(names) != 1 {
		t.Errorf("key directory has the names %v, %v; want only key", names, err)
	}
}

func TestTS16FailedDirectorySyncFailsStore(t *testing.T) {
	s, _ := newStore(t)
	const key = "kd/ca/key"
	old := syncDirFile
	t.Cleanup(func() { syncDirFile = old })
	syncDirFile = func(*os.File) error { return errors.New(failText) }
	seamError(t, s.Store(context.Background(), key, []byte("new")), key)
}

func TestTS16StoreOverAHardLinkKeepsTheOutsideFile(t *testing.T) {
	s, dir := newStore(t)
	ctx := context.Background()
	target := outside(t, dir)
	mustNil(t, os.Link(target, filepath.Join(dir, "acme/cache/hl")))
	mustNil(t, s.Store(ctx, "hl", []byte("new")))
	unchanged(t, target)
	if b, err := s.Load(ctx, "hl"); err != nil || string(b) != "new" {
		t.Fatalf("Load = %q, %v", b, err)
	}
}

// outside makes a directory next to the state directory, with a file that has
// the marker bytes and mode 0640.
func outside(t *testing.T, dir string) (target string) {
	t.Helper()
	out := filepath.Join(filepath.Dir(dir), "outside-"+filepath.Base(dir))
	mustNil(t, os.MkdirAll(out, 0o700))
	target = filepath.Join(out, "file")
	mustNil(t, os.WriteFile(target, []byte(marker), 0o640))
	mustNil(t, os.Chmod(target, 0o640))
	return target
}

// unchanged fails if the outside file differs from the bytes and mode that
// outside gave it, or if the outside directory has another file.
func unchanged(t *testing.T, target string) {
	t.Helper()
	b, err := os.ReadFile(target)
	fi, serr := os.Stat(target)
	if err != nil || serr != nil || string(b) != marker || fi.Mode().Perm() != 0o640 {
		t.Errorf("outside file changed: %q %v %v", b, fi, err)
	}
	if names, _ := os.ReadDir(filepath.Dir(target)); len(names) != 1 {
		t.Errorf("outside directory has %d names, want 1", len(names))
	}
}

// noMarker fails if the text of err holds the marker bytes or the key.
func noMarker(t *testing.T, err error, key string) {
	t.Helper()
	if err == nil {
		t.Error("no error")
	} else if s := err.Error(); strings.Contains(s, "PRIVATE KEY") || (key != "" && strings.Contains(s, key)) ||
		!strings.HasPrefix(s, "listener: cert cache: ") {
		t.Errorf("error text %q", s)
	}
}

func TestTS16SymlinkInPlaceOfFileOrKeyDirectoryIsRefused(t *testing.T) {
	s, dir := newStore(t)
	ctx := context.Background()
	target := outside(t, dir)
	cache := filepath.Join(dir, "acme/cache")
	mustNil(t, os.MkdirAll(filepath.Join(cache, "kd"), 0o700))
	mustNil(t, os.Symlink(target, filepath.Join(cache, "linkfile")))
	mustNil(t, os.Symlink(filepath.Dir(target), filepath.Join(cache, "linkdir")))
	for _, key := range []string{"linkfile", "linkdir", "linkdir/file", "linkdir/new"} {
		_, err := s.Load(ctx, key)
		noMarker(t, err, key)
		_, err = s.Stat(ctx, key)
		noMarker(t, err, key)
		noMarker(t, s.Store(ctx, key, []byte("changed")), key)
		noMarker(t, s.Delete(ctx, key), key)
		if s.Exists(ctx, key) {
			t.Errorf("Exists(%q) is true", key)
		}
		unchanged(t, target)
	}
	if _, err := s.List(ctx, "linkdir", true); err == nil {
		t.Error("List through a link = nil")
	}
	// A link in a listing is an error, not a key.
	if _, err := s.List(ctx, "", false); err == nil {
		t.Error("List with a link in it = nil")
	}
	unchanged(t, target)
}

func TestTS16SymlinkInPlaceOfCacheDirectoryIsRefused(t *testing.T) {
	_, dir := newStore(t)
	target := outside(t, dir)
	state, err := os.OpenRoot(dir)
	mustNil(t, err)
	defer state.Close()
	for _, in := range []string{"acme/cache", "acme"} { // the cache directory, and its parent
		mustNil(t, os.RemoveAll(filepath.Join(dir, "acme")))
		mustNil(t, os.MkdirAll(filepath.Join(dir, "acme/real"), 0o700))
		mustNil(t, os.Symlink("real", filepath.Join(dir, "acme/cache")))
		if in == "acme" {
			mustNil(t, os.RemoveAll(filepath.Join(dir, "acme")))
			mustNil(t, os.Symlink(filepath.Dir(target), filepath.Join(dir, "acme")))
		}
		s, err := Open(state, "acme/cache")
		if err == nil {
			s.Close()
		}
		noMarker(t, err, "")
		unchanged(t, target)
	}
}

func TestTS16DirectoryModeAndOwnerAreChecked(t *testing.T) {
	s, dir := newStore(t)
	ctx := context.Background()
	cache := filepath.Join(dir, "acme/cache")
	target := outside(t, dir)
	mustNil(t, s.Store(ctx, "kd/key", []byte("v")))
	state, err := os.OpenRoot(dir)
	mustNil(t, err)
	defer state.Close()
	for _, p := range []string{cache, filepath.Join(cache, "kd")} {
		for _, mode := range []fs.FileMode{0o755, 0o710, 0o701} {
			mustNil(t, os.Chmod(p, mode))
			_, err := s.Load(ctx, "kd/key")
			noMarker(t, err, "kd/key")
			noMarker(t, s.Store(ctx, "kd/key2", nil), "kd/key2")
			mustNil(t, os.Chmod(p, 0o700))
		}
	}
	// Open checks the cache directory and each directory above it in the state.
	for _, p := range []string{cache, filepath.Join(dir, "acme")} {
		mustNil(t, os.Chmod(p, 0o755))
		o, err := Open(state, "acme/cache")
		if err == nil {
			o.Close()
			t.Errorf("Open accepted mode 755 on %s", p)
		}
		mustNil(t, os.Chmod(p, 0o700))
	}
	if _, err := s.Load(ctx, "kd/key"); err != nil {
		t.Fatalf("Load after the repair = %v", err)
	}
	// The hook gives another owner to one directory. The cache directory has the
	// other owner: Load and Open refuse it.
	setOtherOwner(t, cache)
	_, err = s.Load(ctx, "kd/key")
	wantError(t, err, "load", ruleOwner)
	noMarker(t, err, "kd/key")
	o, err := Open(state, "acme/cache")
	if err == nil {
		o.Close()
	}
	wantError(t, err, "open", ruleOwner)
	// The parent of the cache directory has the other owner: Open refuses it, and
	// Load does not check it.
	setOtherOwner(t, filepath.Join(dir, "acme"))
	o, err = Open(state, "acme/cache")
	if err == nil {
		o.Close()
	}
	wantError(t, err, "open", ruleOwner)
	if _, err := s.Load(ctx, "kd/key"); err != nil {
		t.Errorf("Load with another owner on the parent = %v", err)
	}
	// The key directory has the other owner: Load refuses it.
	setOtherOwner(t, filepath.Join(cache, "kd"))
	_, err = s.Load(ctx, "kd/key")
	wantError(t, err, "load", ruleOwner)
	unchanged(t, target)
}

// setOtherOwner makes the hook give another owner to the file or directory at
// the host path p, and to no other inode. The hook stays until the test ends or
// the next call.
func setOtherOwner(t *testing.T, p string) {
	t.Helper()
	fi, err := os.Lstat(p)
	mustNil(t, err)
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("no Stat_t for %s", p)
	}
	dev, ino := uint64(st.Dev), uint64(st.Ino)
	otherOwner = func(d, i uint64) bool { return d == dev && i == ino }
	t.Cleanup(func() { otherOwner = nil })
}

// A check is not enough if the directory changes after it. These tests change
// the directory between two calls and between Open and the first call.
func TestTS16LinkMadeAfterOpenOrBetweenCallsIsRefused(t *testing.T) {
	s, dir := newStore(t)
	ctx := context.Background()
	target := outside(t, dir)
	cache := filepath.Join(dir, "acme/cache")
	mustNil(t, s.Store(ctx, "kd/key", []byte("v")))
	if _, err := s.Load(ctx, "kd/key"); err != nil {
		t.Fatal(err)
	}
	// The key directory becomes a link between two calls.
	mustNil(t, os.Rename(filepath.Join(cache, "kd"), filepath.Join(cache, "kd-moved")))
	mustNil(t, os.Symlink(filepath.Dir(target), filepath.Join(cache, "kd")))
	_, err := s.Load(ctx, "kd/file")
	noMarker(t, err, "kd/file")
	noMarker(t, s.Store(ctx, "kd/file", []byte("changed")), "kd/file")
	noMarker(t, s.Delete(ctx, "kd/file"), "kd/file")
	unchanged(t, target)
	// The key file becomes a link after Open.
	mustNil(t, os.Remove(filepath.Join(cache, "kd")))
	mustNil(t, os.Rename(filepath.Join(cache, "kd-moved"), filepath.Join(cache, "kd")))
	mustNil(t, os.Remove(filepath.Join(cache, "kd/key")))
	mustNil(t, os.Symlink(target, filepath.Join(cache, "kd/key")))
	_, err = s.Load(ctx, "kd/key")
	noMarker(t, err, "kd/key")
	noMarker(t, s.Store(ctx, "kd/key", []byte("changed")), "kd/key")
	unchanged(t, target)
	// A link replaces the cache directory after Open. The open root still holds
	// the old directory, so nothing outside the root changes.
	mustNil(t, os.Rename(cache, cache+"-moved"))
	mustNil(t, os.Symlink(filepath.Dir(target), cache))
	if err := s.Store(ctx, "new", []byte("changed")); err != nil {
		t.Errorf("Store after the replacement of the cache directory = %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(cache+"-moved", "new")); err != nil || string(b) != "changed" {
		t.Errorf("the old cache directory holds %q, %v", b, err)
	}
	if _, err := os.Lstat(filepath.Join(filepath.Dir(target), "new")); err == nil {
		t.Error("Store made a file in the directory that the link names")
	}
	unchanged(t, target)
}

func TestTS16OpenRefusesADirectorySwappedForALinkAfterTheCheck(t *testing.T) {
	_, dir := newStore(t)
	state, err := os.OpenRoot(dir)
	mustNil(t, err)
	defer state.Close()
	// other is a real directory in the state directory that the link will name.
	other := filepath.Join(dir, "acme/other")
	mustNil(t, os.Mkdir(other, 0o700))
	cache := filepath.Join(dir, "acme/cache")
	betweenCheckAndOpen = func(part string) {
		if part != "cache" {
			return
		}
		mustNil(t, os.Rename(cache, cache+"-real"))
		mustNil(t, os.Symlink("other", cache))
	}
	t.Cleanup(func() { betweenCheckAndOpen = nil })
	s, err := Open(state, "acme/cache")
	if err == nil {
		// If Open accepted the link, this Store would reach the other directory.
		s.Store(context.Background(), "key", []byte("v"))
		s.Close()
	}
	wantError(t, err, "open", ruleLink)
	if names, err := os.ReadDir(other); err != nil || len(names) != 0 {
		t.Errorf("the other directory has %d names, %v; want none", len(names), err)
	}
}

func TestTS16OpenRefusesAParentSwappedForALinkAfterTheCheck(t *testing.T) {
	_, dir := newStore(t)
	state, err := os.OpenRoot(dir)
	mustNil(t, err)
	defer state.Close()
	// other is a real directory in the state directory. It has a cache directory
	// that passes every check, so only the link shows the swap.
	other := filepath.Join(dir, "other")
	mustNil(t, os.MkdirAll(filepath.Join(other, "cache"), 0o700))
	betweenCheckAndOpen = func(part string) {
		if part != "acme" {
			return
		}
		mustNil(t, os.Rename(filepath.Join(dir, "acme"), filepath.Join(dir, "acme-real")))
		mustNil(t, os.Symlink("other", filepath.Join(dir, "acme")))
	}
	t.Cleanup(func() { betweenCheckAndOpen = nil })
	s, err := Open(state, "acme/cache")
	if err == nil {
		// If Open accepted the link, this Store would reach the other directory.
		s.Store(context.Background(), "key", []byte("v"))
		s.Close()
	}
	wantError(t, err, "open", ruleLink)
	if names, err := os.ReadDir(filepath.Join(other, "cache")); err != nil || len(names) != 0 {
		t.Errorf("the cache directory of the other directory has %d names, %v; want none", len(names), err)
	}
}

func TestTS16OpenUsesTheDirectoryThatItOpenedForEarlierPartsWhenAParentChanges(t *testing.T) {
	dir := t.TempDir()
	state, err := os.OpenRoot(dir)
	mustNil(t, err)
	defer state.Close()
	mustNil(t, os.MkdirAll(filepath.Join(dir, "acme/cache"), 0o700))
	// other is a real directory with a cache directory that passes every check.
	// The hook swaps acme for a link to it before the check of cache.
	other := filepath.Join(dir, "other")
	mustNil(t, os.MkdirAll(filepath.Join(other, "cache"), 0o700))
	beforeCheck = func(part string) {
		if part != "cache" {
			return
		}
		mustNil(t, os.Rename(filepath.Join(dir, "acme"), filepath.Join(dir, "acme-real")))
		mustNil(t, os.Symlink("other", filepath.Join(dir, "acme")))
	}
	t.Cleanup(func() { beforeCheck = nil })
	s, err := Open(state, "acme/cache")
	mustNil(t, err)
	defer s.Close()
	mustNil(t, s.Store(context.Background(), "key", []byte("v")))
	if b, err := os.ReadFile(filepath.Join(dir, "acme-real/cache/key")); err != nil || string(b) != "v" {
		t.Errorf("the cache directory below the real acme holds %q, %v; want v", b, err)
	}
	if names, err := os.ReadDir(filepath.Join(other, "cache")); err != nil || len(names) != 0 {
		t.Errorf("the other cache directory has %d names, %v; want none", len(names), err)
	}
}

func TestTS16OpenCallsFsyncOnlyOnDirectoriesThatTheWalkOpened(t *testing.T) {
	dir := t.TempDir()
	state, err := os.OpenRoot(dir)
	mustNil(t, err)
	defer state.Close()
	// other is a real directory with a cache directory. The first fsync swaps
	// acme for a link to it.
	other := filepath.Join(dir, "other")
	mustNil(t, os.MkdirAll(filepath.Join(other, "cache"), 0o700))
	var realAcme, realCache fs.FileInfo
	var steps []string
	old := syncDirFile
	t.Cleanup(func() { syncDirFile = old })
	syncDirFile = func(f *os.File) error {
		if realAcme == nil {
			var err error
			realAcme, err = os.Stat(filepath.Join(dir, "acme"))
			mustNil(t, err)
			realCache, err = os.Stat(filepath.Join(dir, "acme/cache"))
			mustNil(t, err)
			mustNil(t, os.Rename(filepath.Join(dir, "acme"), filepath.Join(dir, "acme-real")))
			mustNil(t, os.Symlink("other", filepath.Join(dir, "acme")))
		}
		fi, err := f.Stat()
		mustNil(t, err)
		step := "a directory that the walk did not open"
		for name, p := range map[string]fs.FileInfo{"cache": realCache, "acme": realAcme} {
			if os.SameFile(fi, p) {
				step = name
			}
		}
		if st, err := os.Stat(dir); err == nil && os.SameFile(fi, st) {
			step = "state"
		}
		steps = append(steps, step)
		return old(f)
	}
	s, err := Open(state, "acme/cache")
	if err == nil {
		s.Close()
	}
	mustNil(t, err)
	if want := []string{"cache", "acme", "state"}; !slices.Equal(steps, want) {
		t.Errorf("fsync of %q, want %q", steps, want)
	}
}

func TestTS16LoadDoesNotReturnTheBytesOfAnotherKeyWhenALinkReplacesTheKeyFile(t *testing.T) {
	s, dir := newStore(t)
	ctx := context.Background()
	cache := filepath.Join(dir, "acme/cache")
	mustNil(t, s.Store(ctx, "key", []byte("own value")))
	mustNil(t, s.Store(ctx, "other-key", []byte("value of another key")))
	calls := 0
	betweenLstatAndOpen = func() {
		if calls++; calls == 1 {
			mustNil(t, os.Remove(filepath.Join(cache, "key")))
			mustNil(t, os.Symlink("other-key", filepath.Join(cache, "key")))
		}
	}
	t.Cleanup(func() { betweenLstatAndOpen = nil })
	b, err := s.Load(ctx, "key")
	if calls < 1 {
		t.Errorf("the hook ran %d times, want 1 or more", calls)
	}
	// The link stays at the key, so the second try gives the link rule.
	wantError(t, err, "load", ruleLink)
	if b != nil {
		t.Errorf("Load returned %d bytes with an error", len(b))
	}
}

func TestTS16LoadGivesTheChangedRuleWhenEveryTryFindsAnotherFile(t *testing.T) {
	s, dir := newStore(t)
	ctx := context.Background()
	cache := filepath.Join(dir, "acme/cache")
	mustNil(t, s.Store(ctx, "key", []byte("v")))
	calls := 0
	betweenLstatAndOpen = func() {
		// A new file with its own inode replaces the key file at each try.
		calls++
		tmp := filepath.Join(cache, ".tmp-replace")
		mustNil(t, os.WriteFile(tmp, []byte("v"), 0o600))
		mustNil(t, os.Rename(tmp, filepath.Join(cache, "key")))
	}
	t.Cleanup(func() { betweenLstatAndOpen = nil })
	b, err := s.Load(ctx, "key")
	wantError(t, err, "load", ruleChanged)
	if b != nil {
		t.Errorf("Load returned %d bytes with an error", len(b))
	}
	if calls != loadTries {
		t.Errorf("Load made %d tries, want %d", calls, loadTries)
	}
}

func TestTS16LoadReadsAtMost64KiBPlusOneByteOfAFileThatGrowsAfterTheLstat(t *testing.T) {
	s, dir := newStore(t)
	ctx := context.Background()
	mustNil(t, s.Store(ctx, "key", []byte("v")))
	// The file is sparse, so the growth costs no disk. The same file is open, so
	// the check of the file identity passes.
	betweenLstatAndOpen = func() {
		mustNil(t, os.Truncate(filepath.Join(dir, "acme/cache/key"), 32<<20))
	}
	t.Cleanup(func() { betweenLstatAndOpen = nil })
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	b, err := s.Load(ctx, "key")
	runtime.ReadMemStats(&after)
	wantError(t, err, "load", ruleSize)
	if b != nil {
		t.Errorf("Load returned %d bytes with an error", len(b))
	}
	// A read of the whole file allocates 32 MiB or more. A read of 64 KiB + 1
	// byte allocates about 290 KiB in all with the race detector, and less without
	// it. A read limit of four times the cap allocates about 630 KiB without the
	// race detector and about 1.2 MiB with it.
	if n := after.TotalAlloc - before.TotalAlloc; n > 384<<10 {
		t.Errorf("Load allocated %d bytes for a file that grew to 32 MiB", n)
	}
}

func TestTS16LoadRefusesAKeyFileWithTwoLinksAtTheLstatEvenIfOneLinkIsGoneAtTheOpen(t *testing.T) {
	s, dir := newStore(t)
	ctx := context.Background()
	cache := filepath.Join(dir, "acme/cache")
	mustNil(t, s.Store(ctx, "key", []byte("v")))
	mustNil(t, os.Link(filepath.Join(cache, "key"), filepath.Join(cache, "second-name")))
	// If Load went on to the open, the hook would remove the second name, and the
	// open file would have one link.
	calls := 0
	betweenLstatAndOpen = func() {
		calls++
		mustNil(t, os.Remove(filepath.Join(cache, "second-name")))
	}
	t.Cleanup(func() { betweenLstatAndOpen = nil })
	b, err := s.Load(ctx, "key")
	// Load refuses at the Lstat, so it stops before the point where it calls the
	// hook.
	if calls != 0 {
		t.Errorf("the hook ran %d times, want 0: Load went on after the Lstat", calls)
	}
	wantError(t, err, "load", ruleLinks)
	if b != nil {
		t.Errorf("Load returned %d bytes with an error", len(b))
	}
}

func TestTS16LoadRefusesAKeyFileThatGetsASecondLinkAfterTheLstat(t *testing.T) {
	s, dir := newStore(t)
	ctx := context.Background()
	cache := filepath.Join(dir, "acme/cache")
	mustNil(t, s.Store(ctx, "key", []byte("v")))
	// The key file has one link at the Lstat. The hook makes a second name for the
	// same file, so the open file has two links.
	calls := 0
	betweenLstatAndOpen = func() {
		calls++
		mustNil(t, os.Link(filepath.Join(cache, "key"), filepath.Join(cache, "second-name")))
	}
	t.Cleanup(func() { betweenLstatAndOpen = nil })
	b, err := s.Load(ctx, "key")
	if calls != 1 {
		t.Errorf("the hook ran %d times, want 1", calls)
	}
	wantError(t, err, "load", ruleLinks)
	if b != nil {
		t.Errorf("Load returned %d bytes with an error", len(b))
	}
}

func TestTS16DeleteOfAKeyBelowAFileGivesNilAndTheKeyIsMissing(t *testing.T) {
	s, dir := newStore(t)
	ctx := context.Background()
	mustNil(t, s.Store(ctx, "f", []byte("v")))
	mustNil(t, s.Delete(ctx, "f/x"))
	mustNil(t, s.Delete(ctx, "f/x/y"))
	if s.Exists(ctx, "f/x") {
		t.Error("Exists of a key below a file is true")
	}
	_, err := s.Load(ctx, "f/x")
	wantError(t, err, "load", ruleMissing)
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Load error %v does not wrap fs.ErrNotExist", err)
	}
	// The file stays.
	if b, err := os.ReadFile(filepath.Join(dir, "acme/cache/f")); err != nil || string(b) != "v" {
		t.Errorf("the file f holds %q, %v; want v", b, err)
	}
}

func TestTS16StoreOverAKeyFileThatIsALinkGivesTheLinkRule(t *testing.T) {
	s, dir := newStore(t)
	target := outside(t, dir)
	mustNil(t, os.Symlink(target, filepath.Join(dir, "acme/cache/linkfile")))
	err := s.Store(context.Background(), "linkfile", []byte("changed"))
	wantError(t, err, "store", ruleLink)
	noMarker(t, err, "linkfile")
	unchanged(t, target)
}

func TestTS16LoadRefusesAKeyFileWithMoreThanOneLink(t *testing.T) {
	s, dir := newStore(t)
	ctx := context.Background()
	target := outside(t, dir)
	cache := filepath.Join(dir, "acme/cache")
	mustNil(t, os.Link(target, filepath.Join(cache, "hl-outside")))
	mustNil(t, s.Store(ctx, "inside", []byte("v")))
	mustNil(t, os.Link(filepath.Join(cache, "inside"), filepath.Join(cache, "hl-inside")))
	for _, key := range []string{"hl-outside", "hl-inside", "inside"} {
		b, err := s.Load(ctx, key)
		if b != nil {
			t.Errorf("Load(%q) returned %d bytes", key, len(b))
		}
		wantError(t, err, "load", ruleLinks)
		noMarker(t, err, key)
	}
	unchanged(t, target)
}

func TestTS16LoadRefusesAKeyFileWithGroupOrOtherBits(t *testing.T) {
	s, dir := newStore(t)
	ctx := context.Background()
	target := outside(t, dir)
	cache := filepath.Join(dir, "acme/cache")
	for _, mode := range []fs.FileMode{0o644, 0o640, 0o604, 0o660, 0o666, 0o610} {
		mustNil(t, s.Store(ctx, "key", []byte(marker)))
		mustNil(t, os.Chmod(filepath.Join(cache, "key"), mode))
		b, err := s.Load(ctx, "key")
		if b != nil {
			t.Errorf("Load of mode %o returned %d bytes", mode, len(b))
		}
		wantError(t, err, "load", ruleFileMode)
		noMarker(t, err, "key")
		mustNil(t, os.Remove(filepath.Join(cache, "key")))
	}
	unchanged(t, target)
}

func TestTS16LoadRefusesAKeyFileOfAnotherOwner(t *testing.T) {
	s, dir := newStore(t)
	ctx := context.Background()
	target := outside(t, dir)
	mustNil(t, s.Store(ctx, "key", []byte(marker)))
	mustNil(t, s.Store(ctx, "key2", []byte("v")))
	setOtherOwner(t, filepath.Join(dir, "acme/cache/key"))
	b, err := s.Load(ctx, "key")
	if b != nil {
		t.Errorf("Load returned %d bytes", len(b))
	}
	wantError(t, err, "load", ruleFileOwner)
	noMarker(t, err, "key")
	// The hook selects one inode: a second key in the same directory still loads.
	if b, err := s.Load(ctx, "key2"); err != nil || string(b) != "v" {
		t.Errorf("Load of the second key = %q, %v", b, err)
	}
	unchanged(t, target)
}

func TestTS16DirectoryOfAnotherUserIsRefused(t *testing.T) {
	ctx := context.Background()
	// A key directory, and a key directory that has the name of the parent of the
	// cache directory.
	for _, kd := range []string{"kd", "acme"} {
		t.Run("key directory "+kd, func(t *testing.T) {
			s, dir := newStore(t)
			target := outside(t, dir)
			mustNil(t, s.Store(ctx, kd+"/key", []byte("v")))
			mustNil(t, s.Store(ctx, "other/key", []byte("v")))
			setOtherOwner(t, filepath.Join(dir, "acme/cache", kd))
			_, err := s.Load(ctx, kd+"/key")
			wantError(t, err, "load", ruleOwner)
			wantError(t, s.Store(ctx, kd+"/key2", []byte("v")), "store", ruleOwner)
			// The hook selects one inode: a key in another key directory still loads.
			if b, err := s.Load(ctx, "other/key"); err != nil || string(b) != "v" {
				t.Errorf("Load in another key directory = %q, %v", b, err)
			}
			unchanged(t, target)
		})
	}
	t.Run("parent of the cache directory", func(t *testing.T) {
		s, dir := newStore(t)
		target := outside(t, dir)
		mustNil(t, s.Store(ctx, "key", []byte("v")))
		state, err := os.OpenRoot(dir)
		mustNil(t, err)
		defer state.Close()
		setOtherOwner(t, filepath.Join(dir, "acme"))
		o, err := Open(state, "acme/cache")
		if err == nil {
			o.Close()
		}
		wantError(t, err, "open", ruleOwner)
		// The open store checks the cache directory and the directories below it,
		// not the parent.
		if b, err := s.Load(ctx, "key"); err != nil || string(b) != "v" {
			t.Errorf("Load by the open store = %q, %v", b, err)
		}
		unchanged(t, target)
	})
}

func TestTS16LoadRefusesAKeyFileWithASetuidSetgidOrStickyBit(t *testing.T) {
	ctx := context.Background()
	for _, bit := range []struct {
		name string
		mode fs.FileMode
	}{{"sticky", os.ModeSticky}, {"setgid", os.ModeSetgid}, {"setuid", os.ModeSetuid}} {
		t.Run(bit.name, func(t *testing.T) {
			s, dir := newStore(t)
			target := outside(t, dir)
			mustNil(t, s.Store(ctx, "key", []byte(marker)))
			p := filepath.Join(dir, "acme/cache/key")
			mustNil(t, os.Chmod(p, 0o600|bit.mode))
			if fi, err := os.Lstat(p); err != nil || fi.Mode()&bit.mode == 0 {
				t.Skipf("the system did not set the %s bit: %v, %v", bit.name, fi, err)
			}
			// The mode is 0600 with one special bit. No group or other bit is set,
			// so the rule for these bits applies, not the rule for the mode.
			b, err := s.Load(ctx, "key")
			if b != nil {
				t.Errorf("Load returned %d bytes", len(b))
			}
			wantError(t, err, "load", ruleFileSpecial)
			noMarker(t, err, "key")
			_, err = s.Stat(ctx, "key")
			wantError(t, err, "stat", ruleFileSpecial)
			if s.Exists(ctx, "key") {
				t.Error("Exists is true for a key file that Load refuses")
			}
			unchanged(t, target)
		})
	}
}

// badKeyFile is a key file that Load refuses, with the rule.
type badKeyFile struct {
	key, rule string
}

// badKeyFiles makes four key files that Load refuses. Two are the names of a file
// with a second hard link in the cache ("inside" and "hl-inside"). One is a hard
// link to the outside file. One is a file with mode 0644.
func badKeyFiles(t *testing.T, s *Store, dir, target string) []badKeyFile {
	t.Helper()
	cache := filepath.Join(dir, "acme/cache")
	mustNil(t, s.Store(context.Background(), "inside", []byte("v")))
	mustNil(t, os.Link(filepath.Join(cache, "inside"), filepath.Join(cache, "hl-inside")))
	mustNil(t, os.Link(target, filepath.Join(cache, "hl-outside")))
	mustNil(t, s.Store(context.Background(), "wide", []byte("v")))
	mustNil(t, os.Chmod(filepath.Join(cache, "wide"), 0o644))
	return []badKeyFile{{"inside", ruleLinks}, {"hl-inside", ruleLinks}, {"hl-outside", ruleLinks}, {"wide", ruleFileMode}}
}

func TestTS16StatAndExistsRefuseAKeyFileThatLoadRefuses(t *testing.T) {
	s, dir := newStore(t)
	ctx := context.Background()
	target := outside(t, dir)
	for _, bad := range badKeyFiles(t, s, dir, target) {
		_, err := s.Stat(ctx, bad.key)
		wantError(t, err, "stat", bad.rule)
		noMarker(t, err, bad.key)
		if s.Exists(ctx, bad.key) {
			t.Errorf("Exists(%q) is true", bad.key)
		}
		_, err = s.Load(ctx, bad.key)
		wantError(t, err, "load", bad.rule)
	}
	unchanged(t, target)

	// A key file of maxValue+1 bytes written on the host path: Load refuses it for
	// its size, so Stat and Exists refuse it too. A file of exactly maxValue bytes
	// is valid for all three.
	cache := filepath.Join(dir, "acme/cache")
	mustNil(t, os.WriteFile(filepath.Join(cache, "big"), bytes.Repeat([]byte("x"), maxValue+1), 0o600))
	mustNil(t, os.WriteFile(filepath.Join(cache, "exact"), bytes.Repeat([]byte("x"), maxValue), 0o600))
	_, err := s.Stat(ctx, "big")
	wantError(t, err, "stat", ruleSize)
	if s.Exists(ctx, "big") {
		t.Error("Exists is true for a key file above the size cap")
	}
	_, err = s.Load(ctx, "big")
	wantError(t, err, "load", ruleSize)
	if _, err := s.Stat(ctx, "exact"); err != nil {
		t.Errorf("Stat of a key file at the size cap = %v", err)
	}
	if !s.Exists(ctx, "exact") {
		t.Error("Exists is false for a key file at the size cap")
	}
	if b, err := s.Load(ctx, "exact"); err != nil || len(b) != maxValue {
		t.Errorf("Load of a key file at the size cap = %d bytes, %v", len(b), err)
	}
}

// Open is best effort when it removes leftover files. It does not fail, and it
// does not go into a directory that it cannot open or that fails the directory
// rules.
func TestTS16OpenSkipsADirectoryThatFailsTheRulesAndGoesOn(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("a directory with mode 0000 is open for root")
	}
	ctx := context.Background()
	first, dir := newStore(t)
	mustNil(t, first.Store(ctx, "good/real", []byte("v")))
	mustNil(t, first.Close())
	cache := filepath.Join(dir, "acme/cache")
	tmpIn := func(d string) string { return filepath.Join(cache, d, tmpPrefix+"left") }
	touch := func(p string) { mustNil(t, os.WriteFile(p, nil, 0o600)) }

	// (a) a key directory with mode 0755 and a leftover file.
	mustNil(t, os.Mkdir(filepath.Join(cache, "wide"), 0o700))
	touch(tmpIn("wide"))
	mustNil(t, os.Chmod(filepath.Join(cache, "wide"), 0o755))
	// (b) a key directory with mode 0000 and a leftover file. The cleanup gives the
	// mode back, so that t.TempDir can remove the directory.
	mustNil(t, os.Mkdir(filepath.Join(cache, "closed"), 0o700))
	touch(tmpIn("closed"))
	mustNil(t, os.Chmod(filepath.Join(cache, "closed"), 0))
	t.Cleanup(func() { os.Chmod(filepath.Join(cache, "closed"), 0o700) })
	// (c) a directory with a name that starts with tmpPrefix and is not empty.
	mustNil(t, os.Mkdir(filepath.Join(cache, tmpPrefix+"dir"), 0o700))
	touch(filepath.Join(cache, tmpPrefix+"dir", "inner"))
	// (d) a good key directory with a leftover file.
	touch(tmpIn("good"))

	state, err := os.OpenRoot(dir)
	mustNil(t, err)
	defer state.Close()
	s, err := Open(state, "acme/cache")
	if err != nil {
		t.Fatalf("Open = %v, want nil", err)
	}
	defer s.Close()

	if _, err := os.Lstat(tmpIn("good")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the leftover file in the good directory stays: %v", err)
	}
	if _, err := os.Lstat(tmpIn("wide")); err != nil {
		t.Errorf("the leftover file in the directory with mode 0755 is gone: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(cache, tmpPrefix+"dir", "inner")); err != nil {
		t.Errorf("the file in the directory that Remove cannot remove is gone: %v", err)
	}
	mustNil(t, os.Chmod(filepath.Join(cache, "closed"), 0o700))
	if _, err := os.Lstat(tmpIn("closed")); err != nil {
		t.Errorf("the leftover file in the directory with mode 0000 is gone: %v", err)
	}
	if b, err := s.Load(ctx, "good/real"); err != nil || string(b) != "v" {
		t.Errorf("Load = %q, %v", b, err)
	}
}

func TestTS16DeleteRemovesAKeyFileThatLoadRefuses(t *testing.T) {
	s, dir := newStore(t)
	ctx := context.Background()
	target := outside(t, dir)
	for _, bad := range badKeyFiles(t, s, dir, target) {
		mustNil(t, s.Delete(ctx, bad.key))
		if _, err := os.Lstat(filepath.Join(dir, "acme/cache", bad.key)); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("Delete(%q) left the name: %v", bad.key, err)
		}
	}
	unchanged(t, target)
}

func TestTS16DirectoryWithSetuidSetgidOrStickyBitIsRefused(t *testing.T) {
	ctx := context.Background()
	for _, bit := range []struct {
		name string
		mode fs.FileMode
	}{{"sticky", os.ModeSticky}, {"setgid", os.ModeSetgid}, {"setuid", os.ModeSetuid}} {
		t.Run(bit.name, func(t *testing.T) {
			s, dir := newStore(t)
			target := outside(t, dir)
			mustNil(t, s.Store(ctx, "kd/key", []byte("v")))
			kd := filepath.Join(dir, "acme/cache/kd")
			mustNil(t, os.Chmod(kd, 0o700|bit.mode))
			if fi, err := os.Lstat(kd); err != nil || fi.Mode()&bit.mode == 0 {
				t.Skipf("the system did not set the %s bit: %v, %v", bit.name, fi, err)
			}
			_, err := s.Load(ctx, "kd/key")
			// The mode is 0700 with one special bit. No group or other bit is set,
			// so the rule for these bits applies, not the rule for the mode.
			wantError(t, err, "load", ruleSpecial)
			wantError(t, s.Store(ctx, "kd/key2", []byte("v")), "store", ruleSpecial)
			unchanged(t, target)
		})
	}
}

// breakDir is one way to make a directory fail one rule of the directory check.
type breakDir struct {
	name  string
	rule  string
	apply func(t *testing.T, p string)
}

var breakDirs = []breakDir{
	{"link", ruleLink, func(t *testing.T, p string) {
		mustNil(t, os.Rename(p, p+"-real"))
		mustNil(t, os.Symlink(filepath.Base(p)+"-real", p))
	}},
	{"mode", ruleMode, func(t *testing.T, p string) { mustNil(t, os.Chmod(p, 0o755)) }},
	{"owner", ruleOwner, func(t *testing.T, p string) { setOtherOwner(t, p) }},
	{"not a directory", ruleNotDir, func(t *testing.T, p string) {
		mustNil(t, os.RemoveAll(p))
		mustNil(t, os.WriteFile(p, nil, 0o600))
	}},
}

// wantError fails unless err is an *Error with the operation op and the rule.
func wantError(t *testing.T, err error, op, rule string) {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) {
		t.Errorf("%s: error %v is not an *Error", op, err)
	} else if e.Op != op || e.Rule != rule {
		t.Errorf("%s: error has operation %q and rule %q, want %q", op, e.Op, e.Rule, rule)
	}
}

func TestTS16DirectoryRuleErrorsNameTheOperation(t *testing.T) {
	for _, tc := range breakDirs {
		t.Run(tc.name, func(t *testing.T) {
			s, dir := newStore(t)
			ctx := context.Background()
			mustNil(t, s.Store(ctx, "kd/key", []byte("v")))
			tc.apply(t, filepath.Join(dir, "acme/cache/kd"))
			// A key below a file cannot exist, so Load and Stat give the rule for
			// a missing key, and Delete gives nil.
			readRule := tc.rule
			if tc.rule == ruleNotDir {
				readRule = ruleMissing
			}
			_, err := s.Load(ctx, "kd/key")
			wantError(t, err, "load", readRule)
			wantError(t, s.Store(ctx, "kd/key2", []byte("v")), "store", tc.rule)
			_, err = s.Stat(ctx, "kd/key")
			wantError(t, err, "stat", readRule)
			_, err = s.List(ctx, "kd", false)
			wantError(t, err, "list", tc.rule)
			if tc.rule == ruleNotDir {
				mustNil(t, s.Delete(ctx, "kd/key"))
			} else {
				wantError(t, s.Delete(ctx, "kd/key"), "delete", tc.rule)
			}
		})
		t.Run(tc.name+" in Open", func(t *testing.T) {
			_, dir := newStore(t)
			state, err := os.OpenRoot(dir)
			mustNil(t, err)
			defer state.Close()
			tc.apply(t, filepath.Join(dir, "acme/cache"))
			o, err := Open(state, "acme/cache")
			if err == nil {
				o.Close()
			}
			wantError(t, err, "open", tc.rule)
		})
	}
}

func TestTS16ErrorsNeverHoldKeyMarkerBytes(t *testing.T) {
	s, dir := newStore(t)
	ctx := context.Background()
	cache := filepath.Join(dir, "acme/cache")
	// A key marker file that is too big, and a key marker file in a directory
	// with open group bits.
	mustNil(t, os.WriteFile(filepath.Join(cache, "marker"), []byte(strings.Repeat(marker, 4000)), 0o600))
	_, err := s.Load(ctx, "marker")
	noMarker(t, err, "marker")
	mustNil(t, os.Mkdir(filepath.Join(cache, "dirkey"), 0o700))
	mustNil(t, os.Chmod(filepath.Join(cache, "dirkey"), 0o755))
	mustNil(t, os.WriteFile(filepath.Join(cache, "dirkey", "marker"), []byte(marker), 0o600))
	_, err = s.Load(ctx, "dirkey/marker")
	noMarker(t, err, "marker")
	_, err = s.List(ctx, "dirkey", true)
	noMarker(t, err, "marker")
}
