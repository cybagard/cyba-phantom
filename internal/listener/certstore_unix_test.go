//go:build unix

package listener

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestTS16NewFilesAreMode0600AndNewDirectoriesMode0700(t *testing.T) {
	s, dir := newStore(t)
	mustNil(t, s.Store(context.Background(), "certificates/ca/site/site.key", []byte("k")))
	cache := filepath.Join(dir, "acme/cache")
	mustNil(t, filepath.WalkDir(cache, func(p string, d fs.DirEntry, err error) error {
		if err != nil || p == cache {
			return err
		}
		fi, err := os.Lstat(p)
		want := fs.FileMode(0o600)
		if fi.IsDir() {
			want = 0o700
		}
		if err == nil && fi.Mode().Perm() != want {
			t.Errorf("%s has mode %o, want %o", p, fi.Mode().Perm(), want)
		}
		return err
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
	mustNil(t, s.Store(ctx, "kd/key", []byte("v")))
	state, err := os.OpenRoot(dir)
	mustNil(t, err)
	defer state.Close()
	for _, p := range []string{cache, filepath.Join(cache, "kd")} {
		for _, mode := range []fs.FileMode{0o755, 0o710, 0o701} {
			mustNil(t, os.Chmod(p, mode))
			_, err := s.Load(ctx, "kd/key")
			noMarker(t, err, "kd/key")
			noMarker(t, s.Store(ctx, "kd/key2", nil), "")
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
	// Another owner, through the hook.
	old := geteuid
	t.Cleanup(func() { geteuid = old })
	geteuid = func() int { return os.Geteuid() + 1 }
	_, err = s.Load(ctx, "kd/key")
	noMarker(t, err, "kd/key")
	if o, err := Open(state, "acme/cache"); err == nil {
		o.Close()
		t.Error("Open accepted a directory of another owner")
	}
}

// A check is fooled if the state changes after it. These tests change the
// directory between two calls and between Open and the first call.
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
	// The cache directory is replaced by a link after Open: the open root still
	// holds the old directory, so nothing outside the root changes.
	mustNil(t, os.Rename(cache, cache+"-moved"))
	mustNil(t, os.Symlink(filepath.Dir(target), cache))
	_ = s.Store(ctx, "new", []byte("changed"))
	unchanged(t, target)
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
	{"owner", ruleOwner, func(t *testing.T, _ string) {
		old := geteuid
		t.Cleanup(func() { geteuid = old })
		geteuid = func() int { return os.Geteuid() + 1 }
	}},
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
			_, err := s.Load(ctx, "kd/key")
			wantError(t, err, "load", tc.rule)
			wantError(t, s.Store(ctx, "kd/key2", []byte("v")), "store", tc.rule)
			_, err = s.Stat(ctx, "kd/key")
			wantError(t, err, "stat", tc.rule)
			_, err = s.List(ctx, "kd", false)
			wantError(t, err, "list", tc.rule)
			wantError(t, s.Delete(ctx, "kd/key"), "delete", tc.rule)
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
