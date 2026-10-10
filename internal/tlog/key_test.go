package tlog

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/note"
)

const testOrigin = "phantom/test"

func newState(t *testing.T) (*os.Root, string) {
	t.Helper()
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	return root, dir
}

func testLogger() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})), &buf
}

func newKeyText(t *testing.T, name string) string {
	t.Helper()
	skey, _, err := note.GenerateKey(rand.Reader, name)
	if err != nil {
		t.Fatal(err)
	}
	return skey
}

// putKey writes the key file with an exact mode (the umask does not matter).
func putKey(t *testing.T, dir, text string, mode os.FileMode) {
	t.Helper()
	p := filepath.Join(dir, keyName)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	// A file left by an earlier call can be read-only (0400); a non-root owner
	// cannot open it for write, so remove it first.
	if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(text), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
}

// secretsOf returns what must never be output: the key text, its base64 part,
// and the seed in base64.
func secretsOf(text string) []string {
	out := []string{strings.TrimSpace(text)}
	// PRIVATE+KEY+name+hash+base64; the base64 part can have a "+" itself.
	if parts := strings.SplitN(strings.TrimSpace(text), "+", 5); len(parts) == 5 {
		out = append(out, parts[4])
		if raw, err := base64.StdEncoding.DecodeString(parts[4]); err == nil && len(raw) > 1 {
			out = append(out, base64.StdEncoding.EncodeToString(raw[1:]))
		}
	}
	return out
}

func assertNoSecret(t *testing.T, what, s string, secrets []string) {
	t.Helper()
	for _, sec := range secrets {
		if sec != "" && strings.Contains(s, sec) {
			t.Errorf("%s contains key material", what)
		}
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func mustSymlink(t *testing.T, target, link string) {
	t.Helper()
	must(t, os.Symlink(target, link))
}

func mustFifo(t *testing.T, path string) {
	t.Helper()
	must(t, syscall.Mkfifo(path, 0o600))
}

// loadWithin runs LoadOrCreateSigner and fails the test if it does not return.
func loadWithin(t *testing.T, root *os.Root, log *slog.Logger, origin string, state bool, size uint64) (note.Signer, error) {
	t.Helper()
	type result struct {
		s   note.Signer
		err error
	}
	done := make(chan result, 1)
	go func() {
		s, err := LoadOrCreateSigner(root, log, origin, state, size)
		done <- result{s, err}
	}()
	select {
	case r := <-done:
		return r.s, r.err
	case <-time.After(5 * time.Second):
		t.Fatal("LoadOrCreateSigner did not return")
		return nil, nil
	}
}

// T-S-13: a key file that breaks a rule gives an error that names the path
// and the failed rule, and the signer does not start.
func TestTS13_KeyFileRules(t *testing.T) {
	good := newKeyText(t, testOrigin)
	cases := []struct {
		name  string
		setup func(t *testing.T, dir string)
		text  string
		rule  string
	}{
		{"mode 0640", func(t *testing.T, dir string) { putKey(t, dir, good, 0o640) }, good, "mode must be exactly 0600"},
		{"mode 0604", func(t *testing.T, dir string) { putKey(t, dir, good, 0o604) }, good, "mode must be exactly 0600"},
		{"mode 0400", func(t *testing.T, dir string) { putKey(t, dir, good, 0o400) }, good, "mode must be exactly 0600"},
		{"larger than 1 KiB", func(t *testing.T, dir string) { putKey(t, dir, good+strings.Repeat("\n", 1100), 0o600) }, good, "must not be larger than 1 KiB"},
		{"wrong key name", func(t *testing.T, dir string) { putKey(t, dir, newKeyText(t, "other/origin"), 0o600) }, "", "key name must equal the configured origin"},
		{"malformed", func(t *testing.T, dir string) { putKey(t, dir, "PRIVATE+KEY+not-a-key", 0o600) }, "", "is not a valid note signer key"},
		{"empty", func(t *testing.T, dir string) { putKey(t, dir, "", 0o600) }, "", "is not a valid note signer key"},
		{"directory", func(t *testing.T, dir string) { must(t, os.MkdirAll(filepath.Join(dir, keyName), 0o700)) }, "", "must be a regular file"},
		{"symlink inside", func(t *testing.T, dir string) {
			putKey(t, dir, good, 0o600)
			must(t, os.Rename(filepath.Join(dir, keyName), filepath.Join(dir, keysDir, "real.key")))
			mustSymlink(t, "real.key", filepath.Join(dir, keyName))
		}, good, "must be a regular file and not a symlink"},
		{"keys is a symlink inside the root", func(t *testing.T, dir string) {
			must(t, os.Mkdir(filepath.Join(dir, "tlog"), 0o700))
			putKey(t, filepath.Join(dir, "tlog"), good, 0o600)
			must(t, os.Rename(filepath.Join(dir, "tlog", keysDir), filepath.Join(dir, "tlog", "k")))
			mustSymlink(t, "tlog/k", filepath.Join(dir, keysDir))
		}, good, "keys must be a real directory and not a symlink"},
		{"FIFO at the key path", func(t *testing.T, dir string) {
			must(t, os.Mkdir(filepath.Join(dir, keysDir), 0o700))
			mustFifo(t, filepath.Join(dir, keyName))
		}, "", "must be a regular file"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root, dir := newState(t)
			tc.setup(t, dir)
			log, buf := testLogger()
			s, err := loadWithin(t, root, log, testOrigin, true, 1)
			if err == nil || s != nil {
				t.Fatalf("got signer %v, error %v; want an error", s, err)
			}
			if !strings.Contains(err.Error(), keyName) {
				t.Errorf("error does not name the path: %v", err)
			}
			if !strings.Contains(err.Error(), tc.rule) {
				t.Errorf("error %q does not have the rule %q", err, tc.rule)
			}
			secrets := append(secretsOf(tc.text), secretsOf(good)...)
			assertNoSecret(t, "error", err.Error(), secrets)
			assertNoSecret(t, "log", buf.String(), secrets)
		})
	}
}

// T-S-13: a symlink that points outside the state directory is an error, and
// the outside file is not opened. The outside file is a FIFO: an open for read
// would block.
func TestTS13_SymlinkOutside(t *testing.T) {
	for _, link := range []string{"file", "keys directory"} {
		t.Run(link, func(t *testing.T) {
			root, dir := newState(t)
			outside := t.TempDir()
			fifo := filepath.Join(outside, "checkpoint.key")
			mustFifo(t, fifo)
			if link == "file" {
				must(t, os.Mkdir(filepath.Join(dir, keysDir), 0o700))
				mustSymlink(t, fifo, filepath.Join(dir, keyName))
			} else {
				mustSymlink(t, outside, filepath.Join(dir, keysDir))
			}
			if _, err := loadWithin(t, root, nil, testOrigin, true, 1); err == nil {
				t.Fatal("want an error")
			}
		})
	}
}

// T-S-13: the owner must be the effective user. The test changes the test
// hook, because it cannot make a file of another owner without root.
func TestTS13_OwnerMismatch(t *testing.T) {
	root, dir := newState(t)
	putKey(t, dir, newKeyText(t, testOrigin), 0o600)
	if _, err := LoadOrCreateSigner(root, nil, testOrigin, true, 1); err != nil {
		t.Fatalf("own file: %v", err)
	}
	old := geteuid
	geteuid = func() int { return os.Geteuid() + 1 }
	t.Cleanup(func() { geteuid = old })
	if _, err := LoadOrCreateSigner(root, nil, testOrigin, true, 1); err == nil || !strings.Contains(err.Error(), "owned by") {
		t.Fatalf("got %v; want an owner error", err)
	}
}

// T-S-13: the first start makes the key and the public key; the second start
// loads the same key.
func TestTS13_FirstStartAndReload(t *testing.T) {
	root, dir := newState(t)
	log, buf := testLogger()
	s1, err := LoadOrCreateSigner(root, log, testOrigin, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]os.FileMode{keyName: 0o600, vkeyName: 0o600, keysDir: 0o700} {
		fi, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if got := fi.Mode().Perm(); got != want {
			t.Errorf("%s mode %o; want %o", name, got, want)
		}
	}
	vkey, err := os.ReadFile(filepath.Join(dir, vkeyName))
	if err != nil {
		t.Fatal(err)
	}
	v, err := note.NewVerifier(strings.TrimSpace(string(vkey)))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), strings.TrimSpace(string(vkey))) {
		t.Error("the log does not have the public key")
	}
	signed, err := note.Sign(&note.Note{Text: testOrigin + "\n1\nAAAA\n"}, s1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := note.Open(signed, note.VerifierList(v)); err != nil {
		t.Fatalf("the public key does not verify: %v", err)
	}
	// The signer state is a signed note of the empty tree.
	msg, err := os.ReadFile(filepath.Join(dir, stateName))
	must(t, err)
	cp, err := ParseCheckpoint(msg, testOrigin, v)
	if err != nil || cp.Size != 0 || cp.Root != emptyRoot {
		t.Errorf("signer state %+v, error %v; want a verified note of size 0", cp, err)
	}
	if fi, err := os.Stat(filepath.Join(dir, stateName)); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("signer state mode, error %v; want 0600", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, stateName+".tmp")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("temporary file: %v; want not exist", err)
	}

	log2, buf2 := testLogger()
	s2, err := LoadOrCreateSigner(root, log2, testOrigin, true, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf2.String(), "checkpoint signing key loaded") || !strings.Contains(buf2.String(), strings.TrimSpace(string(vkey))) {
		t.Error("the reload log does not have the derived public key")
	}
	signed2, err := note.Sign(&note.Note{Text: testOrigin + "\n1\nAAAA\n"}, s2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(signed, signed2) { // Ed25519 is deterministic
		t.Error("the second start loaded another key")
	}
}

// T-S-13: a failed write of the signer state is an error of the first start.
// The key files stay. The next start loads the key and writes no state.
func TestTS13_FirstStartStateWriteFails(t *testing.T) {
	root, dir := newState(t)
	must(t, os.MkdirAll(filepath.Join(dir, stateName+".tmp", "x"), 0o700)) // Remove cannot delete it
	if s, err := loadWithin(t, root, nil, testOrigin, false, 0); err == nil || s != nil || !strings.Contains(err.Error(), "signer state") {
		t.Fatalf("got signer %v, error %v; want a signer state error", s, err)
	}
	for _, name := range []string{keyName, vkeyName} {
		if _, err := os.Lstat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s: %v; want the file to stay", name, err)
		}
	}
	must(t, os.RemoveAll(filepath.Join(dir, stateName+".tmp")))
	if _, err := loadWithin(t, root, nil, testOrigin, false, 0); err != nil {
		t.Fatalf("next start: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, stateName)); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("signer state: %v; want not exist (a key with no state is a fault)", err)
	}
}

// T-S-13: the first start refuses an entry at checkpoint.state and makes no key.
func TestTS13_FirstStartRefusesExistingState(t *testing.T) {
	root, dir := newState(t)
	must(t, os.WriteFile(filepath.Join(dir, stateName), []byte("old state"), 0o600))
	s, err := loadWithin(t, root, nil, testOrigin, false, 0) // a caller that passes false
	if err == nil || s != nil || !strings.Contains(err.Error(), "signer state must not exist on the first start") {
		t.Fatalf("got signer %v, error %v; want the rule error", s, err)
	}
	_, keyErr := os.Lstat(filepath.Join(dir, keyName))
	if b, _ := os.ReadFile(filepath.Join(dir, stateName)); string(b) != "old state" || !errors.Is(keyErr, fs.ErrNotExist) {
		t.Errorf("state %q, key file error %v; want the state unchanged and no key file", b, keyErr)
	}
}

// T-S-13: if the key is missing and the log has a signer state or leaves, the
// function returns an error and makes no file.
func TestTS13_MissingKeyNoNewKey(t *testing.T) {
	for _, tc := range []struct {
		name  string
		state bool
		size  uint64
	}{{"signer state", true, 0}, {"tree size", false, 7}} {
		t.Run(tc.name, func(t *testing.T) {
			root, dir := newState(t)
			s, err := LoadOrCreateSigner(root, nil, testOrigin, tc.state, tc.size)
			if err == nil || s != nil {
				t.Fatalf("got signer %v, error %v; want an error", s, err)
			}
			if entries, _ := os.ReadDir(dir); len(entries) != 0 {
				t.Errorf("the state directory has %d entries; want none", len(entries))
			}
			if _, err := root.Stat(keysDir); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("keys directory: %v; want not exist", err)
			}
		})
	}
}

// T-S-13: the log of the first start and of the load path, and every error
// of the key rules, have no key text, no base64 key, and no seed.
func TestTS13_NoKeyOutput(t *testing.T) {
	root, dir := newState(t)
	log, buf := testLogger()
	_, err := LoadOrCreateSigner(root, log, testOrigin, false, 0)
	must(t, err)
	b, err := os.ReadFile(filepath.Join(dir, keyName))
	must(t, err)
	text := string(b)
	secrets := secretsOf(text)
	if len(secrets) != 3 {
		t.Fatalf("got %d secret forms; want 3", len(secrets))
	}
	_, err = LoadOrCreateSigner(root, log, testOrigin, true, 1)
	must(t, err)
	var errs []error
	for _, mode := range []os.FileMode{0o640, 0o604, 0o400} {
		putKey(t, dir, text, mode)
		_, err := LoadOrCreateSigner(root, log, testOrigin, true, 1)
		errs = append(errs, err)
	}
	putKey(t, dir, text, 0o600)
	_, err = LoadOrCreateSigner(root, log, "another/origin", true, 1) // wrong name
	errs = append(errs, err)
	geteuidOld := geteuid
	t.Cleanup(func() { geteuid = geteuidOld })
	geteuid = func() int { return os.Geteuid() + 1 }
	_, err = LoadOrCreateSigner(root, log, testOrigin, true, 1) // wrong owner
	geteuid = geteuidOld
	errs = append(errs, err)

	// The public key file has hostile content: the private key text.
	must(t, os.Remove(filepath.Join(dir, vkeyName)))
	must(t, os.WriteFile(filepath.Join(dir, vkeyName), []byte(text), 0o600))
	_, err = LoadOrCreateSigner(root, log, testOrigin, true, 1)
	must(t, err)

	if buf.Len() == 0 {
		t.Fatal("no log output to check")
	}
	assertNoSecret(t, "log", buf.String(), secrets)
	for i, err := range errs {
		if err == nil {
			t.Fatalf("error %d is nil", i)
		}
		assertNoSecret(t, "error", err.Error(), secrets)
	}
}

// firstStart makes a key and returns the root, the state directory, and the key text.
func firstStart(t *testing.T) (*os.Root, string, string) {
	t.Helper()
	root, dir := newState(t)
	_, err := LoadOrCreateSigner(root, nil, testOrigin, false, 0)
	must(t, err)
	text, err := os.ReadFile(filepath.Join(dir, keyName))
	must(t, err)
	return root, dir, string(text)
}

// firstStartKeysDir returns a state directory that has an empty keys directory.
func firstStartKeysDir(t *testing.T) (*os.Root, string) {
	t.Helper()
	root, dir := newState(t)
	must(t, os.Mkdir(filepath.Join(dir, keysDir), 0o700))
	return root, dir
}

// vkeyOf returns the value of the vkey attribute of the log.
func vkeyOf(t *testing.T, log string) string {
	t.Helper()
	_, rest, ok := strings.Cut(log, "vkey=")
	if !ok {
		t.Fatal("the log has no public key")
	}
	if i := strings.IndexAny(rest, " \n"); i >= 0 {
		rest = rest[:i]
	}
	return rest
}

// T-S-13: a public key file that is a symlink to the key file, or a copy of it,
// does not put the key text in the log. The load path logs the derived text
// and a fixed warning.
func TestTS13_VkeyIsKeyFile(t *testing.T) {
	for _, kind := range []string{"symlink", "copy"} {
		t.Run(kind, func(t *testing.T) {
			root, dir, text := firstStart(t)
			vpath := filepath.Join(dir, vkeyName)
			must(t, os.Remove(vpath))
			if kind == "symlink" {
				mustSymlink(t, "checkpoint.key", vpath)
			} else {
				must(t, os.WriteFile(vpath, []byte(text), 0o600))
			}
			log, buf := testLogger()
			s, err := loadWithin(t, root, log, testOrigin, true, 1)
			must(t, err)
			assertNoSecret(t, "log", buf.String(), secretsOf(text))
			if !strings.Contains(buf.String(), "checkpoint public key file ") {
				t.Error("the log has no warning about the public key file")
			}
			v, err := note.NewVerifier(vkeyOf(t, buf.String()))
			if err != nil || v.Name() != testOrigin || v.KeyHash() != s.KeyHash() {
				t.Errorf("the logged public key does not match the signer: %v", err)
			}
		})
	}
}

// T-S-13: on the first start, a symlink at the public key path gives an error.
// The write does not follow the symlink, the target does not change, and no
// key file is made.
func TestTS13_VkeySymlinkAtFirstStart(t *testing.T) {
	root, dir := firstStartKeysDir(t)
	target := filepath.Join(dir, "other-state")
	must(t, os.WriteFile(target, []byte("state"), 0o600))
	mustSymlink(t, "../other-state", filepath.Join(dir, vkeyName))
	s, err := loadWithin(t, root, nil, testOrigin, false, 0)
	if err == nil || s != nil || !strings.Contains(err.Error(), "public key file must not exist") {
		t.Fatalf("got signer %v, error %v; want the rule error", s, err)
	}
	if b, _ := os.ReadFile(target); string(b) != "state" {
		t.Errorf("the target of the symlink changed to %q", b)
	}
	if _, err := os.Lstat(filepath.Join(dir, keyName)); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("key file: %v; want not exist", err)
	}
}

// T-S-13: a FIFO at the public key path does not block the load path, and the
// first start refuses it.
func TestTS13_VkeyFifo(t *testing.T) {
	root, dir, _ := firstStart(t)
	vpath := filepath.Join(dir, vkeyName)
	must(t, os.Remove(vpath))
	mustFifo(t, vpath)
	log, buf := testLogger()
	if _, err := loadWithin(t, root, log, testOrigin, true, 1); err != nil {
		t.Fatalf("load: %v", err)
	}
	if !strings.Contains(buf.String(), "checkpoint public key file cannot be checked; the log has the correct key") {
		t.Errorf("the log has no warning: %s", buf)
	}
	root2, dir2 := firstStartKeysDir(t)
	mustFifo(t, filepath.Join(dir2, vkeyName))
	if _, err := loadWithin(t, root2, nil, testOrigin, false, 0); err == nil {
		t.Error("first start with a FIFO at the public key path: want an error")
	}
}

// T-S-13: a symlink to another valid key file that replaces the key between
// the Lstat and the open gives an error. os.Root follows the relative symlink.
func TestTS13_SwapAfterLstat(t *testing.T) {
	root, dir, _ := firstStart(t)
	other := filepath.Join(dir, keysDir, "other.key")
	must(t, os.WriteFile(other, []byte(newKeyText(t, testOrigin)), 0o600))
	must(t, os.Chmod(other, 0o600))
	called := false
	afterLstat = func() {
		called = true
		must(t, os.Remove(filepath.Join(dir, keyName)))
		mustSymlink(t, "other.key", filepath.Join(dir, keyName))
	}
	t.Cleanup(func() { afterLstat = nil })
	s, err := loadWithin(t, root, nil, testOrigin, true, 1)
	if !called {
		t.Fatal("the test hook did not run")
	}
	if err == nil || s != nil || !strings.Contains(err.Error(), keyName) || !strings.Contains(err.Error(), "changed between the check and the open") {
		t.Fatalf("got signer %v, error %v; want the rule error", s, err)
	}
}

// T-S-13: a public key file with other text gives one fixed warning and no
// file bytes in the log. The start succeeds.
func TestTS13_VkeyDiffers(t *testing.T) {
	root, dir, _ := firstStart(t)
	must(t, os.Remove(filepath.Join(dir, vkeyName)))
	must(t, os.WriteFile(filepath.Join(dir, vkeyName), []byte("other-text-marker"), 0o600))
	log, buf := testLogger()
	if _, err := loadWithin(t, root, log, testOrigin, true, 1); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "checkpoint public key file differs from the key; the log has the correct key") {
		t.Errorf("the log has no warning: %s", buf)
	}
	if strings.Contains(buf.String(), "other-text-marker") {
		t.Error("the log has bytes of the public key file")
	}
}

// T-S-13: the load path makes a missing public key file again, with mode 0600.
func TestTS13_MissingVkeyIsWrittenOnLoad(t *testing.T) {
	root, dir, _ := firstStart(t)
	vpath := filepath.Join(dir, vkeyName)
	want, err := os.ReadFile(vpath)
	must(t, err)
	must(t, os.Remove(vpath))
	_, err = LoadOrCreateSigner(root, nil, testOrigin, true, 1)
	must(t, err)
	got, err := os.ReadFile(vpath)
	if err != nil || !bytes.Equal(got, want) {
		t.Errorf("public key file %q, error %v; want %q", got, err, want)
	}
	if fi, err := os.Stat(vpath); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("public key file mode, error %v; want 0600", err)
	}
}

// T-S-13: os.Root.OpenFile follows a relative symlink that stays inside the
// root, so the key load compares the file before and after the open. With
// O_NONBLOCK, the open of a FIFO returns and the file is not a regular file.
func TestTS13_RootOpenFileFlags(t *testing.T) {
	root, dir := newState(t)
	must(t, os.WriteFile(filepath.Join(dir, "target"), []byte("x"), 0o600))
	mustSymlink(t, "target", filepath.Join(dir, "link"))
	f, err := root.OpenFile("link", readFlags, 0)
	if err != nil {
		t.Fatalf("open of an in-root symlink: %v; want success", err)
	}
	if b, _ := io.ReadAll(f); string(b) != "x" {
		t.Errorf("read %q through the symlink; want the target text", b)
	}
	f.Close()
	mustFifo(t, filepath.Join(dir, "fifo"))
	type result struct {
		f   *os.File
		err error
	}
	done := make(chan result, 1)
	go func() {
		f, err := root.OpenFile("fifo", readFlags, 0)
		done <- result{f, err}
	}()
	select {
	case r := <-done:
		if r.err == nil {
			defer r.f.Close()
			if fi, err := r.f.Stat(); err != nil || fi.Mode().IsRegular() {
				t.Errorf("a FIFO must not look like a regular file: %v, %v", fi, err)
			}
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the open of a FIFO blocks")
	}
}
