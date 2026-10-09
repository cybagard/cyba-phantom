package tlog

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
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

const testOrigin = "agent-canary/test"

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

// T-S-13: a key file that breaks a rule gives an error that names the path,
// and the signer does not start.
func TestTS13_KeyFileRules(t *testing.T) {
	good := newKeyText(t, testOrigin)
	cases := []struct {
		name  string
		setup func(t *testing.T, dir string)
		text  string
	}{
		{"mode 0640", func(t *testing.T, dir string) { putKey(t, dir, good, 0o640) }, good},
		{"mode 0604", func(t *testing.T, dir string) { putKey(t, dir, good, 0o604) }, good},
		{"mode 0400", func(t *testing.T, dir string) { putKey(t, dir, good, 0o400) }, good},
		{"larger than 1 KiB", func(t *testing.T, dir string) { putKey(t, dir, good+strings.Repeat("\n", 1100), 0o600) }, good},
		{"wrong key name", func(t *testing.T, dir string) { putKey(t, dir, newKeyText(t, "other/origin"), 0o600) }, ""},
		{"malformed", func(t *testing.T, dir string) { putKey(t, dir, "PRIVATE+KEY+not-a-key", 0o600) }, ""},
		{"empty", func(t *testing.T, dir string) { putKey(t, dir, "", 0o600) }, ""},
		{"directory", func(t *testing.T, dir string) {
			if err := os.MkdirAll(filepath.Join(dir, keyName), 0o700); err != nil {
				t.Fatal(err)
			}
		}, ""},
		{"symlink inside", func(t *testing.T, dir string) {
			putKey(t, dir, good, 0o600)
			if err := os.Rename(filepath.Join(dir, keyName), filepath.Join(dir, "real.key")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(dir, "real.key"), filepath.Join(dir, keyName)); err != nil {
				t.Fatal(err)
			}
		}, good},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root, dir := newState(t)
			tc.setup(t, dir)
			log, buf := testLogger()
			s, err := LoadOrCreateSigner(root, log, testOrigin, true, 1)
			if err == nil || s != nil {
				t.Fatalf("got signer %v, error %v; want an error", s, err)
			}
			if !strings.Contains(err.Error(), keyName) {
				t.Errorf("error does not name the path: %v", err)
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
			if err := syscall.Mkfifo(fifo, 0o600); err != nil {
				t.Fatal(err)
			}
			if link == "file" {
				if err := os.Mkdir(filepath.Join(dir, keysDir), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(fifo, filepath.Join(dir, keyName)); err != nil {
					t.Fatal(err)
				}
			} else if err := os.Symlink(outside, filepath.Join(dir, keysDir)); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				_, err := LoadOrCreateSigner(root, nil, testOrigin, true, 1)
				done <- err
			}()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("want an error")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("the outside file was opened")
			}
		})
	}
}

// T-S-13: the owner must be the effective user. The test changes the seam,
// because it cannot make a file of another owner without root.
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

	s2, err := LoadOrCreateSigner(root, log, testOrigin, true, 1)
	if err != nil {
		t.Fatal(err)
	}
	signed2, err := note.Sign(&note.Note{Text: testOrigin + "\n1\nAAAA\n"}, s2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(signed, signed2) { // Ed25519 is deterministic
		t.Error("the second start loaded another key")
	}
}

// T-S-13: a missing key on a log with a signer state or leaves is an error,
// and no file is made.
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
	if _, err := LoadOrCreateSigner(root, log, testOrigin, false, 0); err != nil {
		t.Fatal(err)
	}
	text, err := os.ReadFile(filepath.Join(dir, keyName))
	if err != nil {
		t.Fatal(err)
	}
	secrets := secretsOf(string(text))
	if len(secrets) != 3 {
		t.Fatalf("got %d secret forms; want 3", len(secrets))
	}
	if _, err := LoadOrCreateSigner(root, log, testOrigin, true, 1); err != nil {
		t.Fatal(err)
	}
	var errs []error
	for _, mode := range []os.FileMode{0o640, 0o604, 0o400} {
		putKey(t, dir, string(text), mode)
		_, err := LoadOrCreateSigner(root, log, testOrigin, true, 1)
		errs = append(errs, err)
	}
	putKey(t, dir, string(text), 0o600)
	_, err = LoadOrCreateSigner(root, log, "another/origin", true, 1) // wrong name
	errs = append(errs, err)
	geteuidOld := geteuid
	geteuid = func() int { return os.Geteuid() + 1 }
	_, err = LoadOrCreateSigner(root, log, testOrigin, true, 1) // wrong owner
	geteuid = geteuidOld
	errs = append(errs, err)

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
