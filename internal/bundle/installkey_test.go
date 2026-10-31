package bundle

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hpke"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/cybagard/cyba-phantom/internal/safefile"
	"github.com/cybagard/cyba-phantom/internal/safefile/safefiletest"
)

var ikKEM = hpke.DHKEM(ecdh.X25519())

func ikText(b []byte) string { return base64.StdEncoding.EncodeToString(b) + "\n" }

func ikMust(t *testing.T, errs ...error) {
	t.Helper()
	for _, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
}

func ikDir(t *testing.T) (string, *os.Root) {
	t.Helper()
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	ikMust(t, err)
	t.Cleanup(func() { root.Close() })
	return dir, root
}

// ikPlant writes a file below the keys directory with exactly this mode.
func ikPlant(t *testing.T, dir, name, text string, mode os.FileMode) {
	t.Helper()
	p := filepath.Join(dir, "keys", name)
	ikMust(t, os.MkdirAll(filepath.Dir(p), 0o700), os.WriteFile(p, []byte(text), mode), os.Chmod(p, mode))
}

func ikKey(t *testing.T) (priv, pub []byte) {
	t.Helper()
	k, err := ikKEM.GenerateKey()
	ikMust(t, err)
	priv, err = k.Bytes()
	ikMust(t, err)
	return priv, k.PublicKey().Bytes()
}

// ikMarkers gives the raw, base64 and hex form of the key bytes.
func ikMarkers(priv []byte) []string {
	return []string{string(priv), base64.StdEncoding.EncodeToString(priv), hex.EncodeToString(priv)}
}

func ikHas(s string, markers []string) bool {
	return slices.ContainsFunc(markers, func(m string) bool { return strings.Contains(s, m) })
}

// ikWalk lists each entry below dir with its mode, inode, bytes and link. It
// reports a temporary file and a key marker outside install.key and planted
// files.
func ikWalk(t *testing.T, dir string, markers []string, planted ...string) string {
	t.Helper()
	var sb strings.Builder
	ikMust(t, filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		fi, _ := d.Info()
		rel, _ := filepath.Rel(dir, p)
		link, _ := os.Readlink(p)
		b, _ := os.ReadFile(p) // nil for a directory
		fmt.Fprintf(&sb, "%s %v %d %q %q\n", rel, fi.Mode(), fi.Sys().(*syscall.Stat_t).Ino, b, link)
		ok := rel == "keys/install.key" || slices.Contains(planted, d.Name())
		if (strings.HasSuffix(rel, ".tmp") && !slices.Contains(planted, d.Name())) || (!ok && ikHas(string(b), markers)) {
			t.Errorf("temporary file or key marker: %s", rel)
		}
		return nil
	}))
	return sb.String()
}

// ikLogs sets the default logger to a buffer that must stay empty.
func ikLogs(t *testing.T) {
	t.Helper()
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() {
		slog.SetDefault(old)
		if buf.Len() != 0 {
			t.Errorf("log output: %q", buf.String())
		}
	})
}

func ikRead(t *testing.T, dir, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "keys", name))
	ikMust(t, err)
	return string(b)
}

// T-S-20: the first call makes keys with mode 0700 and the files with 0600,
// also under a restrictive umask. It sets the umask, so no t.Parallel.
func TestTS20InstallKeyMade(t *testing.T) {
	for _, umask := range []int{0o022, 0o277} {
		dir, root := ikDir(t)
		ikLogs(t)
		old := syscall.Umask(umask)
		key, err := LoadOrCreateInstallKey(root)
		syscall.Umask(old)
		ikMust(t, err)
		for n, want := range map[string]os.FileMode{"keys": os.ModeDir | 0o700, "keys/install.key": 0o600, "keys/install.pub": 0o600} {
			if fi, err := os.Lstat(filepath.Join(dir, n)); err != nil || fi.Mode() != want {
				t.Errorf("umask %o: %s: %v %v", umask, n, fi, err)
			}
		}
		priv, _ := key.Bytes()
		again, err := ikKEM.NewPrivateKey(priv)
		if ikRead(t, dir, "install.key") != ikText(priv) || err != nil || ikRead(t, dir, "install.pub") != ikText(again.PublicKey().Bytes()) {
			t.Errorf("umask %o: the stored key is not the key: %v", umask, err)
		}
		ikWalk(t, dir, ikMarkers(priv))
	}
}

// T-S-20: the second call returns the same key and changes nothing. A seal to
// install.pub opens with the key. After a crash between the two files, the
// next call saves install.pub again.
func TestTS20InstallKeyReload(t *testing.T) {
	dir, root := ikDir(t)
	first, err := LoadOrCreateInstallKey(root)
	ikMust(t, err)
	priv, _ := first.Bytes()
	before := ikWalk(t, dir, ikMarkers(priv))
	second, err := LoadOrCreateInstallKey(root)
	ikMust(t, err)
	if after := ikWalk(t, dir, ikMarkers(priv)); after != before || !bytes.Equal(second.PublicKey().Bytes(), first.PublicKey().Bytes()) {
		t.Errorf("second call changed the files or the key:\n%s\n%s", before, after)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSuffix(ikRead(t, dir, "install.pub"), "\n"))
	pub, err2 := ikKEM.NewPublicKey(raw)
	ikMust(t, err, err2)
	ct, err := hpke.Seal(pub, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), []byte("info"), []byte("text"))
	ikMust(t, err)
	if got, err := hpke.Open(second, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), []byte("info"), ct); err != nil || string(got) != "text" {
		t.Errorf("open: %q %v", got, err)
	}
	pubBefore := ikRead(t, dir, "install.pub")
	ikMust(t, os.Remove(filepath.Join(dir, "keys", "install.pub")))
	_, err = LoadOrCreateInstallKey(root)
	ikMust(t, err)
	fi, err := os.Lstat(filepath.Join(dir, "keys", "install.pub"))
	if err != nil || fi.Mode() != 0o600 || ikRead(t, dir, "install.pub") != pubBefore || ikRead(t, dir, "install.key") != ikText(priv) {
		t.Errorf("after a crash, install.pub or install.key is wrong: %v %v", fi, err)
	}
}

// T-S-20: each fault changes no file, makes no key, and leaves no key byte in
// the error or the log. KEY and PUB in a text stand for the file text of a key.
func TestTS20InstallKeyFaults(t *testing.T) {
	const textRule = "install.key must be the base64 text of a 32-byte key"
	cases := []struct {
		name, key, pub, want string // want: text in the error
		keyMode, pubMode     os.FileMode
		extra                func(t *testing.T, keys, key string)
	}{
		{name: "group read bit", key: "KEY", keyMode: 0o640, want: "install.key safefile: file has the wrong mode"},
		{name: "other read bit", key: "KEY", keyMode: 0o604, want: "install.key safefile: file has the wrong mode"},
		{name: "larger than 1 KiB", key: strings.Repeat("A", 1024) + "\n", want: "too large"},
		{name: "bad base64", key: "!!!!\n", want: textRule},
		{name: "no newline", key: "KEY-", want: textRule},
		{name: "two newlines", key: "KEY\n", want: textRule},
		{name: "wrong length", key: "KEY31", want: textRule},
		{name: "public key only", pub: "PUB", want: "no new key is made"},
		{name: "public key of another key", key: "KEY", pub: "OTHER", want: "install.pub is not the public key"},
		{name: "public key with a group write bit", key: "KEY", pub: "PUB", pubMode: 0o620, want: "install.pub safefile: file has the wrong mode"},
		{name: "public key with bad text", key: "KEY", pub: "bad\n", want: "install.pub must be the base64 text"},
		{name: "symlink", want: "symbolic link", extra: func(t *testing.T, keys, key string) {
			ikMust(t, os.Mkdir(keys, 0o700), os.WriteFile(keys+"/real.key", []byte(key), 0o600), os.Symlink("real.key", keys+"/install.key"))
		}},
		{name: "second hard link", key: "KEY", want: "more than one link", extra: func(t *testing.T, keys, _ string) { ikMust(t, os.Link(keys+"/install.key", keys+"/copy")) }},
		{name: "dangling link as public key", want: "no new key is made", extra: func(t *testing.T, keys, _ string) {
			ikMust(t, os.Mkdir(keys, 0o700), os.Symlink("gone", keys+"/install.pub"))
		}},
		{name: "keys is a symlink", want: "symbolic link", extra: func(t *testing.T, keys, _ string) { ikMust(t, os.Mkdir(keys+"-x", 0o700), os.Symlink("keys-x", keys)) }},
		{name: "keys is a file", want: "wrong type", extra: func(t *testing.T, keys, _ string) { ikMust(t, os.WriteFile(keys, nil, 0o600)) }},
		{name: "keys with a group bit", key: "KEY", want: "keys safefile: file has the wrong mode", extra: func(t *testing.T, keys, _ string) { ikMust(t, os.Chmod(keys, 0o750)) }},
		{name: "keys with all bits", key: "KEY", want: "keys safefile: file has the wrong mode", extra: func(t *testing.T, keys, _ string) { ikMust(t, os.Chmod(keys, 0o777)) }},
		{name: "keys of another owner", key: "KEY", want: "keys safefile: file has the wrong owner", extra: func(t *testing.T, keys, _ string) { ikOtherOwner(t, keys) }},
		{name: "key of another owner", key: "KEY", want: "install.key safefile: file has the wrong owner", extra: func(t *testing.T, keys, _ string) { ikOtherOwner(t, keys+"/install.key") }},
		{name: "public key of another owner", key: "KEY", pub: "PUB", want: "install.pub safefile: file has the wrong owner", extra: func(t *testing.T, keys, _ string) { ikOtherOwner(t, keys+"/install.pub") }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir, root := ikDir(t)
			ikLogs(t)
			priv, pub := ikKey(t)
			_, other := ikKey(t)
			markers := ikMarkers(priv)
			expand := strings.NewReplacer("KEY31", ikText(priv[:31]), "KEY-", strings.TrimSuffix(ikText(priv), "\n"),
				"KEY\n", ikText(priv)+"\n", "KEY", ikText(priv), "PUB", ikText(pub), "OTHER", ikText(other)).Replace
			if c.key != "" {
				ikPlant(t, dir, "install.key", expand(c.key), max(c.keyMode, 0o600))
			}
			if c.pub != "" {
				ikPlant(t, dir, "install.pub", expand(c.pub), max(c.pubMode, 0o600))
			}
			if c.extra != nil {
				c.extra(t, filepath.Join(dir, "keys"), expand("KEY"))
			}
			before := ikWalk(t, dir, markers, "real.key", "copy")
			key, err := LoadOrCreateInstallKey(root)
			if key != nil || !errors.Is(err, ErrInstallKeyFault) {
				t.Fatalf("key %v, error %v", key, err)
			}
			if _, ok := CodeOf(err); ok || !strings.Contains(err.Error(), c.want) {
				t.Errorf("rejection code, or no %q in %v", c.want, err)
			}
			if after := ikWalk(t, dir, markers, "real.key", "copy"); after != before {
				t.Errorf("fault changed files:\n%s\n%s", before, after)
			}
			if ikHas(err.Error()+fmt.Sprintf("%+v", err), markers) {
				t.Error("key marker in the error")
			}
		})
	}
}

// T-S-20: a file that appears at the create or the link step stays. The call
// fails, and only the planted file stays below keys.
func TestTS20InstallKeyNoReplace(t *testing.T) {
	for _, step := range []string{"create", "link"} {
		t.Run(step, func(t *testing.T) {
			dir, root := ikDir(t)
			planted := filepath.Join(dir, "keys", "install.key") + map[string]string{"create": ".tmp"}[step]
			installStep = func(s, name string) {
				if s == step && name == "install.key" {
					ikMust(t, os.WriteFile(planted, []byte("planted"), 0o600))
				}
			}
			t.Cleanup(func() { installStep = nil })
			if key, err := LoadOrCreateInstallKey(root); key != nil || !errors.Is(err, ErrInstallKeyFault) {
				t.Fatalf("key %v, error %v", key, err)
			}
			if b, err := os.ReadFile(planted); err != nil || string(b) != "planted" {
				t.Errorf("planted file: %q %v", b, err)
			}
			ikWalk(t, dir, nil, filepath.Base(planted)) // no other temporary file
		})
	}
}

func ikOtherOwner(t *testing.T, path string) {
	fi, _ := os.Stat(path)
	id, _ := safefile.Identity(fi)
	safefiletest.Set(t, safefiletest.Hooks{OtherOwner: func(o safefile.FileID) bool { return o == id }})
}

// T-S-20: a symlink that replaces keys after the check is a fault. Its target
// stays empty.
func TestTS20InstallKeySwapped(t *testing.T) {
	dir, root := ikDir(t)
	keys, other := filepath.Join(dir, "keys"), filepath.Join(dir, "other")
	ikMust(t, os.Mkdir(keys, 0o700), os.Mkdir(other, 0o700))
	safefiletest.Set(t, safefiletest.Hooks{AfterCheck: func(string) { ikMust(t, os.Remove(keys), os.Symlink("other", keys)) }})
	key, err := LoadOrCreateInstallKey(root)
	if ents, _ := os.ReadDir(other); key != nil || !errors.Is(err, ErrInstallKeyFault) || !strings.Contains(err.Error(), "changed during the check") || len(ents) != 0 {
		t.Errorf("key %v, error %v, files in the other directory %v", key, err, ents)
	}
}

// T-S-20: a leftover temporary name goes away. In case 2, install.pub is 0644.
func TestTS20InstallKeyLeftover(t *testing.T) {
	for _, c := range []struct {
		tmp string
		key bool
	}{{"install.key.tmp", true}, {"install.pub.tmp", true}, {"install.key.tmp", false}} {
		t.Run(fmt.Sprint(c), func(t *testing.T) {
			dir, root := ikDir(t)
			priv, pub := ikKey(t)
			keys := filepath.Join(dir, "keys")
			if c.tmp == "install.pub.tmp" {
				ikPlant(t, dir, "install.pub", ikText(pub), 0o644)
			}
			if c.key {
				ikPlant(t, dir, "install.key", ikText(priv), 0o600)
				ikMust(t, os.Link(filepath.Join(keys, strings.TrimSuffix(c.tmp, ".tmp")), filepath.Join(keys, c.tmp)))
			} else {
				ikPlant(t, dir, c.tmp, "leftover\n", 0o600)
			}
			key, err := LoadOrCreateInstallKey(root)
			ikMust(t, err)
			got, _ := key.Bytes()
			if c.key && !bytes.Equal(got, priv) || ikRead(t, dir, "install.key") != ikText(got) || ikRead(t, dir, "install.pub") != ikText(key.PublicKey().Bytes()) {
				t.Error("the key or a file is wrong")
			}
			ikWalk(t, dir, ikMarkers(got)) // a temporary file is an error
		})
	}
}

// T-S-20: a call leaves no open descriptor. No t.Parallel, as it counts all.
func TestTS20InstallKeyDescriptors(t *testing.T) {
	_, root := ikDir(t)
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skip("no /proc/self/fd")
	}
	for i := range 2 {
		_, err := LoadOrCreateInstallKey(root)
		after, _ := os.ReadDir("/proc/self/fd")
		if ikMust(t, err); len(after) != len(before) {
			t.Errorf("call %d: %d descriptors before, %d after", i+1, len(before), len(after))
		}
	}
}
