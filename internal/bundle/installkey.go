package bundle

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hpke"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"syscall"

	"github.com/cybagard/cyba-phantom/internal/safefile"
)

// The key files are in "keys" below the state directory, as the checkpoint key.
const (
	installKeysDir = "keys"
	installKeyName = "install.key"
	installPubName = "install.pub"
)

// ErrInstallKeyFault is the fault of the install key files, not a rejection
// code: CodeOf gives false. It names the file and the rule, and no key byte.
var ErrInstallKeyFault = errors.New("bundle: install key fault")

// The file rules. The public key file permits the read bits of group and other.
var (
	installKeyRule = safefile.Rule{Type: safefile.Regular, Owner: safefile.OwnerSelfOrRoot, Forbid: 0o077 | fs.ModeSetuid | fs.ModeSetgid | fs.ModeSticky, OneLink: true, MaxSize: 1024}
	installPubRule = safefile.Rule{Type: safefile.Regular, Owner: safefile.OwnerSelfOrRoot, Forbid: 0o022 | fs.ModeSetuid | fs.ModeSetgid | fs.ModeSticky, OneLink: true, MaxSize: 1024}
)

func installKEM() hpke.KEM { return hpke.DHKEM(ecdh.X25519()) }

// LoadOrCreateInstallKey returns the install key, the X25519 private key that
// opens the sealed seeds of a bundle. state is the state directory, which the
// caller opened one time. The files are keys/install.key and keys/install.pub.
//
// The text of each file is the standard base64 form of the key bytes and one
// newline. The key bytes are the output of PrivateKey.Bytes or PublicKey.Bytes.
// A vendor tool reads install.pub. A read is strict. The text must be the
// base64 form of the decoded bytes and one newline. The decoded bytes must
// have the length of an X25519 key.
//
// The function makes a new key only when both files are absent. An entry at
// install.pub with no install.key is a fault. A valid install.key with no
// install.pub gets its public key file again. A public key file for another
// key is a fault. install.key must be a regular file. Its owner is the user
// that runs the sensor, or root. It has no group or other bit, one link, and
// at most 1 KiB. The directory keys must be a real directory. A fault changes
// no file. A new file has mode 0600, also under a restrictive umask. The
// function never replaces an entry. It logs nothing and emits no event.
func LoadOrCreateInstallKey(state *os.Root) (hpke.PrivateKey, error) {
	fi, err := state.Lstat(installKeysDir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		err = state.MkdirAll(installKeysDir, 0o700)
	case err == nil && !fi.IsDir():
		err = errors.New("must be a real directory and not a symlink")
	}
	var keys *os.Root
	if err == nil {
		keys, err = state.OpenRoot(installKeysDir)
	}
	if err != nil {
		return nil, installFault(installKeysDir, err)
	}
	defer keys.Close()
	hasKey, hasPub := installHas(keys, installKeyName), installHas(keys, installPubName)
	if !hasKey && hasPub {
		return nil, installFault(installPubName, "exists but install.key is missing; no new key is made")
	}
	var key hpke.PrivateKey
	names := []string{installKeyName, installPubName}
	if hasKey {
		raw, err := readInstallText(keys, installKeyName, installKeyRule)
		if err != nil {
			return nil, err
		}
		defer clear(raw)
		if key, err = installKEM().NewPrivateKey(raw); err != nil {
			return nil, installFault(installKeyName, "is not an X25519 private key")
		}
		names = names[1:]
	} else if key, err = installKEM().GenerateKey(); err != nil {
		return nil, installFault(installKeyName, err)
	}
	if hasPub {
		got, err := readInstallText(keys, installPubName, installPubRule)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(got, key.PublicKey().Bytes()) {
			return nil, installFault(installPubName, "is not the public key of install.key")
		}
		return key, nil
	}
	if err := writeInstallFiles(state, keys, key, names...); err != nil {
		return nil, err
	}
	return key, nil
}

func installHas(keys *os.Root, name string) bool {
	_, err := keys.Lstat(name)
	return !errors.Is(err, fs.ErrNotExist)
}

// readInstallText reads a file with the rule and decodes it strictly.
func readInstallText(keys *os.Root, name string, rule safefile.Rule) ([]byte, error) {
	b, err := safefile.ReadFile(keys, name, rule)
	if err != nil {
		return nil, installFault(name, err)
	}
	defer clear(b)
	text, ok := strings.CutSuffix(string(b), "\n")
	raw, err := base64.StdEncoding.DecodeString(text)
	if !ok || err != nil || base64.StdEncoding.EncodeToString(raw) != text || len(raw) != 32 {
		return nil, installFault(name, "must be the base64 text of a 32-byte key and one newline")
	}
	return raw, nil
}

// writeInstallFiles writes the named files in order and syncs both directories.
func writeInstallFiles(state, keys *os.Root, key hpke.PrivateKey, names ...string) error {
	priv, err := key.Bytes()
	if err != nil {
		return installFault(installKeyName, err)
	}
	defer clear(priv)
	for _, name := range names {
		data := key.PublicKey().Bytes()
		if name == installKeyName {
			data = priv
		}
		if err := writeInstallFile(keys, name, data); err != nil {
			return installFault(name, err)
		}
	}
	for _, r := range []*os.Root{keys, state} {
		d, err := r.Open(".")
		if err == nil {
			err = errors.Join(d.Sync(), d.Close())
		}
		if err != nil {
			return installFault(installKeysDir, err)
		}
	}
	return nil
}

// installStep is a test hook for the steps "create" and "link" of a write.
var installStep = func(step, name string) {}

// writeInstallFile writes the text of data to a synced temporary file. Then it
// links name to that file. link(2) fails if name exists. A temporary file that
// a crash left goes away first.
func writeInstallFile(keys *os.Root, name string, data []byte) error {
	tmp := name + ".tmp"
	_ = keys.Remove(tmp) // if this fails, the exclusive create below fails
	installStep("create", name)
	f, err := keys.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.WriteString(base64.StdEncoding.EncodeToString(data) + "\n")
	// A umask can only remove bits at the create, so Chmod sets mode 0600.
	err = errors.Join(werr, f.Chmod(0o600), f.Sync(), f.Close())
	if err == nil {
		installStep("link", name)
		err = keys.Link(tmp, name)
	}
	return errors.Join(err, keys.Remove(tmp))
}

// installFault makes the fault error. The rule is a text or a system error.
func installFault(name string, rule any) error {
	return fmt.Errorf("%w: %s %v", ErrInstallKeyFault, name, rule)
}
