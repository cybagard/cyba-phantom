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
	installDirRule = safefile.Rule{Type: safefile.Dir, Owner: safefile.OwnerSelf, Forbid: 0o077 | fs.ModeSetuid | fs.ModeSetgid | fs.ModeSticky}
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
// A read is strict. The text must be the base64 form of the decoded bytes and
// one newline. The decoded bytes must have the length of an X25519 key.
//
// After the check of the keys directory, the function removes a leftover
// install.key.tmp or install.pub.tmp. It never replaces install.key or
// install.pub. It makes a new key only when both files are absent. An entry at
// install.pub with no install.key is a fault. A valid install.key with no
// install.pub gets its public key file again. A public key file for another
// key is a fault. install.key must be a regular file. Its owner is the user
// that runs the sensor, or root. It has no group or other bit, one link, and
// at most 1 KiB. The directory keys must be a real directory of the same user,
// with no group or other bit. When the function refuses a file or directory,
// it changes nothing else. It can still remove a leftover name and make the
// keys directory. When a later step fails, the keys directory and each linked
// file stay. Then the next call writes install.pub if install.key is linked
// and install.pub is not. If no file is linked, it makes a new key. A new file
// has mode 0600, also under a restrictive umask. The function logs nothing and
// emits no event.
func LoadOrCreateInstallKey(state *os.Root) (hpke.PrivateKey, error) {
	_, err := state.Lstat(installKeysDir)
	if errors.Is(err, fs.ErrNotExist) {
		if err = state.MkdirAll(installKeysDir, 0o700); err == nil {
			err = state.Chmod(installKeysDir, 0o700)
		}
	}
	var keys *os.Root
	if err == nil {
		keys, err = safefile.OpenRoot(state, installKeysDir, installDirRule)
	}
	if err != nil {
		return nil, installFault(installKeysDir, err)
	}
	defer keys.Close()
	for _, name := range []string{installKeyName, installPubName} {
		if err := keys.Remove(name + ".tmp"); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, installFault(name+".tmp", err)
		}
	}
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
	text, ok := bytes.CutSuffix(b, []byte("\n"))
	buf := make([]byte, base64.StdEncoding.DecodedLen(len(text)))
	n, err := base64.StdEncoding.Decode(buf, text)
	again := base64.StdEncoding.AppendEncode(make([]byte, 0, len(text)+4), buf[:n])
	defer clear(again)
	if !ok || err != nil || !bytes.Equal(again, text) || n != 32 {
		clear(buf)
		return nil, installFault(name, "must be the base64 text of a 32-byte key and one newline")
	}
	return buf[:n], nil
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

// installStep is nil, except in a test. A test sets it to act at the steps
// "create" and "link" of a file. Production code leaves it nil.
var installStep func(step, name string)

// writeInstallFile saves the text of data in a synced temporary file. Then it
// links name to that file. link(2) fails if name exists. The caller removed a
// temporary file that a crash left.
func writeInstallFile(keys *os.Root, name string, data []byte) error {
	tmp := name + ".tmp"
	if installStep != nil {
		installStep("create", name)
	}
	f, err := keys.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	text := base64.StdEncoding.AppendEncode(make([]byte, 0, len(data)*2), data)
	defer clear(text)
	_, werr := f.Write(append(text, '\n'))
	// A umask can remove bits of a new file, so Chmod sets mode 0600.
	err = errors.Join(werr, f.Chmod(0o600), f.Sync(), f.Close())
	if err == nil {
		if installStep != nil {
			installStep("link", name)
		}
		err = keys.Link(tmp, name)
	}
	return errors.Join(err, keys.Remove(tmp))
}

// installFault makes the fault error. The rule is a text or a system error.
func installFault(name string, rule any) error {
	return fmt.Errorf("%w: %s %v", ErrInstallKeyFault, name, rule)
}
