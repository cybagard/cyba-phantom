package tlog

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/mod/sumdb/note"
)

// The key files are at fixed names below the state directory (ADR-020).
const (
	keysDir    = "keys"
	keyName    = "keys/checkpoint.key"
	vkeyName   = "keys/checkpoint.vkey"
	maxKeySize = 1024
)

// LoadOrCreateSigner returns the checkpoint signer. It opens the key through
// root, the state directory that the caller opened one time. The key name must
// equal origin (tlog.origin).
//
// A key is made only on the first start: no key file, no signer state
// (signerState), and tree size 0. A missing key while a signer state exists or
// the tree has leaves is an error, and no key is made (SEC-16).
//
// The key text, its base64 form, and the seed never go to the log or to an
// error. The function keeps only the signer value. It derives the public key
// text from the key and logs it. It never logs the bytes of a file.
func LoadOrCreateSigner(root *os.Root, log *slog.Logger, origin string, signerState bool, treeSize uint64) (note.Signer, error) {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	path := filepath.Join(root.Name(), keyName)
	keysExist, err := checkKeysDir(root, path)
	if err != nil {
		return nil, err
	}
	if keysExist {
		fi, err := root.Lstat(keyName)
		switch {
		case err == nil:
			return loadSigner(root, log, path, origin, fi)
		case !errors.Is(err, fs.ErrNotExist):
			return nil, keyError(path, "cannot be examined")
		}
	}
	if signerState || treeSize > 0 {
		return nil, keyError(path, "is missing but the log has a signer state or leaves; no new key is made")
	}
	return createSigner(root, log, path, origin)
}

// keyError names the path and the failed rule, and nothing else.
func keyError(path, rule string) error {
	return fmt.Errorf("checkpoint key %s: %s", path, rule)
}

// checkKeysDir reports whether the keys directory exists. An entry that is
// not a real directory (a symlink, for example) is an error.
func checkKeysDir(root *os.Root, path string) (bool, error) {
	fi, err := root.Lstat(keysDir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return false, nil
	case err != nil:
		return false, keyError(path, "keys directory cannot be examined")
	case !fi.IsDir():
		return false, keyError(path, "keys must be a real directory and not a symlink")
	}
	return true, nil
}

func loadSigner(root *os.Root, log *slog.Logger, path, origin string, fi fs.FileInfo) (note.Signer, error) {
	if !fi.Mode().IsRegular() { // also a symlink: Lstat does not follow it
		return nil, keyError(path, "must be a regular file and not a symlink")
	}
	// The flags stop a symlink swapped in after Lstat and a FIFO that blocks.
	f, err := root.OpenFile(keyName, readFlags, 0)
	if err != nil {
		return nil, keyError(path, "cannot be opened")
	}
	defer f.Close()
	fi, err = f.Stat() // the open file, not the name
	if err != nil {
		return nil, keyError(path, "cannot be examined")
	}
	switch {
	case !fi.Mode().IsRegular():
		return nil, keyError(path, "must be a regular file")
	case !ownedByEUID(fi):
		return nil, keyError(path, "must be owned by the user that runs the sensor")
	case fi.Mode()&(fs.ModePerm|fs.ModeSetuid|fs.ModeSetgid|fs.ModeSticky) != 0o600:
		return nil, keyError(path, "mode must be exactly 0600")
	case fi.Size() > maxKeySize:
		return nil, keyError(path, "must not be larger than 1 KiB")
	}
	b, err := io.ReadAll(io.LimitReader(f, maxKeySize+1))
	if err != nil || len(b) > maxKeySize {
		return nil, keyError(path, "cannot be read within 1 KiB")
	}
	signer, err := note.NewSigner(string(b)) // the error text is not passed on
	if err != nil {
		return nil, keyError(path, "is not a valid note signer key")
	}
	if signer.Name() != origin {
		return nil, keyError(path, "key name must equal the configured origin")
	}
	vkey, err := deriveVkey(string(b), origin, signer)
	if err != nil {
		return nil, keyError(path, "public key cannot be derived from the key")
	}
	clear(b) // only the signer stays

	// The load path never reads the public key file. It can be a symlink or a
	// copy of the key. A missing file is made again from the derived text.
	if _, err := root.Lstat(vkeyName); errors.Is(err, fs.ErrNotExist) {
		if err := writeNew(root, vkeyName, vkey+"\n"); err != nil {
			log.Warn("public key file cannot be written")
		}
	}
	log.Info("checkpoint signing key loaded", "name", origin, "key_hash", fmt.Sprintf("%08x", signer.KeyHash()), "vkey", vkey)
	return signer, nil
}

// deriveVkey makes the verifier key text from the private key text: the name,
// the key hash, and base64 of 0x01 followed by the Ed25519 public key. It
// checks the result with note.NewVerifier.
func deriveVkey(skey, origin string, signer note.Signer) (string, error) {
	errBad := errors.New("bad key")
	parts := strings.SplitN(skey, "+", 5)
	if len(parts) != 5 {
		return "", errBad
	}
	raw, err := base64.StdEncoding.DecodeString(parts[4])
	if err != nil || len(raw) != 1+ed25519.SeedSize || raw[0] != 1 {
		return "", errBad
	}
	pub := ed25519.NewKeyFromSeed(raw[1:]).Public().(ed25519.PublicKey)
	clear(raw)
	vkey := fmt.Sprintf("%s+%08x+%s", origin, signer.KeyHash(), base64.StdEncoding.EncodeToString(append([]byte{1}, pub...)))
	v, err := note.NewVerifier(vkey)
	if err != nil || v.Name() != origin || v.KeyHash() != signer.KeyHash() {
		return "", errBad
	}
	return vkey, nil
}

func createSigner(root *os.Root, log *slog.Logger, path, origin string) (note.Signer, error) {
	skey, vkey, err := note.GenerateKey(rand.Reader, origin)
	if err != nil {
		return nil, keyError(path, "cannot make a key for the configured origin")
	}
	signer, err := note.NewSigner(skey)
	if err != nil {
		return nil, keyError(path, "cannot make a key for the configured origin")
	}
	if err := root.MkdirAll(keysDir, 0o700); err != nil {
		return nil, fmt.Errorf("checkpoint key %s: cannot make the keys directory: %w", path, err)
	}
	// Any entry at the public key path is an error. The write must not follow it.
	if _, err := root.Lstat(vkeyName); !errors.Is(err, fs.ErrNotExist) {
		return nil, keyError(path, "public key file must not exist on the first start")
	}
	if err := writeNew(root, keyName, skey); err != nil {
		return nil, fmt.Errorf("checkpoint key %s: cannot write the key file: %w", path, err)
	}
	if err := writeNew(root, vkeyName, vkey+"\n"); err != nil {
		return nil, fmt.Errorf("checkpoint key %s: cannot write the public key file: %w", path, err)
	}
	for _, dir := range []string{keysDir, "."} {
		if err := syncDir(root, dir); err != nil {
			return nil, fmt.Errorf("checkpoint key %s: cannot sync the directory: %w", path, err)
		}
	}
	log.Info("checkpoint signing key made", "name", origin, "vkey", vkey)
	return signer, nil
}

// writeNew makes a new file with mode 0600 and syncs it. O_EXCL means that the
// call never opens or replaces an existing entry, and never follows a symlink.
// A failed write removes the file. Only this call made that file.
func writeNew(root *os.Root, name, text string) error {
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = f.WriteString(text)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = root.Remove(name)
	}
	return err
}

func syncDir(root *os.Root, name string) error {
	d, err := root.Open(name)
	if err != nil {
		return err
	}
	err = d.Sync()
	if cerr := d.Close(); err == nil {
		err = cerr
	}
	return err
}
