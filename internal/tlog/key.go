package tlog

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"

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
// error. The function keeps only the signer value. The public key text is
// public and is logged.
func LoadOrCreateSigner(root *os.Root, log *slog.Logger, origin string, signerState bool, treeSize uint64) (note.Signer, error) {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	path := filepath.Join(root.Name(), keyName)
	fi, err := root.Lstat(keyName)
	switch {
	case err == nil:
		return loadSigner(root, log, path, origin, fi)
	case !errors.Is(err, fs.ErrNotExist):
		return nil, keyError(path, "cannot be examined")
	case signerState || treeSize > 0:
		return nil, keyError(path, "is missing but the log has a signer state or leaves; no new key is made")
	}
	return createSigner(root, log, path, origin)
}

// keyError names the path and the failed rule, and nothing else.
func keyError(path, rule string) error {
	return fmt.Errorf("checkpoint key %s: %s", path, rule)
}

func loadSigner(root *os.Root, log *slog.Logger, path, origin string, fi fs.FileInfo) (note.Signer, error) {
	if !fi.Mode().IsRegular() { // also a symlink: Lstat does not follow it
		return nil, keyError(path, "must be a regular file and not a symlink")
	}
	f, err := root.Open(keyName)
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
	attrs := []any{"name", signer.Name(), "key_hash", fmt.Sprintf("%08x", signer.KeyHash())}
	if v, ok := readVkey(root); ok {
		attrs = append(attrs, "vkey", v)
	}
	log.Info("checkpoint signing key loaded", attrs...)
	return signer, nil
}

// readVkey reads the public key text. It is best effort: it is only for the log.
func readVkey(root *os.Root) (string, bool) {
	f, err := root.Open(vkeyName)
	if err != nil {
		return "", false
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxKeySize))
	return string(b), err == nil && len(b) > 0
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
	if err := writeNew(root, keyName, skey, os.O_EXCL); err != nil {
		return nil, fmt.Errorf("checkpoint key %s: cannot write the key file: %w", path, err)
	}
	if err := writeNew(root, vkeyName, vkey+"\n", os.O_TRUNC); err != nil {
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

// writeNew writes a new file with mode 0600 and syncs it. A failed write of a
// file that this call made removes the file, so no half key stays on disk.
// flag is os.O_EXCL for the key (never replace) or os.O_TRUNC.
func writeNew(root *os.Root, name, text string, flag int) error {
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|flag, 0o600)
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
