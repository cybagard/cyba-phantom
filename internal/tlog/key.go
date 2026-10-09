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
// The function makes a new key only on the first start: no key file, no signer
// state (signerState), and tree size 0. If the key is missing and a signer
// state exists or the tree has leaves, the function returns an error and makes
// no key (SEC-16).
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

// afterLstat is a test hook. Production code leaves it nil. A test sets it to
// change the file system between the Lstat and the open.
var afterLstat func()

// openChecked opens name for read and compares the open file with lfi, the
// Lstat result of the same name. os.Root adds O_NOFOLLOW itself, but it still
// follows a symlink that stays inside the root. The os.SameFile comparison
// finds such a change. The returned string is the failed rule, or empty.
func openChecked(root *os.Root, name string, lfi fs.FileInfo) (*os.File, fs.FileInfo, string) {
	if !lfi.Mode().IsRegular() { // also a symlink: Lstat does not follow it
		return nil, nil, "must be a regular file and not a symlink"
	}
	if afterLstat != nil {
		afterLstat()
	}
	f, err := root.OpenFile(name, readFlags, 0)
	if err != nil {
		return nil, nil, "cannot be opened"
	}
	fi, err := f.Stat() // the open file, not the name
	rule := ""
	switch {
	case err != nil:
		rule = "cannot be examined"
	case !os.SameFile(lfi, fi):
		rule = "changed between the check and the open"
	case !fi.Mode().IsRegular():
		rule = "must be a regular file"
	case fi.Size() > maxKeySize:
		rule = "must not be larger than 1 KiB"
	}
	if rule != "" {
		f.Close()
		return nil, nil, rule
	}
	return f, fi, ""
}

func loadSigner(root *os.Root, log *slog.Logger, path, origin string, lfi fs.FileInfo) (note.Signer, error) {
	f, fi, rule := openChecked(root, keyName, lfi)
	if rule != "" {
		return nil, keyError(path, rule)
	}
	defer f.Close()
	switch {
	case !ownedByEUID(fi):
		return nil, keyError(path, "must be owned by the user that runs the sensor")
	case fi.Mode()&(fs.ModePerm|fs.ModeSetuid|fs.ModeSetgid|fs.ModeSticky) != 0o600:
		return nil, keyError(path, "mode must be exactly 0600")
	}
	b, err := io.ReadAll(io.LimitReader(f, maxKeySize+1))
	if err != nil || len(b) > maxKeySize {
		return nil, keyError(path, "cannot be read within 1 KiB")
	}
	signer, err := note.NewSigner(string(b)) // the error text of note stays out of our error
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
	// This wipes the byte slice only. The string copies stay in memory until
	// the garbage collector frees them.
	clear(b)

	log.Info("checkpoint signing key loaded", "name", origin, "key_hash", fmt.Sprintf("%08x", signer.KeyHash()), "vkey", vkey)
	checkVkey(root, log, vkey)
	return signer, nil
}

// checkVkey writes the public key file again if it is missing. If the file
// exists, checkVkey reads it with the rules of the key file and warns when its
// text differs from vkey. The warnings have fixed text and never have file bytes.
func checkVkey(root *os.Root, log *slog.Logger, vkey string) {
	const (
		cannotCheck = "checkpoint public key file cannot be checked; the log has the correct key"
		differs     = "checkpoint public key file differs from the key; the log has the correct key"
	)
	fi, err := root.Lstat(vkeyName)
	if errors.Is(err, fs.ErrNotExist) {
		err = writeNew(root, vkeyName, vkey+"\n")
		if err == nil {
			err = syncDir(root, keysDir)
		}
		if err != nil {
			log.Warn("public key file cannot be written")
		}
		return
	}
	if err != nil {
		log.Warn(cannotCheck)
		return
	}
	f, _, rule := openChecked(root, vkeyName, fi)
	if rule != "" {
		log.Warn(cannotCheck)
		return
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxKeySize+1))
	switch {
	case err != nil || len(b) > maxKeySize:
		log.Warn(cannotCheck)
	case strings.TrimSpace(string(b)) != vkey:
		log.Warn(differs)
	}
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
	// An entry at the public key path is an error. The write must not follow it.
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
