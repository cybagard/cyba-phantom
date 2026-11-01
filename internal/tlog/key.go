package tlog

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/mod/sumdb/note"

	"github.com/cybagard/cyba-phantom/internal/safefile"
)

// The key files are at fixed names below the state directory (ADR-020).
const (
	keysDir    = "keys"
	keyFile    = "checkpoint.key"
	vkeyFile   = "checkpoint.vkey"
	keyName    = keysDir + "/" + keyFile
	vkeyName   = keysDir + "/" + vkeyFile
	maxKeySize = 1024
)

// The rules of the files that this package reads. A note, a cursor, and the
// signer state have no owner and mode rule. They only have a type and a size.
var (
	keysDirRule = safefile.Rule{Type: safefile.Dir, Owner: safefile.OwnerSelf, Forbid: 0o077}
	keyRule     = safefile.Rule{Type: safefile.Regular, Owner: safefile.OwnerSelf, Exact: 0o600, OneLink: true, MaxSize: maxKeySize}
	vkeyRule    = safefile.Rule{Type: safefile.Regular, Owner: safefile.OwnerAny, MaxSize: maxKeySize}
	noteRule    = safefile.Rule{Type: safefile.Regular, Owner: safefile.OwnerAny, MaxSize: maxNoteSize}
)

// ruleText gives the fixed text of a refusal of safefile for a file with the
// rule r. It has no path and no file bytes.
func ruleText(err error, r safefile.Rule) string {
	switch {
	case errors.Is(err, safefile.ErrSymlink), errors.Is(err, safefile.ErrType):
		return "must be a regular file and not a symlink"
	case errors.Is(err, safefile.ErrOwner):
		return "must be owned by the user that runs the sensor"
	case errors.Is(err, safefile.ErrMode):
		if r.Exact == 0 {
			return "has a mode that is not permitted"
		}
		return fmt.Sprintf("mode must be exactly %04o", r.Exact)
	case errors.Is(err, safefile.ErrLinks):
		return "must have one link only"
	case errors.Is(err, safefile.ErrSize):
		return fmt.Sprintf("must not be larger than %d KiB", r.MaxSize>>10)
	case errors.Is(err, safefile.ErrChanged):
		return "changed between the check and the read"
	case errors.Is(err, safefile.ErrOpen):
		return "cannot be opened"
	}
	return "cannot be read"
}

// missing reports a file that safefile did not find.
func missing(err error) bool {
	return errors.Is(err, safefile.ErrExamine) && errors.Is(err, fs.ErrNotExist)
}

// VKeyName is the public key file below the state directory, for the code
// outside this package.
const VKeyName = vkeyName

// LoadOrCreateSigner returns the checkpoint signer. It opens the key through
// root, the state directory that the caller opened one time. The key name must
// equal origin (tlog.origin).
//
// The function makes a new key only on the first start. That needs no key
// file, no signed checkpoint (signed), and tree size 0. If the key is missing
// and signed is true, the function returns an error. The same holds when the
// tree has leaves. The function makes no key then (SEC-16).
//
// A new key gets a signer state. An entry at checkpoint.state is an error: the
// function makes no key and keeps the entry. The function writes the key file
// and the public key file, and syncs the directories. Then it signs a checkpoint
// of the empty tree (size 0) and writes it as checkpoint.state with the
// crash-safe rule of the checkpointer. If that write fails, the function returns
// an error and the key files stay. The next start then has a key with no signer state.
// That is a fault for the checkpointer, and the operator decides.
//
// The key text, its base64 form, and the seed never go to the log or to an
// error. The function keeps only the signer value. It derives the public key
// text from the key and logs it. It never logs the bytes of a file.
func LoadOrCreateSigner(root *os.Root, log *slog.Logger, origin string, signed bool, treeSize uint64) (note.Signer, error) {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	path := filepath.Join(root.Name(), keyName)
	keys, err := checkKeysDir(root, path)
	if err != nil {
		return nil, err
	}
	if keys != nil {
		defer keys.Close()
		_, err := keys.Lstat(keyFile)
		switch {
		case err == nil:
			return loadSigner(keys, log, path, origin)
		case !errors.Is(err, fs.ErrNotExist):
			return nil, keyError(path, "cannot be examined")
		}
	}
	if signed || treeSize > 0 {
		return nil, keyError(path, "is missing but the log has a signed checkpoint or leaves; no new key is made")
	}
	return createSigner(root, log, path, origin)
}

// keyError names the path and the failed rule, and nothing else.
func keyError(path, rule string) error {
	return fmt.Errorf("checkpoint key %s: %s", path, rule)
}

// checkKeysDir opens the keys directory and returns it as a root. The caller
// closes it. A missing directory gives nil and no error. An entry that is not
// a real directory (a symlink, for example) is an error. A directory with
// group or other bits is an error. A directory of another owner is an error.
func checkKeysDir(root *os.Root, path string) (*os.Root, error) {
	keys, err := safefile.OpenRoot(root, keysDir, keysDirRule)
	switch {
	case err == nil:
		return keys, nil
	case missing(err):
		return nil, nil
	case errors.Is(err, safefile.ErrSymlink), errors.Is(err, safefile.ErrType):
		return nil, keyError(path, "keys must be a real directory and not a symlink")
	case errors.Is(err, safefile.ErrOwner):
		return nil, keyError(path, "keys must be owned by the user that runs the sensor")
	case errors.Is(err, safefile.ErrMode):
		return nil, keyError(path, "keys must not allow group or other access")
	case errors.Is(err, safefile.ErrChanged):
		return nil, keyError(path, "keys changed between the check and the open")
	}
	return nil, keyError(path, "keys directory cannot be examined")
}

// faultAt is a test hook. Production code leaves it nil. A test sets it to
// return an error for a step of a name. The steps are "examine", "open", and
// "read".
var faultAt func(step, name string) error

func fault(step, name string) error {
	if faultAt == nil {
		return nil
	}
	return faultAt(step, name)
}

// loadSigner loads the key below keys, the keys directory that the caller
// checked and opened. Every later access goes through keys, so a swap of the
// directory name after the check has no effect.
func loadSigner(keys *os.Root, log *slog.Logger, path, origin string) (note.Signer, error) {
	// A crash after the link can leave a second name of the key file. The key
	// rule needs one link, so the temporary name goes before the check.
	if err := keys.Remove(keyFile + ".tmp"); err != nil && !errors.Is(err, fs.ErrNotExist) {
		log.Warn("checkpoint key temporary file cannot be removed")
	}
	b, err := safefile.ReadFile(keys, keyFile, keyRule)
	if err != nil {
		return nil, keyError(path, ruleText(err, keyRule))
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
	checkVkey(keys, log, vkey)
	return signer, nil
}

// checkVkey writes the public key file again if it is missing. If the file
// exists, checkVkey reads it with the type and size rule of the key file. It
// does not check the owner and the mode. It warns when the text differs from
// vkey. The warnings have fixed text and never have file bytes.
func checkVkey(keys *os.Root, log *slog.Logger, vkey string) {
	const (
		cannotCheck = "checkpoint public key file cannot be checked; the log has the correct key"
		differs     = "checkpoint public key file differs from the key; the log has the correct key"
	)
	b, err := safefile.ReadFile(keys, vkeyFile, vkeyRule)
	switch {
	case missing(err):
		err = writeNew(keys, vkeyFile, vkey+"\n")
		if err == nil {
			err = syncDir(keys, ".")
		}
		if err != nil {
			log.Warn("checkpoint public key file cannot be written")
		}
	case err != nil:
		log.Warn(cannotCheck)
	case strings.TrimSpace(string(b)) != vkey:
		log.Warn(differs)
	}
	clear(b)
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

// errnoOf returns the system error of a *fs.PathError. The error text then has
// no second path.
func errnoOf(err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}

// mustBeAbsent returns nil if nothing is at name. An entry gives the rule
// error. An Lstat error that is not "not exist" gives its own rule and keeps
// the system error as the cause.
func mustBeAbsent(root *os.Root, path, name, what string) error {
	_, err := root.Lstat(name)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil
	case err == nil:
		return keyError(path, what+" must not exist on the first start")
	}
	return fmt.Errorf("checkpoint key %s: %s cannot be examined: %w", path, what, errnoOf(err))
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
	// An entry at the public key path is an error. The write must not follow it.
	if err := mustBeAbsent(root, path, vkeyName, "public key file"); err != nil {
		return nil, err
	}
	if err := mustBeAbsent(root, path, stateName, "signer state"); err != nil {
		return nil, err
	}
	// The refusals come first. A refused start leaves no keys directory.
	if err := root.MkdirAll(keysDir, 0o700); err != nil {
		return nil, fmt.Errorf("checkpoint key %s: cannot make the keys directory: %w", path, errnoOf(err))
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
	// The signer state of a new key is a signed note of the empty tree. Without
	// it, the checkpointer would find a key with no state, and that is a fault.
	// emptyRoot is the value that Log.RootAt(0) gives.
	msg, err := SignCheckpoint(signer, 0, emptyRoot)
	if err == nil {
		err = writeState(root, msg)
	}
	if err != nil {
		return nil, fmt.Errorf("checkpoint key %s: cannot write the signer state: %w", path, err)
	}
	log.Info("checkpoint signing key made", "name", origin, "vkey", vkey)
	return signer, nil
}

// beforeLink is a test hook. Production code leaves it nil. A test sets it to
// run after writeNew has synced the temporary file and before the link. An
// error from the hook stops writeNew there.
var beforeLink func() error

// writeNew makes a new file with mode 0600. It writes a temporary file and
// syncs it. Then it links the final name to the temporary file and removes the
// temporary name. A crash leaves either no final name or a complete file.
// link(2) fails if the final name exists, so the call never replaces an entry.
// Remove deletes a symlink at the temporary name and not its target. A
// temporary file that an earlier crash left goes away first.
func writeNew(root *os.Root, name, text string) error {
	tmp := name + ".tmp"
	if err := root.Remove(tmp); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	f, err := root.OpenFile(tmp, createFlags, 0o600)
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
	if err == nil && beforeLink != nil {
		err = beforeLink()
	}
	if err == nil {
		err = root.Link(tmp, name)
	}
	if rerr := root.Remove(tmp); err == nil {
		err = rerr
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
