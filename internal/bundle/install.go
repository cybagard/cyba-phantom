package bundle

import (
	"crypto/sha256"
	"errors"
	"os"

	"github.com/cybagard/cyba-phantom/internal/safefile"
)

// The suffixes of the temporary files of an install (SEC-25).
const (
	archiveTemp = ".cbnd.tmp"
	sigTemp     = ".sig.tmp"
)

// ErrInstallFault is the error of LoadFetched for a bundle that passed each
// check. Then the write of its files failed. It is not a rejection code:
// CodeOf gives false. LoadFetched writes one log line and sends no event for
// it. The error holds no path and no byte.
var ErrInstallFault = errors.New("bundle: install fault")

// beforeRename is nil, except in a test. A test sets it to see or to fail a
// rename of the install. It gets the names of the rename.
var beforeRename func(from, to string) error

func renameFile(root *os.Root, from, to string) error {
	if beforeRename != nil {
		if err := beforeRename(from, to); err != nil {
			return err
		}
	}
	return root.Rename(from, to)
}

// LoadFetched checks a fetched archive and its signature file. It installs
// them in the bundle directory and makes the bundle the running bundle. The
// source of the load is SourceFetch.
//
// A fetched archive with the SHA-256 of the running bundle loads nothing. It
// gives nil and no error. It does not wait for the swap gap, and it writes no
// file and no event. An accept gives the new bundle and no error. A rejection
// gives nil and its error. So a caller tells "unchanged" (nil, nil) from
// "loaded" (a bundle) and from a failure (an error).
//
// LoadFetched does the directory-part check and the state-file-name check of
// Load. Then it does each check of Load on the bytes in memory. It reads no
// bundle file. A rejection changes no file and not the running bundle. It
// gives one bundle_rejected event.
//
// After an accept, it writes <name>.cbnd.tmp and <name>.sig.tmp. The rules are
// those of the temporary file of the state write. Then it renames the archive,
// then the signature file, and calls Sync on the directory. Then it writes the
// version state and swaps. A new transition bundle writes its record after the
// two files and before the version state. A failed record write or chain check
// removes the record and keeps the files. The next start loads that pair.
//
// A failed write gives ErrInstallFault and no event. It leaves the running
// bundle and the version state. A failure before the first rename removes the
// two temporary files. A failure at or after the first rename keeps the files.
// The roll-forward of the next start can use them.
func (l *Loader) LoadFetched(archive, sig []byte) (*Bundle, error) {
	if run := l.cur.Load(); run != nil && run.sum == sha256.Sum256(archive) {
		return nil, nil
	}
	l.lock(SourceFetch)
	defer loadMu.Unlock()
	var sum digest
	b, err := l.loadFetched(archive, sig, &sum)
	l.report(SourceFetch, sum, b, err)
	return b, err
}

// loadFetched is LoadFetched without the lock and without the event.
func (l *Loader) loadFetched(archive, sig []byte, rd *digest) (*Bundle, error) {
	dir, name, c, closeDir, err := l.prepare(false)
	if err != nil {
		return nil, err
	}
	defer closeDir()
	// Load refuses a file over these caps at the next start. So a fetch refuses
	// bytes over them, before any check and before any write.
	if len(archive) > MaxBundleBytes || len(sig) > MaxSigBytes {
		return nil, ErrArchiveInvalid
	}
	return l.loadBytes(dir, c, archive, sig, false, rd, func() error { return installPair(dir, name, archive, sig) })
}

// installPair writes the two temporary files, and renames the archive and then
// the signature file. A failure before the first rename removes the temporary
// files.
func installPair(root *os.Root, name string, archive, sig []byte) error {
	for _, f := range []struct {
		tmp  string
		data []byte
	}{{name + archiveTemp, archive}, {name + sigTemp, sig}} {
		if err := writeTemp(root, f.tmp, f.data); err != nil {
			removeInstallTemps(root, name)
			return err
		}
	}
	if err := renameFile(root, name+archiveTemp, name+".cbnd"); err != nil {
		return err
	}
	if err := renameFile(root, name+sigTemp, name+".sig"); err != nil {
		return err
	}
	return syncDir(root)
}

// removeInstallTemps removes the temporary files of an install.
func removeInstallTemps(root *os.Root, name string) {
	_ = root.Remove(name + archiveTemp)
	_ = root.Remove(name + sigTemp)
}

// rollForward is the second try of a start load whose pair gave bad_sig. A
// crash between the two renames of an install leaves the new archive, the old
// signature file and <name>.sig.tmp. rollForward loads the archive with that
// file, with each check. The file must pass the signature file rule.
// On an accept it renames the file to <name>.sig and calls Sync on the
// directory. For a rejection code, it returns the first error. For a state
// fault or an install fault, it returns that fault.
func (l *Loader) rollForward(dir *os.Root, name string, c chain, archive []byte, rd *digest, first error) (*Bundle, error) {
	sig, err := safefile.ReadFile(dir, name+sigTemp, fileRule(MaxSigBytes))
	if err != nil {
		return nil, first
	}
	promote := func() error {
		if err := renameFile(dir, name+sigTemp, name+".sig"); err != nil {
			return err
		}
		return syncDir(dir)
	}
	b, err := l.loadBytes(dir, c, archive, sig, true, rd, promote)
	if err != nil {
		if _, ok := CodeOf(err); !ok {
			return nil, err
		}
		return nil, first
	}
	return b, nil
}
