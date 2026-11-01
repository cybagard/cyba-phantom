// Command bundle-sign makes and signs a bundle for the vendor (SEC-24).
//
// Usage:
//
//	bundle-sign keygen <key_id> <key-file>
//	bundle-sign pack <dir> <out.cbnd>
//	bundle-sign sign <key_id> <key-file> <archive> <out.sig>
//	bundle-sign cosign <key_id> <key-file> <archive> <sig-file> <out.sig>
//	bundle-sign seal <install.pub> <version> <key_id> <out-file>
//	bundle-sign verify <trust-file> <archive> <sig-file>
//
// keygen makes a private key file with mode 0600. The file holds one line:
// "<key_id> <base64 seed>" and a newline. keygen never writes over a file. It
// prints the public key line "<key_id> <base64>" first, then it makes the key
// file. That line is one line of a trust file. keygen never prints the private
// key. If keygen cannot print the line, it makes no key file. For its stdout,
// keygen refuses only the null device. It cannot detect another stdout that
// drops the line. A line printed before a failure is not valid. When keygen
// exits 1, the vendor discards the printed line.
//
// pack writes the files below dir as a gzip tar archive with USTAR headers
// only. dir must have a regular file manifest.json at its top level. If a name
// does not fit USTAR, pack gives an error and makes no output file.
//
// sign reads the archive one time and writes the signature line. It refuses a
// key_id that is not the key ID in the key file. It reads a key file only when
// the file is regular, belongs to the effective user, and has one link. The
// key file must have no group or other bit. keygen and sign check the
// directories of the key file. Each must belong to the effective user or root.
// Each must have no group or other write bit. keygen and sign make the key
// path absolute and clean it as text first. So "lnk/.." names the directory
// that holds lnk, and a trailing "/" has no effect.
//
// cosign adds the second line of a transition bundle. sig-file must hold
// exactly one valid line, and key_id must not be the key ID of that line.
// cosign makes the new line like sign, with the same key file rules. It writes
// the old line and the new line to out.sig.
//
// seal makes the file secrets/token.key for a proprietary bundle. install.pub
// is the public key file of the sensor: canonical base64 of 32 bytes and a
// newline. version and key_id are the values of the manifest. The seed is made
// in bundle.SealSeed. The tool never holds it and never prints it. A seal for
// one version or key ID does not open in a bundle of another.
//
// verify calls bundle.CheckSigned with the keys of the trust file, the check
// of the loader. A transition bundle needs the line of a key of the trust file
// and the line of its new key. Another bundle needs a valid line of its
// manifest key ID. verify prints the key IDs that verified.
//
// After a failed write or file sync, the tool tries to cut the output file to
// size 0. After a failed close, or a failed open, sync or close of the
// directory, the file stays with its data. The tool does not remove a file by
// name. pack and sign do not check the directory of their output file. Use a
// directory that only you can write. If not, another user can replace a name.
//
// Every error text is fixed. Exit codes: 0 success, 1 failure, 2 usage.
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/cybagard/cyba-phantom/internal/bundle"
	"github.com/cybagard/cyba-phantom/internal/safefile"
)

// maxFile is the cap of a bundle file. maxSig is the cap of a signature file.
// maxSmall is the cap of the other files.
const (
	maxFile  = 8 << 20
	maxSig   = 1 << 10
	maxSmall = 4 << 10
)

var (
	errUsage = errors.New(`bundle-sign: usage:
  bundle-sign keygen <key_id> <key-file>
  bundle-sign pack <dir> <out.cbnd>
  bundle-sign sign <key_id> <key-file> <archive> <out.sig>
  bundle-sign cosign <key_id> <key-file> <archive> <sig-file> <out.sig>
  bundle-sign seal <install.pub> <version> <key_id> <out-file>
  bundle-sign verify <trust-file> <archive> <sig-file>`)
	errKeyID  = errors.New("bundle-sign: key ID is not valid")
	errSig    = errors.New("bundle-sign: signature file is not valid")
	errSeal   = errors.New("bundle-sign: version, key ID or install key is not valid")
	errKey    = errors.New("bundle-sign: key file is not usable")
	errRead   = errors.New("bundle-sign: cannot read an input file")
	errWrite  = errors.New("bundle-sign: cannot write the output file")
	errTrust  = errors.New("bundle-sign: trust file is not valid")
	errVerify = errors.New("bundle-sign: bad_sig")
	errName   = errors.New("bundle-sign: a name does not fit the ustar form")
	errPack   = errors.New("bundle-sign: directory cannot be packed")
)

var b64 = base64.StdEncoding

// main asks for SIGPIPE signals. Then a write to a broken pipe on stdout or
// stderr fails with EPIPE. The program does not exit with the signal.
func main() {
	signal.Notify(make(chan os.Signal, 1), syscall.SIGPIPE)
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	cmds := map[string]struct {
		n  int
		do func(a []string, out io.Writer) error
	}{"keygen": {2, keygen}, "pack": {2, pack}, "sign": {4, sign},
		"cosign": {5, cosign}, "seal": {4, seal}, "verify": {3, verify}}
	err := errUsage
	if len(args) > 0 {
		if c, ok := cmds[args[0]]; ok && len(args) == c.n+1 {
			err = c.do(args[1:], stdout)
		}
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		if err == errUsage {
			return 2
		}
		return 1
	}
	return 0
}

// readFile reads the regular file at path, with at most limit bytes. A key file
// must also belong to the effective user, have no group or other bit, and have
// one link. A failure gives fail.
func readFile(path string, limit int64, key bool, fail error) ([]byte, error) {
	r := safefile.Rule{Type: safefile.Regular, Owner: safefile.OwnerAny, MaxSize: limit}
	if key {
		r.Owner, r.Forbid, r.OneLink = safefile.OwnerSelf, 0o077, true
	}
	abs, _ := filepath.Abs(path)
	f, fi, err := safefile.OpenPath(abs, r)
	if err != nil {
		return nil, fail
	}
	defer f.Close()
	if b, err := safefile.ReadAll(f, fi, r); err == nil {
		return b, nil
	}
	return nil, fail
}

// Tests replace these write and sync calls to make a failure.
var (
	writeTo = (*os.File).Write
	syncOne = (*os.File).Sync
	syncDir = (*os.File).Sync
)

// writeNew makes the file at path with mode perm and writes b. It never
// overwrites a file. It syncs the file and then its directory. It never
// removes a file by name. If the write or the file sync fails, it tries to
// truncate the open file to size 0. If the truncate fails, the partial data
// stays. writeNew does not check the directory of the path. The caller must
// use a directory that only the user can write.
func writeNew(path string, b []byte, perm fs.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return errWrite
	}
	if _, err = writeTo(f, b); err == nil {
		err = syncOne(f)
	}
	if err != nil {
		_ = f.Truncate(0)
		_ = f.Close()
		return errWrite
	}
	if f.Close() != nil {
		return errWrite
	}
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return errWrite
	}
	err = syncDir(d)
	if closeErr := d.Close(); err != nil || closeErr != nil {
		return errWrite
	}
	return nil
}

var keyDirRule = safefile.Rule{Type: safefile.Dir, Owner: safefile.OwnerSelfOrRoot, Forbid: 0o022}

// checkKeyDir checks the directory of the key file and all its parents. A
// failure gives errKey. The key file can be absent, so the check of the
// directory itself uses OpenPath.
func checkKeyDir(path string) error {
	abs, _ := filepath.Abs(path)
	dir := filepath.Dir(abs)
	if safefile.CheckPathParents(dir, keyDirRule) != nil {
		return errKey
	}
	r := keyDirRule
	r.FollowEnd = true
	f, _, err := safefile.OpenPath(dir, r)
	if err != nil {
		return errKey
	}
	_ = f.Close()
	return nil
}

// isNull is true when out is the null device. The Go runtime opens it on a
// closed stdout.
func isNull(out io.Writer) bool {
	f, ok := out.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	null, nullErr := os.Stat(os.DevNull)
	return err == nil && nullErr == nil && os.SameFile(fi, null)
}

// keyLine makes the public key line. bundle.ParseKeyLine checks the key ID.
func keyLine(keyID string, pub ed25519.PublicKey) (string, error) {
	line := keyID + " " + b64.EncodeToString(pub)
	if _, _, ok := bundle.ParseKeyLine(line); !ok {
		return "", errKeyID
	}
	return line, nil
}

func keygen(a []string, out io.Writer) error {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	line, err := keyLine(a[0], pub)
	if err != nil {
		return err
	}
	// keygen uses one absolute path for the check and the write.
	path, _ := filepath.Abs(a[1])
	if err := checkKeyDir(path); err != nil {
		return err
	}
	if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) || isNull(out) {
		return errWrite
	}
	if err := printLine(out, line); err != nil {
		return err
	}
	return writeNew(path, []byte(a[0]+" "+b64.EncodeToString(priv.Seed())+"\n"), 0o600)
}

// printLine writes the text and a newline to out. A failure gives errWrite.
func printLine(out io.Writer, text ...any) error {
	if _, err := fmt.Fprintln(out, text...); err != nil {
		return errWrite
	}
	return nil
}

// signLine makes one signature line. The key file holds the key ID, one
// space, the canonical base64 text of a 32-byte seed, and a newline. The key
// ID in the file must be keyID.
func signLine(keyID, keyPath, archivePath string) (string, error) {
	if err := checkKeyDir(keyPath); err != nil {
		return "", err
	}
	b, err := readFile(keyPath, maxSmall, true, errKey)
	if err != nil {
		return "", err
	}
	text, ok := strings.CutSuffix(string(b), "\n")
	id, enc, found := strings.Cut(text, " ")
	seed, err := b64.DecodeString(enc)
	if !ok || !found || err != nil || len(seed) != ed25519.SeedSize || b64.EncodeToString(seed) != enc {
		return "", errKey
	}
	if id != keyID {
		return "", errKeyID
	}
	priv := ed25519.NewKeyFromSeed(seed)
	if _, err := keyLine(keyID, priv.Public().(ed25519.PublicKey)); err != nil {
		return "", err
	}
	archive, err := readFile(archivePath, maxFile, false, errRead)
	if err != nil {
		return "", err
	}
	return keyID + " " + b64.EncodeToString(ed25519.Sign(priv, bundle.SigMessage(archive))) + "\n", nil
}

func sign(a []string, _ io.Writer) error {
	line, err := signLine(a[0], a[1], a[2])
	if err == nil {
		err = writeNew(a[3], []byte(line), 0o644)
	}
	return err
}

func cosign(a []string, _ io.Writer) error {
	prev, err := readFile(a[3], maxSig, false, errRead)
	if err != nil {
		return err
	}
	ids, ok := bundle.SigKeyIDs(prev)
	if !ok || len(ids) != 1 {
		return errSig
	}
	if ids[0] == a[0] {
		return errKeyID
	}
	line, err := signLine(a[0], a[1], a[2])
	if err != nil {
		return err
	}
	return writeNew(a[4], append(prev, line...), 0o644)
}

// seal reads the install public key. The text is the canonical base64 of 32
// bytes and a newline. bundle.SealSeed makes the seed and seals it, so this
// tool never holds the seed.
func seal(a []string, _ io.Writer) error {
	text, err := readFile(a[0], maxSmall, false, errRead)
	if err != nil {
		return err
	}
	enc, ok := strings.CutSuffix(string(text), "\n")
	pub, err := b64.DecodeString(enc)
	if !ok || err != nil || len(pub) != 32 || b64.EncodeToString(pub) != enc {
		return errSeal
	}
	sealed, err := bundle.SealSeed(pub, a[1], a[2])
	if err != nil {
		return errSeal
	}
	return writeNew(a[3], sealed, 0o644)
}

func verify(a []string, out io.Writer) error {
	text, err := readFile(a[0], maxSmall, false, errRead)
	if err != nil {
		return err
	}
	var trust bundle.TrustSet
	rows, ok := strings.CutSuffix(string(text), "\n")
	for _, row := range strings.Split(rows, "\n") {
		id, key, valid := bundle.ParseKeyLine(row)
		ok = ok && valid
		trust = append(trust, bundle.TrustKey{KeyID: id, PublicKey: key, Class: bundle.ClassProprietary})
	}
	if !ok || trust.Check(nil) != nil {
		return errTrust
	}
	archive, err := readFile(a[1], maxFile, false, errRead)
	if err != nil {
		return err
	}
	sig, err := readFile(a[2], maxSig, false, errRead)
	if err != nil {
		return err
	}
	ids, err := bundle.CheckSigned(archive, sig, trust)
	if err != nil {
		return errVerify
	}
	return printLine(out, "valid:", strings.Join(ids, " "))
}

// pack builds the whole archive in memory. An error before writeNew leaves no
// output file. If writeNew fails after it made the file, the file stays at the
// path. The package comment says with what size.
func pack(a []string, _ io.Writer) error {
	root, _ := filepath.Abs(a[0])
	if fi, err := os.Lstat(filepath.Join(root, "manifest.json")); err != nil || !fi.Mode().IsRegular() {
		return errPack
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || (!d.IsDir() && !d.Type().IsRegular()) {
			return errPack
		}
		if d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		data, err := readFile(p, bundle.MaxEntryBytes, false, errPack)
		if err != nil {
			return err
		}
		hdr := &tar.Header{Name: filepath.ToSlash(rel), Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(data)), Format: tar.FormatUSTAR}
		if tw.WriteHeader(hdr) != nil {
			return errName
		}
		if _, err := tw.Write(data); err != nil {
			return errPack
		}
		return nil
	})
	if err != nil {
		return err
	}
	if tw.Close() != nil || zw.Close() != nil || buf.Len() > maxFile {
		return errPack
	}
	if _, err := bundle.ReadArchive(buf.Bytes()); err != nil {
		return errPack
	}
	return writeNew(a[1], buf.Bytes(), 0o644)
}
