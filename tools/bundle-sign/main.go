// Command bundle-sign makes and signs a bundle for the vendor (SEC-24).
//
// Usage:
//
//	bundle-sign keygen <key_id> <key-file>
//	bundle-sign pack <dir> <out.cbnd>
//	bundle-sign sign <key_id> <key-file> <archive> <out.sig>
//	bundle-sign verify <trust-file> <archive> <sig-file>
//
// keygen makes a private key file with mode 0600. It never writes over a
// file. It prints the public key line "<key_id> <base64>". That line is one
// line of a trust file. keygen never prints the private key. If keygen cannot
// print the line, it removes the key file. pack writes the files below dir as
// a gzip tar archive with USTAR headers only. If a name does not fit USTAR,
// pack gives an error and makes no output file. sign reads the archive one
// time and writes the signature line. It reads a key file only when the file
// is regular, belongs to the effective user, and has one link. The key file
// must have no group or other bit. verify calls bundle.VerifySig with the
// keys of the trust file. It does not check the manifest key ID. It prints the
// key IDs of the valid lines.
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
  bundle-sign verify <trust-file> <archive> <sig-file>`)
	errKeyID  = errors.New("bundle-sign: key ID is not valid")
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
	}{"keygen": {2, keygen}, "pack": {2, pack}, "sign": {4, sign}, "verify": {3, verify}}
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

// writeNew makes the file at path with mode perm and writes b. It never
// overwrites a file. If the write, the sync or the close fails, it removes the
// file that it made.
func writeNew(path string, b []byte, perm fs.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return errWrite
	}
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(path)
		return errWrite
	}
	return nil
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
	if err == nil {
		err = writeNew(a[1], []byte(b64.EncodeToString(priv.Seed())+"\n"), 0o600)
	}
	if err == nil {
		if err = printLine(out, line); err != nil {
			_ = os.Remove(a[1])
		}
	}
	return err
}

// printLine writes the text and a newline to out. A failure gives errWrite.
func printLine(out io.Writer, text ...any) error {
	if _, err := fmt.Fprintln(out, text...); err != nil {
		return errWrite
	}
	return nil
}

// signLine makes one signature line. The key file holds the base64 text of a
// 32-byte seed and a newline.
func signLine(keyID, keyPath, archivePath string) (string, error) {
	b, err := readFile(keyPath, maxSmall, true, errKey)
	if err != nil {
		return "", err
	}
	text, ok := strings.CutSuffix(string(b), "\n")
	seed, err := b64.DecodeString(text)
	if !ok || err != nil || len(seed) != ed25519.SeedSize || b64.EncodeToString(seed) != text {
		return "", errKey
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
	ids, err := bundle.VerifySig(archive, sig, trust)
	if err != nil {
		return errVerify
	}
	return printLine(out, "valid:", strings.Join(ids, " "))
}

// pack builds the whole archive in memory. writeNew removes a partial output
// file. So a failure leaves no output file.
func pack(a []string, _ io.Writer) error {
	root, _ := filepath.Abs(a[0])
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
