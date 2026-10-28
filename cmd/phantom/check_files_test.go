package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/cybagard/cyba-phantom/internal/safefile"
	"github.com/cybagard/cyba-phantom/internal/safefile/safefiletest"
)

// fixtureDir makes a private directory below the package directory.
// The file rules refuse a parent with a group or other write bit.
// The system temporary directory can have mode 1777.
func fixtureDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp(pkgDir, "tmp-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

// writeFixture writes an empty file with exactly mode and returns its path.
func writeFixture(t *testing.T, dir, name string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestTS27_CheckFileRules checks that --check applies the file rules to
// acme.ca_root, cert_file and key_file. A refusal exits 1 and the stderr
// names the key and holds the fixed text of the rule. A good file passes
// (SEC-31, T-S-27).
func TestTS27_CheckFileRules(t *testing.T) {
	body := validBody(t)
	const caLine = "  ca: \"https://ca.example.invalid\"\n"
	withRoot := func(p string) string {
		return strings.Replace(body, caLine, caLine+"  ca_root: "+strconv.Quote(p)+"\n", 1)
	}
	withCert := func(cert, key string) string {
		return body + "tls:\n  certs: [{name: a.host.zz, cert_file: " + strconv.Quote(cert) + ", key_file: " + strconv.Quote(key) + "}]\n"
	}
	d := fixtureDir(t)
	goodCert, goodKey := writeFixture(t, d, "good.pem", 0o644), writeFixture(t, d, "good.key", 0o600)
	big := func(name string, size int, mode os.FileMode) string {
		p := writeFixture(t, d, name, mode)
		if err := os.Truncate(p, int64(size)); err != nil {
			t.Fatal(err)
		}
		return p
	}
	fifo := filepath.Join(d, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	open := fixtureDir(t)
	if err := os.Chmod(open, 0o777); err != nil {
		t.Fatal(err)
	}
	inOpen := writeFixture(t, open, "in-open", 0o600)
	const root, cert, key = "acme.ca_root", "tls.certs[0].cert_file", "tls.certs[0].key_file"
	rows := []struct{ name, file, key, detail string }{
		{"root file 0644", withRoot(writeFixture(t, d, "r0644", 0o644)), "", ""},
		{"root file 65536 bytes", withRoot(big("r-max", 65536, 0o600)), "", ""},
		{"cert file 0644", withCert(goodCert, goodKey), "", ""},
		{"root file other write", withRoot(writeFixture(t, d, "r-ow", 0o602)), root, "the CA root file is writable by other"},
		{"root file group write", withRoot(writeFixture(t, d, "r-gw", 0o620)), root, "the CA root file is writable by group"},
		{"root file 65537 bytes", withRoot(big("r-over", 65537, 0o600)), root, "the CA root file is larger than 64 KiB"},
		{"root file FIFO", withRoot(fifo), root, "the CA root file is not a regular file"},
		{"root file below a 0777 directory", withRoot(inOpen), root, "a directory of the CA root file is writable by group or other, or its owner is not root or the sensor user"},
		{"root file missing", withRoot(filepath.Join(d, "missing")), root, "the CA root file cannot be resolved"},
		{"cert file other write", withCert(writeFixture(t, d, "c-ow", 0o602), goodKey), cert, "the certificate file is writable by other"},
		{"cert file group write", withCert(writeFixture(t, d, "c-gw", 0o620), goodKey), cert, "the certificate file is writable by group"},
		{"cert file 65537 bytes", withCert(big("c-over", 65537, 0o600), goodKey), cert, "the certificate file is larger than 64 KiB"},
		{"cert file FIFO", withCert(fifo, goodKey), cert, "the certificate file is not a regular file"},
		{"cert file below a 0777 directory", withCert(inOpen, goodKey), cert, "a directory of the certificate file is writable by group or other, or its owner is not root or the sensor user"},
		{"key file other read", withCert(goodCert, writeFixture(t, d, "k-or", 0o644)), key, "the key file is readable by other"},
		{"key file other write", withCert(goodCert, writeFixture(t, d, "k-ow", 0o602)), key, "the key file is writable by other"},
		{"key file group write", withCert(goodCert, writeFixture(t, d, "k-gw", 0o620)), key, "the key file is writable by group"},
		{"key file 65537 bytes", withCert(goodCert, big("k-over", 65537, 0o600)), key, "the key file is larger than 64 KiB"},
		{"key file FIFO", withCert(goodCert, fifo), key, "the key file is not a regular file"},
		{"key file below a 0777 directory", withCert(goodCert, inOpen), key, "a directory of the key file is writable by group or other, or its owner is not root or the sensor user"},
	}
	// A symlink to a file of another owner. The hook makes the check see
	// the target as a file of another owner. The rows run as any user.
	// A control row has the same symlink and no hook. A row then fails only
	// by the owner rule. One hook set is active at a time. These rows do
	// not run in parallel.
	link := func(name, target string) string {
		p := filepath.Join(d, name)
		if err := os.Symlink(target, p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	rootTarget, certTarget, keyTarget := writeFixture(t, d, "r-target", 0o644), writeFixture(t, d, "c-target", 0o644), writeFixture(t, d, "k-target", 0o600)
	rootLink, certLink, keyLink := link("r-link", rootTarget), link("c-link", certTarget), link("k-link", keyTarget)
	ownerRows := []struct{ name, file, target, key, detail string }{
		{"root symlink to a file of another owner", withRoot(rootLink), rootTarget, root, "the owner of the CA root file is not root or the sensor user"},
		{"cert symlink to a file of another owner", withCert(certLink, goodKey), certTarget, cert, "the owner of the certificate file is not root or the sensor user"},
		{"key symlink to a file of another owner", withCert(goodCert, keyLink), keyTarget, key, "the owner of the key file is not root or the sensor user"},
		{"root symlink, same owner", withRoot(rootLink), "", "", ""},
		{"cert symlink, same owner", withCert(certLink, goodKey), "", "", ""},
		{"key symlink, same owner", withCert(goodCert, keyLink), "", "", ""},
	}
	check := func(t *testing.T, file, key, detail string) {
		t.Helper()
		env := []string{"CKPT_TOKEN=" + strings.Repeat("t", 32)}
		var so, se strings.Builder
		code := run([]string{"--check", writeFile(t, file)}, env, &so, &se)
		if key == "" {
			if code != 0 || se.Len() != 0 {
				t.Errorf("exit %d, stderr %q; want exit 0 and no stderr", code, se.String())
			}
			return
		}
		if code != 1 || !strings.Contains(se.String(), key+" at ") || !strings.Contains(se.String(), detail) {
			t.Errorf("exit %d, stderr %q; want exit 1, the key %q and %q", code, se.String(), key, detail)
		}
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) { check(t, r.file, r.key, r.detail) })
	}
	for _, r := range ownerRows {
		t.Run(r.name, func(t *testing.T) {
			if r.target != "" {
				fi, err := os.Stat(r.target)
				if err != nil {
					t.Fatal(err)
				}
				id, ok := safefile.Identity(fi)
				if !ok {
					t.Fatal("no identity")
				}
				safefiletest.Set(t, safefiletest.Hooks{OtherOwner: func(got safefile.FileID) bool { return got == id }})
			}
			check(t, r.file, r.key, r.detail)
		})
	}
}

// TestTS11_CheckCARoot checks that --check refuses acme.ca_root with a CA
// name such as letsencrypt, and with no acme.ca, which is letsencrypt. The
// stderr names acme.ca_root. An https acme.ca passes (SEC-31, T-S-11).
func TestTS11_CheckCARoot(t *testing.T) {
	body := validBody(t)
	root := writeFixture(t, fixtureDir(t), "root.pem", 0o644)
	const caLine = "  ca: \"https://ca.example.invalid\"\n"
	line := "  ca_root: " + strconv.Quote(root) + "\n"
	rows := []struct {
		name, file string
		refused    bool
	}{
		{"https CA", strings.Replace(body, caLine, caLine+line, 1), false},
		{"letsencrypt", strings.Replace(body, caLine, "  ca: letsencrypt\n"+line, 1), true},
		{"letsencrypt-staging", strings.Replace(body, caLine, "  ca: letsencrypt-staging\n"+line, 1), true},
		{"no acme.ca", strings.Replace(body, caLine, line, 1), true},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			var so, se strings.Builder
			code := run([]string{"--check", writeFile(t, r.file)}, []string{"CKPT_TOKEN=" + strings.Repeat("t", 32)}, &so, &se)
			switch {
			case r.refused && (code != 1 || !strings.Contains(se.String(), "acme.ca_root at ")):
				t.Errorf("exit %d, stderr %q; want exit 1 and a refusal that names acme.ca_root", code, se.String())
			case !r.refused && (code != 0 || se.Len() != 0):
				t.Errorf("exit %d, stderr %q; want exit 0 and no stderr", code, se.String())
			}
		})
	}
}
