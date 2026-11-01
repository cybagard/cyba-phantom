package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/cybagard/cyba-phantom/internal/config"
	"github.com/cybagard/cyba-phantom/internal/listener"
	"github.com/cybagard/cyba-phantom/internal/safefile"
	"github.com/cybagard/cyba-phantom/internal/safefile/safefiletest"
)

// The test root and the test keys are made once. pkiRootKey, pkiLeafKey and
// pkiOtherKey are ECDSA P-256.
// pkiP224Key is ECDSA P-224, a key type that a static leaf may not have.
var (
	pkiOnce                             sync.Once
	pkiRoot                             *x509.Certificate
	pkiRootKey, pkiLeafKey, pkiOtherKey *ecdsa.PrivateKey
	pkiP224Key                          *ecdsa.PrivateKey
)

func pkiInit() {
	pkiOnce.Do(func() {
		gen := func(c elliptic.Curve) *ecdsa.PrivateKey {
			k, err := ecdsa.GenerateKey(c, rand.Reader)
			if err != nil {
				panic(err)
			}
			return k
		}
		pkiRootKey, pkiLeafKey, pkiOtherKey = gen(elliptic.P256()), gen(elliptic.P256()), gen(elliptic.P256())
		pkiP224Key = gen(elliptic.P224())
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test root"},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
			IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &pkiRootKey.PublicKey, pkiRootKey)
		if err == nil {
			pkiRoot, err = x509.ParseCertificate(der)
		}
		if err != nil {
			panic(err)
		}
	})
}

func certBlock(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// rootPEM is the PEM of the test root, a CA certificate.
func rootPEM(t *testing.T) []byte {
	t.Helper()
	pkiInit()
	return certBlock(pkiRoot.Raw)
}

// leafPEM is a leaf for name with the public key pub.
// It is valid from now+from to now+to.
func leafPEM(t *testing.T, name string, from, to time.Duration, pub any) []byte {
	t.Helper()
	pkiInit()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: time.Now().Add(from), NotAfter: time.Now().Add(to), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, pkiRoot, pub, pkiRootKey)
	if err != nil {
		t.Fatal(err)
	}
	return certBlock(der)
}

// certPEM is a leaf of pkiLeafKey for name.
func certPEM(t *testing.T, name string, from, to time.Duration) []byte {
	pkiInit()
	return leafPEM(t, name, from, to, &pkiLeafKey.PublicKey)
}

// goodCertPEM is a leaf for name that is valid for 90 days.
func goodCertPEM(t *testing.T, name string) []byte {
	return certPEM(t, name, -time.Hour, 90*24*time.Hour)
}

func keyPEM(t *testing.T, k *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// leafKeyPEM is the key file that matches the leaf of certPEM.
func leafKeyPEM(t *testing.T) []byte {
	pkiInit()
	return keyPEM(t, pkiLeafKey)
}

// writePEM writes data to a file with exactly mode and returns its path.
func writePEM(t *testing.T, dir, name string, data []byte, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

// fixtureDir makes a private directory below the package directory.
// The file rules refuse a parent with a group or other write bit.
// The system temporary directory can have mode 1777.
func fixtureDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp(pkgDir, "_tmp-")
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
	goodCert, goodKey := writePEM(t, d, "good.pem", goodCertPEM(t, "a.host.zz"), 0o644), writePEM(t, d, "good.key", leafKeyPEM(t), 0o600)
	// A big file is a root file with space bytes after the block.
	big := func(name string, size int, mode os.FileMode) string {
		return writePEM(t, d, name, append(rootPEM(t), bytes.Repeat([]byte(" "), size-len(rootPEM(t)))...), mode)
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
		{"root file 0644", withRoot(writePEM(t, d, "r0644", rootPEM(t), 0o644)), "", ""},
		{"root file 65536 bytes", withRoot(big("r-max", 65536, 0o600)), "", ""},
		{"cert file 0644", withCert(goodCert, goodKey), "", ""},
		{"root file other write", withRoot(writeFixture(t, d, "r-ow", 0o602)), root, "the CA root file is writable by other"},
		{"root file group write", withRoot(writeFixture(t, d, "r-gw", 0o620)), root, "the CA root file is writable by group"},
		{"root file 65537 bytes", withRoot(big("r-over", 65537, 0o600)), root, "the CA root file is larger than 64 KiB"},
		{"root file FIFO", withRoot(fifo), root, "the CA root file is not a regular file"},
		{"root file below a 0777 directory", withRoot(inOpen), root, "a directory of the CA root file is writable by group or other, or has the wrong owner"},
		{"root file missing", withRoot(filepath.Join(d, "missing")), root, "the CA root file cannot be resolved"},
		{"cert file other write", withCert(writeFixture(t, d, "c-ow", 0o602), goodKey), cert, "the certificate file is writable by other"},
		{"cert file group write", withCert(writeFixture(t, d, "c-gw", 0o620), goodKey), cert, "the certificate file is writable by group"},
		{"cert file 65537 bytes", withCert(big("c-over", 65537, 0o600), goodKey), cert, "the certificate file is larger than 64 KiB"},
		{"cert file FIFO", withCert(fifo, goodKey), cert, "the certificate file is not a regular file"},
		{"cert file below a 0777 directory", withCert(inOpen, goodKey), cert, "a directory of the certificate file is writable by group or other, or has the wrong owner"},
		{"key file other read", withCert(goodCert, writeFixture(t, d, "k-or", 0o644)), key, "the key file is readable by other"},
		{"key file other write", withCert(goodCert, writeFixture(t, d, "k-ow", 0o602)), key, "the key file is writable by other"},
		{"key file group write", withCert(goodCert, writeFixture(t, d, "k-gw", 0o620)), key, "the key file is writable by group"},
		{"key file 65537 bytes", withCert(goodCert, big("k-over", 65537, 0o600)), key, "the key file is larger than 64 KiB"},
		{"key file FIFO", withCert(goodCert, fifo), key, "the key file is not a regular file"},
		{"key file below a 0777 directory", withCert(goodCert, inOpen), key, "a directory of the key file is writable by group or other, or has the wrong owner"},
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
	rootTarget, certTarget, keyTarget := writePEM(t, d, "r-target", rootPEM(t), 0o644), writePEM(t, d, "c-target", goodCertPEM(t, "a.host.zz"), 0o644), writePEM(t, d, "k-target", leafKeyPEM(t), 0o600)
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
	root := writePEM(t, fixtureDir(t), "root.pem", rootPEM(t), 0o644)
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

// contentBody returns a config text with entries in tls.certs.
// Entry i has the name "a", "b", ... plus ".host.zz".
// A root path adds acme.ca_root.
func contentBody(t *testing.T, root string, entries ...[2]string) string {
	body := validBody(t)
	if root != "" {
		const caLine = "  ca: \"https://ca.example.invalid\"\n"
		body = strings.Replace(body, caLine, caLine+"  ca_root: "+strconv.Quote(root)+"\n", 1)
	}
	var items []string
	for i, e := range entries {
		items = append(items, "{name: "+string(rune('a'+i))+".host.zz, cert_file: "+strconv.Quote(e[0])+", key_file: "+strconv.Quote(e[1])+"}")
	}
	if len(items) > 0 {
		body += "tls:\n  certs: [" + strings.Join(items, ", ") + "]\n"
	}
	return body
}

// runMode runs the sensor in --check mode or in start mode.
// In start mode, serve is a stub. It returns the exit code, stdout, stderr,
// and the number of serve calls.
func runMode(t *testing.T, check bool, body string) (code int, so, se string, calls int) {
	t.Helper()
	old := serve
	t.Cleanup(func() { serve = old })
	serve = func(*config.Config, content, io.Writer, io.Writer) int { calls++; return 0 }
	args := []string{writeFile(t, body)}
	if check {
		args = append([]string{"--check"}, args...)
	}
	var o, e strings.Builder
	code = run(args, []string{"CKPT_TOKEN=" + strings.Repeat("t", 32)}, &o, &e)
	return code, o.String(), e.String(), calls
}

// TestTS27_RunPassesContent checks that run gives serve the parsed content.
// The config has acme.ca_root and one tls.certs entry. The serve stub gets
// roots and one static entry with the name of that entry (T-S-27).
func TestTS27_RunPassesContent(t *testing.T) {
	d := fixtureDir(t)
	rp := writePEM(t, d, "root.pem", rootPEM(t), 0o644)
	cp := writePEM(t, d, "c.pem", certPEM(t, staticName, -time.Hour, 90*24*time.Hour), 0o644)
	kp := writePEM(t, d, "k.key", leafKeyPEM(t), 0o600)
	var got content
	calls := 0
	old := serve
	t.Cleanup(func() { serve = old })
	serve = func(_ *config.Config, c content, _, _ io.Writer) int { got = c; calls++; return 0 }
	var o, e strings.Builder
	args := []string{writeFile(t, contentBody(t, rp, [2]string{cp, kp}))}
	if code := run(args, []string{"CKPT_TOKEN=" + strings.Repeat("t", 32)}, &o, &e); code != 0 || calls != 1 {
		t.Fatalf("exit %d, serve calls %d, stderr %q", code, calls, e.String())
	}
	if got.roots == nil {
		t.Error("serve got no roots")
	}
	if len(got.static) != 1 || got.static[0].Name != staticName {
		t.Errorf("serve got static entries %v, want one for %q", got.static, staticName)
	}
}

// TestTS27_CheckContent checks that --check and the start refuse a bad
// static or root file. The exit is 1 and the start calls no serve.
// Stderr is one line. It names the key of the file that causes the error.
// The line has no PEM line and no path. It has no byte of the marker.
// The marker is in the bad file (SEC-31, T-S-27, T-S-11).
func TestTS27_CheckContent(t *testing.T) {
	const marker = "MARKER-7f3a91"
	const keyForms = "static certificate: key does not parse; the key file has one block of type PRIVATE KEY (PKCS8), " +
		"RSA PRIVATE KEY (PKCS1) or EC PRIVATE KEY (SEC1)"
	good, key := goodCertPEM(t, "a.host.zz"), leafKeyPEM(t)
	cat := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }
	block := func(typ string) []byte { return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: []byte(marker)}) }
	certDER := func(b []byte) []byte {
		p, _ := pem.Decode(b)
		return p.Bytes
	}
	const certKey, keyKey, entry, root = "tls.certs[0].cert_file: ", "tls.certs[0].key_file: ", "tls.certs[0]: ", "acme.ca_root: "
	rows := []struct {
		name            string
		cert, key, root []byte
		want            string
	}{
		{"leaf for another name", goodCertPEM(t, "c.host.zz"), key, nil, certKey + listener.ErrStaticName.Error()},
		{"expired leaf", certPEM(t, "a.host.zz", -48*time.Hour, -time.Hour), key, nil, certKey + listener.ErrStaticExpired.Error()},
		{"leaf not valid yet", certPEM(t, "a.host.zz", time.Hour, 48*time.Hour), key, nil, certKey + listener.ErrStaticNotYet.Error()},
		{"CA certificate as leaf", rootPEM(t), key, nil, certKey + listener.ErrStaticCA.Error()},
		{"cert block that does not parse", block("CERTIFICATE"), key, nil, certKey + listener.ErrStaticCert.Error()},
		{"leaf with a P-224 key", leafPEM(t, "a.host.zz", -time.Hour, time.Hour, &pkiP224Key.PublicKey), key, nil, certKey + listener.ErrStaticKeyKind.Error()},
		{"cert block with a header", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"}, Bytes: certDER(good)}), key, nil, entry + listener.ErrStaticHeader.Error()},
		{"expired leaf and key that does not parse", certPEM(t, "a.host.zz", -48*time.Hour, -time.Hour), block("PRIVATE KEY"), nil, keyKey + keyForms},
		{"key of another leaf", good, keyPEM(t, pkiOtherKey), nil, entry + listener.ErrStaticMismatch.Error()},
		{"key block that does not parse", good, block("PRIVATE KEY"), nil, keyKey + keyForms},
		{"cert file with a PRIVATE KEY block", cat(good, key), key, nil, entry + listener.ErrStaticType.Error()},
		{"text before a block", cat([]byte(marker+"\n"), good), key, nil, entry + listener.ErrStaticText.Error()},
		{"key file with two blocks", good, cat(key, key), nil, entry + listener.ErrStaticCount.Error()},
		{"empty cert file", nil, key, nil, entry + listener.ErrStaticCount.Error()},
		{"root file with a non-CA certificate", good, key, good, root + "listener: acme: a certificate of the root file is not a CA certificate"},
		{"root file with an OTHER block", good, key, block("OTHER"), root + "listener: acme: the root file has a block that is not a certificate"},
	}
	for _, mode := range []string{"check", "start"} {
		for _, r := range rows {
			t.Run(mode+"/"+r.name, func(t *testing.T) {
				d := fixtureDir(t)
				rootPath := ""
				if r.root != nil {
					rootPath = writePEM(t, d, "root.pem", r.root, 0o644)
				}
				body := contentBody(t, rootPath, [2]string{writePEM(t, d, "c.pem", r.cert, 0o644), writePEM(t, d, "k.key", r.key, 0o600)})
				code, so, se, calls := runMode(t, mode == "check", body)
				if code != 1 || calls != 0 || so != "" || se != "phantom: "+r.want+"\n" {
					t.Errorf("exit %d, serve calls %d, stdout %q, stderr %q; want exit 1, no serve, the line %q", code, calls, so, se, r.want)
				}
				for _, bad := range []string{"-----", d, marker} {
					if strings.Contains(se, bad) {
						t.Errorf("stderr holds %q: %q", bad, se)
					}
				}
			})
		}
	}
}

// TestTS27_CheckContentGood checks that a good entry and a good root pass in
// both modes. The start calls serve one time.
func TestTS27_CheckContentGood(t *testing.T) {
	for _, mode := range []string{"check", "start"} {
		t.Run(mode, func(t *testing.T) {
			d := fixtureDir(t)
			body := contentBody(t, writePEM(t, d, "root.pem", rootPEM(t), 0o644),
				[2]string{writePEM(t, d, "c.pem", goodCertPEM(t, "a.host.zz"), 0o644), writePEM(t, d, "k.key", leafKeyPEM(t), 0o600)})
			code, so, se, calls := runMode(t, mode == "check", body)
			wantCalls, wantOut := 1, ""
			if mode == "check" {
				wantCalls, wantOut = 0, "phantom: config is valid\n"
			}
			if code != 0 || se != "" || calls != wantCalls || so != wantOut {
				t.Errorf("exit %d, stderr %q, stdout %q, serve calls %d", code, se, so, calls)
			}
		})
	}
}

// TestTS27_CheckContentReportsAll checks that the root and each failing entry
// give one line each. The order is the root, then the entries. The check does
// not stop at the first failure.
func TestTS27_CheckContentReportsAll(t *testing.T) {
	d := fixtureDir(t)
	key := leafKeyPEM(t)
	body := contentBody(t, writePEM(t, d, "root.pem", goodCertPEM(t, "a.host.zz"), 0o644),
		[2]string{writePEM(t, d, "c0.pem", certPEM(t, "a.host.zz", -48*time.Hour, -time.Hour), 0o644), writePEM(t, d, "k0.key", key, 0o600)},
		[2]string{writePEM(t, d, "c1.pem", goodCertPEM(t, "c.host.zz"), 0o644), writePEM(t, d, "k1.key", key, 0o600)})
	code, _, se, _ := runMode(t, true, body)
	want := "phantom: acme.ca_root: listener: acme: a certificate of the root file is not a CA certificate\n" +
		"phantom: tls.certs[0].cert_file: " + listener.ErrStaticExpired.Error() + "\n" +
		"phantom: tls.certs[1].cert_file: " + listener.ErrStaticName.Error() + "\n"
	if code != 1 || se != want {
		t.Errorf("exit %d, stderr %q, want exit 1 and %q", code, se, want)
	}
}

// TestTS27_CheckContentReadError checks the line for a file that cannot be
// read. Each row loads a good config, changes the files, and then runs
// checkContent. The file rules apply again to the changed file. A refused
// file gives a line with the key and no path (SEC-31, T-S-27).
func TestTS27_CheckContentReadError(t *testing.T) {
	const root, cert, key = "acme.ca_root", "tls.certs[0].cert_file", "tls.certs[0].key_file"
	rows := []struct {
		name string
		keys []string
		do   func(t *testing.T, d, root, cert, key string)
	}{
		{"files removed", []string{root, cert, key}, func(t *testing.T, d, r, c, k string) {
			must(t, os.Remove(r), os.Remove(c), os.Remove(k))
		}},
		{"key read by other", []string{key}, func(t *testing.T, d, r, c, k string) { must(t, os.Chmod(k, 0o604)) }},
		{"key read by group", nil, func(t *testing.T, d, r, c, k string) { must(t, os.Chmod(k, 0o640)) }},
		{"cert written by group", []string{cert}, func(t *testing.T, d, r, c, k string) { must(t, os.Chmod(c, 0o620)) }},
		{"root written by other", []string{root}, func(t *testing.T, d, r, c, k string) { must(t, os.Chmod(r, 0o602)) }},
		{"parent directory written by group", []string{root, cert, key}, func(t *testing.T, d, r, c, k string) { must(t, os.Chmod(d, 0o770)) }},
		{"parent directory of another owner", []string{root, cert, key}, func(t *testing.T, d, r, c, k string) { otherOwner(t, d) }},
		{"root over 64 KiB", []string{root}, func(t *testing.T, d, r, c, k string) {
			writePEM(t, d, filepath.Base(r), append(rootPEM(t), bytes.Repeat([]byte(" "), 65537-len(rootPEM(t)))...), 0o644)
		}},
		{"cert replaced by a FIFO", []string{cert}, func(t *testing.T, d, r, c, k string) {
			must(t, os.Remove(c), syscall.Mkfifo(c, 0o644))
		}},
		{"key replaced by a link to a file of another owner", []string{key}, func(t *testing.T, d, r, c, k string) {
			o := writePEM(t, d, "other.key", leafKeyPEM(t), 0o600)
			otherOwner(t, o)
			must(t, os.Remove(k), os.Symlink(o, k))
		}},
		{"cert replaced by a link to a file of another owner", []string{cert}, func(t *testing.T, d, r, c, k string) {
			o := writePEM(t, d, "other.pem", goodCertPEM(t, "a.host.zz"), 0o644)
			otherOwner(t, o)
			must(t, os.Remove(c), os.Symlink(o, c))
		}},
		{"key over 64 KiB", []string{key}, func(t *testing.T, d, r, c, k string) {
			writePEM(t, d, filepath.Base(k), append(leafKeyPEM(t), bytes.Repeat([]byte(" "), 65537-len(leafKeyPEM(t)))...), 0o600)
		}},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			d := fixtureDir(t)
			rp, cp, kp := writePEM(t, d, "root.pem", rootPEM(t), 0o644), writePEM(t, d, "c.pem", goodCertPEM(t, "a.host.zz"), 0o644), writePEM(t, d, "k.key", leafKeyPEM(t), 0o600)
			cfg, err := config.Load(writeFile(t, contentBody(t, rp, [2]string{cp, kp})), []string{"CKPT_TOKEN=" + strings.Repeat("t", 32)})
			if err != nil {
				t.Fatal(err)
			}
			r.do(t, d, rp, cp, kp)
			want := ""
			for _, k := range r.keys {
				want += "phantom: " + k + ": the file cannot be read\n"
			}
			var se strings.Builder
			if _, ok := checkContent(cfg, time.Now(), &se); ok != (want == "") || se.String() != want {
				t.Errorf("ok %v, stderr %q, want %q", ok, se.String(), want)
			}
		})
	}
}

// must fails the test at the first error.
func must(t *testing.T, errs ...error) {
	t.Helper()
	for _, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
}

// otherOwner makes the file rules see the path as owned by another user.
func otherOwner(t *testing.T, p string) {
	t.Helper()
	fi, err := os.Stat(p)
	must(t, err)
	id, _ := safefile.Identity(fi)
	safefiletest.Set(t, safefiletest.Hooks{OtherOwner: func(got safefile.FileID) bool { return got == id }})
}
