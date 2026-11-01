package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hpke"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cybagard/cyba-phantom/internal/bundle"
)

// runCmd runs a command and returns the stdout, the stderr and the exit code.
func runCmd(args ...string) (string, string, int) {
	var out, errOut bytes.Buffer
	code := run(args, &out, &errOut)
	return out.String(), errOut.String(), code
}

func runOK(t *testing.T, args ...string) string {
	t.Helper()
	out, errText, code := runCmd(args...)
	if code != 0 || errText != "" {
		t.Fatalf("%s: code %d, stderr %q", args[0], code, errText)
	}
	return out
}

// runFail checks that a command fails with the exit code and the error.
func runFail(t *testing.T, want int, err error, args ...string) {
	t.Helper()
	if _, errText, code := runCmd(args...); code != want || errText != err.Error()+"\n" {
		t.Errorf("%s: code %d, stderr %q; want %d, %q", args[0], code, errText, want, err)
	}
}

// tempDir makes a private directory below the package directory. The key
// directory rule refuses a parent with a group or other write bit. The system
// temporary directory can have the sticky bit and mode 1777.
func tempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp(".", "_tmp-")
	if err != nil {
		t.Fatal(err)
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(abs) })
	if checkKeyDir(filepath.Join(abs, "k.key")) != nil {
		t.Fatalf("test directory %s is not usable: each directory from / to the test directory must belong to you or root, with no group or other write bit", abs)
	}
	return abs
}

func write(t *testing.T, path, text string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(text), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

// packBundle packs a bundle with a valid manifest of key ID k1. verify reads
// the manifest, so its archive must be a real bundle.
func packBundle(t *testing.T, dir, out string) {
	t.Helper()
	src := filepath.Join(dir, "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(src, "manifest.json"), `{"version":"2026.10.01-1","min_engine":"1.0.0",`+
		`"created":"2026-10-01T00:00:00Z","expires":"2027-01-01T00:00:00Z","key_id":"k1"}`, 0o644)
	runOK(t, "pack", src, out)
}

// failWriter is a writer that always fails.
type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("raw write error") }

// T-S-20: keygen and sign make a signature file that VerifySig accepts.
func TestTS20RoundTrip(t *testing.T) {
	dir := tempDir(t)
	p := func(n string) string { return filepath.Join(dir, n) }
	packBundle(t, dir, p("a.cbnd"))
	var trust []string
	for _, id := range []string{"k1", "k2"} {
		line := runOK(t, "keygen", id, p(id+".key"))
		if fi, err := os.Stat(p(id + ".key")); err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("key file %s: %v", id, err)
		}
		trust = append(trust, line)
	}
	write(t, p("trust"), strings.Join(trust, ""), 0o644)
	runOK(t, "sign", "k1", p("k1.key"), p("a.cbnd"), p("one.sig"))
	if got := runOK(t, "verify", p("trust"), p("a.cbnd"), p("one.sig")); got != "valid: k1\n" {
		t.Errorf("verify one line: %q", got)
	}
	runOK(t, "sign", "k2", p("k2.key"), p("a.cbnd"), p("two.sig"))
	both := p("both.sig")
	one, _ := os.ReadFile(p("one.sig"))
	two, _ := os.ReadFile(p("two.sig"))
	write(t, both, string(one)+string(two), 0o644)
	if got := runOK(t, "verify", p("trust"), p("a.cbnd"), both); got != "valid: k1 k2\n" {
		t.Errorf("verify two lines: %q", got)
	}
	write(t, p("b.cbnd"), "other bytes", 0o644)
	runFail(t, 1, errVerify, "verify", p("trust"), p("b.cbnd"), both)
	runFail(t, 1, errWrite, "sign", "k1", p("k1.key"), p("a.cbnd"), p("one.sig"))
	runFail(t, 1, errWrite, "keygen", "k3", p("k1.key"))
	runFail(t, 2, errUsage, "sign", "k1")
	for _, line := range []string{"bundle-sign keygen <key_id> <key-file>", "bundle-sign pack <dir> <out.cbnd>",
		"bundle-sign sign <key_id> <key-file> <archive> <out.sig>",
		"bundle-sign cosign <key_id> <key-file> <archive> <sig-file> <out.sig>",
		"bundle-sign seal <install.pub> <version> <key_id> <out-file>", "bundle-sign verify <trust-file> <archive> <sig-file>"} {
		if !strings.Contains(errUsage.Error(), line) {
			t.Errorf("usage text lacks %q", line)
		}
	}
	// An error of the output stream has the fixed text too.
	var errOut bytes.Buffer
	if code := run([]string{"verify", p("trust"), p("a.cbnd"), both}, failWriter{}, &errOut); code != 1 || errOut.String() != errWrite.Error()+"\n" {
		t.Errorf("failed output: code %d, stderr %q", code, errOut.String())
	}
	// verify refuses a signature file of more than 1 KiB.
	write(t, p("big.sig"), strings.Repeat("a", 1025), 0o644)
	runFail(t, 1, errRead, "verify", p("trust"), p("a.cbnd"), p("big.sig"))
}

// T-S-20: if keygen cannot print the public line, it fails with errWrite and
// makes no key file.
func TestTS20KeygenMakesNoKeyOnPrintFailure(t *testing.T) {
	key := filepath.Join(tempDir(t), "k.key")
	var errOut bytes.Buffer
	if code := run([]string{"keygen", "k1", key}, failWriter{}, &errOut); code != 1 || errOut.String() != errWrite.Error()+"\n" {
		t.Errorf("code %d, stderr %q", code, errOut.String())
	}
	if _, err := os.Stat(key); err == nil {
		t.Error("key file stays after a print failure")
	}
}

const helperEnv = "BUNDLE_SIGN_TEST_MAIN"

// TestMainHelper runs the real main in a child process. It does nothing in a
// normal test run. The arguments of main follow "--" in os.Args.
func TestMainHelper(t *testing.T) {
	i := slices.Index(os.Args, "--")
	if os.Getenv(helperEnv) != "1" || i < 0 {
		t.Skip("helper of the child-process tests")
	}
	os.Args = append([]string{os.Args[0]}, os.Args[i+1:]...)
	main()
}

// childCode runs the real main in a child process and returns the exit code.
func childCode(t *testing.T, cmd *exec.Cmd) int {
	t.Helper()
	cmd.Env = append(os.Environ(), helperEnv+"=1")
	switch err := cmd.Run().(type) {
	case nil:
		return 0
	case *exec.ExitError:
		return err.ExitCode()
	default:
		t.Fatal(err)
		return -1
	}
}

// helperCmd makes the command that runs main with args in a child process.
func helperCmd(args ...string) *exec.Cmd {
	return exec.Command(os.Args[0], append([]string{"-test.run=^TestMainHelper$", "--"}, args...)...)
}

// T-S-20: the helper variable in the environment does not break a test run. A
// child test binary with the variable and with no "--" exits 0.
func TestTS20HelperSkipsWithoutDashes(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestMainHelper$")
	if code := childCode(t, cmd); code != 0 {
		t.Errorf("exit code %d, want 0", code)
	}
}

// T-S-20: keygen with the null device as output fails with errWrite and makes
// no key file. The Go runtime opens the null device on a closed stdout.
func TestTS20KeygenNullOutput(t *testing.T) {
	key := filepath.Join(tempDir(t), "k.key")
	var errOut bytes.Buffer
	cmd := helperCmd("keygen", "k1", key)
	cmd.Stdout, cmd.Stderr = nil, &errOut
	if code := childCode(t, cmd); code != 1 || errOut.String() != errWrite.Error()+"\n" {
		t.Errorf("code %d, stderr %q", code, errOut.String())
	}
	if _, err := os.Stat(key); err == nil {
		t.Error("key file made with a null output")
	}
}

// T-S-20: a broken stdout pipe gives the fixed write error and exit code 1, not
// the SIGPIPE exit. keygen makes no key file. This runs the real main in a
// child process with the read end of its stdout pipe closed.
func TestTS20BrokenPipe(t *testing.T) {
	dir := tempDir(t)
	p := func(n string) string { return filepath.Join(dir, n) }
	packBundle(t, dir, p("a.cbnd"))
	trust := runOK(t, "keygen", "k1", p("k.key"))
	write(t, p("trust"), trust, 0o644)
	runOK(t, "sign", "k1", p("k.key"), p("a.cbnd"), p("a.sig"))
	for name, args := range map[string][]string{
		"keygen": {"keygen", "k2", p("new.key")},
		"verify": {"verify", p("trust"), p("a.cbnd"), p("a.sig")},
	} {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		r.Close()
		var errOut bytes.Buffer
		cmd := helperCmd(args...)
		cmd.Stdout, cmd.Stderr = w, &errOut
		code := childCode(t, cmd)
		w.Close()
		if code != 1 || errOut.String() != errWrite.Error()+"\n" {
			t.Errorf("%s: code %d, stderr %q; want 1, %q", name, code, errOut.String(), errWrite.Error()+"\n")
		}
	}
	if _, err := os.Stat(p("new.key")); err == nil {
		t.Error("keygen: key file stays after a broken pipe")
	}
}

// T-S-20: sign refuses an archive of more than 8 MiB. It makes no signature
// file.
func TestTS20SignArchiveCap(t *testing.T) {
	dir := tempDir(t)
	p := func(n string) string { return filepath.Join(dir, n) }
	runOK(t, "keygen", "k1", p("k.key"))
	write(t, p("max.cbnd"), strings.Repeat("a", maxFile), 0o644)
	runOK(t, "sign", "k1", p("k.key"), p("max.cbnd"), p("max.sig"))
	write(t, p("big.cbnd"), strings.Repeat("a", maxFile+1), 0o644)
	runFail(t, 1, errRead, "sign", "k1", p("k.key"), p("big.cbnd"), p("big.sig"))
	if _, err := os.Stat(p("big.sig")); err == nil {
		t.Error("signature file made for an archive over the cap")
	}
}

// T-S-20: sign refuses a key file with a group or other bit, a symlink or a
// second link. It makes no signature file. Each case starts from a valid key
// file, so a case fails on its own rule. A valid key file in mode 0600 signs.
func TestTS20KeyFileIsChecked(t *testing.T) {
	dir := tempDir(t)
	p := func(n string) string { return filepath.Join(dir, n) }
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	runOK(t, "keygen", "k1", p("h.key"))
	valid, err := os.ReadFile(p("h.key"))
	must(err)
	write(t, p("a.cbnd"), "archive", 0o644)
	runOK(t, "sign", "k1", p("h.key"), p("a.cbnd"), p("ok.sig"))
	for name, set := range map[string]func(){
		"mode 0640": func() { must(os.Chmod(p("k.key"), 0o640)) },
		"mode 0604": func() { must(os.Chmod(p("k.key"), 0o604)) },
		"symlink":   func() { must(os.Remove(p("k.key"))); must(os.Symlink(p("h.key"), p("k.key"))) },
		"hard link": func() { must(os.Link(p("k.key"), p("second.key"))) },
		"not a key": func() { must(os.WriteFile(p("k.key"), []byte("not a key\n"), 0o600)) },
	} {
		must(os.RemoveAll(p("k.key")))
		must(os.RemoveAll(p("second.key")))
		must(os.RemoveAll(p("m.sig")))
		write(t, p("k.key"), string(valid), 0o600)
		set()
		runFail(t, 1, errKey, "sign", "k1", p("k.key"), p("a.cbnd"), p("m.sig"))
		if _, err := os.Stat(p("m.sig")); err == nil {
			t.Errorf("%s: signature file made", name)
		}
	}
}

// T-S-20: a marker in the key file never appears in the output or in an error.
// This holds for each command, with a key file in mode 0600 and in mode 0640.
// The output of keygen does not hold the private key.
func TestTS20KeyMarkerNeverAppears(t *testing.T) {
	dir := tempDir(t)
	p := func(n string) string { return filepath.Join(dir, n) }
	seed := []byte("marker-seed-0123456789-abcdefgh!")
	secrets := []string{string(seed), b64.EncodeToString(seed), b64.EncodeToString(ed25519.NewKeyFromSeed(seed))}
	write(t, p("a.cbnd"), "archive", 0o644)
	write(t, p("one.sig"), "k1 "+strings.Repeat("A", 86)+"==\n", 0o644)
	for i, mode := range []os.FileMode{0o600, 0o640} {
		write(t, p("m.key"), "k1 "+b64.EncodeToString(seed)+"\n", mode)
		o := func(n string) string { return p(string(rune('a'+i)) + n) }
		var all string
		for _, args := range [][]string{
			{"sign", "k1", p("m.key"), p("a.cbnd"), o("1.sig")},
			{"keygen", "k1", p("m.key")},
			{"verify", p("m.key"), p("a.cbnd"), p("one.sig")},
			{"pack", p("m.key"), o("p.cbnd")},
		} {
			out, errText, _ := runCmd(args...)
			all += out + errText
		}
		for _, s := range secrets {
			if strings.Contains(all, s) {
				t.Errorf("mode %v: output holds key bytes", mode)
			}
		}
	}
	line := runOK(t, "keygen", "k1", p("n.key"))
	if text, _ := os.ReadFile(p("n.key")); strings.Contains(line, strings.TrimSpace(string(text))) {
		t.Error("keygen printed the private key")
	}
}

// T-S-20: pack writes USTAR headers only. An archive with a name of more than
// 100 bytes, in the prefix and name fields, passes ReadArchive. A name that
// does not fit gives an error and leaves no output file. So does a symlink
// below traps/, or an archive that ReadArchive refuses.
func TestTS20Pack(t *testing.T) {
	dir := tempDir(t)
	src := filepath.Join(dir, "src")
	deep := filepath.Join(src, "traps", strings.Repeat("d", 30), strings.Repeat("e", 30), strings.Repeat("f", 30))
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	long := filepath.Join(deep, "file-"+strings.Repeat("g", 30))
	write(t, long, "long data", 0o644)
	write(t, filepath.Join(src, "manifest.json"), "{}", 0o644)
	out := filepath.Join(dir, "out.cbnd")
	runOK(t, "pack", src, out)
	b, _ := os.ReadFile(out)
	a, err := bundle.ReadArchive(b)
	rel, _ := filepath.Rel(src, long)
	if data, ok := a.File(rel); err != nil || !ok || string(data) != "long data" || len(rel) <= 100 || a.Len() != 2 {
		t.Fatalf("name of %d bytes: found %v, error %v", len(rel), ok, err)
	}
	runFail(t, 1, errWrite, "pack", src, out)
	bad := filepath.Join(dir, "bad")
	if err := os.MkdirAll(filepath.Join(bad, "traps"), 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(bad, "manifest.json"), "{}", 0o644)
	write(t, filepath.Join(bad, "traps", strings.Repeat("n", 101)), "x", 0o644)
	runFail(t, 1, errName, "pack", bad, filepath.Join(dir, "bad.cbnd"))
	if _, err := os.Stat(filepath.Join(dir, "bad.cbnd")); err == nil {
		t.Error("output file stays after a name error")
	}
	// A symlink below traps/ has a valid name and is next to a manifest.
	// The symlink is the only reason to refuse it. A top-level name that
	// ReadArchive refuses is a second case. Each gives errPack and leaves no
	// output file.
	linked := filepath.Join(dir, "linked")
	if err := os.MkdirAll(filepath.Join(linked, "traps"), 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(linked, "manifest.json"), "{}", 0o644)
	if err := os.Symlink(filepath.Join(linked, "manifest.json"), filepath.Join(linked, "traps", "link.json")); err != nil {
		t.Fatal(err)
	}
	refused := filepath.Join(dir, "refused")
	if err := os.MkdirAll(refused, 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(refused, "manifest.json"), "{}", 0o644)
	write(t, filepath.Join(refused, "notallowed.bin"), "x", 0o644)
	for name, srcDir := range map[string]string{"symlink": linked, "refused by ReadArchive": refused} {
		outFile := filepath.Join(dir, strings.ReplaceAll(name, " ", "-")+".cbnd")
		runFail(t, 1, errPack, "pack", srcDir, outFile)
		if _, err := os.Stat(outFile); err == nil {
			t.Errorf("%s: output file made", name)
		}
	}
}

func noFile(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); err == nil {
		t.Errorf("file %s exists", path)
	}
}

// T-S-20: sign refuses a key_id that is not the key ID in the key file. It
// refuses a key file of another form. It makes no signature file.
func TestTS20SignChecksKeyFileForm(t *testing.T) {
	dir := tempDir(t)
	p := func(n string) string { return filepath.Join(dir, n) }
	write(t, p("a.cbnd"), "archive", 0o644)
	runOK(t, "keygen", "k1", p("k1.key"))
	runOK(t, "keygen", "k2", p("k2.key"))
	runFail(t, 1, errKeyID, "sign", "k1", p("k2.key"), p("a.cbnd"), p("m.sig"))
	noFile(t, p("m.sig"))
	valid, _ := os.ReadFile(p("k1.key"))
	id, seed, _ := strings.Cut(strings.TrimSuffix(string(valid), "\n"), " ")
	// Each text is a wrong form. In order: old form, extra space, trailing
	// space, CR, no newline, second line, short seed.
	for _, text := range []string{
		seed + "\n",
		id + "  " + seed + "\n",
		id + " " + seed + " \n",
		id + " " + seed + "\r\n",
		id + " " + seed,
		id + " " + seed + "\n" + id + " " + seed + "\n",
		id + " " + seed[:40] + "\n",
	} {
		write(t, p("f.key"), text, 0o600)
		runFail(t, 1, errKey, "sign", "k1", p("f.key"), p("a.cbnd"), p("m.sig"))
		noFile(t, p("m.sig"))
		if err := os.Remove(p("f.key")); err != nil {
			t.Fatal(err)
		}
	}
}

// T-S-20: keygen and sign refuse a key file in a directory with a group or
// other write bit. They refuse it below such a directory. They refuse it
// through a symlink to such a directory.
func TestTS20KeyDirIsChecked(t *testing.T) {
	dir := tempDir(t)
	p := func(n string) string { return filepath.Join(dir, n) }
	write(t, p("a.cbnd"), "archive", 0o644)
	runOK(t, "keygen", "k1", p("good.key"))
	valid, err := os.ReadFile(p("good.key"))
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []os.FileMode{0o777, 0o757, 0o775} {
		bad := p("bad")
		if err := os.Mkdir(bad, 0o700); err != nil {
			t.Fatal(err)
		}
		inner := filepath.Join(bad, "inner")
		if err := os.Mkdir(inner, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(bad, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(bad, p("link")); err != nil {
			t.Fatal(err)
		}
		for name, key := range map[string]string{
			"directory": filepath.Join(bad, "k.key"), "parent": filepath.Join(inner, "k.key"),
			"symlink": p("link/k.key"),
		} {
			write(t, key, string(valid), 0o600)
			runFail(t, 1, errKey, "sign", "k1", key, p("a.cbnd"), p("m.sig"))
			noFile(t, p("m.sig"))
			if err := os.Remove(key); err != nil {
				t.Fatal(err)
			}
			var errOut bytes.Buffer
			if code := run([]string{"keygen", "k1", key}, &bytes.Buffer{}, &errOut); code != 1 || errOut.String() != errKey.Error()+"\n" {
				t.Errorf("%s, mode %o: keygen code %d, stderr %q", name, mode, code, errOut.String())
			}
			noFile(t, key)
		}
		if err := os.Chmod(bad, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(p("link")); err != nil {
			t.Fatal(err)
		}
		if err := os.RemoveAll(bad); err != nil {
			t.Fatal(err)
		}
	}
}

// T-S-20: keygen writes the key file in the directory that it checked. A path
// with "lnk/.." names a private directory as text. The kernel follows lnk and
// then ".." to a directory with mode 0777. keygen and sign use the checked
// directory.
func TestTS20KeyPathIsOneDirectory(t *testing.T) {
	dir := tempDir(t)
	p := func(n string) string { return filepath.Join(dir, n) }
	open := p("open")
	for _, d := range []string{p("good"), filepath.Join(open, "sub")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(open, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(open, "sub"), p("good/lnk")); err != nil {
		t.Fatal(err)
	}
	write(t, p("a.cbnd"), "archive", 0o644)
	key := p("good") + "/lnk/../k.key"
	runOK(t, "keygen", "k1", key)
	if fi, err := os.Stat(p("good/k.key")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("key file in the checked directory: %v, %v", fi, err)
	}
	noFile(t, filepath.Join(open, "k.key"))
	noFile(t, filepath.Join(open, "sub", "k.key"))
	runOK(t, "sign", "k1", key, p("a.cbnd"), p("m.sig"))
}

// T-S-20: keygen and sign accept a key directory that is a symlink to a
// directory with mode 0700.
func TestTS20KeyDirSymlinkToPrivate(t *testing.T) {
	dir := tempDir(t)
	p := func(n string) string { return filepath.Join(dir, n) }
	if err := os.Mkdir(p("priv"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(p("priv"), p("plink")); err != nil {
		t.Fatal(err)
	}
	write(t, p("a.cbnd"), "archive", 0o644)
	runOK(t, "keygen", "k1", p("plink/k.key"))
	if _, err := os.Stat(p("priv/k.key")); err != nil {
		t.Errorf("key file: %v", err)
	}
	runOK(t, "sign", "k1", p("plink/k.key"), p("a.cbnd"), p("m.sig"))
}

// T-S-20: keygen on a path that exists gives errWrite. It prints nothing and
// does not change the file.
func TestTS20KeygenRefusesExistingPath(t *testing.T) {
	key := filepath.Join(tempDir(t), "k.key")
	write(t, key, "old key text\n", 0o600)
	out, errText, code := runCmd("keygen", "k1", key)
	if code != 1 || errText != errWrite.Error()+"\n" || out != "" {
		t.Errorf("code %d, stderr %q, stdout %q", code, errText, out)
	}
	if b, err := os.ReadFile(key); err != nil || string(b) != "old key text\n" {
		t.Errorf("file %q, error %v; want the old bytes", b, err)
	}
}

// T-S-20: pack refuses a directory with no regular file manifest.json at its
// top level.
func TestTS20PackNeedsManifest(t *testing.T) {
	dir := tempDir(t)
	empty := filepath.Join(dir, "empty")
	nested := filepath.Join(dir, "nested")
	// ReadArchive accepts traps/manifest.json, so only the manifest check
	// refuses that directory.
	traps := filepath.Join(dir, "traps")
	linked := filepath.Join(dir, "linked")
	isDir := filepath.Join(dir, "isdir")
	for _, d := range []string{empty, filepath.Join(nested, "x"), filepath.Join(traps, "traps"),
		linked, filepath.Join(isDir, "manifest.json")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write(t, filepath.Join(nested, "x", "manifest.json"), "{}", 0o644)
	write(t, filepath.Join(traps, "traps", "manifest.json"), "{}", 0o644)
	// manifest.json is a symlink to a regular file, or it is a directory.
	write(t, filepath.Join(linked, "real.json"), "{}", 0o644)
	if err := os.Symlink("real.json", filepath.Join(linked, "manifest.json")); err != nil {
		t.Fatal(err)
	}
	for _, src := range []string{empty, nested, traps, linked, isDir} {
		out := filepath.Join(dir, filepath.Base(src)+".cbnd")
		runFail(t, 1, errPack, "pack", src, out)
		noFile(t, out)
	}
}

// swap replaces a seam for one test.
func swap[T any](t *testing.T, v *T, to T) {
	old := *v
	t.Cleanup(func() { *v = old })
	*v = to
}

// T-S-20: after a failed write or file sync, writeNew leaves an empty file at
// the path and gives errWrite. The directory is synced after the file.
func TestTS20WriteNewFailure(t *testing.T) {
	dir := tempDir(t)
	failure := errors.New("injected")
	path := func(n string) string { return filepath.Join(dir, n) }
	var synced []string
	swap(t, &syncDir, func(f *os.File) error { synced = append(synced, f.Name()); return nil })
	if err := writeNew(path("ok"), []byte("data"), 0o600); err != nil || len(synced) != 1 || synced[0] != dir {
		t.Errorf("success: error %v, directory syncs %v", err, synced)
	}
	t.Run("directory sync", func(t *testing.T) {
		swap(t, &syncDir, func(*os.File) error { return failure })
		if err := writeNew(path("dirsync"), []byte("data"), 0o600); err != errWrite {
			t.Errorf("error %v", err)
		}
		// The file keeps its data after a failed directory sync.
		if b, err := os.ReadFile(path("dirsync")); err != nil || string(b) != "data" {
			t.Errorf("file %q, error %v; want data", b, err)
		}
		if fi, err := os.Stat(path("dirsync")); err != nil || fi.Size() != 4 {
			t.Errorf("file %v, error %v; want size 4", fi, err)
		}
	})
	// The write stores the data and then fails, so the file has data to cut.
	t.Run("write", func(t *testing.T) {
		swap(t, &writeTo, func(f *os.File, b []byte) (int, error) {
			if _, err := f.Write(b); err != nil {
				t.Error(err)
			}
			return 0, failure
		})
		if err := writeNew(path("write"), []byte("data"), 0o600); err != errWrite {
			t.Errorf("error %v", err)
		}
	})
	t.Run("file sync", func(t *testing.T) {
		swap(t, &syncOne, func(*os.File) error { return failure })
		if err := writeNew(path("sync"), []byte("data"), 0o600); err != errWrite {
			t.Errorf("error %v", err)
		}
	})
	for _, n := range []string{"write", "sync"} {
		if fi, err := os.Stat(path(n)); err != nil || fi.Size() != 0 {
			t.Errorf("%s: file %v, error %v; want size 0", n, fi, err)
		}
	}
}

const testVersion = "2026.10.01-1"

// rig is a state directory with an install key, and a work directory.
type rig struct {
	t       *testing.T
	dir     string
	state   string
	root    *os.Root
	install hpke.PrivateKey
}

func newRig(t *testing.T) *rig {
	t.Helper()
	state := t.TempDir()
	for _, d := range []string{"bundle", "keys", "tlog"} {
		if err := os.Mkdir(filepath.Join(state, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	root, err := os.OpenRoot(state)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	key, err := bundle.LoadOrCreateInstallKey(root)
	if err != nil {
		t.Fatal(err)
	}
	return &rig{t, tempDir(t), state, root, key}
}

func (r *rig) p(name string) string { return filepath.Join(r.dir, name) }

// build seals a seed for sealVer and id, and packs it with a manifest.
func (r *rig) build(name, rotation, id, sealVer string) {
	r.t.Helper()
	src := r.p(name + ".d")
	if err := os.MkdirAll(filepath.Join(src, "secrets"), 0o755); err != nil {
		r.t.Fatal(err)
	}
	now := time.Now().UTC()
	const stamp = "2006-01-02T15:04:05Z"
	manifest := fmt.Sprintf(`{"version":%q,"min_engine":"1.0.0","created":%q,"expires":%q,"key_id":%q%s}`,
		testVersion, now.Add(-time.Hour).Format(stamp), now.Add(24*time.Hour).Format(stamp), id, rotation)
	write(r.t, filepath.Join(src, "manifest.json"), manifest, 0o644)
	pub := filepath.Join(r.state, "keys", "install.pub")
	runOK(r.t, "seal", pub, sealVer, id, filepath.Join(src, "secrets", "token.key"))
	runOK(r.t, "pack", src, r.p(name+".cbnd"))
}

// load copies the files into the bundle directory with mode 0600. Then it
// loads them with the trust lines and the install key.
func (r *rig) load(key hpke.PrivateKey, archive, sig string, lines ...string) (*bundle.Bundle, error) {
	r.t.Helper()
	var trust bundle.TrustSet
	for _, l := range lines {
		id, pub, ok := bundle.ParseKeyLine(strings.TrimSpace(l))
		if !ok {
			r.t.Fatalf("trust line %q", l)
		}
		trust = append(trust, bundle.TrustKey{KeyID: id, PublicKey: pub, Class: bundle.ClassProprietary})
	}
	for ext, from := range map[string]string{".cbnd": archive, ".sig": sig} {
		b, err := os.ReadFile(from)
		if err == nil {
			err = os.WriteFile(filepath.Join(r.state, "bundle", "current"+ext), b, 0o600)
		}
		if err != nil {
			r.t.Fatal(err)
		}
	}
	return bundle.NewLoader(r.root, "bundle/current.cbnd", trust, key).Load(true)
}

// T-S-20: sign with the old key, then cosign with the new key. The loader
// accepts the file for a transition bundle. verify accepts it with the old
// key. verify refuses the one-line file.
func TestTS20CosignTransition(t *testing.T) {
	r := newRig(t)
	oldLine := runOK(t, "keygen", "k1", r.p("old.key"))
	newLine := runOK(t, "keygen", "k2", r.p("new.key"))
	r.build("t", `,"rotation":{"from":"k1","key":"`+strings.Fields(newLine)[1]+`"}`, "k2", testVersion)
	runOK(t, "sign", "k1", r.p("old.key"), r.p("t.cbnd"), r.p("one.sig"))
	runOK(t, "cosign", "k2", r.p("new.key"), r.p("t.cbnd"), r.p("one.sig"), r.p("two.sig"))
	b, err := r.load(r.install, r.p("t.cbnd"), r.p("two.sig"), oldLine)
	if err != nil {
		t.Fatal(err)
	}
	if m := b.Manifest(); m.KeyID != "k2" {
		t.Errorf("loaded key ID %q", m.KeyID)
	}
	write(t, r.p("trust"), oldLine, 0o644)
	if got := runOK(t, "verify", r.p("trust"), r.p("t.cbnd"), r.p("two.sig")); got != "valid: k1 k2\n" {
		t.Errorf("verify: %q", got)
	}
	runFail(t, 1, errVerify, "verify", r.p("trust"), r.p("t.cbnd"), r.p("one.sig"))
}

// T-S-20: cosign refuses a key file with a group or other bit. It refuses a
// signature file of two lines or of a wrong form. It refuses a key ID that is
// in the file. It makes no output file.
func TestTS20CosignRefusals(t *testing.T) {
	r := newRig(t)
	write(t, r.p("a.cbnd"), "archive", 0o644)
	for _, id := range []string{"k1", "k2", "k3"} {
		runOK(t, "keygen", id, r.p(id+".key"))
	}
	runOK(t, "sign", "k1", r.p("k1.key"), r.p("a.cbnd"), r.p("one.sig"))
	runOK(t, "sign", "k2", r.p("k2.key"), r.p("a.cbnd"), r.p("two.sig"))
	one, _ := os.ReadFile(r.p("one.sig"))
	two, _ := os.ReadFile(r.p("two.sig"))
	write(t, r.p("both.sig"), string(one)+string(two), 0o644)
	write(t, r.p("bad.sig"), "junk\n", 0o644)
	key, _ := os.ReadFile(r.p("k3.key"))
	write(t, r.p("m640.key"), string(key), 0o640)
	write(t, r.p("m604.key"), string(key), 0o604)
	for _, c := range []struct {
		name, id, key, sig string
		err                error
	}{
		{"mode 0640", "k3", "m640.key", "one.sig", errKey},
		{"mode 0604", "k3", "m604.key", "one.sig", errKey},
		{"two lines", "k3", "k3.key", "both.sig", errSig},
		{"key ID in the file", "k1", "k1.key", "one.sig", errKeyID},
		{"bad file", "k3", "k3.key", "bad.sig", errSig},
		{"no file", "k3", "k3.key", "none.sig", errRead},
	} {
		runFail(t, 1, c.err, "cosign", c.id, r.p(c.key), r.p("a.cbnd"), r.p(c.sig), r.p("out.sig"))
		noFile(t, r.p("out.sig"))
	}
}

// T-S-20: a seed that seal writes opens with the install key of the sensor.
// It gives seed_invalid for another install key and for another version.
func TestTS20SealOpensWithInstallKey(t *testing.T) {
	r := newRig(t)
	line := runOK(t, "keygen", "k1", r.p("k.key"))
	r.build("a", "", "k1", testVersion)
	r.build("v", "", "k1", "2026.10.01-2")
	for _, n := range []string{"a", "v"} {
		runOK(t, "sign", "k1", r.p("k.key"), r.p(n+".cbnd"), r.p(n+".sig"))
	}
	for name, c := range map[string]struct {
		key     hpke.PrivateKey
		archive string
	}{"other install key": {newRig(t).install, "a"}, "other version": {r.install, "v"}} {
		_, err := r.load(c.key, r.p(c.archive+".cbnd"), r.p(c.archive+".sig"), line)
		if code, ok := bundle.CodeOf(err); !ok || code != bundle.CodeSeedInvalid {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := r.load(r.install, r.p("a.cbnd"), r.p("a.sig"), line); err != nil {
		t.Errorf("install key of the sensor: %v", err)
	}
}

// T-S-20: seal refuses a public key file of a wrong form. It refuses a version
// or key ID that is not valid. It makes no output file.
func TestTS20SealRefusals(t *testing.T) {
	r := newRig(t)
	good, _ := os.ReadFile(filepath.Join(r.state, "keys", "install.pub"))
	enc := strings.TrimSuffix(string(good), "\n")
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	// The last base64 character has two unused bits. Set one of them.
	loose := enc[:42] + string(alphabet[strings.IndexByte(alphabet, enc[42])^1]) + "="
	for _, c := range []struct {
		name, pub, version, id string
		err                    error
	}{
		{"not canonical", loose + "\n", testVersion, "k1", errKey},
		{"short key", b64.EncodeToString(make([]byte, 31)) + "\n", testVersion, "k1", errKey},
		{"no newline", enc, testVersion, "k1", errKey},
		{"version", enc + "\n", "2026.10.01", "k1", errSeal},
		{"key ID", enc + "\n", testVersion, "K1", errSeal},
		{"no file", "", testVersion, "k1", errRead},
	} {
		pub := r.p("pub")
		_ = os.Remove(pub)
		if c.pub != "" {
			write(t, pub, c.pub, 0o644)
		}
		runFail(t, 1, c.err, "seal", pub, c.version, c.id, r.p("out.key"))
		noFile(t, r.p("out.key"))
	}
}
