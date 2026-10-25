package main

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

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

func write(t *testing.T, path, text string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(text), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

// failWriter is a writer that always fails.
type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("raw write error") }

// T-S-20: keygen and sign make a signature file that VerifySig accepts.
func TestTS20RoundTrip(t *testing.T) {
	dir := t.TempDir()
	p := func(n string) string { return filepath.Join(dir, n) }
	write(t, p("a.cbnd"), "archive bytes", 0o644)
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
		"bundle-sign sign <key_id> <key-file> <archive> <out.sig>", "bundle-sign verify <trust-file> <archive> <sig-file>"} {
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
// leaves no key file.
func TestTS20KeygenRemovesKeyOnPrintFailure(t *testing.T) {
	key := filepath.Join(t.TempDir(), "k.key")
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
	if os.Getenv(helperEnv) != "1" {
		t.Skip("helper of TestTS20BrokenPipe")
	}
	for i, a := range os.Args {
		if a == "--" {
			os.Args = append([]string{os.Args[0]}, os.Args[i+1:]...)
			break
		}
	}
	main()
}

// T-S-20: a broken stdout pipe gives the fixed write error and exit code 1, not
// the SIGPIPE exit. keygen removes the key file. This runs the real main in a
// child process with the read end of its stdout pipe closed.
func TestTS20BrokenPipe(t *testing.T) {
	dir := t.TempDir()
	p := func(n string) string { return filepath.Join(dir, n) }
	write(t, p("a.cbnd"), "archive", 0o644)
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
		cmd := exec.Command(os.Args[0], append([]string{"-test.run=^TestMainHelper$", "--"}, args...)...)
		cmd.Env = append(os.Environ(), helperEnv+"=1")
		cmd.Stdout, cmd.Stderr = w, &errOut
		err = cmd.Run()
		w.Close()
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else if err != nil {
			t.Fatal(err)
		}
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
	dir := t.TempDir()
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
	dir := t.TempDir()
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
	dir := t.TempDir()
	p := func(n string) string { return filepath.Join(dir, n) }
	seed := []byte("marker-seed-0123456789-abcdefgh!")
	secrets := []string{string(seed), b64.EncodeToString(seed), b64.EncodeToString(ed25519.NewKeyFromSeed(seed))}
	write(t, p("a.cbnd"), "archive", 0o644)
	write(t, p("one.sig"), "k1 "+strings.Repeat("A", 86)+"==\n", 0o644)
	for i, mode := range []os.FileMode{0o600, 0o640} {
		write(t, p("m.key"), b64.EncodeToString(seed)+"\n", mode)
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
	dir := t.TempDir()
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
	write(t, filepath.Join(refused, "notallowed.bin"), "x", 0o644)
	for name, srcDir := range map[string]string{"symlink": linked, "refused by ReadArchive": refused} {
		outFile := filepath.Join(dir, strings.ReplaceAll(name, " ", "-")+".cbnd")
		runFail(t, 1, errPack, "pack", srcDir, outFile)
		if _, err := os.Stat(outFile); err == nil {
			t.Errorf("%s: output file made", name)
		}
	}
}
