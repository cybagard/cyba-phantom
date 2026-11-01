package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/cybagard/cyba-phantom/internal/config"
	"github.com/cybagard/cyba-phantom/internal/config/configtest"
	"github.com/cybagard/cyba-phantom/internal/safefile"
)

// TestMain stops the run when a directory above the package has a group or
// other write bit or another owner. The htpasswd directory rule refuses each
// fixture below such a directory, and many tests would fail with other texts.
func TestMain(m *testing.M) {
	// The file name is for the walk: it checks the package directory and above.
	if err := safefile.CheckPathParents(filepath.Join(pkgDir, "main_test.go"), dirRule); err != nil {
		fmt.Fprintf(os.Stderr, "the tests need a checkout whose parent directories have no group or other write bit and are owned by root or the current user: %v\n", err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

// dirRule is the rule for a directory of the htpasswd file. The owner is root
// or the current user. The mode has no group or other write bit. It is a
// copy of htpasswdDirRule in internal/config.
var dirRule = safefile.Rule{Type: safefile.Dir, Owner: safefile.OwnerSelfOrRoot, Forbid: 0o022}

type failNet struct{ t *testing.T }

func (f failNet) DialContext(context.Context, string, string) (net.Conn, error) {
	f.t.Fatal("the check load dialed")
	return nil, nil
}

func (f failNet) LookupHost(context.Context, string) ([]string, error) {
	f.t.Fatal("the check load resolved a name")
	return nil, nil
}

func writeFile(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// fixtureDirEnv names the directory for the fixture files of a child process.
const fixtureDirEnv = "CYBA_TEST_FIXTURE_DIR"

// pkgDir is the package directory. A test can change the working directory.
var pkgDir = func() string {
	wd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	return wd
}()

// validBody returns a config file that passes all validators. The htpasswd file must exist.
// The file is in a private directory below the package directory. The htpasswd
// rule refuses a parent with a group or other write bit. The system
// temporary directory can have mode 1777. A child process that ends with
// os.Exit gets its directory in fixtureDirEnv, so its parent removes it.
func validBody(t *testing.T) string {
	t.Helper()
	base := pkgDir
	if d := os.Getenv(fixtureDirEnv); d != "" {
		base = d
	}
	d, err := os.MkdirTemp(base, "_tmp-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	p := filepath.Join(d, "htpasswd")
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	return "acme:\n  email: sec@example.com\n  ca: \"https://ca.example.invalid\"\n  names: [decoy.host.zz]\nops:\n  basic_auth_htpasswd: " + strconv.Quote(p) + "\ntlog:\n  origin: test/origin\n  publish:\n    - {type: https-put, url: \"https://ckpt.example.invalid/put\", token_env: CKPT_TOKEN}\n"
}

// TestTS10_Usage checks that a run with no argument exits 2 and prints the fixed usage line.
func TestTS10_Usage(t *testing.T) {
	var stdout, stderr strings.Builder
	if code := run(nil, nil, &stdout, &stderr); code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
	if want := "usage: phantom [--check] <config-path>\n"; stderr.String() != want {
		t.Errorf("stderr = %q, want %q", stderr.String(), want)
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want empty", stdout.String())
	}
}

// TestTS10_UnknownFlag checks that a flag name with control characters
// is not printed. The run gives exit 2 and the fixed usage line on
// stderr, and nothing on stdout (T-S-10).
func TestTS10_UnknownFlag(t *testing.T) {
	var stdout, stderr strings.Builder
	if code := run([]string{"--x\x1b[31m", "f.yaml"}, nil, &stdout, &stderr); code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
	if want := "usage: phantom [--check] <config-path>\n"; stderr.String() != want {
		t.Errorf("stderr = %q, want %q", stderr.String(), want)
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want empty", stdout.String())
	}
	for _, part := range []string{"\x1b", "[31m", "--x"} {
		if out := stdout.String() + stderr.String(); strings.Contains(out, part) {
			t.Errorf("the output %q holds %q of the flag name", out, part)
		}
	}
}

// requireNoNet fails the test when the Dialer or the Resolver of --check
// gives an error other than errNoNet. The caller passes noNet values,
// so the calls use no network.
func requireNoNet(t *testing.T, label string, d noNet, r noNet) {
	t.Helper()
	if _, err := d.DialContext(t.Context(), "tcp", "example.invalid:80"); !errors.Is(err, errNoNet) {
		t.Errorf("%s dial error = %v", label, err)
	}
	if _, err := r.LookupHost(t.Context(), "example.invalid"); !errors.Is(err, errNoNet) {
		t.Errorf("%s lookup error = %v", label, err)
	}
}

// TestTS10_CheckWiring checks that run gives --check the no-network Net,
// and gives the start no such Net (SEC-11). It also checks the stdout
// of both modes (T-S-10). The test checks the types first. It calls a
// method only on a noNet value.
func TestTS10_CheckWiring(t *testing.T) {
	const valid = "phantom: config is valid\n"
	var got config.Net
	old := loadWith
	loadWith = func(_ string, _ []string, n config.Net) (*config.Config, error) {
		got = n
		return &config.Config{}, nil
	}
	t.Cleanup(func() { loadWith = old })
	starts := 0
	oldServe := serve
	serve = func(*config.Config, io.Writer, io.Writer) int { starts++; return 0 }
	t.Cleanup(func() { serve = oldServe })
	var stdout, stderr strings.Builder
	if code := run([]string{"--check", "f.yaml"}, nil, &stdout, &stderr); code != 0 || starts != 0 {
		t.Fatalf("--check: exit %d, starts %d, stdout %q, stderr %q", code, starts, stdout.String(), stderr.String())
	}
	if stdout.String() != valid || stderr.Len() != 0 {
		t.Errorf("--check: stdout %q, stderr %q; want %q and nothing", stdout.String(), stderr.String(), valid)
	}
	d, dOK := got.Dialer.(noNet)
	r, rOK := got.Resolver.(noNet)
	if !dOK || !rOK {
		t.Errorf("--check: Dialer %T, Resolver %T; want noNet for both", got.Dialer, got.Resolver)
	} else {
		requireNoNet(t, "--check", d, r)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"f.yaml"}, nil, &stdout, &stderr); code != 0 || starts != 1 {
		t.Fatalf("start: exit %d, starts %d, stdout %q, stderr %q", code, starts, stdout.String(), stderr.String())
	}
	if strings.Contains(stdout.String(), valid) {
		t.Errorf("start: stdout %q holds the --check line", stdout.String())
	}
	if got.Dialer == nil {
		t.Error("the start Dialer is nil")
	}
	if got.Resolver == nil {
		t.Error("the start Resolver is nil")
	}
	if _, ok := got.Dialer.(noNet); ok {
		t.Error("the start Dialer is noNet")
	}
	if _, ok := got.Resolver.(noNet); ok {
		t.Error("the start Resolver is noNet")
	}
}

// TestTS10_CheckNoDial checks that the load of a valid file calls no Dialer and no Resolver (SEC-11).
func TestTS10_CheckNoDial(t *testing.T) {
	if _, err := config.LoadWith(writeFile(t, validBody(t)), []string{"CKPT_TOKEN=token"}, config.Net{Dialer: failNet{t}, Resolver: failNet{t}}); err != nil {
		t.Fatal(err)
	}
	requireNoNet(t, "noNet", noNet{}, noNet{})
}

// TestTS10_CheckFileRules checks two refusals of --check. One is a config file
// that other users can write. The other is an htpasswd file below a directory
// that every user can write. Each gives exit 1 and the text of the load
// (T-S-10).
func TestTS10_CheckFileRules(t *testing.T) {
	env := []string{"CKPT_TOKEN=" + strings.Repeat("t", 32)}
	t.Run("config file 0602", func(t *testing.T) {
		file := writeFile(t, validBody(t))
		if err := os.Chmod(file, 0o602); err != nil {
			t.Fatal(err)
		}
		var so, se strings.Builder
		code := run([]string{"--check", file}, env, &so, &se)
		if code != 1 || !strings.Contains(se.String(), "group or other writable") {
			t.Errorf("exit %d, stderr %q; want exit 1 and \"group or other writable\"", code, se.String())
		}
	})
	t.Run("htpasswd file below a 0777 directory", func(t *testing.T) {
		d, err := os.MkdirTemp(pkgDir, "_tmp-")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.RemoveAll(d) })
		if err := os.Chmod(d, 0o777); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(d, "htpasswd")
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		var so, se strings.Builder
		code := run([]string{"--check", writeFile(t, validBody(t))}, append(env, "PHANTOM_OPS_BASIC_AUTH_HTPASSWD="+p), &so, &se)
		const dir = "a directory of the htpasswd file is writable by group or other, or its owner is not root or the sensor user"
		if code != 1 || !strings.Contains(se.String(), "ops.basic_auth_htpasswd") || !strings.Contains(se.String(), dir) {
			t.Errorf("exit %d, stderr %q; want exit 1, the key and %q", code, se.String(), dir)
		}
	})
}

// TestTS10_CheckExec runs the binary. A valid file gives exit 0. An invalid
// file gives a non-zero exit, with the key and the source in stderr (FR-12).
// The output has no secret marker (T-S-10). An acme.ca value that is not a
// URL fails and names acme.ca (SEC-12). A URL with a password in its user
// information never shows the password or the user information.
func TestTS10_CheckExec(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "phantom")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	const marker = "SECRET-MARKER-7c1f9a"
	const urlUser, urlPass = "urluser-4b2e", "URLPASS-9d1a3f"
	var outs string
	runCheck := func(file string, env ...string) (code int, stdout, stderr string) {
		var so, se strings.Builder
		cmd := exec.Command(bin, "--check", file)
		// The publisher of validBody names CKPT_TOKEN.
		cmd.Env = append(append(os.Environ(), "CKPT_TOKEN="+marker), env...)
		cmd.Stdout, cmd.Stderr = &so, &se
		err := cmd.Run()
		// outs holds the output of every run.
		defer func() { outs += so.String() + se.String() }()
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else if err != nil {
			t.Fatal(err)
		}
		return code, so.String(), se.String()
	}
	bad := writeFile(t, "acme:\n  email: sec@example.com\nlisten:\n  nope: 1\n")
	code, so, se := runCheck(writeFile(t, validBody(t)))
	if code != 0 || so != "phantom: config is valid\n" || se != "" {
		t.Errorf("valid file: exit %d, stdout %q, stderr %q", code, so, se)
	}
	code, _, se = runCheck(writeFile(t, validBody(t)), "PHANTOM_ACME_CA=not a url")
	if code == 0 {
		t.Error("acme.ca not a URL: exit 0")
	}
	if !strings.Contains(se, "acme.ca") {
		t.Errorf("acme.ca not a URL: stderr %q lacks acme.ca", se)
	}
	// A URL key with user information and a password: the run shows
	// neither (SEC-13). The check on outs at the end looks for both.
	userInfo := urlUser + ":" + urlPass + "@"
	code, _, se = runCheck(writeFile(t, validBody(t)), "PHANTOM_ACME_CA=https://"+userInfo+"ca.example.invalid")
	if code == 0 || !strings.Contains(se, "acme.ca") {
		t.Errorf("acme.ca with user information: exit %d, stderr %q; want a refusal that names acme.ca", code, se)
	}
	pub := strings.Replace(validBody(t), "https://ckpt.example.invalid/put", "https://"+userInfo+"ckpt.example.invalid/put", 1)
	code, _, se = runCheck(writeFile(t, pub))
	if code == 0 || !strings.Contains(se, "tlog.publish[0].url") {
		t.Errorf("publisher url with user information: exit %d, stderr %q; want a refusal that names tlog.publish[0].url", code, se)
	}
	code, _, se = runCheck(bad)
	if code == 0 {
		t.Error("invalid file: exit 0")
	}
	for _, want := range []string{"listen.nope", "config.yaml:4"} {
		if !strings.Contains(se, want) {
			t.Errorf("invalid file: stderr %q lacks %q", se, want)
		}
	}
	// The loader never prints the value of a URL key or a secret key. The email
	// value has a wrong type, so the loader prints it. The marker is in the
	// user information of a URL-like text. So the printed value must show
	// REDACTED@ and not the marker. CKPT_TOKEN holds the marker in every run.
	code, _, se = runCheck(writeFile(t, "acme:\n  email: !!int \"https://u:"+marker+"@h.example\"\n"))
	if code == 0 {
		t.Error("wrong type: exit 0")
	}
	if !strings.Contains(se, "REDACTED@") {
		t.Errorf("wrong type: stderr %q lacks REDACTED@", se)
	}
	// A *_env key can hold a pasted secret in place of a name. The error names
	// the key path and never the variable name. This holds for an unset
	// variable and for a short one (SEC-13).
	const nameMarker = "JBSWY3DPEHPK3PXPZZSECRETQ7"
	tok := strings.Replace(validBody(t), "CKPT_TOKEN", nameMarker, 1)
	hook := validBody(t) + "alerts:\n  sinks:\n    - {type: webhook, url: \"https://hook.example.invalid/a\", hmac_secret_env: " + nameMarker + "}\n"
	for _, c := range []struct {
		name, body, env, key string
	}{
		{"token unset", tok, "", "tlog.publish[0].token_env"},
		{"hmac unset", hook, "", "alerts.sinks[0].hmac_secret_env"},
		{"hmac short", hook, nameMarker + "=short", "alerts.sinks[0].hmac_secret_env"},
	} {
		env := []string{}
		if c.env != "" {
			env = append(env, c.env)
		}
		code, so, se := runCheck(writeFile(t, c.body), env...)
		if code == 0 || !strings.Contains(se, c.key) {
			t.Errorf("%s: exit %d, stderr %q lacks %s", c.name, code, se, c.key)
		}
		if strings.Contains(so+se, nameMarker) {
			t.Errorf("%s: the output holds the variable name: %q", c.name, so+se)
		}
	}
	if strings.Contains(outs, marker) || strings.Contains(outs, urlPass) || strings.Contains(outs, urlUser) || strings.Contains(outs, nameMarker) {
		t.Errorf("output holds a secret: %q", outs)
	}
}

// TestTS11_CheckStorePath checks that --check refuses each bad store.path with
// exit 1 and the error text of the load. It also checks that --check accepts a
// good path (SEC-20, T-S-11). Each row also names the rule in the detail of the
// error. The state directory is the default one.
func TestTS11_CheckStorePath(t *testing.T) {
	const s = "/var/lib/phantom/"
	file := writeFile(t, validBody(t))
	check := func(path string, extra ...string) (code int, stderr string, loadErr string) {
		env := append([]string{"CKPT_TOKEN=" + strings.Repeat("t", 32), "PHANTOM_STORE_PATH=" + path}, extra...)
		var so, se strings.Builder
		code = run([]string{"--check", file}, env, &so, &se)
		if _, err := config.Load(file, env); err != nil {
			loadErr = err.Error()
		}
		return code, se.String(), loadErr
	}
	if code, se, _ := check(s + "db/events-2.db"); code != 0 {
		t.Errorf("good path: exit %d, stderr %q", code, se)
	}
	for _, c := range []struct {
		name, path string
		extra      []string
		detail     string
	}{
		{"question mark", s + "events.db?mode=rwc", nil, "each path part below"},
		{"hash", s + "events.db#x", nil, "each path part below"},
		{"space", s + "my events.db", nil, "each path part below"},
		{"non-ASCII letter", s + "évents.db", nil, "each path part below"},
		{"parent part", s + "a/../events.db", nil, "the path must be clean"},
		{"state directory", "/var/lib/phantom", nil, "the path text must be below the state directory"},
		{"tlog.dir", s + "tlog/e.db", nil, "must not be in tlog.dir"},
		{"acme.cache_dir", s + "certs/e.db", nil, "must not be in acme.cache_dir"},
		{"directory of bundle.path", s + "bundle/e.db", nil, "must not be in the directory of bundle.path"},
		{"keys", s + "keys/e.db", nil, "must not be in the keys directory"},
		{"checkpoints", s + "checkpoints/e.db", nil, "must not be in the checkpoints directory"},
		{"checkpoint.state", s + "checkpoint.state", nil, "must not be checkpoint.state\n"},
		{"checkpoint.state.tmp", s + "checkpoint.state.tmp", nil, "must not be checkpoint.state.tmp"},
		{"writer.stop", s + "writer.stop", nil, "must not be writer.stop"},
		{"tlog.dir set", s + "t2/e.db", []string{"PHANTOM_TLOG_DIR=" + s + "t2"}, "must not be in tlog.dir"},
		{"acme.cache_dir set", s + "c/e.db", []string{"PHANTOM_ACME_CACHE_DIR=" + s + "c"}, "must not be in acme.cache_dir"},
		{"bundle.path set", s + "b/e.db", []string{"PHANTOM_BUNDLE_PATH=" + s + "b/x.cbnd"}, "must not be in the directory of bundle.path"},
		{"keys in other case", s + "Keys/e.db", nil, "must not be in the keys directory"},
		{"writer.stop in other case", s + "WRITER.STOP", nil, "must not be writer.stop"},
		{"tlog.dir in other case", s + "TLOG/e.db", nil, "must not be in tlog.dir"},
		{"tlog.dir set in other case", s + "logs/e.db", []string{"PHANTOM_TLOG_DIR=" + s + "LOGS"}, "must not be in tlog.dir"},
		{"acme.cache_dir in other case", s + "Certs/e.db", nil, "must not be in acme.cache_dir"},
		{"directory of bundle.path in other case", s + "Bundle/e.db", nil, "must not be in the directory of bundle.path"},
		{"checkpoints in other case", s + "CheckPoints/e.db", nil, "must not be in the checkpoints directory"},
		{"checkpoint.state in other case", s + "Checkpoint.State", nil, "must not be checkpoint.state\n"},
		{"checkpoint.state.tmp in other case", s + "CHECKPOINT.STATE.TMP", nil, "must not be checkpoint.state.tmp"},
		{"acme.cache_dir set in other case", s + "c/e.db", []string{"PHANTOM_ACME_CACHE_DIR=" + s + "C"}, "must not be in acme.cache_dir"},
		{"bundle.path set in other case", s + "b/e.db", []string{"PHANTOM_BUNDLE_PATH=" + s + "B/x.cbnd"}, "must not be in the directory of bundle.path"},
	} {
		t.Run(c.name, func(t *testing.T) {
			code, se, loadErr := check(c.path, c.extra...)
			_, after, found := strings.Cut(se, "store.path at PHANTOM_STORE_PATH: ")
			if code != 1 || !found || !strings.Contains(after, c.detail) || loadErr == "" || se != loadErr+"\n" {
				t.Errorf("exit %d, stderr %q, load error %q; want detail %q", code, se, loadErr, c.detail)
			}
		})
	}
}

// TestTS11_CheckTLogDir checks that --check refuses a bad tlog.dir and a bad
// acme.cache_dir. The exit code is 1. The text is the error of the load
// (SEC-11, SEC-21, T-S-11).
func TestTS11_CheckTLogDir(t *testing.T) {
	const s = "/var/lib/phantom/"
	file := writeFile(t, validBody(t))
	for _, c := range []struct{ name, env, key, detail string }{
		{"tlog.dir is the state directory", "PHANTOM_TLOG_DIR=/var/lib/phantom", "tlog.dir at PHANTOM_TLOG_DIR: ", "the path text must be below the state directory"},
		{"tlog.dir in other case", "PHANTOM_TLOG_DIR=" + s + "Keys", "tlog.dir at PHANTOM_TLOG_DIR: ", "must not be in or above the keys directory"},
		{"acme.cache_dir in other case", "PHANTOM_ACME_CACHE_DIR=" + s + "WRITER.STOP", "acme.cache_dir at PHANTOM_ACME_CACHE_DIR: ", "must not be or be in writer.stop"},
	} {
		t.Run(c.name, func(t *testing.T) {
			env := []string{"CKPT_TOKEN=" + strings.Repeat("t", 32), c.env}
			var so, se strings.Builder
			code := run([]string{"--check", file}, env, &so, &se)
			_, loadErr := config.Load(file, env)
			if _, after, found := strings.Cut(se.String(), c.key); code != 1 || !found || !strings.Contains(after, c.detail) || loadErr == nil || se.String() != loadErr.Error()+"\n" {
				t.Errorf("exit %d, stderr %q, load error %v; want %q%q", code, se.String(), loadErr, c.key, c.detail)
			}
		})
	}
}

// TestTS11_CheckBundlePath checks that --check refuses each bad bundle.path with exit 1 and the error text of the load,
// and accepts the default (SEC-23). The state directory is the default one.
func TestTS11_CheckBundlePath(t *testing.T) {
	const s = "/var/lib/phantom/"
	file := writeFile(t, validBody(t))
	check := func(extra ...string) (code int, stderr string, loadErr string) {
		env := append([]string{"CKPT_TOKEN=" + strings.Repeat("t", 32)}, extra...)
		var so, se strings.Builder
		code = run([]string{"--check", file}, env, &so, &se)
		if _, err := config.Load(file, env); err != nil {
			loadErr = err.Error()
		}
		return code, se.String(), loadErr
	}
	if code, se, _ := check(); code != 0 {
		t.Errorf("default: exit %d, stderr %q", code, se)
	}
	for _, p := range []string{"db2/x.cbnd", "writer.stop2/x.cbnd"} {
		if code, se, _ := check("PHANTOM_BUNDLE_PATH="+s+p, "PHANTOM_STORE_PATH="+s+"db"); code != 0 {
			t.Errorf("%s: exit %d, stderr %q", p, code, se)
		}
	}
	for _, c := range []struct {
		name, path string
		extra      []string
		detail     string
	}{
		{"space", s + "bundle/my bundle.cbnd", nil, "each path part"},
		{"file name", s + "bundle/current.bin", nil, "must end in .cbnd"},
		{"state directory", s + "current.cbnd", nil, "must not be the state directory"},
		{"tlog.dir", s + "tlog/x.cbnd", nil, "in or above tlog.dir"},
		{"above tlog.dir", s + "a/x.cbnd", []string{"PHANTOM_TLOG_DIR=" + s + "a/t"}, "in or above tlog.dir"},
		{"acme.cache_dir", s + "certs/x.cbnd", nil, "in or above acme.cache_dir"},
		{"above acme.cache_dir", s + "c/x.cbnd", []string{"PHANTOM_ACME_CACHE_DIR=" + s + "c/d"}, "in or above acme.cache_dir"},
		{"keys", s + "keys/x.cbnd", nil, "keys directory"},
		{"checkpoints", s + "checkpoints/x.cbnd", nil, "checkpoints directory"},
		{"store.path", s + "b2/x.cbnd", []string{"PHANTOM_STORE_PATH=" + s + "b2/x.cbnd"}, "must not be store.path"},
		{"keys in other case", s + "Keys/x.cbnd", nil, "keys directory"},
		{"writer.stop in other case", s + "WRITER.STOP/x.cbnd", nil, "be in writer.stop"},
		{"file name .cbnd alone", s + "bundle/.cbnd", nil, "character before .cbnd"},
		{"in checkpoint.state", s + "checkpoint.state/a/x.cbnd", nil, "be in checkpoint.state"},
		{"store.path in other case", s + "B/x.cbnd", []string{"PHANTOM_STORE_PATH=" + s + "b/x.cbnd"}, "must not be store.path"},
		{"store.path-journal in other case", s + "DB-Journal/x.cbnd", []string{"PHANTOM_STORE_PATH=" + s + "db"}, "or a file of it"},
	} {
		t.Run(c.name, func(t *testing.T) {
			code, se, loadErr := check(append([]string{"PHANTOM_BUNDLE_PATH=" + c.path}, c.extra...)...)
			_, after, found := strings.Cut(se, "bundle.path at PHANTOM_BUNDLE_PATH: ")
			if code != 1 || !found || !strings.Contains(after, c.detail) || loadErr == "" || se != loadErr+"\n" {
				t.Errorf("exit %d, stderr %q, load error %q", code, se, loadErr)
			}
		})
	}
}

// TestTS11_CheckACME checks three kinds of bad value with --check.
// These are a bad acme.names list, a bad acme.cache_dir, and a
// limits.header_bytes outside 8192 to 16384. Each gives exit 1.
// Stderr names the key. The test also checks that --check accepts the
// edges. A row for a fixed refusal checks the whole stderr
// (SEC-21, SEC-31, SEC-02, T-S-11, T-S-27, T-U-10).
func TestTS11_CheckACME(t *testing.T) {
	body := validBody(t)
	names := func(list string) string { return strings.Replace(body, "[decoy.host.zz]", list, 1) }
	// many returns a list of n distinct names; label returns a label of n bytes.
	many := func(n int) string {
		var l []string
		for i := range n {
			l = append(l, "n"+strconv.Itoa(i)+".host.zz")
		}
		return "[" + strings.Join(l, ", ") + "]"
	}
	label := func(n int) string { return strings.Repeat("a", n) }
	// certs returns the body with a tls.certs entry for name. Without names, it
	// has no acme.names and no acme.email.
	certs := func(name string, withNames bool) string {
		b := body
		if !withNames {
			b = strings.Replace(b, "  email: sec@example.com\n", "", 1)
			b = strings.Replace(b, "  names: [decoy.host.zz]\n", "", 1)
		}
		d := fixtureDir(t)
		cert, key := writePEM(t, d, "static.pem", goodCertPEM(t, name), 0o644), writePEM(t, d, "static.key", leafKeyPEM(t), 0o600)
		return b + "tls:\n  certs: [{name: " + name + ", cert_file: " + strconv.Quote(cert) + ", key_file: " + strconv.Quote(key) + "}]\n"
	}
	// cacheRefused returns the whole stderr of a refusal of acme.cache_dir by
	// a path rule. Then it adds the lines of the other keys. Stderr must start
	// with the line of acme.cache_dir, so a refusal by another key alone fails.
	cacheRefused := func(detail string, more ...string) string {
		return "config: acme.cache_dir at PHANTOM_ACME_CACHE_DIR: " + detail + "\n" + strings.Join(more, "")
	}
	const bundleSide = "config: bundle.path at PHANTOM_BUNDLE_PATH: the directory must not be in or above acme.cache_dir\n"
	const bundleSideDefault = "config: bundle.path at default: the directory must not be in or above acme.cache_dir\n"
	// The tlog.dir rule is in or above acme.cache_dir.
	// So it gives its own error.
	const tlogSide = "config: tlog.dir at PHANTOM_TLOG_DIR: the path must not be in or above acme.cache_dir\n"
	const tlogSideDefault = "config: tlog.dir at default: the path must not be in or above acme.cache_dir\n"
	rows := []struct {
		name, file string
		key        string // key is "" for a file that passes.
		env        []string
		stderr     string // stderr is the whole text of a fixed refusal, or "".
	}{
		{"valid", body, "", nil, ""},
		{"header 8192", body, "", []string{"PHANTOM_LIMITS_HEADER_BYTES=8192"}, ""},
		{"header 16384", body, "", []string{"PHANTOM_LIMITS_HEADER_BYTES=16384"}, ""},
		{"header 8191", body, "limits.header_bytes", []string{"PHANTOM_LIMITS_HEADER_BYTES=8191"}, ""},
		{"header 16385", body, "limits.header_bytes", []string{"PHANTOM_LIMITS_HEADER_BYTES=16385"}, ""},
		{"no names", names("[]"), "acme.names", nil, ""},
		{"17 names", names(many(17)), "acme.names", nil, ""},
		{"upper case", names("[Decoy.host.zz]"), "acme.names", nil, ""},
		{"wildcard", names(`["*.host.zz"]`), "acme.names", nil, ""},
		{"IP literal", names("[192.0.2.1]"), "acme.names", nil, ""},
		{"IPv6 literal", names(`["2001:db8::1"]`), "acme.names", nil, ""},
		{"trailing dot", names("[decoy.host.zz.]"), "acme.names", nil, ""},
		{"one label", names("[decoy]"), "acme.names", nil, ""},
		{"label of 64 bytes", names("[" + label(64) + ".zz]"), "acme.names", nil, ""},
		{"leading hyphen", names("[-decoy.host.zz]"), "acme.names", nil, ""},
		{"localhost", names("[localhost]"), "acme.names", nil, ""},
		{"x.localhost", names("[x.localhost]"), "acme.names", nil, ""},
		{"x.local", names("[x.local]"), "acme.names", nil, ""},
		// The valid body has an https acme.ca, so this name passes.
		{"internal name", names("[x.internal]"), "", nil, ""},
		{"x.home.arpa", names("[x.home.arpa]"), "acme.names", nil, ""},
		{"local", names("[local]"), "acme.names", nil, ""},
		{"internal", names("[internal]"), "acme.names", nil, ""},
		{"name of 254 bytes", names("[" + label(63) + "." + label(63) + "." + label(63) + "." + label(62) + "]"), "acme.names", nil, ""},
		{"home.arpa", names("[home.arpa]"), "acme.names", nil, ""},
		{"16 names", names(many(16)), "", nil, ""},
		{"label of 63 bytes", names("[" + label(63) + ".zz]"), "", nil, ""},
		{"name of 253 bytes", names("[" + label(63) + "." + label(63) + "." + label(63) + "." + label(61) + "]"), "", nil, ""},
		{"duplicate", names("[a.host.zz, a.host.zz]"), "acme.names", nil, ""},
		{"tls.certs only", certs("a.host.zz", false), "", nil, ""},
		{"tls.certs special-use name", certs("x.test", true), "tls.certs[0].name", nil, ""},
		{"name in acme.names and tls.certs", certs("decoy.host.zz", true), "tls.certs[0].name", nil, ""},
		{"names override", body, "PHANTOM_ACME_NAMES", []string{"PHANTOM_ACME_NAMES=a.host.zz"}, ""},
		{"cache dir with a space", body, "acme.cache_dir", []string{"PHANTOM_ACME_CACHE_DIR=/var/lib/phantom/my certs"}, ""},
		{"cache dir is the state directory", body, "acme.cache_dir", []string{"PHANTOM_ACME_CACHE_DIR=/var/lib/phantom"},
			"config: acme.cache_dir at PHANTOM_ACME_CACHE_DIR: the path text must be below the state directory: value \"/var/lib/phantom\"\n"},
		{"cache dir is a sibling", body, "", []string{"PHANTOM_ACME_CACHE_DIR=/var/lib/phantom/certs2"}, ""},
		{"cache dir is tlog.dir", body, "acme.cache_dir", []string{"PHANTOM_ACME_CACHE_DIR=/var/lib/phantom/tlog"}, ""},
		{"cache dir in tlog.dir", body, "acme.cache_dir", []string{"PHANTOM_ACME_CACHE_DIR=/var/lib/phantom/tlog/c"}, ""},
		{"cache dir above tlog.dir", body, "acme.cache_dir", []string{"PHANTOM_ACME_CACHE_DIR=/var/lib/phantom/x", "PHANTOM_TLOG_DIR=/var/lib/phantom/x/tlog"}, ""},
		{"cache dir is the bundle directory", body, "acme.cache_dir", []string{"PHANTOM_ACME_CACHE_DIR=/var/lib/phantom/bundle"},
			cacheRefused("the path must not be in or above the directory of bundle.path", bundleSideDefault)},
		{"cache dir in the bundle directory", body, "acme.cache_dir", []string{"PHANTOM_ACME_CACHE_DIR=/var/lib/phantom/bundle/c"},
			cacheRefused("the path must not be in or above the directory of bundle.path", bundleSideDefault)},
		{"cache dir above the bundle directory", body, "acme.cache_dir", []string{"PHANTOM_ACME_CACHE_DIR=/var/lib/phantom/b", "PHANTOM_BUNDLE_PATH=/var/lib/phantom/b/x/current.cbnd"},
			cacheRefused("the path must not be in or above the directory of bundle.path", bundleSide)},
		{"cache dir is keys", body, "acme.cache_dir", []string{"PHANTOM_ACME_CACHE_DIR=/var/lib/phantom/keys"}, ""},
		{"cache dir in keys", body, "acme.cache_dir", []string{"PHANTOM_ACME_CACHE_DIR=/var/lib/phantom/keys/c"}, ""},
		{"cache dir is checkpoints", body, "acme.cache_dir", []string{"PHANTOM_ACME_CACHE_DIR=/var/lib/phantom/checkpoints"}, ""},
		{"cache dir in checkpoints", body, "acme.cache_dir", []string{"PHANTOM_ACME_CACHE_DIR=/var/lib/phantom/checkpoints/c"}, ""},
		{"cache dir is keys in other case", body, "acme.cache_dir", []string{"PHANTOM_ACME_CACHE_DIR=/var/lib/phantom/Keys"}, ""},
		{"cache dir is tlog.dir in other case", body, "acme.cache_dir", []string{"PHANTOM_ACME_CACHE_DIR=/var/lib/phantom/TLOG"}, ""},
		{"cache dir in tlog.dir in other case", body, "acme.cache_dir", []string{"PHANTOM_ACME_CACHE_DIR=/var/lib/phantom/Tlog/c"},
			cacheRefused("the path must not be in or above tlog.dir", tlogSideDefault)},
		{"cache dir in keys in other case", body, "acme.cache_dir", []string{"PHANTOM_ACME_CACHE_DIR=/var/lib/phantom/KEYS/c"},
			cacheRefused("the path must not be in or above the keys directory")},
		{"cache dir in the bundle directory in other case", body, "acme.cache_dir", []string{"PHANTOM_ACME_CACHE_DIR=/var/lib/phantom/Bundle/c"},
			cacheRefused("the path must not be in or above the directory of bundle.path", bundleSideDefault)},
		{"cache dir in checkpoints in other case", body, "acme.cache_dir", []string{"PHANTOM_ACME_CACHE_DIR=/var/lib/phantom/CheckPoints/c"},
			cacheRefused("the path must not be in or above the checkpoints directory")},
		{"cache dir above tlog.dir set in other case", body, "acme.cache_dir", []string{"PHANTOM_ACME_CACHE_DIR=/var/lib/phantom/x", "PHANTOM_TLOG_DIR=/var/lib/phantom/X/tlog"},
			cacheRefused("the path must not be in or above tlog.dir", tlogSide)},
		{"cache dir in other case above tlog.dir", body, "acme.cache_dir", []string{"PHANTOM_ACME_CACHE_DIR=/var/lib/phantom/X", "PHANTOM_TLOG_DIR=/var/lib/phantom/x/tlog"},
			cacheRefused("the path must not be in or above tlog.dir", tlogSide)},
		{"cache dir in other case above the bundle directory", body, "acme.cache_dir", []string{"PHANTOM_ACME_CACHE_DIR=/var/lib/phantom/B", "PHANTOM_BUNDLE_PATH=/var/lib/phantom/b/x/current.cbnd"},
			cacheRefused("the path must not be in or above the directory of bundle.path", bundleSide)},
		{"cache dir in tlog.dir set in other case", body, "acme.cache_dir", []string{"PHANTOM_ACME_CACHE_DIR=/var/lib/phantom/t/c", "PHANTOM_TLOG_DIR=/var/lib/phantom/T"},
			cacheRefused("the path must not be in or above tlog.dir", tlogSide)},
		{"cache dir above the bundle directory, bundle.path set in other case", body, "acme.cache_dir", []string{"PHANTOM_ACME_CACHE_DIR=/var/lib/phantom/b", "PHANTOM_BUNDLE_PATH=/var/lib/phantom/B/x/current.cbnd"},
			cacheRefused("the path must not be in or above the directory of bundle.path", bundleSide)},
		{"cache dir in the bundle directory, bundle.path set in other case", body, "acme.cache_dir", []string{"PHANTOM_ACME_CACHE_DIR=/var/lib/phantom/b/c", "PHANTOM_BUNDLE_PATH=/var/lib/phantom/B/current.cbnd"},
			cacheRefused("the path must not be in or above the directory of bundle.path", bundleSide)},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			env := append([]string{"CKPT_TOKEN=" + strings.Repeat("t", 32)}, r.env...)
			var so, se strings.Builder
			code := run([]string{"--check", writeFile(t, r.file)}, env, &so, &se)
			if r.key == "" {
				if code != 0 || se.Len() != 0 {
					t.Errorf("exit %d, stderr %q; want exit 0 and no stderr", code, se.String())
				}
				return
			}
			if code != 1 || !strings.Contains(se.String(), r.key) {
				t.Errorf("exit %d, stderr %q; want exit 1 and a refusal that names %q", code, se.String(), r.key)
			}
			if r.stderr != "" && se.String() != r.stderr {
				t.Errorf("stderr %q; want %q", se.String(), r.stderr)
			}
		})
	}
}

// afterFile returns the text of s after the config file name. The temporary
// directory name holds the test name, so the leak check skips it.
func afterFile(s string) string {
	_, rest, _ := strings.Cut(s, "config.yaml")
	return rest
}

// TestTS26_CheckPrivateLists checks that --check applies the private list
// rules. A refusal exits 1 and names the key of the entry. For a ninth
// entry, a duplicate, or a list that its item cannot use, it names the
// list. A row with a leak text checks that stderr does not hold it. A valid
// list passes (SEC-30, T-S-26, T-S-11).
func TestTS26_CheckPrivateLists(t *testing.T) {
	body := validBody(t)
	acme := func(list string) string {
		return strings.Replace(body, "  names: [decoy.host.zz]\n", "  names: [decoy.host.zz]\n  ca_private: "+list+"\n", 1)
	}
	publish := func(list string) string {
		return strings.Replace(body, "token_env: CKPT_TOKEN}", "token_env: CKPT_TOKEN, private: "+list+"}", 1)
	}
	bundle := func(url, list string) string {
		return body + "bundle:\n" + url + "  fetch_private: " + list + "\n"
	}
	const nine = `[10.0.0.1, 10.0.0.2, 10.0.0.3, 10.0.0.4, 10.0.0.5, 10.0.0.6, 10.0.0.7, 10.0.0.8, 10.0.0.9]`
	const fetch = "  fetch_url: \"https://bundle.example.invalid/x\"\n"
	sink := func(item string) string { return body + "alerts:\n  sinks:\n    - " + item + "\n" }
	syslog := func(addr, list string) string {
		return sink(`{type: syslog, addr: "` + addr + `", private: ` + list + "}")
	}
	webhook := func(list string) string {
		return sink(`{type: webhook, url: "https://hook.example.invalid/x", hmac_secret_env: HMAC_KEY, private: ` + list + "}")
	}
	smtp := func(list string) string {
		return sink(`{type: smtp, host: "smtp://mail.example.invalid:587", from: a@example.com, to: [b@example.com], private: ` + list + "}")
	}
	// The key is "" for a file that passes. The stderr of a refusal must not
	// hold the leak text. An empty leak means no check for that row.
	type checkRow struct{ name, file, key, leak string }
	rows := []checkRow{
		{"acme list", acme(`["10.0.0.0/8", "fc00::/7"]`), "", ""},
		{"acme empty list", acme(`[]`), "", ""},
		{"acme host name", acme(`[corp.internal.zz]`), "acme.ca_private[0]", "corp.internal.zz"},
		{"acme port", acme(`["10.0.0.1:443"]`), "acme.ca_private[0]", "10.0.0.1:443"},
		{"acme nine", acme(nine), "acme.ca_private", "10.0.0.9"},
		{"acme duplicate", acme(`[10.0.0.1, 10.0.0.1]`), "acme.ca_private", ""},
		{"acme duplicate in two spellings", acme(`[10.0.0.1, "10.0.0.1/32"]`), "acme.ca_private", "10.0.0.1/32"},
		{"acme duplicate in other case", acme(`["fd00::a", "FD00::A"]`), "acme.ca_private", "FD00::A"},
		{"acme wide entry", acme(`["0.0.0.0/0"]`), "acme.ca_private[0]", "0.0.0.0/0"},
		{"acme letsencrypt", strings.Replace(acme(`[10.0.0.1]`), `"https://ca.example.invalid"`, "letsencrypt", 1), "acme.ca_private", ""},
		{"publish list", publish(`["10.1.0.0/16"]`), "", ""},
		{"publish metadata range", publish(`["169.254.0.0/16"]`), "tlog.publish[0].private[0]", "169.254.0.0/16"},
		{"publish nine", publish(nine), "tlog.publish[0].private", "10.0.0.9"},
		{"publish duplicate", publish(`[10.0.0.1, 10.0.0.1]`), "tlog.publish[0].private", ""},
		{"bundle list", bundle(fetch, `[10.0.0.1]`), "", ""},
		{"bundle no fetch_url", bundle("", `[10.0.0.1]`), "bundle.fetch_private", ""},
		{"bundle bad entry", bundle(fetch, `["10.0.0.1/8"]`), "bundle.fetch_private[0]", "10.0.0.1/8"},
		{"udp sink list", syslog("udp://127.0.0.1:514", `[10.0.0.1]`), "alerts.sinks[0].private", ""},
		{"tcp sink list", syslog("tcp://127.0.0.1:514", `[10.0.0.1]`), "alerts.sinks[0].private", ""},
		{"udp sink empty list", syslog("udp://127.0.0.1:514", `[]`), "alerts.sinks[0].private", ""},
		{"tls sink list", syslog("tls://logs.example.invalid:6514", `[10.0.0.1]`), "", ""},
		{"webhook list", webhook(`[10.0.0.1]`), "", ""},
		{"webhook bad entry", webhook(`["192.0.2.1"]`), "alerts.sinks[0].private[0]", "192.0.2.1"},
		{"smtp list", smtp(`[10.0.0.1]`), "", ""},
		{"smtp duplicate", smtp(`[10.0.0.1, "10.0.0.1/32"]`), "alerts.sinks[0].private", "10.0.0.1/32"},
	}
	// These entries are the refused entries of the load test.
	for _, e := range []string{"0.0.0.0/0", "::/0", "198.18.0.0/15", "192.0.2.1", "64:ff9b::/96", "2002::/16",
		"fec0::/10", "::ffff:10.0.0.0/104", "fe80::1%eth0", "10.0.0.1/8", "127.0.0.1", "100.0.0.0/8"} {
		leak := e
		if len(e) < 8 { // ::/0 is too short for a fair check.
			leak = ""
		}
		rows = append(rows, checkRow{"entry " + e, acme(`["` + e + `"]`), "acme.ca_private[0]", leak})
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			env := []string{"CKPT_TOKEN=" + strings.Repeat("t", 32), "HMAC_KEY=" + strings.Repeat("h", 32)}
			var so, se strings.Builder
			code := run([]string{"--check", writeFile(t, r.file)}, env, &so, &se)
			switch {
			case r.key == "" && (code != 0 || se.Len() != 0):
				t.Errorf("exit %d, stderr %q; want exit 0 and no stderr", code, se.String())
			case r.key != "" && (code != 1 || !strings.Contains(se.String(), "config: "+r.key+" at ")):
				t.Errorf("exit %d, stderr %q; want exit 1 and a refusal that names %q", code, se.String(), r.key)
			case r.leak != "" && strings.Contains(afterFile(se.String()), r.leak):
				t.Errorf("stderr %q holds the entry", se.String())
			}
		})
	}
}

// TestTS11_CheckEmailMarks checks that --check refuses an acme.email, an smtp
// from, and an smtp to. Each value holds one of the characters of
// configtest.EmailMarks. The exit code is 1. Stderr names the key and
// gives the rule. It does not hold the character (T-S-11).
func TestTS11_CheckEmailMarks(t *testing.T) {
	body := validBody(t)
	smtp := func(from, to string) string {
		return body + "alerts:\n  sinks:\n    - {type: smtp, host: \"smtp://mail.example.invalid:587\", from: \"" + from + "\", to: [\"" + to + "\"]}\n"
	}
	for _, m := range configtest.EmailMarks {
		// A double-quoted YAML scalar reads this escape.
		esc := fmt.Sprintf(`\u%04x`, m)
		for _, r := range []struct{ key, file string }{
			{"acme.email", strings.Replace(body, "sec@example.com", `"a@example.com`+esc+`"`, 1)},
			{"alerts.sinks[0].from", smtp("a@example.com"+esc, "c@example.com")},
			{"alerts.sinks[0].to[0]", smtp("a@example.com", "c@example.com"+esc)},
		} {
			t.Run(r.key+" "+esc, func(t *testing.T) {
				env := []string{"CKPT_TOKEN=" + strings.Repeat("t", 32)}
				var so, se strings.Builder
				code := run([]string{"--check", writeFile(t, r.file)}, env, &so, &se)
				rule := "the address must have only printable ASCII characters 0x21-0x7E"
				// Each error text has spaces, so the check skips the space.
				leak := m != ' ' && strings.ContainsRune(se.String(), m)
				if code != 1 || !strings.Contains(se.String(), r.key) || !strings.Contains(se.String(), rule) || leak {
					t.Errorf("exit %d, stderr %q, want a refusal that names %q, gives the rule, and not the character", code, se.String(), r.key)
				}
			})
		}
	}
}
