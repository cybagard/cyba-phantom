package main

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/cybagard/cyba-phantom/internal/config"
)

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

// validBody returns a config file that passes all validators. The htpasswd file must exist.
func validBody(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "htpasswd")
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	return "acme:\n  email: sec@example.com\n  ca: \"https://ca.example.invalid\"\n  names: [decoy.example.com]\nops:\n  basic_auth_htpasswd: " + strconv.Quote(p) + "\ntlog:\n  origin: test/origin\n  publish:\n    - {type: https-put, url: \"https://ckpt.example.invalid/put\", token_env: CKPT_TOKEN}\n"
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

// TestTS10_CheckWiring checks that run gives --check the no-network Net, and gives the start no such Net (SEC-11).
func TestTS10_CheckWiring(t *testing.T) {
	var got config.Net
	old := loadWith
	loadWith = func(_ string, _ []string, n config.Net) (*config.Config, error) { got = n; return nil, nil }
	t.Cleanup(func() { loadWith = old })
	starts := 0
	oldServe := serve
	serve = func(*config.Config, io.Writer, io.Writer) int { starts++; return 0 }
	t.Cleanup(func() { serve = oldServe })
	var out strings.Builder
	if code := run([]string{"--check", "f.yaml"}, nil, &out, &out); code != 0 || starts != 0 {
		t.Fatalf("--check: exit %d, starts %d, output %q", code, starts, out.String())
	}
	if _, err := got.Dialer.DialContext(t.Context(), "tcp", "example.invalid:80"); !errors.Is(err, errNoNet) {
		t.Errorf("--check dial error = %v", err)
	}
	if _, err := got.Resolver.LookupHost(t.Context(), "example.invalid"); !errors.Is(err, errNoNet) {
		t.Errorf("--check lookup error = %v", err)
	}
	if code := run([]string{"f.yaml"}, nil, &out, &out); code != 0 || starts != 1 {
		t.Fatalf("start: exit %d, starts %d, output %q", code, starts, out.String())
	}
	if _, ok := got.Dialer.(noNet); ok {
		t.Error("the start uses noNet")
	}
}

// TestTS10_CheckNoDial checks that the load of a valid file calls no Dialer and no Resolver (SEC-11).
func TestTS10_CheckNoDial(t *testing.T) {
	if _, err := config.LoadWith(writeFile(t, validBody(t)), []string{"CKPT_TOKEN=token"}, config.Net{Dialer: failNet{t}, Resolver: failNet{t}}); err != nil {
		t.Fatal(err)
	}
	if _, err := (noNet{}).DialContext(t.Context(), "tcp", "example.invalid:80"); !errors.Is(err, errNoNet) {
		t.Errorf("noNet dial error = %v", err)
	}
	if _, err := (noNet{}).LookupHost(t.Context(), "example.invalid"); !errors.Is(err, errNoNet) {
		t.Errorf("noNet lookup error = %v", err)
	}
}

// TestTS10_CheckExec runs the binary: exit 0 for a valid file, non-zero for an invalid file
// with the key and the source in stderr (FR-12), no secret marker in the output (T-S-10), and
// URL syntax checks only: an acme.ca value that is not a URL fails and names acme.ca (FR-12).
func TestTS10_CheckExec(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "phantom")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	const marker = "SECRET-MARKER-7c1f9a"
	var outs string
	run := func(file string, env ...string) (code int, stdout, stderr string) {
		var so, se strings.Builder
		cmd := exec.Command(bin, "--check", file)
		cmd.Env = append(append(os.Environ(), "CKPT_TOKEN="+marker), env...) // The publisher of validBody names CKPT_TOKEN.
		cmd.Stdout, cmd.Stderr = &so, &se
		err := cmd.Run()
		defer func() { outs += so.String() + se.String() }() // outs holds the output of every run.
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else if err != nil {
			t.Fatal(err)
		}
		return code, so.String(), se.String()
	}
	bad := writeFile(t, "acme:\n  email: sec@example.com\nlisten:\n  nope: 1\n")
	code, _, se := run(writeFile(t, validBody(t)))
	if code != 0 {
		t.Errorf("valid file: exit %d, stderr %q", code, se)
	}
	code, _, se = run(writeFile(t, validBody(t)), "PHANTOM_ACME_CA=not a url")
	if code == 0 {
		t.Error("acme.ca not a URL: exit 0")
	}
	if !strings.Contains(se, "acme.ca") {
		t.Errorf("acme.ca not a URL: stderr %q lacks acme.ca", se)
	}
	code, _, se = run(bad)
	if code == 0 {
		t.Error("invalid file: exit 0")
	}
	for _, want := range []string{"listen.nope", "config.yaml:4"} {
		if !strings.Contains(se, want) {
			t.Errorf("invalid file: stderr %q lacks %q", se, want)
		}
	}
	// The loader never prints the value of a URL key or a secret key. The email value has a wrong
	// type, so the loader prints it. The marker is in the user information of a URL-like text, so the
	// printed value must show REDACTED@ and not the marker. CKPT_TOKEN holds the marker in every run.
	code, _, se = run(writeFile(t, "acme:\n  email: !!int \"https://u:"+marker+"@h.example\"\n"))
	if code == 0 {
		t.Error("wrong type: exit 0")
	}
	if !strings.Contains(se, "REDACTED@") {
		t.Errorf("wrong type: stderr %q lacks REDACTED@", se)
	}
	// A *_env key can hold a pasted secret in place of a name. The error names the key path and
	// never the variable name, for an unset variable and for a short one (SEC-13).
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
		code, so, se := run(writeFile(t, c.body), env...)
		if code == 0 || !strings.Contains(se, c.key) {
			t.Errorf("%s: exit %d, stderr %q lacks %s", c.name, code, se, c.key)
		}
		if strings.Contains(so+se, nameMarker) {
			t.Errorf("%s: the output holds the variable name: %q", c.name, so+se)
		}
	}
	if strings.Contains(outs, marker) || strings.Contains(outs, "pw@") || strings.Contains(outs, nameMarker) {
		t.Errorf("output holds a secret: %q", outs)
	}
}

// TestTS11_CheckStorePath checks that --check refuses each bad store.path with exit 1 and the error text of the load,
// and accepts a good path (SEC-20, T-S-11). Each row also names the rule in the detail of the error.
// The state directory is the default one.
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
		{"state directory", "/var/lib/phantom", nil, "the path must be below the state directory"},
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
	} {
		t.Run(c.name, func(t *testing.T) {
			code, se, loadErr := check(c.path, c.extra...)
			_, after, found := strings.Cut(se, "store.path at PHANTOM_STORE_PATH: ")
			if code != 1 || !found || !strings.Contains(after, c.detail) || loadErr == "" || se != loadErr+"\n" {
				t.Errorf("exit %d, stderr %q, load error %q", code, se, loadErr)
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

// TestTS11_CheckACME checks that --check refuses a bad acme.names list, a bad acme.cache_dir, and a
// limits.header_bytes outside 8192 to 16384 with exit 1 and the key in stderr, and accepts the edges (SEC-21, SEC-02, T-S-11, T-U-10).
func TestTS11_CheckACME(t *testing.T) {
	body := validBody(t)
	names := func(list string) string { return strings.Replace(body, "[decoy.example.com]", list, 1) }
	// many returns a list of n distinct names; label returns a label of n bytes.
	many := func(n int) string {
		var l []string
		for i := range n {
			l = append(l, "n"+strconv.Itoa(i)+".example")
		}
		return "[" + strings.Join(l, ", ") + "]"
	}
	label := func(n int) string { return strings.Repeat("a", n) }
	rows := []struct {
		name, file string
		key        string // key is "" for a file that passes.
		env        []string
	}{
		{"valid", body, "", nil},
		{"header 8192", body, "", []string{"PHANTOM_LIMITS_HEADER_BYTES=8192"}},
		{"header 16384", body, "", []string{"PHANTOM_LIMITS_HEADER_BYTES=16384"}},
		{"header 8191", body, "limits.header_bytes", []string{"PHANTOM_LIMITS_HEADER_BYTES=8191"}},
		{"header 16385", body, "limits.header_bytes", []string{"PHANTOM_LIMITS_HEADER_BYTES=16385"}},
		{"no names", names("[]"), "acme.names", nil},
		{"17 names", names(many(17)), "acme.names", nil},
		{"upper case", names("[Decoy.example.com]"), "acme.names", nil},
		{"wildcard", names(`["*.example.com"]`), "acme.names", nil},
		{"IP literal", names("[192.0.2.1]"), "acme.names", nil},
		{"IPv6 literal", names(`["2001:db8::1"]`), "acme.names", nil},
		{"trailing dot", names("[decoy.example.com.]"), "acme.names", nil},
		{"one label", names("[decoy]"), "acme.names", nil},
		{"label of 64 bytes", names("[" + label(64) + ".example]"), "acme.names", nil},
		{"leading hyphen", names("[-decoy.example.com]"), "acme.names", nil},
		{"localhost", names("[localhost]"), "acme.names", nil},
		{"x.localhost", names("[x.localhost]"), "acme.names", nil},
		{"x.local", names("[x.local]"), "acme.names", nil},
		{"internal name", names("[x.internal]"), "acme.names", nil},
		{"x.home.arpa", names("[x.home.arpa]"), "acme.names", nil},
		{"local", names("[local]"), "acme.names", nil},
		{"internal", names("[internal]"), "acme.names", nil},
		{"name of 254 bytes", names("[" + label(63) + "." + label(63) + "." + label(63) + "." + label(62) + "]"), "acme.names", nil},
		{"home.arpa", names("[home.arpa]"), "", nil},
		{"16 names", names(many(16)), "", nil},
		{"label of 63 bytes", names("[" + label(63) + ".example]"), "", nil},
		{"name of 253 bytes", names("[" + label(63) + "." + label(63) + "." + label(63) + "." + label(61) + "]"), "", nil},
		{"duplicate", names("[a.example, a.example]"), "acme.names", nil},
		{"names override", body, "PHANTOM_ACME_NAMES", []string{"PHANTOM_ACME_NAMES=a.example"}},
		{"cache dir with a space", body, "acme.cache_dir", []string{"PHANTOM_ACME_CACHE_DIR=/var/lib/phantom/my certs"}},
		{"cache dir is the state directory", body, "acme.cache_dir", []string{"PHANTOM_ACME_CACHE_DIR=/var/lib/phantom"}},
		{"cache dir is a sibling", body, "", []string{"PHANTOM_ACME_CACHE_DIR=/var/lib/phantom/certs2"}},
		{"cache dir is tlog.dir", body, "acme.cache_dir", []string{"PHANTOM_ACME_CACHE_DIR=/var/lib/phantom/tlog"}},
		{"cache dir in tlog.dir", body, "acme.cache_dir", []string{"PHANTOM_ACME_CACHE_DIR=/var/lib/phantom/tlog/c"}},
		{"cache dir above tlog.dir", body, "acme.cache_dir", []string{"PHANTOM_ACME_CACHE_DIR=/var/lib/phantom/x", "PHANTOM_TLOG_DIR=/var/lib/phantom/x/tlog"}},
		{"cache dir is the bundle directory", body, "acme.cache_dir", []string{"PHANTOM_ACME_CACHE_DIR=/var/lib/phantom/bundle"}},
		{"cache dir in the bundle directory", body, "acme.cache_dir", []string{"PHANTOM_ACME_CACHE_DIR=/var/lib/phantom/bundle/c"}},
		{"cache dir above the bundle directory", body, "acme.cache_dir", []string{"PHANTOM_ACME_CACHE_DIR=/var/lib/phantom/b", "PHANTOM_BUNDLE_PATH=/var/lib/phantom/b/x/current.cbnd"}},
		{"cache dir is keys", body, "acme.cache_dir", []string{"PHANTOM_ACME_CACHE_DIR=/var/lib/phantom/keys"}},
		{"cache dir in keys", body, "acme.cache_dir", []string{"PHANTOM_ACME_CACHE_DIR=/var/lib/phantom/keys/c"}},
		{"cache dir is checkpoints", body, "acme.cache_dir", []string{"PHANTOM_ACME_CACHE_DIR=/var/lib/phantom/checkpoints"}},
		{"cache dir in checkpoints", body, "acme.cache_dir", []string{"PHANTOM_ACME_CACHE_DIR=/var/lib/phantom/checkpoints/c"}},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			env := append([]string{"CKPT_TOKEN=" + strings.Repeat("t", 32)}, r.env...)
			var so, se strings.Builder
			code := run([]string{"--check", writeFile(t, r.file)}, env, &so, &se)
			if r.key == "" && (code != 0 || se.Len() != 0) || r.key != "" && (code != 1 || !strings.Contains(se.String(), r.key)) {
				t.Errorf("exit %d, stderr %q, want a refusal that names %q", code, se.String(), r.key)
			}
		})
	}
}
