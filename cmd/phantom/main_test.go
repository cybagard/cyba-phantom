package main

import (
	"context"
	"errors"
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
	return "acme:\n  email: sec@example.com\n  ca: \"https://ca.example.invalid\"\nops:\n  basic_auth_htpasswd: " + strconv.Quote(p) + "\ntlog:\n  origin: test/origin\n  publish:\n    - {type: https-put, url: \"https://ckpt.example.invalid/put\", token_env: CKPT_TOKEN}\n"
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
	var out strings.Builder
	if code := run([]string{"--check", "f.yaml"}, nil, &out, &out); code != 0 {
		t.Fatalf("--check: exit %d, output %q", code, out.String())
	}
	if _, err := got.Dialer.DialContext(t.Context(), "tcp", "example.invalid:80"); !errors.Is(err, errNoNet) {
		t.Errorf("--check dial error = %v", err)
	}
	if _, err := got.Resolver.LookupHost(t.Context(), "example.invalid"); !errors.Is(err, errNoNet) {
		t.Errorf("--check lookup error = %v", err)
	}
	if code := run([]string{"f.yaml"}, nil, &out, &out); code != 0 {
		t.Fatalf("start: exit %d, output %q", code, out.String())
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
