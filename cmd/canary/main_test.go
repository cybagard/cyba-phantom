package main

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
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

const valid = "acme:\n  email: sec@example.com\nlisten:\n  http: \"http://user:pw@example.invalid:80\"\n"

// TestTS10_CheckNoDial checks that the load of a valid file calls no Dialer and no Resolver (SEC-11).
func TestTS10_CheckNoDial(t *testing.T) {
	if _, err := config.LoadWith(writeFile(t, valid), nil, config.Net{Dialer: failNet{t}, Resolver: failNet{t}}); err != nil {
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
// with the key and the source in stderr (FR-12), and no secret marker in the output (T-S-10).
func TestTS10_CheckExec(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "canary")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	const marker = "SECRET-MARKER-7c1f9a"
	// The key table has no *_env key or secret key yet, so the marker is the override of a known key.
	env := append(os.Environ(), "CANARY_ACME_CA="+marker)
	run := func(file string) (code int, stdout, stderr string) {
		var so, se strings.Builder
		cmd := exec.Command(bin, "--check", file)
		cmd.Env, cmd.Stdout, cmd.Stderr = env, &so, &se
		err := cmd.Run()
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else if err != nil {
			t.Fatal(err)
		}
		return code, so.String(), se.String()
	}
	bad := writeFile(t, "acme:\n  email: sec@example.com\nlisten:\n  nope: 1\n")
	code, so, se := run(writeFile(t, valid))
	if code != 0 {
		t.Errorf("valid file: exit %d, stderr %q", code, se)
	}
	outs := so + se
	code, so, se = run(bad)
	if code == 0 {
		t.Error("invalid file: exit 0")
	}
	for _, want := range []string{"listen.nope", "config.yaml:4"} {
		if !strings.Contains(se, want) {
			t.Errorf("invalid file: stderr %q lacks %q", se, want)
		}
	}
	if outs += so + se; strings.Contains(outs, marker) || strings.Contains(outs, "pw@") {
		t.Errorf("output holds a secret: %q", outs)
	}
}
