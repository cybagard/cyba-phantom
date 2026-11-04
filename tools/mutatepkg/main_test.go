package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const mod = "example.com/m"

func p(rel, name string) pkg {
	imp := mod
	if rel != "." {
		imp += "/" + rel
	}
	return pkg{Import: imp, Rel: rel, Name: name}
}

func TestMappedFollowsGremlinsWalk(t *testing.T) {
	for _, c := range []struct {
		p    pkg
		want string
	}{
		{p("internal/config", "config"), "internal/config"},
		{p("cmd/phantom", "main"), "."},
		{p("internal/a/b", "a"), "internal/a"},
		{p(".", "m"), "."},
	} {
		if got := mapped(c.p); got != c.want {
			t.Errorf("mapped(%v) = %q, want %q", c.p, got, c.want)
		}
	}
}

func TestPlanPackageArgumentOfMutantTest(t *testing.T) {
	for _, c := range []struct {
		name     string
		pkgs     []pkg
		from, to string
	}{
		{"main package gets its own path", []pkg{p("cmd/phantom", "main")}, mod, mod + "/cmd/phantom"},
		{"package that gremlins maps right needs no change", []pkg{p("internal/config", "config")}, "", ""},
		{"module root package needs no change", []pkg{p(".", "m")}, "", ""},
		{"mapped package next to a main package", []pkg{p("t", "t"), p("t/x", "x"), p("t/cmd", "main")}, mod, mod + "/t/cmd"},
	} {
		from, to, err := plan(mod, c.pkgs)
		if err != nil || from != c.from || to != c.to {
			t.Errorf("%s: plan = %q %q %v, want %q %q", c.name, from, to, err, c.from, c.to)
		}
	}
}

func TestPlanRefusesPackageThatIsNotKnown(t *testing.T) {
	for _, c := range []struct {
		name string
		pkgs []pkg
		want []string
	}{
		{"two main packages", []pkg{p("tools/a", "main"), p("tools/b", "main")},
			[]string{mod + "/tools/a", mod + "/tools/b", "module path"}},
		{"main package and root package", []pkg{p(".", "m"), p("cmd/x", "main")},
			[]string{mod + "/cmd/x", mod, "module path"}},
		{"parent directory", []pkg{p("internal/a/b", "a")},
			[]string{mod + "/internal/a/b", "parent directory"}},
	} {
		_, _, err := plan(mod, c.pkgs)
		if err == nil {
			t.Errorf("%s: no error", c.name)
			continue
		}
		for _, w := range c.want {
			if !strings.Contains(err.Error(), w) {
				t.Errorf("%s: error %q lacks %q", c.name, err, w)
			}
		}
	}
}

// writeModule makes a module in a new directory with the given files.
func writeModule(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	files["go.mod"] = "module " + mod + "\n\ngo 1.21\n"
	for name, body := range files {
		full := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func runIn(t *testing.T, dir string, args ...string) (int, string, string) {
	t.Helper()
	t.Chdir(dir)
	var out, errb bytes.Buffer
	rc := run(args, &out, &errb)
	return rc, out.String(), errb.String()
}

func TestRunPackageArgumentOfMutantTest(t *testing.T) {
	dir := writeModule(t, map[string]string{
		"cmd/app/main.go":          "package main\n\nfunc main() {}\n",
		"cmd/app/main_test.go":     "package main\n",
		"internal/cfg/cfg.go":      "package cfg\n",
		"internal/cfg/cfg_test.go": "package cfg\n",
	})
	rc, out, errs := runIn(t, dir, "./cmd/app")
	if rc != 0 || out != mod+" "+mod+"/cmd/app\n" {
		t.Errorf("cmd/app: rc %d, out %q, err %q", rc, out, errs)
	}
	rc, out, errs = runIn(t, dir, "./internal/cfg")
	if rc != 0 || out != "" {
		t.Errorf("internal/cfg: rc %d, out %q, err %q", rc, out, errs)
	}
}

func TestRunRefusesPackageThatIsNotKnown(t *testing.T) {
	dir := writeModule(t, map[string]string{
		"tools/a/main.go": "package main\n\nfunc main() {}\n",
		"tools/b/main.go": "package main\n\nfunc main() {}\n",
	})
	rc, out, errs := runIn(t, dir, "./tools")
	if rc != 2 || out != "" || !strings.Contains(errs, mod+"/tools/a") || !strings.Contains(errs, mod+"/tools/b") {
		t.Errorf("rc %d, out %q, err %q", rc, out, errs)
	}
}

func TestRunErrors(t *testing.T) {
	dir := writeModule(t, map[string]string{"a/a.go": "package a\n"})
	if rc, _, _ := runIn(t, dir); rc != 2 {
		t.Errorf("no argument: rc %d, want 2", rc)
	}
	if rc, _, _ := runIn(t, dir, "./missing"); rc != 1 {
		t.Errorf("missing directory: rc %d, want 1", rc)
	}
}

// fakeGo is a go command that prints each argument on its own line.
const fakeGo = "#!/bin/sh\nfor a; do echo \"arg:$a\"; done\n"

func wrapperRun(t *testing.T, from, to string, args ...string) (string, error) {
	t.Helper()
	if _, err := exec.LookPath("timeout"); err != nil {
		t.Skip("no timeout command")
	}
	dir := t.TempDir()
	goBin := filepath.Join(dir, "fakego")
	if err := os.WriteFile(goBin, []byte(fakeGo), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", append([]string{"../mutate-go.sh"}, args...)...)
	cmd.Env = append(os.Environ(), "MUTATE_GO="+goBin, "MUTATE_CAP=30", "MUTATE_RUN="+dir,
		"MUTATE_FROM="+from, "MUTATE_TO="+to)
	out, err := cmd.Output()
	return string(out), err
}

func TestWrapperPackageArgumentOfMutantTest(t *testing.T) {
	for _, c := range []struct {
		name     string
		from, to string
		args     []string
		want     string
	}{
		{"last argument is the module path", mod, mod + "/cmd/app",
			[]string{"test", "-timeout", "1s", "-failfast", mod},
			"arg:test\narg:-timeout\narg:1s\narg:-failfast\narg:" + mod + "/cmd/app\n"},
		{"module path in another position", mod, mod + "/cmd/app",
			[]string{"test", mod, "-failfast", "./x"},
			"arg:test\narg:" + mod + "\narg:-failfast\narg:./x\n"},
		{"another go command", mod, mod + "/cmd/app",
			[]string{"list", mod},
			"arg:list\narg:" + mod + "\n"},
		{"no replacement set", "", "",
			[]string{"test", mod},
			"arg:test\narg:" + mod + "\n"},
		{"argument with a space", mod, mod + "/cmd/app",
			[]string{"test", "-run", "a b", mod},
			"arg:test\narg:-run\narg:a b\narg:" + mod + "/cmd/app\n"},
	} {
		got, err := wrapperRun(t, c.from, c.to, c.args...)
		if err != nil || got != c.want {
			t.Errorf("%s: got %q (%v), want %q", c.name, got, err, c.want)
		}
	}
}
