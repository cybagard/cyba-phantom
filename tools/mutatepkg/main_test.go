package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
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
	if _, ok := files["go.mod"]; !ok {
		files["go.mod"] = "module " + mod + "\n\ngo 1.21\n"
	}
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
		"cmd/app/e2e/e2e_test.go":  "package main\n",
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

func TestRunPackageWithCgoFile(t *testing.T) {
	t.Setenv("CGO_ENABLED", "1")
	dir := writeModule(t, map[string]string{
		"cmd/app/main.go": "package main\n\nfunc main() {}\n",
		"cmd/app/c.go":    "package main\n\nimport \"C\"\n",
	})
	rc, out, errs := runIn(t, dir, "./cmd/app")
	if rc != 0 || out != mod+" "+mod+"/cmd/app\n" {
		t.Errorf("cgo package: rc %d, out %q, err %q", rc, out, errs)
	}
}

func TestRunRefusesGoModNameThatGremlinsReadsWrong(t *testing.T) {
	for _, c := range []struct{ name, gomod string }{
		{"comment on the first line", "// comment\nmodule " + mod + "\n\ngo 1.21\n"},
		{"comment after the module path", "module " + mod + " // c\n\ngo 1.21\n"},
	} {
		dir := writeModule(t, map[string]string{
			"go.mod":          c.gomod,
			"cmd/app/main.go": "package main\n\nfunc main() {}\n",
		})
		rc, out, errs := runIn(t, dir, "./cmd/app")
		if rc != 2 || out != "" || !strings.Contains(errs, "go.mod") || !strings.Contains(errs, strconv.Quote(mod)) {
			t.Errorf("%s: rc %d, out %q, err %q", c.name, rc, out, errs)
		}
	}
}

func TestRunNoPackageMatchesPattern(t *testing.T) {
	dir := writeModule(t, map[string]string{"cmd/app/main.go": "package main\n\nfunc main() {}\n"})
	rc, out, errs := runIn(t, dir, "cmd/app")
	if rc != 1 || out != "" || !strings.Contains(errs, "no package matches the pattern") {
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

// wrapperCall runs the wrapper with a fake go command (the script goScript)
// and the extra environment env. It returns the output, the exit status and
// the MUTATE_RUN directory.
func wrapperCall(t *testing.T, goScript string, env []string, args ...string) (string, int, string) {
	t.Helper()
	if _, err := exec.LookPath("timeout"); err != nil {
		t.Skip("no timeout command")
	}
	dir := t.TempDir()
	goBin := filepath.Join(dir, "fakego")
	if err := os.WriteFile(goBin, []byte(goScript), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", append([]string{"../mutate-go.sh"}, args...)...)
	cmd.Env = append(append(os.Environ(), "MUTATE_GO="+goBin, "MUTATE_CAP=30", "MUTATE_RUN="+dir), env...)
	out, err := cmd.Output()
	rc := 0
	if ee, ok := err.(*exec.ExitError); ok {
		rc = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return string(out), rc, dir
}

func wrapperRun(t *testing.T, from, to string, args ...string) (string, error) {
	t.Helper()
	out, rc, _ := wrapperCall(t, fakeGo, []string{"MUTATE_FROM=" + from, "MUTATE_TO=" + to}, args...)
	if rc != 0 {
		return out, fmt.Errorf("exit status %d", rc)
	}
	return out, nil
}

func TestWrapperWritesReplacedLineForEachReplacement(t *testing.T) {
	for _, c := range []struct {
		name string
		args []string
		want string
	}{
		{"replacement", []string{"test", mod}, "\n"},
		{"last argument is not the module path", []string{"test", mod, "./x"}, ""},
		{"other go command", []string{"list", mod}, ""},
	} {
		_, rc, dir := wrapperCall(t, fakeGo, []string{"MUTATE_FROM=" + mod, "MUTATE_TO=" + mod + "/cmd/app"}, c.args...)
		got, err := os.ReadFile(filepath.Join(dir, "replaced"))
		if rc != 0 || (c.want == "" && err == nil) || (c.want != "" && string(got) != c.want) {
			t.Errorf("%s: rc %d, replaced %q (%v), want %q", c.name, rc, got, err, c.want)
		}
	}
	_, _, dir := wrapperCall(t, fakeGo, []string{"MUTATE_FROM=", "MUTATE_TO="}, "test", mod)
	if _, err := os.Stat(filepath.Join(dir, "replaced")); err == nil {
		t.Error("no replacement set: the file replaced exists")
	}
}

func TestWrapperExitsTwoWhenTestCannotLoadOrBuild(t *testing.T) {
	setup := "#!/bin/sh\nprintf 'no required module provides package x\\nFAIL\\t" + mod + " [setup failed]\\n'\nexit 1\n"
	build := "#!/bin/sh\nprintf '# " + mod + "\\nx.go:1:1: bad\\nFAIL\\t" + mod + " [build failed]\\n'\nexit 1\n"
	failing := "#!/bin/sh\nprintf -- '--- FAIL: TestX (0.00s)\\nFAIL\\nFAIL\\t" + mod + "\\t0.01s\\nFAIL\\n'\nexit 1\n"
	for _, c := range []struct {
		name   string
		script string
		args   []string
		rc     int
		want   string
	}{
		{"setup failed", setup, []string{"test", mod}, 2, "FAIL\t" + mod + " [setup failed]"},
		{"build failed", build, []string{"test", mod}, 2, "FAIL\t" + mod + " [build failed]"},
		{"test failure", failing, []string{"test", mod}, 1, "--- FAIL: TestX"},
		{"another go command", setup, []string{"build", mod}, 1, "[setup failed]"},
	} {
		out, rc, dir := wrapperCall(t, c.script, nil, c.args...)
		if rc != c.rc || !strings.Contains(out, c.want) {
			t.Errorf("%s: rc %d, out %q, want rc %d and %q", c.name, rc, out, c.rc, c.want)
		}
		if c.args[0] == "test" {
			files, _ := filepath.Glob(filepath.Join(dir, "test-output.*"))
			if len(files) != 1 {
				t.Errorf("%s: output files %v, want one", c.name, files)
			}
		}
	}
}

func TestWrapperRecordsGoCommandStoppedAtTimeLimit(t *testing.T) {
	out, rc, dir := wrapperCall(t, "#!/bin/sh\nexec sleep 30\n", []string{"MUTATE_CAP=1"}, "build", mod)
	got, err := os.ReadFile(filepath.Join(dir, "capped"))
	if rc != 137 || string(got) != "\n" {
		t.Errorf("rc %d, out %q, capped %q (%v), want 137 and one line", rc, out, got, err)
	}
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

const (
	done     = "Mutation testing completed in 1 second\n"
	goodSums = "Killed: 437, Lived: 12, Not covered: 53\nTimed out: 2, Not viable: 8, Skipped: 0\n"
	zeroSums = "Killed: 0, Lived: 0, Not covered: 0\nTimed out: 0, Not viable: 30, Skipped: 0\n"
	goodOut  = "     KILLED CONDITIONALS_BOUNDARY at x.go:1:2\n" + done + goodSums
	zeroOut  = "  NOT VIABLE CONDITIONALS_BOUNDARY at x.go:1:2\n" + done + zeroSums

	passOutput  = "ok  \t" + mod + "\t0.01s\n"
	setupOutput = "no required module provides package x\nFAIL\t" + mod + " [setup failed]\n"
	buildOutput = "x.go:1:1: bad\nFAIL\t" + mod + " [build failed]\n"
)

// runDir makes a run directory with the given files and runs the check mode.
// MUTATE_FROM and MUTATE_TO have the two halves of fix.
func runDir(t *testing.T, files map[string]string, fix string) (int, string) {
	t.Helper()
	from, to, _ := strings.Cut(fix, " ")
	return runDirEnv(t, files, fix, from, to)
}

// runDirEnv is runDir with the given MUTATE_FROM and MUTATE_TO. A file name
// that ends in a slash makes a directory.
func runDirEnv(t *testing.T, files map[string]string, fix, from, to string) (int, string) {
	t.Helper()
	t.Setenv("MUTATE_FROM", from)
	t.Setenv("MUTATE_TO", to)
	dir := t.TempDir()
	for name, body := range files {
		if strings.HasSuffix(name, "/") {
			if err := os.Mkdir(filepath.Join(dir, name), 0o755); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var out, errb bytes.Buffer
	rc := run([]string{"-check", dir, fix}, &out, &errb)
	if out.Len() != 0 {
		t.Errorf("stdout %q, want empty", out.String())
	}
	return rc, errb.String()
}

func TestCheckFailsWhenPlannedReplacementDidNotHappen(t *testing.T) {
	fix := mod + " " + mod + "/cmd/app"
	rc, errs := runDir(t, map[string]string{"out": goodOut}, fix)
	const want = "mutate FAIL: the go wrapper replaced no package (" + mod + " with " + mod + "/cmd/app)"
	if rc != 1 || !strings.HasPrefix(errs, want) || strings.Count(errs, "\n") != 1 {
		t.Errorf("rc %d, err %q", rc, errs)
	}
	// Only NOT VIABLE status lines are a mutant status as well.
	rc, errs = runDir(t, map[string]string{"out": zeroOut}, fix)
	if rc != 1 || !strings.HasPrefix(errs, want) || strings.Count(errs, "\n") != 1 {
		t.Errorf("only not viable: rc %d, err %q", rc, errs)
	}
	// A directory named replaced is no file that the wrapper wrote.
	rc, errs = runDir(t, map[string]string{"out": goodOut, "replaced/": ""}, fix)
	if rc != 1 || !strings.HasPrefix(errs, want) || strings.Count(errs, "\n") != 1 {
		t.Errorf("replaced is a directory: rc %d, err %q", rc, errs)
	}
	// The file replaced makes the same run pass.
	rc, errs = runDir(t, map[string]string{"out": goodOut, "replaced": "\n"}, fix)
	if rc != 0 || errs != "" {
		t.Errorf("with replaced: rc %d, err %q", rc, errs)
	}
	// No mutant status, so the guard has nothing to judge.
	rc, errs = runDir(t, map[string]string{"out": done + "Killed: 1, Lived: 0, Not covered: 0\n" +
		"Timed out: 0, Not viable: 0, Skipped: 0\n"}, fix)
	if rc != 0 || errs != "" {
		t.Errorf("no mutant status: rc %d, err %q", rc, errs)
	}
	// No replacement planned.
	rc, errs = runDir(t, map[string]string{"out": goodOut}, "")
	if rc != 0 || errs != "" {
		t.Errorf("no replacement planned: rc %d, err %q", rc, errs)
	}
}

func TestCheckFailsWhenNoMutantRanATest(t *testing.T) {
	// The file replaced exists and no test-output file does. Only the counts
	// tell.
	rc, errs := runDir(t, map[string]string{"out": zeroOut, "replaced": "\n"}, mod+" "+mod+"/cmd/app")
	if rc != 1 || !strings.HasPrefix(errs, "mutate FAIL: no mutant ran a test") || !strings.Contains(errs, "30") ||
		strings.Count(errs, "\n") != 1 {
		t.Errorf("rc %d, err %q", rc, errs)
	}
	for _, c := range []struct{ name, counts string }{
		{"a lived mutant", "Killed: 0, Lived: 1, Not covered: 0\nTimed out: 0, Not viable: 30, Skipped: 0\n"},
		{"a killed mutant", "Killed: 1, Lived: 0, Not covered: 0\nTimed out: 0, Not viable: 30, Skipped: 0\n"},
		{"a timed out mutant", "Killed: 0, Lived: 0, Not covered: 0\nTimed out: 1, Not viable: 30, Skipped: 0\n"},
		{"no mutant at all", "Killed: 0, Lived: 0, Not covered: 4\nTimed out: 0, Not viable: 0, Skipped: 0\n"},
		// The sum of the three counts, not a difference of two of them.
		{"killed and lived are equal", "Killed: 2, Lived: 2, Not covered: 0\nTimed out: 0, Not viable: 30, Skipped: 0\n"},
		{"lived and timed out are equal", "Killed: 0, Lived: 1, Not covered: 0\nTimed out: 1, Not viable: 30, Skipped: 0\n"},
		{"killed and timed out are equal", "Killed: 1, Lived: 0, Not covered: 0\nTimed out: 1, Not viable: 30, Skipped: 0\n"},
	} {
		rc, errs := runDir(t, map[string]string{"out": done + c.counts, "replaced": "\n"}, "")
		if rc != 0 || errs != "" {
			t.Errorf("%s: rc %d, err %q", c.name, rc, errs)
		}
	}
}

func TestCheckFailsWhenSummaryLineIsMissing(t *testing.T) {
	const (
		first  = "Killed: 5, Lived: 1, Not covered: 0\n"
		second = "Timed out: 0, Not viable: 2, Skipped: 0\n"
	)
	for _, c := range []struct{ name, out, want string }{
		{"no Killed line", done + second, "no line with Killed and Lived"},
		{"no Timed out line", done + first, "no line with Timed out and Not viable"},
		{"no summary", done, "no line with Killed and Lived"},
		{"no completed line", first + second, "no completed line"},
		{"Killed line twice", done + first + first + second, "2 lines with Killed and Lived"},
		{"Timed out line twice", done + first + second + second, "2 lines with Timed out and Not viable"},
		// A whole line before the completed line does not count.
		{"summary before completed line", first + second + done, "no line with Killed and Lived"},
		{"Killed line before completed line", first + done + second, "no line with Killed and Lived"},
	} {
		rc, errs := runDir(t, map[string]string{"out": c.out, "replaced": "\n"}, "")
		if rc != 1 || !strings.HasPrefix(errs, "mutate FAIL: the gremlins output has "+c.want) ||
			strings.Count(errs, "\n") != 1 {
			t.Errorf("%s: rc %d, err %q", c.name, rc, errs)
		}
	}
}

func TestCheckTakesSummaryFromWholeLinesOnly(t *testing.T) {
	// A status line with such a file name is no summary line. Only the
	// NOT VIABLE count tells that no mutant ran.
	out := done + "     KILLED X at Killed: 3, Lived: 0.go\n" + zeroSums
	rc, errs := runDir(t, map[string]string{"out": out, "replaced": "\n"}, "")
	if rc != 1 || !strings.HasPrefix(errs, "mutate FAIL: no mutant ran a test") {
		t.Errorf("file name in a status line: rc %d, err %q", rc, errs)
	}
	// The same text before the completed line, as a whole line.
	out = "Killed: 3, Lived: 0, Not covered: 0\n" + done + zeroSums
	rc, errs = runDir(t, map[string]string{"out": out, "replaced": "\n"}, "")
	if rc != 1 || !strings.HasPrefix(errs, "mutate FAIL: no mutant ran a test") {
		t.Errorf("summary before completed line: rc %d, err %q", rc, errs)
	}
	// Text after a summary line makes it no summary line.
	out = done + "Killed: 5, Lived: 1, Not covered: 0 x\n" + "Timed out: 0, Not viable: 2, Skipped: 0\n"
	rc, errs = runDir(t, map[string]string{"out": out, "replaced": "\n"}, "")
	if rc != 1 || !strings.HasPrefix(errs, "mutate FAIL: the gremlins output has no line with Killed and Lived") {
		t.Errorf("text after the line: rc %d, err %q", rc, errs)
	}
}

func TestCheckFailsWhenEnvIsNotTheReplacement(t *testing.T) {
	fix := mod + " " + mod + "/cmd/app"
	files := map[string]string{"out": goodOut, "replaced": "\n"}
	for _, c := range []struct {
		name, fix, from, to string
		ok                  bool
	}{
		{"both halves", fix, mod, mod + "/cmd/app", true},
		{"no replacement and no values", "", "", "", true},
		{"wrong to", fix, mod, mod + "/tools/dco", false},
		{"wrong from", fix, mod + "/x", mod + "/cmd/app", false},
		{"empty to", fix, mod, "", false},
		{"empty from", fix, "", mod + "/cmd/app", false},
		{"values with an empty fix", "", mod, mod + "/cmd/app", false},
		{"from with an empty fix", "", mod, "", false},
		{"to with an empty fix", "", "", mod + "/cmd/app", false},
	} {
		rc, errs := runDirEnv(t, files, c.fix, c.from, c.to)
		if c.ok && (rc != 0 || errs != "") {
			t.Errorf("%s: rc %d, err %q", c.name, rc, errs)
		}
		if !c.ok && (rc != 1 || !strings.HasPrefix(errs, "mutate FAIL: MUTATE_FROM or MUTATE_TO differs") ||
			strings.Count(errs, "\n") != 1) {
			t.Errorf("%s: rc %d, err %q", c.name, rc, errs)
		}
	}
}

func TestCheckRefusesRunDirectoryThatIsNotAbsolute(t *testing.T) {
	for _, dir := range []string{"", "run", "./run"} {
		var out, errb bytes.Buffer
		rc := run([]string{"-check", dir, ""}, &out, &errb)
		if rc != 2 || !strings.Contains(errb.String(), "usage: mutatepkg <pkg> | mutatepkg -check <run directory> <replacement>") {
			t.Errorf("dir %q: rc %d, err %q", dir, rc, errb.String())
		}
	}
}

func TestCheckFailsWhenPackageCannotLoad(t *testing.T) {
	rc, errs := runDir(t, map[string]string{
		"out":             goodOut,
		"replaced":        "\n",
		"test-output.100": passOutput,
		"test-output.200": setupOutput,
	}, mod+" "+mod+"/cmd/app")
	if rc != 1 || !strings.HasPrefix(errs, "mutate FAIL: the package could not load") || !strings.Contains(errs, "test-output.200") ||
		strings.Count(errs, "\n") != 1 {
		t.Errorf("rc %d, err %q", rc, errs)
	}
}

func TestCheckPassesGoodRun(t *testing.T) {
	// A build failure is a not viable mutant and is no cause to fail.
	rc, errs := runDir(t, map[string]string{
		"out":             goodOut,
		"replaced":        "\n",
		"test-output.100": passOutput,
		"test-output.200": buildOutput,
		"test-output.300": "--- FAIL: TestX (0.00s)\nFAIL\nFAIL\t" + mod + "\t0.01s\n",
		// Text after the bracket makes it no setup failure of the wrapper.
		"test-output.400": "FAIL\t" + mod + " [setup failed] more\n",
	}, mod+" "+mod+"/cmd/app")
	if rc != 0 || errs != "" {
		t.Errorf("rc %d, err %q", rc, errs)
	}
}

func TestCheckErrors(t *testing.T) {
	t.Setenv("MUTATE_FROM", "")
	t.Setenv("MUTATE_TO", "")
	var out, errb bytes.Buffer
	if rc := run([]string{"-check", t.TempDir(), ""}, &out, &errb); rc != 1 || !strings.HasPrefix(errb.String(), "mutate FAIL:") {
		t.Errorf("no out file: rc %d, err %q", rc, errb.String())
	}
	if rc := run([]string{"-check", t.TempDir()}, &out, &errb); rc != 2 {
		t.Errorf("missing argument: rc %d, want 2", rc)
	}
}

func TestMakefileCallsCheckAfterGremlins(t *testing.T) {
	data, err := os.ReadFile("../../Makefile")
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	// The whole recipe line of the call, from the tab to the line end, sits
	// after the end of the gremlins run and before the list of mutants.
	const call = "\n\t" + `"$$d/mutatepkg" -check "$$d" "$$fix" || exit $$?; \` + "\n"
	const ended = `grep -q 'Mutation testing completed' "$$d/out"`
	const list = "\n\t" + `echo "== not killed =="; \` + "\n"
	gremlins := strings.Index(text, `gremlins unleash`)
	end := strings.Index(text, ended)
	at := strings.Index(text, call)
	next := strings.Index(text, list)
	if strings.Count(text, call) != 1 || gremlins < 0 || end < gremlins || at < end || next < at {
		t.Errorf("positions: gremlins %d, ended %d, check %d, list %d", gremlins, end, at, next)
	}
	// The old guard tested MUTATE_FROM and needed the file replaced to be
	// missing. It saw neither a broken export nor a package that did not load.
	if strings.Contains(text, `[ -n "$$MUTATE_FROM" ] && [ ! -e "$$d/replaced" ]`) {
		t.Error("the Makefile still has the old guard")
	}
}
