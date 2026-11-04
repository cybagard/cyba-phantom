// Command mutatepkg tells "make mutate" which package to test for each
// mutant. It refuses a PKG when it cannot know the package.
//
// Usage:
//
//	mutatepkg <pkg>
//	mutatepkg -check <run directory> <replacement>
//
// Run it in the module root. <pkg> is the PKG of "make mutate", a directory
// such as ./cmd/phantom. The packages are the ones below it, itself included.
//
// Gremlins finds the package of a mutant from the package name of the mutated
// file. It walks up from the directory of the file, to the first directory
// whose path ends with the package name. If there is none, it uses the module
// path. Then the test run of the mutant fails at once, and gremlins counts the
// failure as a kill. A package main in cmd/phantom is such a package.
//
// mutatepkg gives each package the same walk. A package whose directory is
// found is right. Each other package gets the module path from gremlins.
//   - One package gets the module path, and it is not the module root
//     package. mutatepkg prints "<module path> <import path>". The go wrapper
//     (mutate-go.sh) replaces the first with the second.
//   - No package gets the module path, or only the module root package does.
//     It prints nothing.
//   - Two or more packages get the module path. Or a package gets another
//     directory (a parent). It cannot know the package of a mutant. It names
//     the packages on stderr and exits 2.
//
// Gremlins reads the module name from the first line of go.mod, with the
// prefix "module " removed. If that text is not the module path from go
// list, mutatepkg names both and exits 2. A comment on the line does this.
//
// The -check mode runs after gremlins. <run directory> is an absolute path.
// <replacement> is the output of the first mode. It reads the files out,
// replaced and test-output.* in the run directory. It also reads MUTATE_FROM
// and MUTATE_TO from its environment. It prints one "mutate FAIL:" line and
// exits 1 in five cases.
//   - MUTATE_FROM and MUTATE_TO are not the two halves of <replacement>. The
//     halves are the text before and after its first space. Both must be
//     empty if <replacement> is empty.
//   - A replacement was planned, the file replaced is not a regular file,
//     and the gremlins output has a mutant status.
//   - The counts are unknown. Two lines give them: "Killed, Lived" and
//     "Timed out, Not viable". Each must be in the gremlins output once,
//     after the line "Mutation testing completed".
//   - Killed, Lived and Timed out are 0, and Not viable is not 0.
//   - A test-output file has the FAIL line of a setup failure.
//
// Exit codes: 0 done, 1 a failed check, 2 usage or a refused PKG. Exit code 2
// also means -check got an empty or a relative run directory. Exit code 1
// also means go list failed or no package matches PKG.
package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// pkg is a package with Go files that are not tests.
type pkg struct {
	Import string // import path
	Rel    string // directory relative to the module root, "." for the root
	Name   string // package name
}

// mapped returns the directory that gremlins picks for a package. It walks
// up from the package directory. It stops at the first directory whose path
// ends with the package name. It returns "." (the module path) if none does.
func mapped(p pkg) string {
	for d := p.Rel; d != "."; d = path.Dir(d) {
		if strings.HasSuffix(d, p.Name) {
			return d
		}
	}
	return "."
}

// plan returns the replacement for the module path, or empty strings if none
// is needed. It returns an error that names the packages if no replacement
// is right.
func plan(module string, pkgs []pkg) (from, to string, err error) {
	var module0, wrong []pkg // module0: packages that get the module path
	for _, p := range pkgs {
		switch m := mapped(p); {
		case m == p.Rel:
			if m == "." {
				module0 = append(module0, p)
			}
		case m == ".":
			module0 = append(module0, p)
		default:
			wrong = append(wrong, p)
		}
	}
	if len(wrong) > 0 {
		return "", "", fmt.Errorf("gremlins maps %s to a parent directory, so the package of a mutant is not known",
			describe(wrong))
	}
	if len(module0) > 1 {
		return "", "", fmt.Errorf("gremlins maps %s to the module path, so the package of a mutant is not known",
			describe(module0))
	}
	if len(module0) == 1 && module0[0].Rel != "." {
		return module, module0[0].Import, nil
	}
	return "", "", nil
}

// describe names packages by import path and package name.
func describe(pkgs []pkg) string {
	s := make([]string, len(pkgs))
	for i, p := range pkgs {
		s[i] = "package " + p.Import + " (name " + p.Name + ")"
	}
	return strings.Join(s, ", ")
}

// list returns the module path, the module directory and the packages at and
// below dir, from go list. It skips a package with no Go file that is not a
// test.
func list(dir string) (string, string, []pkg, error) {
	pattern := strings.TrimSuffix(dir, "/") + "/..."
	format := "{{.Module.Path}}|{{.Module.Dir}}|{{.ImportPath}}|{{.Dir}}|{{.Name}}|{{len .GoFiles}}|{{len .CgoFiles}}"
	var stderr bytes.Buffer
	cmd := exec.Command("go", "list", "-f", format, pattern)
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", "", nil, fmt.Errorf("go list %s: %v\n%s", pattern, err, stderr.String())
	}
	text := strings.TrimSpace(string(out))
	if text == "" {
		return "", "", nil, fmt.Errorf("no package matches the pattern %s", pattern)
	}
	var module, moduleDir string
	var pkgs []pkg
	for _, line := range strings.Split(text, "\n") {
		f := strings.Split(line, "|")
		if len(f) != 7 {
			return "", "", nil, fmt.Errorf("go list %s: unexpected line %q", pattern, line)
		}
		files, _ := strconv.Atoi(f[5])
		cgo, _ := strconv.Atoi(f[6])
		if files+cgo == 0 {
			continue
		}
		rel, err := filepath.Rel(f[1], f[3])
		if err != nil {
			return "", "", nil, err
		}
		module, moduleDir = f[0], f[1]
		pkgs = append(pkgs, pkg{Import: f[2], Rel: filepath.ToSlash(rel), Name: f[4]})
	}
	if len(pkgs) == 0 {
		return "", "", nil, fmt.Errorf("go list %s: no package with Go files", pattern)
	}
	return module, moduleDir, pkgs, nil
}

// checkGoMod compares the module path with the name that gremlins reads. It
// takes the first line of go.mod in dir and removes the prefix "module ".
func checkGoMod(dir, module string) error {
	data, err := os.ReadFile(filepath.Join(dir, "go.mod"))
	if err != nil {
		return err
	}
	first, _, _ := bytes.Cut(data, []byte("\n"))
	if name := string(bytes.TrimPrefix(first, []byte("module "))); name != module {
		return fmt.Errorf("gremlins reads the module name %q from the first line of go.mod, but the module path is %q", name, module)
	}
	return nil
}

// Patterns of the gremlins output and of the FAIL line that the go wrapper
// (mutate-go.sh) turns into exit status 2. A summary line is a whole line.
var (
	statusLine  = regexp.MustCompile(`(?m)^ *(KILLED|LIVED|TIMED OUT|NOT VIABLE) `)
	completed   = regexp.MustCompile(`(?m)^Mutation testing completed`)
	killedLived = regexp.MustCompile(`(?m)^ *Killed: (\d+), Lived: (\d+), Not covered: \d+$`)
	timedViable = regexp.MustCompile(`(?m)^ *Timed out: (\d+), Not viable: (\d+), Skipped: \d+$`)
	setupFailed = regexp.MustCompile(`(?m)^FAIL\t[^ \t]+ \[setup failed\]$`)
)

// count returns the two numbers of the one match of re in text. It returns
// an error that names the two counts if there is no match or more than one.
func count(re *regexp.Regexp, text, names string) (int, int, error) {
	ms := re.FindAllStringSubmatch(text, -1)
	switch {
	case len(ms) == 0:
		return 0, 0, fmt.Errorf("gremlins printed no line with %s, so the check cannot count the mutants", names)
	case len(ms) > 1:
		return 0, 0, fmt.Errorf("gremlins printed %d lines with %s, so the check cannot count the mutants", len(ms), names)
	}
	a, _ := strconv.Atoi(ms[0][1])
	b, _ := strconv.Atoi(ms[0][2])
	return a, b, nil
}

// checkRun reads the run directory of "make mutate" after gremlins ended. It
// returns an error that names the cause if no mutant ran a test on PKG.
// The environment variables MUTATE_FROM and MUTATE_TO must be the two halves
// of fix. These are the values that the go wrapper reads. Both are empty if
// fix is empty.
// It also returns an error if the output lacks a summary line, or has
// one twice. The counts are then unknown. Both lines come after the line
// "Mutation testing completed". The file "out" has the gremlins output.
// The file "replaced" must be a regular file. It has a line for each
// replacement of the go wrapper. fix is the output of the plan mode.
//
// The go wrapper writes a file test-output.<pid> for each go test call. That
// includes the pre-check and the coverage run of gremlins. Both passed, or
// the run would have ended before this check, so they have no setup FAIL line.
func checkRun(dir, fix string) error {
	from, to, _ := strings.Cut(fix, " ")
	envFrom, envTo := os.Getenv("MUTATE_FROM"), os.Getenv("MUTATE_TO")
	if envFrom != from || envTo != to {
		return fmt.Errorf("MUTATE_FROM %q and MUTATE_TO %q are not the plan %q %q, so a mutant can test another package", envFrom, envTo, from, to)
	}
	data, err := os.ReadFile(filepath.Join(dir, "out"))
	if err != nil {
		return err
	}
	out := string(data)
	if fix != "" && statusLine.MatchString(out) {
		if fi, err := os.Lstat(filepath.Join(dir, "replaced")); err != nil || !fi.Mode().IsRegular() {
			return fmt.Errorf("the go wrapper replaced no package (%s with %s), so no mutant ran on PKG", from, to)
		}
	}
	loc := completed.FindStringIndex(out)
	if loc == nil {
		return fmt.Errorf("the gremlins output has no completed line, so the check cannot count the mutants")
	}
	summary := out[loc[1]:]
	killed, lived, err := count(killedLived, summary, "Killed and Lived")
	if err != nil {
		return err
	}
	timed, viable, err := count(timedViable, summary, "Timed out and Not viable")
	if err != nil {
		return err
	}
	if killed+lived+timed == 0 && viable != 0 {
		return fmt.Errorf("no mutant ran a test (killed, lived and timed out are 0, not viable is %d)", viable)
	}
	files, err := filepath.Glob(filepath.Join(dir, "test-output.*"))
	if err != nil {
		return err
	}
	for _, f := range files {
		text, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		if setupFailed.Match(text) {
			return fmt.Errorf("the package could not load in a go test call (%s), so no mutant ran", filepath.Base(f))
		}
	}
	return nil
}

func run(args []string, stdout, stderr io.Writer) int {
	const usage = "usage: mutatepkg <pkg> | mutatepkg -check <run directory> <replacement>"
	if len(args) > 0 && args[0] == "-check" {
		if len(args) != 3 || !filepath.IsAbs(args[1]) {
			fmt.Fprintln(stderr, usage)
			return 2
		}
		if err := checkRun(args[1], args[2]); err != nil {
			fmt.Fprintln(stderr, "mutate FAIL:", err)
			return 1
		}
		return 0
	}
	if len(args) != 1 || args[0] == "" {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	module, moduleDir, pkgs, err := list(args[0])
	if err != nil {
		fmt.Fprintln(stderr, "mutate:", err)
		return 1
	}
	if err := checkGoMod(moduleDir, module); err != nil {
		fmt.Fprintf(stderr, "mutate: PKG %s refused: %v\n", args[0], err)
		return 2
	}
	from, to, err := plan(module, pkgs)
	if err != nil {
		fmt.Fprintf(stderr, "mutate: PKG %s refused: %v\n", args[0], err)
		return 2
	}
	if from != "" {
		fmt.Fprintln(stdout, from, to)
	}
	return 0
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}
