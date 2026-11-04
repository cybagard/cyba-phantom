// Command mutatepkg tells "make mutate" which package to test for each
// mutant. It refuses a PKG when it cannot know the package.
//
// Usage:
//
//	mutatepkg <pkg>
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
// Exit codes: 0 done, 1 go list failed, 2 usage or a refused PKG.
package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
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

// list returns the module path and the packages at and below dir, from go
// list. It skips a package with no Go file that is not a test.
func list(dir string) (string, []pkg, error) {
	pattern := strings.TrimSuffix(dir, "/") + "/..."
	format := "{{.Module.Path}}|{{.Module.Dir}}|{{.ImportPath}}|{{.Dir}}|{{.Name}}|{{len .GoFiles}}|{{len .CgoFiles}}"
	var stderr bytes.Buffer
	cmd := exec.Command("go", "list", "-f", format, pattern)
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", nil, fmt.Errorf("go list %s: %v\n%s", pattern, err, stderr.String())
	}
	var module string
	var pkgs []pkg
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		f := strings.Split(line, "|")
		if len(f) != 7 {
			return "", nil, fmt.Errorf("go list %s: unexpected line %q", pattern, line)
		}
		files, _ := strconv.Atoi(f[5])
		cgo, _ := strconv.Atoi(f[6])
		if files+cgo == 0 {
			continue
		}
		rel, err := filepath.Rel(f[1], f[3])
		if err != nil {
			return "", nil, err
		}
		module = f[0]
		pkgs = append(pkgs, pkg{Import: f[2], Rel: filepath.ToSlash(rel), Name: f[4]})
	}
	if len(pkgs) == 0 {
		return "", nil, fmt.Errorf("go list %s: no package with Go files", pattern)
	}
	return module, pkgs, nil
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 || args[0] == "" {
		fmt.Fprintln(stderr, "usage: mutatepkg <pkg>")
		return 2
	}
	module, pkgs, err := list(args[0])
	if err != nil {
		fmt.Fprintln(stderr, "mutate:", err)
		return 1
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
