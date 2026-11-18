package verify

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestTS14_NoNetworkOrExecImports checks that the verifier code imports no
// package from forbidden (SEC-18, T-S-14). The forbidden packages cover the
// network, child processes, plugins, cgo and x/sys. The verifier supports only
// Linux and macOS, so the import check covers only linux and darwin. It lists
// the dependencies without test files for each GOOS, GOARCH and cgo setting.
// It also checks the GOOS of each output line.
//
// The build check completes the import check. It takes each GOOS of
// "go tool dist list" at run time, except linux and darwin, with one GOARCH.
// Android and ios are in the list. For each GOOS, a build of the package must
// fail, and its output must name the verify guard or the safefile guard. So
// no other GOOS builds the verifier code without an import check. The check
// also needs the safefile package to have exactly one of safefile_unix.go and
// safefile_other.go, and a build with safefile_other.go must name its guard.
// The test fails if the list has no other GOOS.
//
// The test does not prove that the code opens no network connection. A package
// for raw system calls (syscall) is not forbidden, because package os needs it.
// A file behind a custom build tag is not checked. The review of the code is
// the other part of the proof.
func TestTS14_NoNetworkOrExecImports(t *testing.T) {
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("the go tool is not on PATH: %v", err)
	}
	forbidden := map[string]bool{
		"net": true, "net/http": true, "crypto/tls": true, "os/exec": true,
		"plugin": true, "runtime/cgo": true,
		"golang.org/x/sys/unix": true, "golang.org/x/sys/windows": true,
	}
	const self = "github.com/cybagard/cyba-phantom/internal/verify"
	pkgs := []string{
		self,
		"github.com/cybagard/cyba-phantom/internal/tlog/verifier",
		"github.com/cybagard/cyba-phantom/cmd/phantom-verify",
	}
	for _, goos := range []string{"linux", "darwin"} {
		for _, goarch := range []string{"amd64", "arm64"} {
			for _, cgo := range []string{"0", "1"} {
				t.Run(goos+"/"+goarch+"/cgo="+cgo, func(t *testing.T) {
					for _, pkg := range pkgs {
						cmd := exec.Command(goTool, "list", "-deps",
							"-f", "{{context.GOOS}} {{.ImportPath}}", pkg)
						// The last entry of a name wins. The entries after
						// os.Environ() replace the test environment.
						cmd.Env = append(os.Environ(),
							"GOOS="+goos, "GOARCH="+goarch, "CGO_ENABLED="+cgo,
							"GOFLAGS=-mod=readonly")
						out, listErr := cmd.Output()
						if listErr != nil {
							var exitErr *exec.ExitError
							if errors.As(listErr, &exitErr) {
								t.Errorf("go list -deps %s: %v\n%s", pkg, listErr, exitErr.Stderr)
							} else {
								t.Errorf("go list -deps %s: %v", pkg, listErr)
							}
							continue
						}
						found, wrongOS := false, false
						for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
							fields := strings.Fields(line)
							if len(fields) != 2 {
								t.Errorf("go list -deps %s: line %q is not \"GOOS import-path\"", pkg, line)
								continue
							}
							if fields[0] != goos {
								t.Errorf("go list -deps %s used GOOS=%s for %s, want %s",
									pkg, fields[0], fields[1], goos)
								wrongOS = true
								break
							}
							dep := fields[1]
							if dep == pkg {
								found = true
							}
							if forbidden[dep] {
								t.Errorf("%s depends on %s", pkg, dep)
							}
						}
						if !found && !wrongOS {
							t.Errorf("go list -deps %s did not list the package itself", pkg)
						}
					}
				})
			}
		}
	}

	listOut, err := exec.Command(goTool, "tool", "dist", "list").Output()
	if err != nil {
		t.Fatalf("go tool dist list: %v", err)
	}
	var otherOS []string
	archOf := map[string]string{}
	for _, line := range strings.Fields(string(listOut)) {
		goos, goarch, ok := strings.Cut(line, "/")
		if !ok {
			t.Fatalf("go tool dist list: line %q is not \"GOOS/GOARCH\"", line)
		}
		if goos == "linux" || goos == "darwin" {
			continue
		}
		if _, seen := archOf[goos]; !seen {
			archOf[goos] = goarch
			otherOS = append(otherOS, goos)
		}
	}
	if len(otherOS) == 0 {
		t.Fatal("go tool dist list has no GOOS other than linux and darwin")
	}
	guards := []string{
		"the_verify_package_supports_linux_and_darwin_only",
		"the_safefile_package_supports_unix_only",
	}
	for _, goos := range otherOS {
		t.Run(goos, func(t *testing.T) {
			cmd := exec.Command(goTool, "build", self)
			cmd.Env = append(os.Environ(),
				"GOOS="+goos, "GOARCH="+archOf[goos], "CGO_ENABLED=0",
				"GOFLAGS=-mod=readonly")
			out, buildErr := cmd.CombinedOutput()
			if buildErr == nil {
				t.Fatalf("go build %s for %s/%s succeeded, want a guard error",
					self, goos, archOf[goos])
			}
			named := false
			for _, guard := range guards {
				if strings.Contains(string(out), guard) {
					named = true
				}
			}
			if !named {
				t.Errorf("go build %s for %s/%s names no guard: %v\n%s",
					self, goos, archOf[goos], buildErr, out)
			}

			// The safefile package has the unix file or the guard file.
			// Neither file means that the package builds without a guard.
			const safefilePkg = "github.com/cybagard/cyba-phantom/internal/safefile"
			listCmd := exec.Command(goTool, "list",
				"-f", "{{range .GoFiles}}{{.}} {{end}}", safefilePkg)
			listCmd.Env = cmd.Env
			files, listErr := listCmd.Output()
			if listErr != nil {
				t.Fatalf("go list %s for %s/%s: %v", safefilePkg, goos, archOf[goos], listErr)
			}
			hasUnix, hasOther := false, false
			for _, f := range strings.Fields(string(files)) {
				hasUnix = hasUnix || f == "safefile_unix.go"
				hasOther = hasOther || f == "safefile_other.go"
			}
			if hasUnix == hasOther {
				t.Fatalf("%s/%s: safefile files %q: want exactly one of safefile_unix.go and safefile_other.go",
					goos, archOf[goos], files)
			}
			if !hasOther {
				return
			}
			safeCmd := exec.Command(goTool, "build", safefilePkg)
			safeCmd.Env = cmd.Env
			safeOut, safeErr := safeCmd.CombinedOutput()
			if safeErr == nil {
				t.Errorf("go build %s for %s/%s succeeded, want the guard error",
					safefilePkg, goos, archOf[goos])
			} else if !strings.Contains(string(safeOut), guards[1]) {
				t.Errorf("go build %s for %s/%s names no safefile guard: %v\n%s",
					safefilePkg, goos, archOf[goos], safeErr, safeOut)
			}
		})
	}
}
