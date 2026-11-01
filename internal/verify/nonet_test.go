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
// network, child processes, plugins, cgo and x/sys. The test lists the
// dependencies without test files for each GOOS, GOARCH and cgo setting. It
// also checks the GOOS of each output line.
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
	for _, goos := range []string{"linux", "darwin", "windows", "freebsd"} {
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
}
