package verify

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestTS14_NoNetworkOrExecImports checks that the verifier code imports none of
// the packages in forbidden: the packages for the network, for a child process,
// for plugins and for cgo, and the x/sys packages (SEC-18, T-S-14). The test
// lists the packages that the verifier code needs, with the test files left
// out, for each GOOS, GOARCH and cgo setting in the loop.
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
		// The standard library of GOOS has this package, and not the other one.
		present, absent := "internal/syscall/unix", "internal/syscall/windows"
		if goos == "windows" {
			present, absent = absent, present
		}
		for _, goarch := range []string{"amd64", "arm64"} {
			for _, cgo := range []string{"0", "1"} {
				t.Run(goos+"/"+goarch+"/cgo="+cgo, func(t *testing.T) {
					for _, pkg := range pkgs {
						cmd := exec.Command(goTool, "list", "-deps", pkg)
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
						found, hasPresent, hasAbsent := false, false, false
						for _, dep := range strings.Fields(string(out)) {
							switch dep {
							case pkg:
								found = true
							case present:
								hasPresent = true
							case absent:
								hasAbsent = true
							}
							if forbidden[dep] {
								t.Errorf("%s depends on %s", pkg, dep)
							}
						}
						if !found {
							t.Errorf("go list -deps %s did not list the package itself", pkg)
						}
						if pkg == self && (!hasPresent || hasAbsent) {
							t.Errorf("go list did not use GOOS=%s: the deps of %s must hold %s and must not hold %s",
								goos, pkg, present, absent)
						}
					}
				})
			}
		}
	}
}
