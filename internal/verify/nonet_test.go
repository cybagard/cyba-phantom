package verify

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestTS14_NoNetworkOrExecImports checks that the verifier code imports no
// package for the network, for a child process, for plugins, for cgo or for raw
// system calls (SEC-18, T-S-14). For each of four operating systems, the list
// of packages that the verifier code needs, with the test files left out, must
// not hold one of these packages.
func TestTS14_NoNetworkOrExecImports(t *testing.T) {
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("the go tool is not on PATH: %v", err)
	}
	forbidden := map[string]bool{
		"net": true, "net/http": true, "crypto/tls": true, "os/exec": true,
		"plugin": true, "runtime/cgo": true, "golang.org/x/sys/unix": true,
	}
	for _, goos := range []string{"linux", "darwin", "windows", "freebsd"} {
		t.Run(goos, func(t *testing.T) {
			for _, pkg := range []string{
				"github.com/cybagard/cyba-phantom/internal/verify",
				"github.com/cybagard/cyba-phantom/internal/tlog/verifier",
				"github.com/cybagard/cyba-phantom/cmd/phantom-verify",
			} {
				cmd := exec.Command(goTool, "list", "-deps", pkg)
				cmd.Env = append(os.Environ(), "GOOS="+goos)
				out, err := cmd.Output()
				if err != nil {
					var exitErr *exec.ExitError
					if errors.As(err, &exitErr) {
						t.Fatalf("go list -deps %s: %v\n%s", pkg, err, exitErr.Stderr)
					}
					t.Fatalf("go list -deps %s: %v", pkg, err)
				}
				found := false
				for _, dep := range strings.Fields(string(out)) {
					if dep == pkg {
						found = true
					}
					if forbidden[dep] {
						t.Errorf("%s depends on %s", pkg, dep)
					}
				}
				if !found {
					t.Fatalf("go list -deps %s did not list the package itself", pkg)
				}
			}
		})
	}
}
