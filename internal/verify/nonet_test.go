package verify

import (
	"errors"
	"os/exec"
	"strings"
	"testing"
)

// TestTS14_NoNetworkImports checks that the verifier code imports no network
// package (SEC-18, T-S-14). The list of packages that the verifier code needs,
// with the test files left out, must not hold a network package.
func TestTS14_NoNetworkImports(t *testing.T) {
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("the go tool is not on PATH: %v", err)
	}
	forbidden := map[string]bool{"net": true, "net/http": true, "crypto/tls": true}
	for _, pkg := range []string{
		"github.com/cybagard/cyba-phantom/internal/verify",
		"github.com/cybagard/cyba-phantom/internal/tlog/verifier",
		"github.com/cybagard/cyba-phantom/cmd/phantom-verify",
	} {
		out, err := exec.Command(goTool, "list", "-deps", pkg).Output()
		if err != nil {
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				t.Fatalf("go list -deps %s: %v\n%s", pkg, err, exitErr.Stderr)
			}
			t.Fatalf("go list -deps %s: %v", pkg, err)
		}
		deps := strings.Fields(string(out))
		found := false
		for _, dep := range deps {
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
}
