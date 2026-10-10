package verify

import (
	"os/exec"
	"strings"
	"testing"
)

// TestVerifierImportsNoNetwork checks that the verifier opens no network
// connection (SEC-18, T-S-14). The list of packages that the verifier code
// needs, with the test files left out, must not hold a network package.
func TestVerifierImportsNoNetwork(t *testing.T) {
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("the go tool is not on PATH: %v", err)
	}
	forbidden := map[string]bool{"net": true, "net/http": true, "crypto/tls": true}
	for _, pkg := range []string{
		"github.com/cybagard/cyba-phantom/internal/verify",
		"github.com/cybagard/cyba-phantom/internal/tlog/verifier",
	} {
		out, err := exec.Command(goTool, "list", "-deps", pkg).CombinedOutput()
		if err != nil {
			t.Fatalf("go list -deps %s: %v\n%s", pkg, err, out)
		}
		deps := strings.Fields(string(out))
		if len(deps) == 0 {
			t.Fatalf("go list -deps %s printed no package", pkg)
		}
		for _, dep := range deps {
			if forbidden[dep] {
				t.Errorf("%s depends on %s", pkg, dep)
			}
		}
	}
}
