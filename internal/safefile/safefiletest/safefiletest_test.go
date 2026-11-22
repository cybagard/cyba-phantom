package safefiletest_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// program calls the real Set in a binary that is not a test binary. A fake
// testing.TB records the failure, so Fatalf returns and Set runs on if it
// does not stop itself.
const program = `package main

import (
	"fmt"
	"testing"

	"github.com/cybagard/cyba-phantom/internal/safefile/safefiletest"
)

type fakeT struct {
	testing.TB
	msg      string
	cleanups int
}

func (f *fakeT) Helper()                       {}
func (f *fakeT) Cleanup(func())                { f.cleanups++ }
func (f *fakeT) Fatalf(s string, a ...any)     { f.msg = fmt.Sprintf(s, a...) }

func main() {
	f := &fakeT{}
	safefiletest.Set(f, safefiletest.Hooks{})
	fmt.Printf("msg=%q cleanups=%d\n", f.msg, f.cleanups)
}
`

func TestTS23_SetFailsOutsideTestBinary(t *testing.T) {
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	top, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	// An overlay puts the program in the module without a file there.
	tmp := t.TempDir()
	src := filepath.Join(tmp, "main.go")
	if err := os.WriteFile(src, []byte(program), 0o600); err != nil {
		t.Fatal(err)
	}
	virtual := filepath.Join(top, "internal", "safefile", "safefiletest", "outside", "main.go")
	overlay, err := json.Marshal(map[string]map[string]string{"Replace": {virtual: src}})
	if err != nil {
		t.Fatal(err)
	}
	ov := filepath.Join(tmp, "overlay.json")
	if err := os.WriteFile(ov, overlay, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(goTool, "run", "-overlay", ov,
		"./internal/safefile/safefiletest/outside")
	cmd.Dir = top
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go run: %v\n%s", err, out)
	}
	got := string(out)
	if !strings.Contains(got, "test binaries only") {
		t.Errorf("Set did not fail outside a test binary: %s", got)
	}
	if !strings.Contains(got, "cleanups=0") {
		t.Errorf("Set installed hooks outside a test binary: %s", got)
	}
}
