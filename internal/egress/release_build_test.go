package egress_test

import (
	"debug/buildinfo"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestTS21ReleaseBuildReadsNoGoEnvFile checks that make build ignores the go
// env file. The test writes a file that sets GOFLAGS to a sentinel tag. It
// shows that the go tool reads this file. Then it runs make build and fails
// when a binary records a -tags setting. The test cannot see a GOFLAGS
// variable of the caller. It does not see other go env file settings that
// leave no -tags setting. It builds for the host platform only.
func TestTS21ReleaseBuildReadsNoGoEnvFile(t *testing.T) {
	const flag = "-tags=ts21sentinel"
	goEnvFile := filepath.Join(t.TempDir(), "env")
	if err := os.WriteFile(goEnvFile, []byte("GOFLAGS="+flag+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The variables below can hide the file or change the make child.
	var env []string
	for _, e := range os.Environ() {
		name, _, _ := strings.Cut(e, "=")
		switch name {
		case "GOFLAGS", "MAKEFLAGS", "MFLAGS", "MAKELEVEL", "GOENV":
		default:
			env = append(env, e)
		}
	}
	env = append(env, "GOENV="+goEnvFile)

	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("the go tool is not on PATH: %v", err)
	}
	control := exec.Command(goTool, "env", "GOFLAGS")
	control.Env = env
	out, err := control.CombinedOutput()
	if err != nil || strings.TrimSpace(string(out)) != flag {
		t.Fatalf("control: go env GOFLAGS = %q, %v; want %q", out, err, flag)
	}

	makeTool, err := exec.LookPath("make")
	if err != nil {
		t.Fatalf("make is not on PATH: %v", err)
	}
	binDir := t.TempDir()
	build := exec.Command(makeTool, "-C", moduleRoot(t), "build", "BINDIR="+binDir)
	build.Env = env
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("make build: %v\n%s", err, out)
	}

	for _, name := range []string{"phantom", "phantom-verify"} {
		info, err := buildinfo.ReadFile(filepath.Join(binDir, name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, s := range info.Settings {
			if s.Key == "-tags" {
				t.Errorf("%s records -tags=%s: make build read the go env file", name, s.Value)
			}
		}
	}
}
