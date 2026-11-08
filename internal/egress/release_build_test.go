package egress_test

import (
	"debug/buildinfo"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const ts21Flag = "-tags=ts21sentinel"

// TestTS21ReleaseBuildReadsNoGoEnvFile checks that make build ignores the go
// env file. The test writes a file that sets GOFLAGS to a sentinel tag. It
// shows that the go tool reads this file. Then it runs make build and fails
// when a binary records a -tags setting. The test has two rows. In the first
// row, GOENV names the file. In the second row, GOENV is not set and the
// file is in the default place, below XDG_CONFIG_HOME. The second row runs
// on linux only, the platform of the release build.
// The test cannot see a GOFLAGS variable of the caller. It does not see
// other go env file settings that leave no -tags setting. It does not see a
// recipe that sets GOENV to another fixed file. The test puts files only at
// the place that GOENV names and at the default place. It builds for the
// host platform only.
func TestTS21ReleaseBuildReadsNoGoEnvFile(t *testing.T) {
	t.Run("GOENV names the file", func(t *testing.T) {
		file := writeGoEnvFile(t, t.TempDir())
		checkReleaseBuild(t, append(cleanEnv(), "GOENV="+file), file)
	})
	t.Run("default file", func(t *testing.T) {
		if runtime.GOOS != "linux" {
			t.Skip("this row runs on linux only, not on " + runtime.GOOS)
		}
		xdg := t.TempDir()
		goDir := filepath.Join(xdg, "go")
		if err := os.Mkdir(goDir, 0o700); err != nil {
			t.Fatal(err)
		}
		file := writeGoEnvFile(t, goDir)
		env := append(cleanEnv(), "XDG_CONFIG_HOME="+xdg)
		checkReleaseBuild(t, env, file)
	})
}

// writeGoEnvFile writes a go env file named env in dir. The file sets GOFLAGS
// to the sentinel flag. It returns the path of the file.
func writeGoEnvFile(t *testing.T, dir string) string {
	t.Helper()
	file := filepath.Join(dir, "env")
	if err := os.WriteFile(file, []byte("GOFLAGS="+ts21Flag+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return file
}

// cleanEnv returns the environment of the test without some variables.
// These variables can hide the go env file or change the make child.
func cleanEnv() []string {
	var env []string
	for _, e := range os.Environ() {
		name, _, _ := strings.Cut(e, "=")
		switch name {
		case "GOFLAGS", "MAKEFLAGS", "MFLAGS", "MAKELEVEL", "GOENV":
		default:
			env = append(env, e)
		}
	}
	return env
}

// checkReleaseBuild shows that the go tool reads file when it runs with env.
// Then it runs make build with env in a new folder. It checks the build info
// of both binaries.
func checkReleaseBuild(t *testing.T, env []string, file string) {
	t.Helper()
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("the go tool is not on PATH: %v", err)
	}
	control := exec.Command(goTool, "env", "GOENV", "GOFLAGS")
	control.Env = env
	out, err := control.CombinedOutput()
	if want := file + "\n" + ts21Flag; err != nil || strings.TrimSpace(string(out)) != want {
		t.Fatalf("control: go env GOENV GOFLAGS = %q, %v; want %q", out, err, want)
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

	flagKey, _, _ := strings.Cut(ts21Flag, "=")
	for _, name := range []string{"phantom", "phantom-verify"} {
		info, err := buildinfo.ReadFile(filepath.Join(binDir, name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, s := range info.Settings {
			if s.Key == flagKey {
				t.Errorf("%s records %s=%s: make build read the go env file", name, s.Key, s.Value)
			}
		}
	}
}
