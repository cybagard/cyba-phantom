package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The tests of tools/mirror-diff.sh. The script is a shell script, so the
// tests run it on a temporary AGENTS.md and a temporary golden file.

// mirrorScript is the absolute path of the script. Other tests change the
// working directory, so the path is set at package start.
var mirrorScript, _ = filepath.Abs("../mirror-diff.sh")

func mirrorTable() string {
	lines := []string{"| Rule | Digest |", "|------|--------|"}
	for _, id := range cRuleIDs() {
		lines = append(lines, fmt.Sprintf("| %s | digest of %s |", id, id))
	}
	return strings.Join(lines, "\n") + "\n"
}

// runMirrorDiff runs the script on an AGENTS.md with the given text after
// the table. It returns the exit status and stderr.
func runMirrorDiff(t *testing.T, table, after string) (int, string) {
	t.Helper()
	dir := t.TempDir()
	agents := filepath.Join(dir, "AGENTS.md")
	golden := filepath.Join(dir, "golden.md")
	if err := os.WriteFile(agents, []byte("# Agents\n\n"+table+after), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(golden, []byte(mirrorTable()), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", mirrorScript, agents, golden)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	err := cmd.Run()
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode(), stderr.String()
	} else if err != nil {
		t.Fatal(err)
	}
	return 0, stderr.String()
}

func TestMirrorDiffInSync(t *testing.T) {
	for name, after := range map[string]string{
		"table at the end":       "",
		"text after the table":   "\nMore text.\n",
		"line right after table": "More text.\n",
	} {
		if rc, stderr := runMirrorDiff(t, mirrorTable(), after); rc != 0 {
			t.Errorf("%s: exit %d, want 0: %s", name, rc, stderr)
		}
	}
}

func TestMirrorDiffExtraRow(t *testing.T) {
	rc, stderr := runMirrorDiff(t, mirrorTable(), "| C11 | x |\n")
	if rc != 2 {
		t.Fatalf("exit %d, want 2: %s", rc, stderr)
	}
	if !strings.Contains(stderr, "AGENTS.md") {
		t.Errorf("stderr does not name the file: %q", stderr)
	}
	if strings.Contains(stderr, "C11") || strings.Contains(stderr, "| x") {
		t.Errorf("stderr has table text: %q", stderr)
	}
}

func TestMirrorDiffChangedRow(t *testing.T) {
	changed := strings.Replace(mirrorTable(), "digest of C3", "other digest", 1)
	if rc, stderr := runMirrorDiff(t, changed, ""); rc != 1 {
		t.Errorf("exit %d, want 1: %s", rc, stderr)
	}
}
