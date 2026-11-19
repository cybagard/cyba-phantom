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
// working directory, so TestMain sets the path before any test runs.
var mirrorScript string

func TestMain(m *testing.M) {
	var err error
	if mirrorScript, err = filepath.Abs("../mirror-diff.sh"); err != nil {
		fmt.Fprintln(os.Stderr, "mirror-diff script path:", err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

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
	return runMirrorDiffText(t, "# Agents\n\n"+table+after)
}

// runMirrorDiffText runs the script on an AGENTS.md with exactly this text.
func runMirrorDiffText(t *testing.T, text string) (int, string) {
	t.Helper()
	dir := t.TempDir()
	agents := filepath.Join(dir, "AGENTS.md")
	golden := filepath.Join(dir, "golden.md")
	if err := os.WriteFile(agents, []byte(text), 0o644); err != nil {
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
		"table at the end":                   "",
		"text after the table":               "\nMore text.\n",
		"a line with only spaces, then text": " \t \nMore text.\n",
	} {
		if rc, stderr := runMirrorDiff(t, mirrorTable(), after); rc != 0 {
			t.Errorf("%s: exit %d, want 0: %s", name, rc, stderr)
		}
	}
	crlf := strings.ReplaceAll("# Agents\n\n"+mirrorTable()+"\nMore text.\n", "\n", "\r\n")
	if rc, stderr := runMirrorDiffText(t, crlf); rc != 0 {
		t.Errorf("CRLF line ends, blank line, text: exit %d, want 0: %s", rc, stderr)
	}
}

func TestMirrorDiffExtraRow(t *testing.T) {
	for name, after := range map[string]string{
		"row after the table":          "| C11 | x |\n",
		"row without a leading pipe":   "C11 | x\n",
		"row with 3 spaces":            "   | C11 | x |\n",
		"row with a tab":               "\t| C11 | x |\n",
		"plain text right after table": "More text.\n",
	} {
		rc, stderr := runMirrorDiff(t, mirrorTable(), after)
		if rc != 2 {
			t.Errorf("%s: exit %d, want 2: %s", name, rc, stderr)
		}
		if !strings.Contains(stderr, "AGENTS.md") {
			t.Errorf("%s: stderr does not name the file: %q", name, stderr)
		}
		if strings.Contains(stderr, "C11") || strings.Contains(stderr, "| x") || strings.Contains(stderr, "More text") {
			t.Errorf("%s: stderr has table text: %q", name, stderr)
		}
	}
	crlf := strings.ReplaceAll("# Agents\n\n"+mirrorTable()+"| C11 | x |\n", "\n", "\r\n")
	if rc, stderr := runMirrorDiffText(t, crlf); rc != 2 {
		t.Errorf("CRLF line ends, 13th row: exit %d, want 2: %s", rc, stderr)
	}
}

func TestMirrorDiffChangedRow(t *testing.T) {
	changed := strings.Replace(mirrorTable(), "digest of C3", "other digest", 1)
	if rc, stderr := runMirrorDiff(t, changed, ""); rc != 1 {
		t.Errorf("exit %d, want 1: %s", rc, stderr)
	}
}
