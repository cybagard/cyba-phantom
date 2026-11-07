package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// These tests pin one operator or one bound of the checker. The file name
// sorts before the other test files. A loop that never ends fails here
// first, after the wait in bounded. That holds when go test runs with
// -failfast and in file order, with no -shuffle.

// bounded fails the test when f takes over 2 s. A loop that counts the wrong
// way never ends. This wait fails the test long before go test -timeout or
// the gremlins timeout stops it.
func bounded(t *testing.T, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { f(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("no result after 2 s")
	}
}

func TestLoopsEndForShortInput(t *testing.T) {
	_, root := newTree(t, defaultRows[:1], defaultFiles())
	t.Chdir(root)
	// A flag with a value, then the next argument.
	bounded(t, func() {
		if got := run([]string{"tests", "spec", "--milestone", "M-1"}); got != 0 {
			t.Errorf("run: got %d, want 0", got)
		}
	})
	bounded(t, func() {
		if got := expandOne("T-U-01..03"); !slices.Equal(got, []string{"T-U-01", "T-U-02", "T-U-03"}) {
			t.Errorf("expandOne = %v", got)
		}
	})
	bounded(t, func() {
		if got := checkMatrix(base01, base07, base08); len(got) != 0 {
			t.Errorf("checkMatrix = %v", got)
		}
	})
	// A continued line joins the next line and ends on it.
	bounded(t, func() {
		l, end := logicalLine([]string{"a", "b\\", "c"}, 1)
		if l != "b c" || end != 2 {
			t.Errorf("logicalLine = %q, %d", l, end)
		}
		if hasRule([]string{"a", "b\\", "c"}, "x") {
			t.Error("no rule x")
		}
	})
	// The scan skips a "$" and the character after it once.
	bounded(t, func() {
		if isAssignment(" $a") {
			t.Error(`" $a" is no assignment`)
		}
	})
	// A reference with no closer counts as an assignment.
	bounded(t, func() {
		if !isAssignment(" $(a") {
			t.Error(`" $(a" is an assignment`)
		}
	})
}

func TestRunAcceptsEachModeOnAValidSpec(t *testing.T) {
	dir := newSpec(t)
	for _, c := range []struct {
		args []string
		want int
	}{
		{[]string{"matrix", dir}, 0},
		{[]string{"stamp", dir}, 0},
		{[]string{"all", dir}, 0},
		{[]string{"stamp", dir, "--write"}, 0},
		{[]string{"matrix", dir, "--write"}, 2},
		{[]string{"all", dir, "--write"}, 2},
		{[]string{"matrix", dir, "--milestone", "M-1"}, 2},
	} {
		if got := run(c.args); got != c.want {
			t.Errorf("run(%q) = %d, want %d", c.args, got, c.want)
		}
	}
}

func TestRunPrintsAtMostTheCapOfFindings(t *testing.T) {
	var ids []string
	for i := 0; i < 99; i++ {
		ids = append(ids, fmt.Sprintf("T-U-%02d", i))
	}
	_, root := newTree(t, []string{"| M-1 | " + strings.Join(ids, ", ") + " |"}, nil)
	t.Chdir(root)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	t.Cleanup(func() {
		os.Stdout = old
		w.Close()
		r.Close()
	})
	code := run([]string{"tests", "spec", "--milestone", "M-1"})
	os.Stdout = old
	w.Close()
	out, _ := io.ReadAll(r)
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	var n int
	if _, err := fmt.Sscanf(lines[len(lines)-1], "trace FAIL: %d finding(s)", &n); err != nil {
		t.Fatalf("last line %q: %v", lines[len(lines)-1], err)
	}
	if code != 1 || n <= maxPrintedFindings || len(lines) != maxPrintedFindings+2 {
		t.Fatalf("code %d, %d findings, %d lines", code, n, len(lines))
	}
	for _, l := range lines[:maxPrintedFindings] {
		if !strings.HasPrefix(l, "trace: ") {
			t.Errorf("not a finding line: %q", l)
		}
	}
	if want := fmt.Sprintf("trace: … %d more finding(s) not shown", n-maxPrintedFindings); lines[maxPrintedFindings] != want {
		t.Errorf("more line = %q, want %q", lines[maxPrintedFindings], want)
	}
}

func TestIsModeNamesTheFourModes(t *testing.T) {
	for s, want := range map[string]bool{"matrix": true, "stamp": true, "all": true, "tests": true, "spec": false, "": false} {
		if got := isMode(s); got != want {
			t.Errorf("isMode(%q) = %v, want %v", s, got, want)
		}
	}
}

func TestLoadSpecCapsAtTheBound(t *testing.T) {
	dir := t.TempDir()
	// maxFileLines + 1 lines, the last one with no newline.
	writeFile(t, dir, "f.md", strings.Repeat("x\n", maxFileLines)+"x")
	if _, findings, _ := loadSpec(dir + "/f.md"); len(findings) != 1 {
		t.Errorf("last line without a newline: findings %v, want one", findings)
	}
	// A line of exactly maxLineBytes bytes is legal.
	writeFile(t, dir, "f.md", strings.Repeat("x", maxLineBytes)+"\n")
	if _, findings, _ := loadSpec(dir + "/f.md"); len(findings) != 0 {
		t.Errorf("line at the cap: findings %v, want none", findings)
	}
}

func TestParseTestPlanKeepsARowWithTwoCells(t *testing.T) {
	var f []string
	got := parseTestPlan("| T-U-01 | FR-01 |\n", &f)
	if len(f) != 0 || len(got) != 1 || !slices.Equal(got[0].covers, []string{"FR-01"}) {
		t.Errorf("got %v, findings %v", got, f)
	}
}

func TestParseMatrixFileGroups(t *testing.T) {
	const head, sep = "| Req | Design | Tests |\n", "|-----|--------|-------|\n"
	const row = "| FR-01 | 02 | T-U-01 |\n"
	for _, c := range []struct {
		name, text             string
		finding                string
		header, sep, first, nr int
	}{
		{"rowless group after text", "a\n\n\n\n\n" + head + sep, "", 5, 6, 7, 0},
		{"header with no separator", "a\n" + head, "", 1, -1, 2, 0},
		{"row before the separator", head + row + sep + row, "", 0, 2, 1, 2},
		{"two separators and one before the header", sep + head + sep + sep, "", 1, 2, 3, 0},
		{"row on the first line", row, "08-traceability: row FR-01 lies outside a table (line 1)", -1, -1, -1, 0},
		{"row on the third line", "a\nb\n" + row, "08-traceability: row FR-01 lies outside a table (line 3)", -1, -1, -1, 0},
	} {
		var f []string
		_, groups := parseMatrixFile(c.text, &f)
		if c.finding != "" {
			if !slices.Equal(f, []string{c.finding}) || len(groups) != 0 {
				t.Errorf("%s: findings %v, want %q", c.name, f, c.finding)
			}
			continue
		}
		if len(f) != 0 || len(groups) != 1 {
			t.Errorf("%s: findings %v, %d groups", c.name, f, len(groups))
			continue
		}
		if g := groups[0]; g.header != c.header || g.sep != c.sep || g.first != c.first || len(g.rows) != c.nr {
			t.Errorf("%s: group %+v, want header %d sep %d first %d", c.name, g, c.header, c.sep, c.first)
		}
	}
}

func TestExpandOneRanges(t *testing.T) {
	for tok, want := range map[string][]string{
		"T-U-03..03": {"T-U-03"},
		"T-U-03..02": nil,
		"T-U-09":     {"T-U-09"},
	} {
		if got := expandOne(tok); !slices.Equal(got, want) {
			t.Errorf("expandOne(%q) = %v, want %v", tok, got, want)
		}
	}
}

func TestReemitTestsOrder(t *testing.T) {
	plan := func(ids ...string) []test {
		var ts []test
		for i, id := range ids {
			ts = append(ts, test{id: id, order: i})
		}
		return ts
	}
	for _, c := range []struct {
		name, cell, want string
		tests            []test
		findings         int
	}{
		{"prose sorts first", "T-U-01, prose", "prose, T-U-01", plan("T-U-01"), 0},
		{"equal prose keeps order", "x, y, T-U-01", "x, y, T-U-01", plan("T-U-01"), 0},
		{"unknown ID sorts last, no finding", "T-U-09, T-U-01", "T-U-01, T-U-09", plan("T-U-01"), 0},
		{"unknown member keeps the first position", "T-U-03, T-U-01..02", "T-U-01..02, T-U-03", plan("T-U-01", "T-U-03"), 1},
		{"range takes the first member", "T-U-02, T-U-01..03", "T-U-01..03, T-U-02", plan("T-U-01", "T-U-02", "T-U-03"), 0},
		{"gap in a range", "T-U-01..03", "T-U-01..03", plan("T-U-01", "T-U-05", "T-U-02", "T-U-03"), 1},
	} {
		var f []string
		if got := reemitTests("FR-01", c.cell, c.tests, &f); got != c.want || len(f) != c.findings {
			t.Errorf("%s: got %q with %v, want %q with %d findings", c.name, got, f, c.want, c.findings)
		}
	}
}

func TestDiffFindingText(t *testing.T) {
	head := func(n int) string {
		return fmt.Sprintf("08-traceability: re-emitted matrix differs from the committed file at %d line(s):", n)
	}
	line := func(n int) string { return fmt.Sprintf("08-traceability: line %d differs (committed vs canonical)", n) }
	for _, c := range []struct {
		name, committed, canonical string
		want                       []string
	}{
		{"same", "a\nb", "a\nb", nil},
		{"one line differs", "a\nb\nc", "a\nX\nc", []string{head(1), line(2)}},
		{"committed is longer", "a\nb\nc", "a\nb", []string{head(1), line(3)}},
		{"canonical is longer", "a", "a\nb", []string{head(1), line(2)}},
	} {
		if got := diffFinding(c.committed, c.canonical); !slices.Equal(got, c.want) {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
	// The finding names ten lines and counts the rest.
	got := diffFinding(strings.Repeat("a\n", 12), strings.Repeat("b\n", 12))
	if len(got) != 12 || got[0] != head(12) || got[1] != line(1) || got[10] != line(10) ||
		got[11] != "… 2 more differing line(s)" {
		t.Errorf("twelve lines: got %q", got)
	}
}

func TestMatrixFindingText(t *testing.T) {
	cell := "| FR-01 | 02 | %s |"
	for _, c := range []struct{ name, tests, want string }{
		{"only missing", "T-U-01", "08-traceability: FR-01 Tests cell disagrees with 07; missing: T-I-01"},
		{"only extra", "T-U-01, T-I-01, T-A-01", "08-traceability: FR-01 Tests cell disagrees with 07; extra: T-A-01"},
	} {
		dir := newSpec(t)
		replaceLine(t, dir, "08-traceability.md", "| FR-01 | 02 | T-U-01, T-I-01 |", fmt.Sprintf(cell, c.tests))
		if got := check(t, dir); !slices.Contains(got, c.want) {
			t.Errorf("%s: findings %q, want %q", c.name, got, c.want)
		}
	}
	// A table with both kinds of row is one finding, not a second difference.
	dir := newSpec(t)
	replaceLine(t, dir, "08-traceability.md",
		"| C10 | this matrix, tools/trace | — (no T-ID) |",
		"| C10 | this matrix, tools/trace | — (no T-ID) |\n| G1 | 07 harness | T-I-01, T-A-02 |")
	got := check(t, dir)
	if !slices.Contains(got, "08-traceability: table 1 mixes goal and requirement rows") {
		t.Errorf("mixed table: findings %q", got)
	}
	for _, f := range got {
		if strings.Contains(f, "re-emitted") {
			t.Errorf("mixed table: canonical differs: %q", got)
		}
	}
	// C10 is a declared requirement: a test that covers it is one finding.
	dir = newSpec(t)
	replaceLine(t, dir, "07-test-plan.md", "| T-U-04 | C8 | retention |", "| T-U-04 | C8, C10 | retention |")
	const c10 = "07-test-plan: test T-U-04 covers C10; no test may cover the trace check"
	if got := check(t, dir); !slices.Equal(got, []string{c10}) {
		t.Errorf("C10 covered: findings %q, want only %q", got, c10)
	}
}

func TestStampWriteFailsOnAFindingFromTheSpecDir(t *testing.T) {
	dir := newSpec(t)
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := run([]string{"stamp", dir, "--write"}); got != 1 {
		t.Errorf("run(stamp --write) with a subdirectory = %d, want 1", got)
	}
}

func TestMilestoneIDDigits(t *testing.T) {
	for cell, want := range map[string]string{"M-0": "M-0", "M-9": "M-9", "M-09 (x)": "M-09", "M-/": "", "M-:": ""} {
		if got := milestoneID(cell); got != want {
			t.Errorf("milestoneID(%q) = %q, want %q", cell, got, want)
		}
	}
}

func TestParseMilestonesTableShapes(t *testing.T) {
	const head = "## 5. Exit criteria per milestone\n"
	const hdr, sep = "| Milestone | Must pass |\n", "|---|---|\n"
	for _, c := range []struct {
		name, text string
		rows       int
		err        string
	}{
		{"blank line before the table", head + "\n" + hdr + sep + "| M-1 | T-U-01 |\n", 1, ""},
		{"header and a row, no separator", head + hdr + "| M-1 | T-U-01 |\n", 1, ""},
		{"a row after a blank line is not in the table", head + hdr + sep + "| M-1 | T-U-01 |\n\n| M-2 | T-U-02 |\n", 1, ""},
		{"header and separator only", head + hdr + sep, 0, "no milestone table"},
		{"header only", head + hdr, 0, "no milestone table"},
	} {
		rows, _, err := parseMilestones(c.text)
		switch {
		case c.err == "" && (err != nil || len(rows) != c.rows):
			t.Errorf("%s: %d rows, err %v, want %d rows", c.name, len(rows), err, c.rows)
		case c.err != "" && (err == nil || !strings.Contains(err.Error(), c.err)):
			t.Errorf("%s: err %v, want %q", c.name, err, c.err)
		}
	}
}

func TestIDFromTestNameBounds(t *testing.T) {
	for name, want := range map[string]string{
		"TestTA01x": "T-A-01", "TestTZ01x": "T-Z-01", "TestTU90x": "T-U-90", "TestTU09x": "T-U-09", "TestTU00x": "T-U-00",
		"TestT@01x": "", "TestT[01x": "", "TestTU/1x": "", "TestTU:1x": "",
	} {
		if got := idFromTestName(name); got != want {
			t.Errorf("idFromTestName(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestTestsModeFindingsNameThePathAndLine(t *testing.T) {
	files := defaultFiles()
	files["sub/bad_test.go"] = "package x\nfunc (\n"
	files["Makefile"] = "# trace-test: T-P-07 perf\n.RECIPEPREFIX := p\nperf:\n"
	specDir, root := newTree(t, defaultRows[:1], files)
	got := testsAt(t, specDir, root, "M-1")
	wantTestsFinding(t, got, "tests: "+printableName("sub/bad_test.go")+" does not parse as Go")
	wantTestsFinding(t, got, "Makefile line 2 uses .RECIPEPREFIX")
}

func TestHasRuleNestedReferenceEnds(t *testing.T) {
	// The inner opener raises the depth, so the reference ends at the last ")".
	if !hasRule([]string{"perf: $(a(b)c);x=1"}, "perf") {
		t.Error("a semicolon after the reference makes a rule")
	}
}
