package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Fixtures for tests mode. A test builds a tree in t.TempDir(). The tree
// has a spec directory with 07-test-plan.md, Go files and a Makefile. The
// test names in this file do not start with TestT, a letter and two
// digits. Thus the real-tree check does not see them as tests of a test ID.

const plan07Head = `# 07 — Test plan (fixture)

## 3. Test cases

| ID | Covers | Test |
|----|--------|------|
| T-U-01 | FR-01 | a |
| T-U-02 | FR-01 | b |
| T-U-03 | FR-01 | c |
| T-U-04 | FR-01 | d |
| T-U-05 | FR-01 | e |
| T-U-06 | FR-01 | f |
| T-P-07 | NFR-01 | g |

## 5. Exit criteria per milestone
| Milestone | Must pass |
|-----------|-----------|
`

var defaultRows = []string{
	"| M-1 | T-U-01, T-U-06, T-P-07 |",
	"| M-2 | + T-U-02..04 |",
	"| M-3 (RC) | everything incl. T-U-05 |",
}

const defaultMakefile = "# trace-test: T-P-07 perf\nperf:\n\ttrue\n"

// goTests returns Go source with one empty test func for each name.
func goTests(names ...string) string {
	var b strings.Builder
	b.WriteString("package x\n\nimport \"testing\"\n\n")
	for _, n := range names {
		b.WriteString("func " + n + "(t *testing.T) {}\n\n")
	}
	return b.String()
}

func defaultFiles() map[string]string {
	return map[string]string{
		"a_test.go": goTests("TestTU01Renders", "TestTU06_Golden"),
		"Makefile":  defaultMakefile,
	}
}

// newTree writes a spec directory and files; it returns both paths.
func newTree(t *testing.T, rows []string, files map[string]string) (specDir, root string) {
	t.Helper()
	root = t.TempDir()
	specDir = filepath.Join(root, "spec")
	if err := os.Mkdir(specDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, specDir, "07-test-plan.md", plan07Head+strings.Join(rows, "\n")+"\n")
	for name, content := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return specDir, root
}

func testsAt(t *testing.T, specDir, root, ms string) []string {
	t.Helper()
	findings, err := runTests(specDir, root, ms)
	if err != nil {
		t.Fatalf("runTests: %v", err)
	}
	return findings
}

func hasFinding(findings []string, subs ...string) bool {
	for _, f := range findings {
		ok := true
		for _, s := range subs {
			ok = ok && strings.Contains(f, s)
		}
		if ok {
			return true
		}
	}
	return false
}

func wantTestsClean(t *testing.T, specDir, root, ms string) {
	t.Helper()
	for _, f := range testsAt(t, specDir, root, ms) {
		t.Errorf("unexpected finding: %s", f)
	}
}

func wantTestsFinding(t *testing.T, findings []string, subs ...string) {
	t.Helper()
	if !hasFinding(findings, subs...) {
		t.Errorf("no finding with %q; got: %v", subs, findings)
	}
}

func TestTestsModeCleanTree(t *testing.T) {
	specDir, root := newTree(t, defaultRows[:1], defaultFiles())
	wantTestsClean(t, specDir, root, "M-1")
}

func TestTestsModeIDWithNoTestFails(t *testing.T) {
	files := defaultFiles()
	files["a_test.go"] = goTests("TestTU06_Golden")
	specDir, root := newTree(t, defaultRows, files)
	got := testsAt(t, specDir, root, "M-1")
	wantTestsFinding(t, got, "T-U-01", "no Go test")
	if len(got) != 1 {
		t.Errorf("want one finding, got: %v", got)
	}
}

func TestTestsModeDuplicateIDInTwoRowsFails(t *testing.T) {
	rows := []string{
		"| M-1 | T-U-01, T-U-06, T-P-07 |",
		"| M-2 | + T-U-02..04, T-U-06 |",
		"| M-3 (RC) | everything incl. T-U-05, T-U-03 |",
	}
	specDir, root := newTree(t, rows, defaultFiles())
	got := testsAt(t, specDir, root, "M-1")
	wantTestsFinding(t, got, "T-U-06", "M-1, M-2")
	wantTestsFinding(t, got, "T-U-03", "M-2, M-3")
	if hasFinding(got, "T-U-01", "more than one") {
		t.Errorf("T-U-01 is in one row only: %v", got)
	}
}

func TestTestsModeDuplicateCheckCoversAllRows(t *testing.T) {
	// The duplicate is in rows after the given milestone: still a finding.
	rows := []string{
		"| M-1 | T-U-01, T-U-06, T-P-07 |",
		"| M-2 | + T-U-02 |",
		"| M-3 (RC) | everything incl. T-U-02 |",
	}
	specDir, root := newTree(t, rows, defaultFiles())
	wantTestsFinding(t, testsAt(t, specDir, root, "M-1"), "T-U-02", "M-2, M-3")
}

func TestTestsModeRangeExpansion(t *testing.T) {
	files := defaultFiles()
	files["b_test.go"] = goTests("TestTU02", "TestTU04_x")
	specDir, root := newTree(t, defaultRows, files)
	got := testsAt(t, specDir, root, "M-2")
	wantTestsFinding(t, got, "T-U-03")
	if len(got) != 1 {
		t.Errorf("want only T-U-03, got: %v", got)
	}
}

func TestTestsModeIsCumulative(t *testing.T) {
	files := defaultFiles()
	files["a_test.go"] = goTests("TestTU06")
	specDir, root := newTree(t, defaultRows[:2], files)
	// M-2 includes the M-1 row: T-U-01 is missing, and so are T-U-02..04.
	got := testsAt(t, specDir, root, "M-2")
	for _, id := range []string{"T-U-01", "T-U-02", "T-U-03", "T-U-04"} {
		wantTestsFinding(t, got, id, "up to M-2")
	}
	// M-1 does not include the M-2 row.
	got = testsAt(t, specDir, root, "M-1")
	if hasFinding(got, "T-U-02") {
		t.Errorf("M-1 must not need T-U-02: %v", got)
	}
}

func TestTestsModeLabelledRowAndLead(t *testing.T) {
	specDir, root := newTree(t, defaultRows, defaultFiles())
	got := testsAt(t, specDir, root, "M-3")
	wantTestsFinding(t, got, "T-U-05", "up to M-3")
	wantTestsFinding(t, got, "T-U-02")
}

func TestTestsModeMentionIsNotAMarker(t *testing.T) {
	files := defaultFiles()
	files["Makefile"] = "# T-P-07 reproducibility\n# see trace-test T-P-07 perf\nperf:\n\ttrue\n"
	specDir, root := newTree(t, defaultRows[:1], files)
	wantTestsFinding(t, testsAt(t, specDir, root, "M-1"), "T-P-07", "no marker")
}

func TestTestsModeMarkerForMissingTargetFails(t *testing.T) {
	for _, mk := range []string{
		"# trace-test: T-P-07 perf\nbuild:\n\ttrue\n",
		"# trace-test: T-P-07 perf\nperf-inner:\n\ttrue\n",
		"# trace-test: T-P-07 perf\nperf := 1\n",
		"# trace-test: T-P-07 perf\nperf:=1\n",
		"# trace-test: T-P-07 perf\nperf::=1\n",
		"# trace-test: T-P-07 perf\nperf: X = 1\n",
		"# trace-test: T-P-07 perf\nperf: X := 1\n",
		"# trace-test: T-P-07 perf\nperf: X?=1\n",
		"# trace-test: T-P-07 perf\nperf: $(X)Y=1\n",
		"# trace-test: T-P-07 perf\nperf: ${X}Y=1\n",
		"# trace-test: T-P-07 perf\nperf: \\\nX = 1\n",
		"# trace-test: T-P-07 perf\n\tperf:\n",
		"# trace-test: T-P-07 perf\n",
	} {
		files := defaultFiles()
		files["Makefile"] = mk
		specDir, root := newTree(t, defaultRows[:1], files)
		got := testsAt(t, specDir, root, "M-1")
		wantTestsFinding(t, got, "T-P-07", "target")
		wantTestsFinding(t, got, "T-P-07", "no marker")
	}
}

func TestTestsModeRuleLinesAreRules(t *testing.T) {
	for _, line := range []string{
		"perf:",
		"perf: build test",
		"perf:: build",
		"perf: $(OBJS:.c=.o)",
		"perf: ${OBJS:.c=.o}",
		"perf: build ; X=1",
		"perf: # X=1",
		"perf:\n\tX=1",
		"perf: ) $(X=1)", // a stray closer does not lower the depth
		"perf: } ${X=1}",
		"perf: x$", // "$" at the end of the line
		"perf: \\\n; true",
		"perf: \\\\\nX = 1", // two backslashes do not continue the line
	} {
		files := defaultFiles()
		files["Makefile"] = "# trace-test: T-P-07 perf\n" + line + "\n"
		specDir, root := newTree(t, defaultRows[:1], files)
		got := testsAt(t, specDir, root, "M-1")
		if hasFinding(got, "T-P-07") {
			t.Errorf("%q is a rule: %v", line, got)
		}
	}
}

// A continued line does not change the line numbers of the file.
func TestTestsModeContinuedLinesKeepMarkerLineNumbers(t *testing.T) {
	files := defaultFiles()
	files["Makefile"] = "x: \\\ny\n# trace-test: T-P-07\nperf:\n\ttrue\n"
	specDir, root := newTree(t, defaultRows[:1], files)
	wantTestsFinding(t, testsAt(t, specDir, root, "M-1"), "Makefile line 3", "malformed marker")
}

func TestTestsModeMalformedMarkerIsFinding(t *testing.T) {
	for _, line := range []string{
		"# trace-test: T-P-07",
		"# trace-test: T-P-07 perf extra",
		"# trace-test: T-P-07  perf",
		"# trace-test: T-P-7 perf",
		"# trace-test: T-P-07 pe rf",
		"# trace-test:T-P-07 perf",
		"# trace-test: T-P-07 perf\r",
		"# trace-test: T-P-07 pe$(x)",
		"# trace-test: T-P-07 .perf",
	} {
		files := defaultFiles()
		files["Makefile"] = line + "\nperf:\n\ttrue\n"
		specDir, root := newTree(t, defaultRows[:1], files)
		got := testsAt(t, specDir, root, "M-1")
		wantTestsFinding(t, got, "Makefile line 1", "malformed marker")
		wantTestsFinding(t, got, "T-P-07", "no marker")
	}
}

func TestTestsModeMarkerCoversOnlyItsID(t *testing.T) {
	files := defaultFiles()
	files["Makefile"] = "# trace-test: T-U-01 perf\nperf:\n\ttrue\n"
	files["a_test.go"] = goTests("TestTU06")
	specDir, root := newTree(t, defaultRows[:1], files)
	got := testsAt(t, specDir, root, "M-1")
	wantTestsFinding(t, got, "T-P-07", "no marker")
	if hasFinding(got, "T-U-01") {
		t.Errorf("a marker covers T-U-01: %v", got)
	}
}

func TestTestsModeNoMakefileIsNoMarker(t *testing.T) {
	files := defaultFiles()
	delete(files, "Makefile")
	specDir, root := newTree(t, defaultRows[:1], files)
	wantTestsFinding(t, testsAt(t, specDir, root, "M-1"), "T-P-07")
}

func TestTestsModeSymlinkedMakefileIsFinding(t *testing.T) {
	files := defaultFiles()
	delete(files, "Makefile")
	specDir, root := newTree(t, defaultRows[:1], files)
	other := filepath.Join(t.TempDir(), "real")
	if err := os.WriteFile(other, []byte(defaultMakefile), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, filepath.Join(root, "Makefile")); err != nil {
		t.Skipf("symlink: %v", err)
	}
	got := testsAt(t, specDir, root, "M-1")
	wantTestsFinding(t, got, "Makefile: not a regular file")
	wantTestsFinding(t, got, "T-P-07", "no marker")
}

func TestTestsModeOversizedMakefileIsFinding(t *testing.T) {
	files := defaultFiles()
	files["Makefile"] = defaultMakefile + strings.Repeat("#\n", maxFileBytes)
	specDir, root := newTree(t, defaultRows[:1], files)
	wantTestsFinding(t, testsAt(t, specDir, root, "M-1"), "Makefile: exceeds the")
}

func TestTestsModeNameInLiteralOrCommentDoesNotCount(t *testing.T) {
	files := defaultFiles()
	files["a_test.go"] = goTests("TestTU06") + "// func TestTU01Fake(t *testing.T) {}\n" +
		"var s = `func TestTU01Raw(t *testing.T) {}`\n" +
		"var u = \"TestTU01\"\n" +
		"/*\nfunc TestTU01Block(t *testing.T) {}\n*/\n"
	specDir, root := newTree(t, defaultRows[:1], files)
	wantTestsFinding(t, testsAt(t, specDir, root, "M-1"), "T-U-01")
}

func TestTestsModeOnlyTopLevelTestFuncsCount(t *testing.T) {
	files := defaultFiles()
	files["a_test.go"] = goTests("TestTU06") +
		"type s struct{}\n\nfunc (s) TestTU01(t *testing.T) {}\n\n" +
		"func helper() { _ = func(t *testing.T) {} }\n" +
		"func TestTU01NoParam() {}\n" +
		"func BenchmarkTU01(b *testing.B) {}\n"
	files["plain.go"] = "package x\n\nfunc TestTU01(t int) {}\n"
	specDir, root := newTree(t, defaultRows[:1], files)
	wantTestsFinding(t, testsAt(t, specDir, root, "M-1"), "T-U-01")
}

func TestTestsModeNameMatchRules(t *testing.T) {
	cases := []struct {
		name, id string
	}{
		{"TestTU06", "T-U-06"},
		{"TestTU06_Golden", "T-U-06"},
		{"TestTU06Name", "T-U-06"},
		{"TestTU061", ""},
		{"TestTU0612", ""},
		{"TestTU01١", ""},
		{"TestTU01١x", ""},
		{"TestTU01é", "T-U-01"},
		{"TestTU6", ""},
		{"TestTU", ""},
		{"TestTu06", ""},
		{"TestTU0", ""},
		{"TestT1006", ""},
		{"Test", ""},
		{"TestSomething", ""},
		{"XTestTU06", ""},
		{"testTU06", ""},
	}
	for _, c := range cases {
		if got := idFromTestName(c.name); got != c.id {
			t.Errorf("idFromTestName(%q) = %q, want %q", c.name, got, c.id)
		}
	}
}

func TestTestsModeLongerNumberDoesNotMatch(t *testing.T) {
	files := defaultFiles()
	files["a_test.go"] = goTests("TestTU061", "TestTU0601", "TestTU01")
	specDir, root := newTree(t, defaultRows[:1], files)
	got := testsAt(t, specDir, root, "M-1")
	wantTestsFinding(t, got, "T-U-06")
	if hasFinding(got, "T-U-01") {
		t.Errorf("TestTU01 covers T-U-01: %v", got)
	}
}

func TestTestsModeWalkSkipsAndDoesNotFollow(t *testing.T) {
	files := defaultFiles()
	files["a_test.go"] = goTests("TestTU06")
	for _, dir := range []string{"testdata", "vendor", ".git", ".hidden", "pkg/testdata", "pkg/.cache"} {
		files[dir+"/x_test.go"] = goTests("TestTU01")
	}
	specDir, root := newTree(t, defaultRows[:1], files)

	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "x_test.go"), []byte(goTests("TestTU01")), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "linkdir")); err != nil {
		t.Skipf("symlink: %v", err)
	}
	if err := os.Symlink(filepath.Join(outside, "x_test.go"), filepath.Join(root, "link_test.go")); err != nil {
		t.Skipf("symlink: %v", err)
	}
	wantTestsFinding(t, testsAt(t, specDir, root, "M-1"), "T-U-01")
}

// A file that go test never builds gives no test ID.
func TestTestsModeUnbuiltFilesDoNotCount(t *testing.T) {
	ignored := "//go:build ignore\n\n" + goTests("TestTU01")
	for name, content := range map[string]string{
		"_x_test.go":               goTests("TestTU01"),
		".x_test.go":               goTests("TestTU01"),
		"_dir/x_test.go":           goTests("TestTU01"),
		"pkg/_dir/deep/x_test.go":  goTests("TestTU01"),
		"ignored_test.go":          ignored,
		"a_plan9_test.go":          goTests("TestTU01"),
		"b_test.go":                "//go:build plan9\n\n" + goTests("TestTU01"),
		"norace_test.go":           "//go:build !race\n\n" + goTests("TestTU01"),
		"nested/x_test.go":         goTests("TestTU01"),
		"pkg/nested/sub/x_test.go": goTests("TestTU01"),
	} {
		files := defaultFiles()
		files["a_test.go"] = goTests("TestTU06")
		files["nested/go.mod"] = "module x\n"
		files["pkg/nested/go.mod"] = "module x\n"
		files[name] = content
		specDir, root := newTree(t, defaultRows[:1], files)
		wantTestsFinding(t, testsAt(t, specDir, root, "M-1"), "T-U-01", "no Go test")
	}
}

func TestTestsModeBuiltFilesCount(t *testing.T) {
	for name, content := range map[string]string{
		"x_test.go":           "//go:build !plan9\n\n" + goTests("TestTU01"),
		"y_test.go":           "//go:build unix || windows || js\n\n" + goTests("TestTU01"),
		"race_test.go":        "//go:build race\n\n" + goTests("TestTU01"),
		"sub/pkg/y_test.go":   goTests("TestTU01"),
		"sub/dir_x/z_test.go": goTests("TestTU01"),
	} {
		files := defaultFiles()
		files["a_test.go"] = goTests("TestTU06")
		files["go.mod"] = "module x\n" // the go.mod of the root is not nested
		files[name] = content
		specDir, root := newTree(t, defaultRows[:1], files)
		got := testsAt(t, specDir, root, "M-1")
		if hasFinding(got, "T-U-01") {
			t.Errorf("%s: a built file must count, got: %v", name, got)
		}
	}
}

// A build line that does not parse gives a finding, and the file does not
// count: go test does not run it.
func TestTestsModeBadBuildLineIsFindingAndDoesNotCount(t *testing.T) {
	for _, line := range []string{"//go:build (", "//go:build ignore &&"} {
		files := defaultFiles()
		files["a_test.go"] = goTests("TestTU06")
		files["bad_test.go"] = line + "\n\n" + goTests("TestTU01")
		specDir, root := newTree(t, defaultRows[:1], files)
		got := testsAt(t, specDir, root, "M-1")
		wantTestsFinding(t, got, "tests: unlisted file", "has a build line that does not parse")
		wantTestsFinding(t, got, "T-U-01", "no Go test")
		if len(got) != 2 {
			t.Errorf("%q: want two findings, got: %v", line, got)
		}
	}
}

// A go.mod that is a directory or a dangling symlink makes no nested module:
// the go tool builds that directory. A go.mod file or a link to one does.
func TestTestsModeNestedModuleNeedsAGoModFile(t *testing.T) {
	for _, c := range []struct {
		name   string
		setup  func(t *testing.T, dir string)
		nested bool
	}{
		{"file", func(t *testing.T, dir string) { writeFile(t, dir, "go.mod", "module x\n") }, true},
		{"directory", func(t *testing.T, dir string) {
			if err := os.Mkdir(filepath.Join(dir, "go.mod"), 0o755); err != nil {
				t.Fatal(err)
			}
		}, false},
		{"dangling symlink", func(t *testing.T, dir string) {
			if err := os.Symlink("absent", filepath.Join(dir, "go.mod")); err != nil {
				t.Skip("symlinks unavailable:", err)
			}
		}, false},
		{"symlink to a file", func(t *testing.T, dir string) {
			writeFile(t, dir, "real.mod", "module x\n")
			if err := os.Symlink("real.mod", filepath.Join(dir, "go.mod")); err != nil {
				t.Skip("symlinks unavailable:", err)
			}
		}, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			files := defaultFiles()
			files["a_test.go"] = goTests("TestTU06")
			files["sub/x_test.go"] = goTests("TestTU01")
			specDir, root := newTree(t, defaultRows[:1], files)
			c.setup(t, filepath.Join(root, "sub"))
			if got := hasFinding(testsAt(t, specDir, root, "M-1"), "T-U-01"); got != c.nested {
				t.Errorf("T-U-01 missing = %v, want %v", got, c.nested)
			}
		})
	}
}

// The build check reads the bytes that the parser reads. A constraint in
// the given bytes decides, not the file on disk.
func TestTestsModeBuildCheckUsesTheGivenBytes(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "x_test.go", goTests("TestTU01"))
	if built, err := isBuilt(dir, "x_test.go", []byte("//go:build ignore\n\npackage x\n")); built || err != nil {
		t.Errorf("built %v, err %v: the check read the file on disk, not the given bytes", built, err)
	}
	if built, err := isBuilt(dir, "absent_test.go", []byte("package x\n")); !built || err != nil {
		t.Errorf("built %v, err %v: the check needs no file on disk", built, err)
	}
}

// Each file has its own FileSet, so the walk keeps no line table.
func TestTestsModeParseUsesOwnFileSet(t *testing.T) {
	src := []byte("package x\n")
	a, err := parseTestFile("a_test.go", src)
	if err != nil {
		t.Fatal(err)
	}
	b, err := parseTestFile("b_test.go", src)
	if err != nil {
		t.Fatal(err)
	}
	if a.Package != b.Package {
		t.Errorf("positions differ (%d, %d): the files share a FileSet", a.Package, b.Package)
	}
}

func TestTestsModeWalkFindsNestedTests(t *testing.T) {
	files := defaultFiles()
	files["a_test.go"] = goTests("TestTU06")
	files["internal/deep/er/x_test.go"] = goTests("TestTU01")
	specDir, root := newTree(t, defaultRows[:1], files)
	wantTestsClean(t, specDir, root, "M-1")
}

func TestTestsModeFileCap(t *testing.T) {
	old := maxTestFiles
	maxTestFiles = 3
	t.Cleanup(func() { maxTestFiles = old })

	files := defaultFiles()
	delete(files, "a_test.go")
	files["f1_test.go"] = goTests("TestTU06")
	files["f2_test.go"] = goTests("TestTU01")
	files["f3_test.go"] = goTests("TestTU02")
	specDir, root := newTree(t, defaultRows[:1], files)
	wantTestsClean(t, specDir, root, "M-1") // exactly at the cap: no finding

	writeFile(t, root, "f4_test.go", goTests("TestTU03"))
	wantTestsFinding(t, testsAt(t, specDir, root, "M-1"), "more than 3 test files")
}

func TestTestsModeParseErrorIsFindingWithHiddenName(t *testing.T) {
	files := defaultFiles()
	files["evil\x1b[31m\nname_test.go"] = "package x\nfunc (\n"
	specDir, root := newTree(t, defaultRows[:1], files)
	got := testsAt(t, specDir, root, "M-1")
	wantTestsFinding(t, got, "unlisted file", "does not parse")
	for _, f := range got {
		if strings.ContainsAny(f, "\x1b\n") || strings.Contains(f, "evil") {
			t.Errorf("finding carries PR text: %q", f)
		}
	}
}

func TestTestsModeOversizedGoFileIsFinding(t *testing.T) {
	files := defaultFiles()
	files["big_test.go"] = "package x\n" + strings.Repeat("//\n", maxFileBytes)
	specDir, root := newTree(t, defaultRows[:1], files)
	wantTestsFinding(t, testsAt(t, specDir, root, "M-1"), "exceeds the")
}

func TestTestsModeUnreadablePathIsFinding(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root reads any directory")
	}
	files := defaultFiles()
	files["locked/x_test.go"] = goTests("TestTU01")
	specDir, root := newTree(t, defaultRows[:1], files)
	locked := filepath.Join(root, "locked")
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(locked, 0o755) })
	wantTestsFinding(t, testsAt(t, specDir, root, "M-1"), "could not be read")
}

func TestTestsModeUndeclaredIDIsFinding(t *testing.T) {
	rows := []string{
		"| M-1 | T-U-01, T-U-06, T-P-07 |",
		"| M-2 | + T-U-02..04 |",
		"| M-3 (RC) | everything incl. T-U-05, T-X-99, T-U-07..08 |",
	}
	specDir, root := newTree(t, rows, defaultFiles())
	// The rule applies to every row, not only the rows up to M-1.
	got := testsAt(t, specDir, root, "M-1")
	wantTestsFinding(t, got, "T-X-99", "no test table declares")
	wantTestsFinding(t, got, "T-U-07", "no test table declares")
	wantTestsFinding(t, got, "T-U-08", "no test table declares")
	if hasFinding(got, "T-U-05", "declares") {
		t.Errorf("T-U-05 is declared: %v", got)
	}
}

func TestTestsModeInvalidItemIsFinding(t *testing.T) {
	for _, item := range []string{"T-U-5", "T-U-05..03", "T-U-02..T-U-04", "t-u-02", "T-U-02..", "T-UU-02", "prose", "T-U-02 T-U-03", "T-U-02..04..05"} {
		rows := []string{"| M-1 | T-U-01, T-U-06, T-P-07, " + item + " |"}
		specDir, root := newTree(t, rows, defaultFiles())
		got := testsAt(t, specDir, root, "M-1")
		wantTestsFinding(t, got, "milestone row M-1 item 4", "not a valid test ID or range")
		for _, f := range got {
			if strings.Contains(f, "prose") {
				t.Errorf("finding prints cell text: %q", f)
			}
		}
	}
	rows := []string{"| M-1 | T-U-01, , T-U-06, T-P-07 |"}
	specDir, root := newTree(t, rows, defaultFiles())
	wantTestsFinding(t, testsAt(t, specDir, root, "M-1"), "item 2", "not a valid")
}

func TestTestsModeRowShapeFindings(t *testing.T) {
	rows := []string{
		"| M-1 | T-U-01, T-U-06, T-P-07 |",
		"| M-2 | + T-U-02 | extra |",
		"| later | + T-U-03 |",
		"| M-1 (again) | + T-U-04 |",
		"| M-x | + T-U-05 |",
		"| M- | + T-U-05 |",
	}
	specDir, root := newTree(t, rows, defaultFiles())
	got := testsAt(t, specDir, root, "M-1")
	wantTestsFinding(t, got, "milestone row 2 has 3 cells")
	wantTestsFinding(t, got, "milestone row 3 does not start with a milestone ID")
	wantTestsFinding(t, got, "milestone M-1 has more than one row")
	wantTestsFinding(t, got, "milestone row 5 does not start")
	wantTestsFinding(t, got, "milestone row 6 does not start")
}

func TestTestsModeSameIDTwiceInOneRow(t *testing.T) {
	rows := []string{"| M-1 | T-U-01, T-U-01, T-U-06, T-P-07 |"}
	specDir, root := newTree(t, rows, defaultFiles())
	got := testsAt(t, specDir, root, "M-1")
	if hasFinding(got, "more than one milestone row") {
		t.Errorf("one row is not two rows: %v", got)
	}
}

func TestTestsModeExitTableErrors(t *testing.T) {
	root := t.TempDir()
	spec := filepath.Join(root, "spec")
	if err := os.Mkdir(spec, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, text := range map[string]string{
		"no heading":  "# 07\n\n| Milestone | Must pass |\n|--|--|\n| M-1 | T-U-01 |\n",
		"no table":    "# 07\n\n## 5. Exit criteria per milestone\nProse only.\n\n## 6. Next\n| M-1 | T-U-01 |\n",
		"header only": "# 07\n\n## 5. Exit criteria per milestone\n| Milestone | Must pass |\n|---|---|\n",
		"empty file":  "",
	} {
		writeFile(t, spec, "07-test-plan.md", text)
		if _, err := runTests(spec, root, "M-1"); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

func TestTestsModeTableEndsAtNextHeading(t *testing.T) {
	specDir, root := newTree(t, defaultRows[:1], defaultFiles())
	text := readSpec(t, specDir, "07-test-plan.md")
	writeFile(t, specDir, "07-test-plan.md", text+"\n## 6. Next\n| M-9 | + T-U-02 |\n")
	wantTestsClean(t, specDir, root, "M-1")
	if _, err := runTests(specDir, root, "M-9"); err == nil {
		t.Error("a row below the next heading is not in the table")
	}
}

func TestTestsModeUnknownMilestoneIsError(t *testing.T) {
	specDir, root := newTree(t, defaultRows, defaultFiles())
	for _, ms := range []string{"M-9", "m-1", "M-1 ", "M-3 (RC)", "x\x1b[31m", "M-"} {
		_, err := runTests(specDir, root, ms)
		if err == nil {
			t.Errorf("milestone %q: want an error", ms)
			continue
		}
		if strings.Contains(err.Error(), "\x1b") {
			t.Errorf("error carries a raw control character: %q", err)
		}
	}
}

func TestTestsModeSpecDirErrors(t *testing.T) {
	_, root := newTree(t, defaultRows, defaultFiles())
	if _, err := runTests(filepath.Join(root, "absent"), root, "M-1"); err == nil {
		t.Error("absent spec dir: want an error")
	}
	if _, err := runTests(filepath.Join(root, "spec"), filepath.Join(root, "absent"), "M-1"); err == nil {
		t.Error("absent root: want an error")
	}
	if _, err := runTests(filepath.Join(root, "spec"), filepath.Join(root, "Makefile"), "M-1"); err == nil {
		t.Error("root that is a file: want an error")
	}
}

func TestTestsModeSpecFileCapsAreFindings(t *testing.T) {
	specDir, root := newTree(t, defaultRows, defaultFiles())
	writeFile(t, specDir, "07-test-plan.md", strings.Repeat("\n", maxFileLines+1))
	if got := testsAt(t, specDir, root, "M-1"); len(got) == 0 {
		t.Error("want a finding for the line cap")
	}
}

func TestTestsModeMilestoneID(t *testing.T) {
	for cell, want := range map[string]string{
		"M-1":       "M-1",
		"M-5 (RC)":  "M-5",
		"M-12 text": "M-12",
		"M-":        "",
		"M-x":       "",
		"M-1x":      "",
		"X-1":       "",
		"":          "",
		"m-1":       "",
	} {
		if got := milestoneID(cell); got != want {
			t.Errorf("milestoneID(%q) = %q, want %q", cell, got, want)
		}
	}
}

func TestTestsModeRunExitCodes(t *testing.T) {
	_, root := newTree(t, defaultRows[:1], defaultFiles())
	t.Chdir(root)
	if got := run([]string{"tests", "spec", "--milestone", "M-1"}); got != 0 {
		t.Errorf("clean tree: got %d, want 0", got)
	}
	if got := run([]string{"tests", "--milestone=M-1", "spec"}); got != 0 {
		t.Errorf("--milestone=M-1: got %d, want 0", got)
	}
	if got := run([]string{"tests", "spec", "--milestone", "M-9"}); got != 2 {
		t.Errorf("unknown milestone: got %d, want 2", got)
	}
	if got := run([]string{"tests", "spec"}); got != 2 {
		t.Errorf("no --milestone: got %d, want 2", got)
	}
	if got := run([]string{"tests", "spec", "--milestone"}); got != 2 {
		t.Errorf("--milestone without a value: got %d, want 2", got)
	}
	if got := run([]string{"matrix", "spec", "--milestone", "M-1"}); got != 2 {
		t.Errorf("--milestone in matrix mode: got %d, want 2", got)
	}
	if got := run([]string{"tests", "nodir", "--milestone", "M-1"}); got != 2 {
		t.Errorf("absent spec dir: got %d, want 2", got)
	}
	if err := os.Remove(filepath.Join(root, "Makefile")); err != nil {
		t.Fatal(err)
	}
	if got := run([]string{"tests", "spec", "--milestone", "M-1"}); got != 1 {
		t.Errorf("T-P-07 without marker: got %d, want 1", got)
	}
}

func TestTestsModeRunManyFindingsAreCapped(t *testing.T) {
	var ids []string
	for i := 0; i < 99; i++ {
		ids = append(ids, "T-U-"+string(rune('0'+i/10))+string(rune('0'+i%10)))
	}
	rows := []string{"| M-1 | " + strings.Join(ids, ", ") + " |"}
	_, root := newTree(t, rows, nil)
	t.Chdir(root)
	if got := run([]string{"tests", "spec", "--milestone", "M-1"}); got != 1 {
		t.Errorf("got %d, want 1", got)
	}
}

// copyRealTree copies the files that tests mode reads from the repository
// root into a new directory: *_test.go files, the Makefile, and 07.
func copyRealTree(t *testing.T) string {
	t.Helper()
	src := filepath.Join("..", "..")
	dst := t.TempDir()
	err := filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, path)
		if d.IsDir() {
			if path != src && skipDir(d.Name()) {
				return fs.SkipDir
			}
			return nil
		}
		rel = filepath.ToSlash(rel)
		if !d.Type().IsRegular() || (rel != "Makefile" && rel != "spec/07-test-plan.md" && !strings.HasSuffix(rel, "_test.go")) {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		out := filepath.Join(dst, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
			return err
		}
		return os.WriteFile(out, data, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	return dst
}

func TestTestsModeRealTreeNeedsTheMarker(t *testing.T) {
	root := copyRealTree(t)
	specDir := filepath.Join(root, "spec")
	wantTestsClean(t, specDir, root, "M-1")

	mk := readSpec(t, root, "Makefile")
	const line = "# trace-test: T-P-07 perf\n"
	if !strings.Contains(mk, line) {
		t.Fatal("the Makefile has no marker for T-P-07")
	}
	writeFile(t, root, "Makefile", strings.Replace(mk, line, "", 1))
	got := testsAt(t, specDir, root, "M-1")
	if len(got) != 1 || !strings.Contains(got[0], "T-P-07") {
		t.Errorf("want one finding for T-P-07, got: %v", got)
	}
	t.Chdir(root)
	if code := run([]string{"tests", "spec", "--milestone", "M-1"}); code != 1 {
		t.Errorf("exit code %d, want 1", code)
	}
}
