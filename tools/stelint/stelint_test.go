package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// gitRun runs a git subcommand in dir and fails the test on error.
func gitRun(t *testing.T, dir string, args ...string) string {
	t.Helper()
	full := append([]string{"-C", dir, "-c", "user.name=t", "-c", "user.email=t@example.com"}, args...)
	out, err := exec.Command("git", full...).CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func newRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	gitRun(t, dir, "init", "-b", "main")
	return dir
}

// writeFile writes a file in the repository and makes the directories.
func writeFile(t *testing.T, dir, name, text string) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
}

// commitAll commits the work tree and returns the new commit.
func commitAll(t *testing.T, dir, msg string) string {
	t.Helper()
	gitRun(t, dir, "add", "-A")
	gitRun(t, dir, "commit", "-m", msg)
	return gitRun(t, dir, "rev-parse", "HEAD")
}

func runLint(dir string, args ...string) (int, string, string) {
	var out, errOut bytes.Buffer
	code := run(args, dir, &out, &errOut)
	return code, out.String(), errOut.String()
}

// comment returns a "//" comment of exactly n columns.
func comment(n int) string { return "// " + strings.Repeat("x", n-3) }

func hitLines(src string) []hit { return longLines([]byte(src)) }

// bidi is a right-to-left override. It does not print, and clean escapes it
// as bidiEsc.
var (
	bidi    = string(rune(0x202e))
	bidiEsc = `\u` + "202e"
)

func TestWidth(t *testing.T) {
	cases := []struct {
		name, line string
		want       int
	}{
		{"empty", "", 0},
		{"plain", "abc", 3},
		{"tab at column 0", "\tx", 5},
		{"tab after one character", "a\tx", 5},
		{"tab after three characters", "abc\tx", 5},
		{"tab at a multiple of 4", "abcd\tx", 9},
		{"two tabs", "\t\tx", 9},
		{"tab after a tab and a character", "\ta\tx", 9},
		{"multibyte characters are one column", "äö€", 3},
	}
	for _, c := range cases {
		if got := width(c.line); got != c.want {
			t.Errorf("%s: width(%q) = %d, want %d", c.name, c.line, got, c.want)
		}
	}
}

func TestLimitIs80Columns(t *testing.T) {
	if got := hitLines(comment(80) + "\n"); len(got) != 0 {
		t.Errorf("80 columns: got %v, want no hit", got)
	}
	got := hitLines(comment(81) + "\n")
	if len(got) != 1 || got[0] != (hit{1, 81}) {
		t.Errorf("81 columns: got %v, want one hit {1 81}", got)
	}
}

func TestIndentCounts(t *testing.T) {
	// 2 tabs are 8 columns, so a comment of 73 columns is 81 in the line.
	src := "func f() {\n\t\t" + comment(73) + "\n}\n"
	got := hitLines(src)
	if len(got) != 1 || got[0] != (hit{2, 81}) {
		t.Errorf("got %v, want one hit {2 81}", got)
	}
	// Spaces count one column each.
	src = "func f() {\n        " + comment(72) + "\n}\n"
	if got := hitLines(src); len(got) != 0 {
		t.Errorf("8 spaces and 72 columns: got %v, want no hit", got)
	}
}

func TestTabNotAtMultipleOf4(t *testing.T) {
	// "ab" then a tab: the tab adds 2 columns, to column 4. A fixed width of 4
	// would give 82 columns and a false hit.
	line := "ab\t// " + strings.Repeat("x", 80-4-3)
	if w := width(line); w != 80 {
		t.Fatalf("test line has %d columns, want 80", w)
	}
	if got := hitLines(line + "\n"); len(got) != 0 {
		t.Errorf("got %v, want no hit at 80 columns", got)
	}
	got := hitLines(line + "x\n")
	if len(got) != 1 || got[0].cols != 81 {
		t.Errorf("got %v, want one hit at 81 columns", got)
	}
}

func TestURLOnlyLineIsExempt(t *testing.T) {
	url := "https://example.com/" + strings.Repeat("a", 100)
	exempt := []string{
		"// " + url + "\n",
		"//" + url + "\n",
		"//    http://example.com/" + strings.Repeat("a", 100) + "\n",
		"/* " + url + " */\n",
		"/*\n * " + url + "\n */\n",
		"/*\n" + url + "\n*/\n",
	}
	for _, src := range exempt {
		if got := hitLines(src); len(got) != 0 {
			t.Errorf("%q: got %v, want no hit", src, got)
		}
	}
	notExempt := []string{
		"// see " + url + "\n",
		"// " + url + " more\n",
		"// ftp://example.com/" + strings.Repeat("a", 100) + "\n",
		"// https://" + strings.Repeat(" ", 80) + "\n",
		"x := 1 // " + url + "\n",
		"/* " + url + " */ x := 1\n",
	}
	for _, src := range notExempt {
		if got := hitLines(src); len(got) == 0 {
			t.Errorf("%q: got no hit, want one", src)
		}
	}
}

func TestDirectivesAreExempt(t *testing.T) {
	long := strings.Repeat("x", 100)
	for _, src := range []string{
		"//go:generate " + long + "\n",
		"//go:build " + long + "\n",
		"//go:embed " + long + "\n",
		"//go:linkname " + long + "\n",
		"//line " + long + ":1\n",
	} {
		if got := hitLines(src); len(got) != 0 {
			t.Errorf("%q: got %v, want no hit", src, got)
		}
	}
	// A comment that only looks like a directive is prose.
	for _, src := range []string{
		"// go:generate " + long + "\n",
		"//go:" + long + "\n",
		"//go:generate\t" + long + "\n",
		"//line foo.go:1 " + long + "\n",
		"//line " + strings.Repeat("a ", 50) + "\n",
		"//lines " + long + "\n",
	} {
		if got := hitLines(src); len(got) != 1 {
			t.Errorf("%q: got %v, want one hit", src, got)
		}
	}
}

func TestLineDirectiveDoesNotMoveLines(t *testing.T) {
	src := "//line other.go:50\n" + comment(90) + "\n"
	got := hitLines(src)
	if len(got) != 1 || got[0].line != 2 {
		t.Errorf("got %v, want one hit on line 2", got)
	}
}

func TestCommentKinds(t *testing.T) {
	long := strings.Repeat("x", 90)
	src := strings.Join([]string{
		`s := "// ` + long + `"`,            // 1: a string, not a comment
		"r := `// " + long + "`",            // 2: a raw string
		`c := '/'`,                          // 3
		"x := 1 // " + long,                 // 4: end-of-line comment
		"/* " + long + " */",                // 5: one-line block
		"/*",                                // 6
		"short",                             // 7
		long,                                // 8: long line inside a block
		"*/ y := 2",                         // 9
		"y := 3 /* a */ /* b */ // " + long, // 10: three comments on a line
		"",
	}, "\n")
	var lines []int
	for _, h := range hitLines(src) {
		lines = append(lines, h.line)
	}
	want := []int{4, 5, 8, 10}
	if len(lines) != len(want) {
		t.Fatalf("hit lines = %v, want %v", lines, want)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Fatalf("hit lines = %v, want %v", lines, want)
		}
	}
}

func TestCRLFIsNotCounted(t *testing.T) {
	src := comment(80) + "\r\n" + comment(81) + "\r\n"
	got := hitLines(src)
	if len(got) != 1 || got[0] != (hit{2, 81}) {
		t.Errorf("got %v, want one hit {2 81}", got)
	}
}

func TestCleanEscapes(t *testing.T) {
	got := clean("a\x1b[31m\nb" + bidi + "\xffc.go")
	for _, r := range got {
		if r < 0x20 || r == 0x7f || r == 0x202e {
			t.Errorf("clean left %q in %q", r, got)
		}
	}
	if want := `a\u001b[31m\u000ab` + bidiEsc + `\xffc.go`; got != want {
		t.Errorf("clean = %q, want %q", got, want)
	}
	if got := clean("pkg/ä.go"); got != "pkg/ä.go" {
		t.Errorf("clean changed a printable path: %q", got)
	}
}

// baseRepo makes a repository with a file that holds a long comment line. It
// returns the directory and the first commit.
func baseRepo(t *testing.T) (dir, base string) {
	t.Helper()
	dir = newRepo(t)
	writeFile(t, dir, "a.go", "package a\n\n"+comment(95)+"\nfunc f() {}\n")
	return dir, commitAll(t, dir, "base")
}

func TestChangedLongCommentFails(t *testing.T) {
	dir, base := baseRepo(t)
	writeFile(t, dir, "a.go", "package a\n\n"+comment(95)+"\nfunc f() {}\n\n"+comment(100)+"\nfunc g() {}\n")
	head := commitAll(t, dir, "add")
	code, out, _ := runLint(dir, base, head)
	if code != 1 {
		t.Fatalf("code = %d, want 1; output:\n%s", code, out)
	}
	if !strings.Contains(out, "a.go:6: 100 columns (limit 80)\n") {
		t.Errorf("no hit line for a.go:6 in:\n%s", out)
	}
	if strings.Contains(out, "a.go:3:") {
		t.Errorf("the unchanged long line is a hit:\n%s", out)
	}
}

func TestChangedFileBelowSubdirectoryFails(t *testing.T) {
	dir, base := baseRepo(t)
	writeFile(t, dir, "pkg/sub/x.go", "package sub\n\n"+comment(93)+"\n")
	head := commitAll(t, dir, "add")
	code, out, _ := runLint(dir, base, head)
	if code != 1 || !strings.Contains(out, "pkg/sub/x.go:3: 93 columns (limit 80)\n") {
		t.Errorf("code = %d, output:\n%s", code, out)
	}
}

func TestAttributesDoNotHideChangedFile(t *testing.T) {
	dir, base := baseRepo(t)
	writeFile(t, dir, ".gitattributes", "*.go -diff\n")
	writeFile(t, dir, "a.go", "package a\n\n"+comment(95)+"\nfunc f() {}\n\n"+comment(93)+"\n")
	head := commitAll(t, dir, "attributes")
	code, out, _ := runLint(dir, base, head)
	if code != 1 || !strings.Contains(out, "a.go:6: 93 columns (limit 80)\n") {
		t.Errorf("code = %d, output:\n%s", code, out)
	}
}

func TestQuotedPathWithSpaceFails(t *testing.T) {
	dir, base := baseRepo(t)
	writeFile(t, dir, "d s/ä b.go", "package a\n\n"+comment(93)+"\n")
	head := commitAll(t, dir, "odd path")
	code, out, errOut := runLint(dir, base, head)
	if code != 1 || !strings.Contains(out, "d s/ä b.go:3: 93 columns (limit 80)\n") {
		t.Errorf("code = %d, output:\n%s%s", code, out, errOut)
	}
}

func TestEditedLongCommentFails(t *testing.T) {
	dir, base := baseRepo(t)
	writeFile(t, dir, "a.go", "package a\n\n"+comment(96)+"\nfunc f() {}\n")
	head := commitAll(t, dir, "edit")
	code, out, _ := runLint(dir, base, head)
	if code != 1 || !strings.Contains(out, "a.go:3: 96 columns (limit 80)\n") {
		t.Errorf("code = %d, output:\n%s", code, out)
	}
}

func TestUnchangedLongCommentPasses(t *testing.T) {
	dir, base := baseRepo(t)
	// A change in the same file, away from the long line.
	writeFile(t, dir, "a.go", "package a\n\n"+comment(95)+"\nfunc f() {}\n\n"+comment(80)+"\nfunc g() {}\n")
	writeFile(t, dir, "b.go", "package a\n\n"+comment(20)+"\n")
	head := commitAll(t, dir, "add")
	code, out, errOut := runLint(dir, base, head)
	if code != 0 {
		t.Fatalf("code = %d, want 0; output:\n%s%s", code, out, errOut)
	}
	if strings.Contains(out, "columns (limit") {
		t.Errorf("unexpected hit:\n%s", out)
	}
}

func TestInsertAboveMovesLongLine(t *testing.T) {
	dir, base := baseRepo(t)
	// New lines above the long line move it. The text is the same, so it is
	// not a changed line.
	writeFile(t, dir, "a.go", "package a\n\nvar x = 1\nvar y = 2\n"+comment(95)+"\nfunc f() {}\n")
	head := commitAll(t, dir, "insert")
	if code, out, _ := runLint(dir, base, head); code != 0 {
		t.Errorf("code = %d, want 0; output:\n%s", code, out)
	}
}

func TestLineNumbersComeFromHead(t *testing.T) {
	dir, base := baseRepo(t)
	writeFile(t, dir, "a.go", "package a\n\nvar x = 1\n"+comment(95)+"\nfunc f() {}\n")
	commitAll(t, dir, "one")
	// The work tree changes after the commit and does not count.
	writeFile(t, dir, "a.go", strings.Repeat("// c\n", 10)+"package a\n")
	code, out, _ := runLint(dir, base, "HEAD")
	if code != 0 {
		t.Errorf("code = %d, want 0 (the long line did not change); output:\n%s", code, out)
	}
}

func TestDiffBodyLooksLikeHeader(t *testing.T) {
	dir, base := baseRepo(t)
	// An added line that starts with "++ " shows in the patch as "+++ ".
	writeFile(t, dir, "a.go", "package a\n\n"+comment(95)+"\nfunc f() {}\n\n/*\n++ b/other.go\n*/\n"+comment(99)+"\n")
	head := commitAll(t, dir, "add")
	code, out, _ := runLint(dir, base, head)
	if code != 1 || !strings.Contains(out, "a.go:9: 99 columns") {
		t.Errorf("code = %d, output:\n%s", code, out)
	}
}

func TestNewAndRenamedFiles(t *testing.T) {
	dir, base := baseRepo(t)
	writeFile(t, dir, "new.go", "package a\n\n"+comment(85)+"\n")
	head := commitAll(t, dir, "new file")
	if code, out, _ := runLint(dir, base, head); code != 1 || !strings.Contains(out, "new.go:3: 85 columns") {
		t.Errorf("new file: code = %d, output:\n%s", code, out)
	}
	// A pure rename changes no line.
	gitRun(t, dir, "mv", "a.go", "c.go")
	renamed := commitAll(t, dir, "rename")
	if code, out, _ := runLint(dir, head, renamed); code != 0 {
		t.Errorf("rename: code = %d, output:\n%s", code, out)
	}
}

func TestDeletedAndOtherFilesAreSkipped(t *testing.T) {
	dir, base := baseRepo(t)
	gitRun(t, dir, "rm", "-q", "a.go")
	writeFile(t, dir, "notes.txt", comment(200)+"\n")
	writeFile(t, dir, "x.go.txt", comment(200)+"\n")
	head := commitAll(t, dir, "delete")
	if code, out, _ := runLint(dir, base, head); code != 0 {
		t.Errorf("code = %d, output:\n%s", code, out)
	}
}

func TestTestdataIsSkipped(t *testing.T) {
	dir, base := baseRepo(t)
	long := "package a\n\n" + comment(120) + "\n"
	writeFile(t, dir, "testdata/f.go", long)
	writeFile(t, dir, "pkg/testdata/sub/f.go", long)
	head := commitAll(t, dir, "fixtures")
	if code, out, _ := runLint(dir, base, head); code != 0 {
		t.Errorf("diff mode: code = %d, output:\n%s", code, out)
	}
	_, out, _ := runLint(dir, "-all")
	if strings.Contains(out, "testdata") {
		t.Errorf("report lists a testdata file:\n%s", out)
	}
	// A file named like the directory is not skipped.
	writeFile(t, dir, "testdata.go", long)
	head2 := commitAll(t, dir, "not a directory")
	if code, _, _ := runLint(dir, head, head2); code != 1 {
		t.Errorf("testdata.go: code = %d, want 1", code)
	}
}

func TestEmptyBaseDoesNotRun(t *testing.T) {
	dir, _ := baseRepo(t)
	code, out, _ := runLint(dir, "", "HEAD")
	if code != 0 {
		t.Errorf("code = %d, want 0", code)
	}
	if !strings.Contains(out, "did not run") || strings.Count(out, "\n") != 1 {
		t.Errorf("want one line that says the check did not run, got:\n%s", out)
	}
}

func TestUnknownBaseIsAnError(t *testing.T) {
	dir, _ := baseRepo(t)
	code, out, errOut := runLint(dir, "no-such-ref", "HEAD")
	if code != 2 || out != "" || !strings.Contains(errOut, "failed") {
		t.Errorf("code = %d, out = %q, err = %q", code, out, errOut)
	}
	if code, _, _ := runLint(dir, "-all", "no-such-ref"); code != 2 {
		t.Errorf("-all with an unknown ref: code = %d, want 2", code)
	}
}

func TestUsageErrors(t *testing.T) {
	dir, _ := baseRepo(t)
	for _, args := range [][]string{
		{},
		{"one"},
		{"a", "b", "c"},
		{"-all", "a", "b"},
		{"-x"},
		{"-h"},
		{"--", "-bad", "HEAD"},
		{"HEAD", ""},
	} {
		if code, _, _ := runLint(dir, args...); code != 2 {
			t.Errorf("args %q: code = %d, want 2", args, code)
		}
	}
}

func TestReportMode(t *testing.T) {
	dir, _ := baseRepo(t)
	writeFile(t, dir, "b/b.go", "package b\n\nvar x = 1 // "+strings.Repeat("y", 80)+"\n"+comment(80)+"\n")
	writeFile(t, dir, "ok.go", "package ok\n")
	commitAll(t, dir, "more")
	code, out, errOut := runLint(dir, "-all")
	if code != 0 {
		t.Fatalf("code = %d, want 0; stderr: %s", code, errOut)
	}
	want := "a.go:3: 95 columns (limit 80)\n" +
		"b/b.go:3: 93 columns (limit 80)\n" +
		"stelint: 2 comment line(s) over 80 columns in 2 file(s)\n" +
		"stelint: 0 comment sentence(s) over 20 words in 0 file(s)\n"
	if out != want {
		t.Errorf("output:\n%s\nwant:\n%s", out, want)
	}
	// The report reads the commit, not the work tree.
	writeFile(t, dir, "a.go", "package a\n")
	if _, out2, _ := runLint(dir, "-all", "HEAD"); out2 != want {
		t.Errorf("report changed with the work tree:\n%s", out2)
	}
}

func TestReportModeSkipsSymlinks(t *testing.T) {
	dir, _ := baseRepo(t)
	if err := os.Symlink("a.go", filepath.Join(dir, "link.go")); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	commitAll(t, dir, "link")
	_, out, _ := runLint(dir, "-all")
	if strings.Contains(out, "link.go") {
		t.Errorf("report lists a symlink:\n%s", out)
	}
}

func TestOutputHasNoControlCharacters(t *testing.T) {
	dir, base := baseRepo(t)
	name := "evil\x1b[31m\nname" + bidi + ".go"
	writeFile(t, dir, name, "package a\n\n"+comment(99)+"\n")
	writeFile(t, dir, "nonascii-ä€.go", "package a\n\n"+comment(99)+"\n")
	head := commitAll(t, dir, "odd names")
	_, diffOut, _ := runLint(dir, base, head)
	_, allOut, _ := runLint(dir, "-all")
	for mode, out := range map[string]string{"diff": diffOut, "all": allOut} {
		for _, line := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
			for _, r := range line {
				if r < 0x20 || r == 0x7f || r == 0x202e {
					t.Errorf("%s: raw character %q in %q", mode, r, line)
				}
			}
		}
		if strings.Count(out, "columns (limit 80)") < 2 {
			t.Errorf("%s: want a hit for each odd name, got:\n%s", mode, out)
		}
		if !strings.Contains(out, `evil\u001b[31m\u000aname`+bidiEsc+`.go:3: 99 columns`) {
			t.Errorf("%s: escaped name missing in:\n%s", mode, out)
		}
		if !strings.Contains(out, "nonascii-ä€.go:3:") {
			t.Errorf("%s: printable name changed in:\n%s", mode, out)
		}
	}
}

func TestFileOverLimitIsRefused(t *testing.T) {
	dir, base := baseRepo(t)
	big := "package a\n\n" + comment(99) + "\n"
	writeFile(t, dir, "big.go", big)
	head := commitAll(t, dir, "big")
	old := maxFileBytes
	maxFileBytes = len(big) - 1
	defer func() { maxFileBytes = old }()
	for _, args := range [][]string{{base, head}, {"-all"}} {
		code, out, errOut := runLint(dir, args...)
		if code != 2 || !strings.Contains(errOut, "not parsed") || strings.Contains(out, "columns (limit") {
			t.Errorf("args %q: code = %d, out = %q, err = %q", args, code, out, errOut)
		}
	}
	// At the limit the file is read.
	maxFileBytes = len(big)
	if code, _, _ := runLint(dir, base, head); code != 1 {
		t.Errorf("file at the limit: code = %d, want 1", code)
	}
}

func TestDiffOverLimitIsRefused(t *testing.T) {
	dir, base := baseRepo(t)
	writeFile(t, dir, "a.go", "package a\n\n"+comment(95)+"\nfunc f() {}\n"+strings.Repeat("var x = 1\n", 50))
	head := commitAll(t, dir, "many lines")
	old := maxDiffBytes
	maxDiffBytes = 20
	defer func() { maxDiffBytes = old }()
	for _, args := range [][]string{{base, head}, {"-all"}} {
		code, _, errOut := runLint(dir, args...)
		if code != 2 || !strings.Contains(errOut, "not parsed") {
			t.Errorf("args %q: code = %d, err = %q", args, code, errOut)
		}
	}
}

func TestParseDiffErrors(t *testing.T) {
	for _, patch := range []string{
		"+++ b/a.go\n@@ nonsense @@\n",
		"+++ b/a.go\n@@ -1 +x @@\n",
		"+++ \"b/a\\q.go\"\n",
		"+++ a.go\n",
	} {
		if _, err := parseDiff(patch); err == nil {
			t.Errorf("parseDiff(%q): want an error", patch)
		}
	}
	targets, err := parseDiff("+++ \"b/sp\\303\\244ce.go\"\n@@ -0,0 +1,2 @@\n+a\n+b\n+++ b/with space.go\t\n@@ -3 +4 @@\n-a\n+b\n\\ No newline at end of file\n+++ /dev/null\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 2 || targets[0].path != "späce.go" || !targets[0].has(2) || targets[0].has(3) ||
		targets[1].path != "with space.go" || !targets[1].has(4) || targets[1].has(3) || targets[1].has(5) {
		t.Errorf("targets = %+v", targets)
	}
}

func TestParseDiffQuotedPathWithTab(t *testing.T) {
	targets, err := parseDiff("+++ \"b/sp ace\\303\\244.go\"\t\n@@ -0,0 +1 @@\n+a\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 || targets[0].path != "sp aceä.go" || !targets[0].has(1) {
		t.Errorf("targets = %+v", targets)
	}
}

func TestParseDiffFileAfterRemovedLines(t *testing.T) {
	targets, err := parseDiff("+++ b/a.go\n@@ -1 +1 @@\n-x\n+y\n+++ b/c.go\n@@ -0,0 +5 @@\n+z\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 2 || targets[1].path != "c.go" || !targets[1].has(5) || targets[1].has(1) {
		t.Errorf("targets = %+v", targets)
	}
}

func TestParseDiffRanges(t *testing.T) {
	targets, err := parseDiff("+++ b/a.go\n@@ -1 +2,3 @@\n-x\n+a\n+b\n+c\n@@ -9,0 +20 @@\n+d\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 || len(targets[0].spans) != 2 {
		t.Fatalf("targets = %+v", targets)
	}
	for line, want := range map[int]bool{1: false, 2: true, 4: true, 5: false, 19: false, 20: true, 21: false} {
		if got := targets[0].has(line); got != want {
			t.Errorf("has(%d) = %v, want %v", line, got, want)
		}
	}
}

func TestParseDiffRefusesHunkPastFileLimit(t *testing.T) {
	for _, patch := range []string{
		"+++ b/a.go\n@@ -0,0 +1,4000000 @@\n",
		"+++ b/a.go\n@@ -0,0 +4000000 @@\n+x\n",
		"+++ b/a.go\n@@ -0,0 +1048576,2 @@\n",
	} {
		if _, err := parseDiff(patch); err == nil {
			t.Errorf("parseDiff(%q): want an error", patch)
		}
	}
	// A hunk that ends at the limit is read.
	if _, err := parseDiff("+++ b/a.go\n@@ -0,0 +1048576 @@\n+x\n"); err != nil {
		t.Errorf("hunk at the limit: %v", err)
	}
}

func TestOwnCommentLinesAreShort(t *testing.T) {
	// The tool reads its own source and test with its own rule.
	for _, name := range []string{"main.go", "stelint_test.go"} {
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, h := range longLines(src) {
			t.Errorf("%s:%d: %d columns (limit %d)", name, h.line, h.cols, maxColumns)
		}
		for _, s := range longSentences(src) {
			t.Errorf("%s:%d: %d words (limit %d)", name, s.first, s.words, maxWords)
		}
	}
}

// ws returns n words that are not an end mark.
func ws(n int) string { return strings.TrimSpace(strings.Repeat("w ", n)) }

// sentences runs the sentence rule and returns the hits as {first, last,
// words}.
func sentences(src string) []sentence { return longSentences([]byte(src)) }

func TestSentenceRules(t *testing.T) {
	// A case has the source and the expected hits. A 20-word case passes. A
	// 21-word case fails. A split turns 21 or more words into passing parts.
	cases := []struct {
		name, src string
		want      []sentence
	}{
		{"20 words pass", "// " + ws(20) + ".\n", nil},
		{"21 words fail", "// " + ws(21) + ".\n", []sentence{{1, 1, 21}}},
		{"no end mark: end of text", "// " + ws(21), []sentence{{1, 1, 21}}},

		// End marks.
		{"period splits", "// " + ws(15) + ". " + ws(15) + ".\n", nil},
		{"question mark splits", "// " + ws(15) + "? " + ws(15) + "?\n", nil},
		{"exclamation mark splits", "// " + ws(15) + "! " + ws(15) + "!\n", nil},
		{"mark at a line end splits", "// " + ws(15) + ".\n// " + ws(15) + ".\n", nil},
		{"mark inside a word does not split", "// " + ws(10) + " a.b?c!d " + ws(10) + "\n", []sentence{{1, 1, 21}}},
		{"mark before a bracket does not split", "// " + ws(15) + ".) " + ws(15) + "\n", []sentence{{1, 1, 30}}},
		{"sentence over two lines", "// " + ws(11) + "\n// " + ws(10) + ".\n", []sentence{{1, 2, 21}}},
		{"first word line", "// " + ws(5) + ".\n// " + ws(11) + "\n// " + ws(10) + ".\n", []sentence{{2, 3, 21}}},

		// Paragraph end and list item end.
		{"one paragraph", "// " + ws(15) + "\n// " + ws(15) + "\n", []sentence{{1, 2, 30}}},
		{"blank line ends a paragraph", "// " + ws(15) + "\n//\n// " + ws(15) + "\n", nil},
		{"heading ends a sentence", "// # " + ws(15) + "\n// " + ws(15) + "\n", nil},
		{"list items end", "// - " + ws(15) + "\n// - " + ws(15) + "\n", nil},
		{"numbered items end", "// 1. " + ws(15) + "\n// 2) " + ws(15) + "\n", nil},
		{"star and bullet items end", "// * " + ws(15) + "\n// • " + ws(15) + "\n// + " + ws(15) + "\n", nil},
		{"list item at 20 words", "//   - " + ws(20) + "\n", nil},
		{"list item at 21 words", "//   - " + ws(21) + "\n", []sentence{{1, 1, 21}}},
		{"list item continuation", "// - " + ws(11) + "\n//   " + ws(10) + "\n", []sentence{{1, 2, 21}}},
		{"text after a list is a new paragraph", "// - a\n// " + ws(15) + "\n// " + ws(15) + "\n", []sentence{{2, 3, 30}}},

		// A colon before a vertical list.
		{"colon before a list at 21", "// " + ws(21) + ":\n// - a\n// - b\n", []sentence{{1, 1, 21}}},
		{"colon before a list at 20", "// " + ws(20) + ":\n// - a\n// - b\n", nil},
		{"colon before a list splits", "// " + ws(15) + ":\n// - " + ws(15) + "\n", nil},

		// A colon in a line.
		{"colon in a line at 20", "// " + ws(9) + ": " + ws(11) + ".\n", nil},
		{"colon in a line at 21", "// " + ws(10) + ": " + ws(11) + ".\n", []sentence{{1, 1, 21}}},

		// Semicolon, dash and parenthesis.
		{"semicolon at 20", "// " + ws(10) + "; " + ws(10) + ".\n", nil},
		{"semicolon at 21", "// " + ws(10) + "; " + ws(11) + ".\n", []sentence{{1, 1, 21}}},
		{"dash is a word and does not end", "// " + ws(10) + " - " + ws(10) + ".\n", []sentence{{1, 1, 21}}},
		{"dash at 20", "// " + ws(10) + " - " + ws(9) + ".\n", nil},
		{"parenthesis at 21", "// " + ws(10) + " (" + ws(11) + ").\n", []sentence{{1, 1, 21}}},
		{"parenthesis at 20", "// " + ws(10) + " (" + ws(10) + ").\n", nil},

		// A code span.
		{"end mark in a code span at 21", "// `a. b? c!` " + ws(20) + ".\n", []sentence{{1, 1, 21}}},
		{"end mark in a code span at 20", "// `a. b? c!` " + ws(19) + ".\n", nil},
		{"code span with spaces is one word at 20", "// `a b c d e f` " + ws(19) + ".\n", nil},
		{"code span with spaces is one word at 21", "// `a b c d e f` " + ws(20) + ".\n", []sentence{{1, 1, 21}}},
		{"code span over two lines", "// `a\n// b` " + ws(19) + ".\n", nil},
		{"code span joined to a word", "// x`a b`y " + ws(19) + ".\n", nil},
		{"backtick with no close is a character", "// ` " + ws(19) + ".\n", nil},
		{"backtick with no close at 21", "// ` " + ws(20) + ".\n", []sentence{{1, 1, 21}}},

		// A Markdown link.
		{"link text counts at 20", "// [one two three](https://example.com/a?b=1.) " + ws(17) + ".\n", nil},
		{"link text counts at 21", "// [one two three](https://example.com/a?b=1.) " + ws(18) + ".\n", []sentence{{1, 1, 21}}},
		{"link url with an end mark", "// [a](https://example.com/x.y.z?q=1!) " + ws(20) + ".\n", []sentence{{1, 1, 21}}},
		{"link before an end mark", "// [a b](https://example.com). " + ws(19) + ".\n", nil},
		{"bracket without a url", "// [a b] (c) " + ws(18) + ".\n", []sentence{{1, 1, 21}}},
		{"bracket with an open url", "// [a b](c " + ws(19) + ".\n", []sentence{{1, 1, 21}}},

		// A code block.
		{"code block is not counted", "// " + ws(5) + ".\n//\n//\t" + ws(30) + "\n//\n// " + ws(20) + ".\n", nil},
		{"text after a code block at 21", "// " + ws(5) + ".\n//\n//\t" + ws(30) + "\n//\n// " + ws(21) + ".\n", []sentence{{5, 5, 21}}},
		{"code block with two spaces", "//\n//  " + ws(30) + "\n", nil},
		{"code block ends the text before it", "// " + ws(15) + ":\n//\n//\t" + ws(30) + "\n", nil},
		{"fenced code block", "// ```\n// " + ws(30) + "\n// ```\n// " + ws(20) + ".\n", nil},
		{"text after a fence at 21", "// ```\n// " + ws(30) + "\n// ```\n// " + ws(21) + ".\n", []sentence{{4, 4, 21}}},
		{"indent in a paragraph is not code", "// " + ws(11) + "\n//\t" + ws(10) + ".\n", []sentence{{1, 2, 21}}},
	}
	for _, c := range cases {
		got := sentences(c.src)
		if len(got) != len(c.want) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("%s: got %v, want %v", c.name, got, c.want)
				break
			}
		}
	}
}

func TestSentenceCommentGroups(t *testing.T) {
	cases := []struct {
		name, src string
		want      []sentence
	}{
		{"adjacent lines are one text", "// " + ws(11) + "\n// " + ws(10) + "\n", []sentence{{1, 2, 21}}},
		{"code between lines splits", "// " + ws(11) + "\nvar x = 1\n// " + ws(10) + "\n", nil},
		{"blank line between comments splits", "// " + ws(11) + "\n\n// " + ws(10) + "\n", nil},
		{"trailing comment is alone", "x := 1 // " + ws(11) + "\n// " + ws(10) + "\n", nil},
		{"trailing comment is a text", "x := 1 // " + ws(21) + "\n", []sentence{{1, 1, 21}}},
		{"line after a trailing comment starts a text", "x := 1 // a\n// " + ws(11) + "\n// " + ws(10) + "\n", []sentence{{2, 3, 21}}},
		{"indented comments join", "func f() {\n\t// " + ws(11) + "\n\t// " + ws(10) + "\n}\n", []sentence{{2, 3, 21}}},
		{"directive splits", "// " + ws(11) + "\n//go:generate x\n// " + ws(10) + "\n", nil},
		{"directive text is skipped", "//go:generate " + ws(30) + "\n", nil},
		{"block comment: lines of one text", "/*\n" + ws(11) + "\n" + ws(10) + "\n*/\n", []sentence{{2, 3, 21}}},
		{"block comment: stars are removed", "/*\n * " + ws(11) + "\n * " + ws(10) + "\n */\n", []sentence{{2, 3, 21}}},
		{"block comment at 20", "/* " + ws(20) + ". */\n", nil},
		{"block comment at 21", "/* " + ws(21) + ". */\n", []sentence{{1, 1, 21}}},
		{"block comment: indent does not make code", "/*\n\t" + ws(21) + ".\n*/\n", []sentence{{2, 2, 21}}},
		{"string is not a comment", "s := \"// " + ws(30) + "\"\n", nil},
		{"carriage returns", "// " + ws(21) + ".\r\n", []sentence{{1, 1, 21}}},
		{"hits are in line order", "/* " + ws(21) + ". */\nx := 1 // " + ws(22) + "\n", []sentence{{1, 1, 21}, {2, 2, 22}}},
		{"no comment", "package a\n", nil},
	}
	for _, c := range cases {
		got := sentences(c.src)
		if len(got) != len(c.want) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("%s: got %v, want %v", c.name, got, c.want)
				break
			}
		}
	}
}

func TestSentenceTimeIsLinear(t *testing.T) {
	// Each text has a mark that repeats and never closes. A search that
	// starts again at each mark would take quadratic time and not finish.
	n := 200000
	for _, unit := range []string{"[a](", "](", "[](x", "`a ", "[a]( ", "x`"} {
		src := "// " + strings.Repeat(unit, n) + "\n"
		done := make(chan []sentence, 1)
		go func() { done <- sentences(src) }()
		select {
		case <-done:
		case <-time.After(20 * time.Second):
			t.Fatalf("unit %q: no result after 20 s", unit)
		}
	}
}

// sentRepo makes a repository with a file that holds a comment sentence of 21
// words. It returns the directory and the first commit.
func sentRepo(t *testing.T) (dir, base string) {
	t.Helper()
	dir = newRepo(t)
	writeFile(t, dir, "a.go", "package a\n\n// "+ws(21)+".\nfunc f() {}\n")
	return dir, commitAll(t, dir, "base")
}

func TestChangedLongSentenceFails(t *testing.T) {
	dir, base := sentRepo(t)
	writeFile(t, dir, "a.go", "package a\n\n// "+ws(21)+".\nfunc f() {}\n\n// "+ws(21)+".\nfunc g() {}\n")
	head := commitAll(t, dir, "add")
	code, out, _ := runLint(dir, base, head)
	if code != 1 {
		t.Fatalf("code = %d, want 1; output:\n%s", code, out)
	}
	if !strings.Contains(out, "a.go:6: 21 words (limit 20)\n") {
		t.Errorf("no hit line for a.go:6 in:\n%s", out)
	}
	if strings.Contains(out, "a.go:3:") {
		t.Errorf("the unchanged long sentence is a hit:\n%s", out)
	}
	if !strings.Contains(out, "stelint FAIL: 0 changed comment line(s) over 80 columns, 1 comment sentence(s) over 20 words\n") {
		t.Errorf("no fail line in:\n%s", out)
	}
}

func TestUnchangedLongSentencePasses(t *testing.T) {
	dir, base := sentRepo(t)
	writeFile(t, dir, "a.go", "package a\n\nvar x = 1\n\n// "+ws(21)+".\nfunc f() {}\n\n// "+ws(20)+".\nfunc g() {}\n")
	head := commitAll(t, dir, "move and add")
	code, out, errOut := runLint(dir, base, head)
	if code != 0 {
		t.Fatalf("code = %d, want 0; output:\n%s%s", code, out, errOut)
	}
	if strings.Contains(out, "words (limit") {
		t.Errorf("unexpected hit:\n%s", out)
	}
}

func TestSentenceWithOneChangedLineFails(t *testing.T) {
	dir := newRepo(t)
	writeFile(t, dir, "a.go", "package a\n\n// "+ws(11)+"\n// "+ws(8)+".\nfunc f() {}\n")
	base := commitAll(t, dir, "base")
	// The edit adds two words on the second line only. The sentence has 21
	// words, and its first line is not a changed line.
	writeFile(t, dir, "a.go", "package a\n\n// "+ws(11)+"\n// "+ws(10)+".\nfunc f() {}\n")
	head := commitAll(t, dir, "edit")
	code, out, _ := runLint(dir, base, head)
	if code != 1 || !strings.Contains(out, "a.go:3: 21 words (limit 20)\n") {
		t.Errorf("code = %d, output:\n%s", code, out)
	}
}

func TestSplitSentenceRepairsComment(t *testing.T) {
	dir, base := sentRepo(t)
	writeFile(t, dir, "a.go", "package a\n\n// "+ws(10)+".\n// "+ws(11)+".\nfunc f() {}\n")
	head := commitAll(t, dir, "split")
	if code, out, _ := runLint(dir, base, head); code != 0 {
		t.Errorf("code = %d, want 0; output:\n%s", code, out)
	}
}

func TestSentenceHitInTestdataIsSkipped(t *testing.T) {
	dir, base := sentRepo(t)
	writeFile(t, dir, "testdata/f.go", "package a\n\n// "+ws(30)+".\n")
	head := commitAll(t, dir, "fixture")
	if code, out, _ := runLint(dir, base, head); code != 0 {
		t.Errorf("code = %d, output:\n%s", code, out)
	}
}

func TestReportModeCountsSentences(t *testing.T) {
	dir, _ := sentRepo(t)
	writeFile(t, dir, "b/b.go", "package b\n\nvar x = 1 // "+ws(22)+".\n// "+ws(30)+"\n"+comment(95)+"\n")
	writeFile(t, dir, "ok.go", "package ok\n\n// "+ws(20)+".\n")
	commitAll(t, dir, "more")
	code, out, errOut := runLint(dir, "-all")
	if code != 0 {
		t.Fatalf("code = %d, want 0; stderr: %s", code, errOut)
	}
	want := "a.go:3: 21 words (limit 20)\n" +
		"b/b.go:5: 95 columns (limit 80)\n" +
		"b/b.go:3: 22 words (limit 20)\n" +
		"b/b.go:4: 31 words (limit 20)\n" +
		"stelint: 1 comment line(s) over 80 columns in 1 file(s)\n" +
		"stelint: 3 comment sentence(s) over 20 words in 2 file(s)\n"
	if out != want {
		t.Errorf("output:\n%s\nwant:\n%s", out, want)
	}
}

func TestHasAny(t *testing.T) {
	tg := target{spans: []span{{3, 2}, {10, 1}}}
	for _, c := range []struct {
		first, last int
		want        bool
	}{
		{1, 2, false}, {1, 3, true}, {4, 4, true}, {5, 9, false},
		{5, 10, true}, {10, 20, true}, {11, 20, false}, {1, 100, true},
	} {
		if got := tg.hasAny(c.first, c.last); got != c.want {
			t.Errorf("hasAny(%d, %d) = %v, want %v", c.first, c.last, got, c.want)
		}
	}
	if !(target{all: true}).hasAny(1, 1) || (target{}).hasAny(1, 1) {
		t.Error("hasAny with all set or with no span is wrong")
	}
}
