// Tests mode: each test ID of a milestone must have a Go test.
//
// 07-test-plan.md section 5 lists the test IDs of each milestone. The
// tests mode reads that table and checks three rules:
//
//   - a test ID is in one milestone row only;
//   - the test tables of 07 declare each ID of the milestone table;
//   - each ID of the rows down to the given milestone has a Go test or a
//     Makefile marker.
//
// The tool reads the rows in table order, from the top down to the row of
// the given milestone.
//
// A Go test is a top-level func in a *_test.go file. Its name is TestT,
// then the letter and the two digits of the ID. After the digits, the name
// ends or has a character that is not a digit (of any script). Thus T-S-16
// gives TestTS16Anything. The tool finds the funcs with go/parser. Thus a
// name in a string or a comment does not count.
//
// A file that go test does not build does not count either. The file has
// a name or a directory that starts with "_" or ".". Or it is in a nested
// module. Or it is for another GOOS or GOARCH. Or a build constraint is
// false, with the tag "race" set as in every CI test run. A build line that
// does not parse gives a finding.
//
// A marker is a Makefile line "# trace-test: T-P-07 perf". It names the ID
// and a target. The Makefile must have a line that starts with the target
// name and a colon, and the rest of the line is not a variable assignment.
// A line that ends in a backslash goes on in the next line, as in make.
// The tool does not run make.
//
// Findings print test IDs, milestone IDs, row and line numbers, and counts.
// A file path shows as "unlisted file <hash>" (printableName). No text of
// a table cell, a Go file or a Makefile line is printed. The table, the
// tree and the Makefile come from a PR.

package main

import (
	"bytes"
	"errors"
	"fmt"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	// exitHeading is the heading of the table that tests mode reads.
	exitHeading = "## 5. Exit criteria per milestone"

	// markerPrefix starts a marker line in the Makefile.
	markerPrefix = "# trace-test: "
)

// maxTestFiles caps the *_test.go files that tests mode parses. A test
// lowers it to reach the cap with few files.
var maxTestFiles = 5000

// msRow is one row of the milestone table.
type msRow struct {
	name string   // label for findings: the milestone ID, or "row n"
	ms   string   // the milestone ID, or "" when the cell is not one
	ids  []string // test IDs after the range expansion, in cell order
}

// marker is one marker line of the Makefile.
type marker struct {
	id, target string
}

// runTests runs the tests mode over one spec directory and one tree.
func runTests(specDir, root, milestone string) ([]string, error) {
	if err := checkSpecDir(specDir); err != nil {
		return nil, err
	}
	text, findings, err := loadSpec(filepath.Join(specDir, "07-test-plan.md"))
	if err != nil {
		return nil, err
	}
	if len(findings) > 0 {
		return findings, nil // malformed input: the rules are skipped
	}
	rows, rowFindings, err := parseMilestones(text)
	if err != nil {
		return nil, err
	}
	findings = append(findings, rowFindings...)

	upto := -1
	for i, r := range rows {
		if r.ms == milestone {
			upto = i
			break
		}
	}
	if upto < 0 {
		return nil, fmt.Errorf("unknown milestone %q: no such row in the milestone table", milestone)
	}

	var ignored []string
	declared := map[string]bool{}
	for _, t := range parseTestPlan(text, &ignored) {
		declared[t.id] = true
	}
	findings = append(findings, checkRows(rows, declared)...)

	have, walkFindings, err := findTestFuncs(root)
	if err != nil {
		return nil, err
	}
	findings = append(findings, walkFindings...)
	marked, markFindings, err := findMarkers(filepath.Join(root, "Makefile"))
	if err != nil {
		return nil, err
	}
	findings = append(findings, markFindings...)

	seen := map[string]bool{}
	for _, r := range rows[:upto+1] {
		for _, id := range r.ids {
			if seen[id] {
				continue
			}
			seen[id] = true
			if !have[id] && !marked[id] {
				findings = append(findings, fmt.Sprintf("tests: %s (up to %s) has no Go test and no marker", id, milestone))
			}
		}
	}
	return findings, nil
}

// parseMilestones reads the table below the section 5 heading. It
// returns an error when the heading or the table is absent.
func parseMilestones(text string) ([]msRow, []string, error) {
	lines := strings.Split(text, "\n")
	start := -1
	for i, l := range lines {
		if strings.TrimSpace(l) == exitHeading {
			start = i + 1
			break
		}
	}
	if start < 0 {
		return nil, nil, errors.New("07-test-plan.md has no heading for the exit criteria per milestone")
	}

	var rows []msRow
	var findings []string
	tableLines := 0
	for _, l := range lines[start:] {
		if strings.HasPrefix(strings.TrimSpace(l), "#") {
			break
		}
		cells := splitRow(l)
		if cells == nil {
			if tableLines > 0 {
				break // a non-table line ends the table
			}
			continue
		}
		tableLines++
		if tableLines == 1 || isSepRow(cells) {
			continue // header and separator
		}
		n := len(rows) + 1
		if len(cells) != 2 {
			findings = append(findings, fmt.Sprintf("07-test-plan: milestone row %d has %d cells, want 2", n, len(cells)))
			rows = append(rows, msRow{name: fmt.Sprintf("row %d", n)})
			continue
		}
		row := msRow{name: fmt.Sprintf("row %d", n)}
		row.ms = milestoneID(cells[0])
		if row.ms == "" {
			findings = append(findings, fmt.Sprintf("07-test-plan: milestone row %d does not start with a milestone ID", n))
		} else {
			row.name = row.ms
		}
		ids, bad := expandList(cells[1])
		row.ids = ids
		for _, item := range bad {
			findings = append(findings, fmt.Sprintf("07-test-plan: milestone row %s item %d is not a valid test ID or range", row.name, item))
		}
		rows = append(rows, row)
	}
	if tableLines < 2 || len(rows) == 0 {
		return nil, nil, errors.New("07-test-plan.md has no milestone table below the exit criteria heading")
	}
	named := map[string]bool{}
	for _, r := range rows {
		if r.ms != "" && named[r.ms] {
			findings = append(findings, fmt.Sprintf("07-test-plan: milestone %s has more than one row", r.ms))
		}
		named[r.ms] = true
	}
	return rows, findings, nil
}

// milestoneID returns the ID at the start of a milestone cell: "M-5" for
// "M-5 (RC)". It returns "" when the cell does not start with one.
func milestoneID(cell string) string {
	id, _, _ := strings.Cut(cell, " ")
	if len(id) < 3 || !strings.HasPrefix(id, "M-") {
		return ""
	}
	for _, c := range id[2:] {
		if c < '0' || c > '9' {
			return ""
		}
	}
	return id
}

// expandList expands the list cell of a milestone row: it removes the
// lead, then expands each item. bad holds the numbers (from 1) of the
// items that are not a test ID or a range.
func expandList(cell string) (ids []string, bad []int) {
	switch {
	case strings.HasPrefix(cell, "+ "):
		cell = cell[2:]
	case strings.HasPrefix(cell, "everything incl. "):
		cell = cell[len("everything incl. "):]
	}
	for i, tok := range strings.Split(cell, ",") {
		got := expandOne(strings.TrimSpace(tok))
		if got == nil {
			bad = append(bad, i+1)
			continue
		}
		ids = append(ids, got...)
	}
	return ids, bad
}

// checkRows applies the duplicate rule and the declared rule to all rows.
func checkRows(rows []msRow, declared map[string]bool) []string {
	where := map[string][]int{} // test ID -> row indices, in row order
	var order []string
	for i, r := range rows {
		for _, id := range r.ids {
			if idx := where[id]; len(idx) > 0 && idx[len(idx)-1] == i {
				continue // the same ID twice in one row: not a second row
			}
			if _, ok := where[id]; !ok {
				order = append(order, id)
			}
			where[id] = append(where[id], i)
		}
	}
	sort.Strings(order)
	var findings []string
	for _, id := range order {
		if idx := where[id]; len(idx) > 1 {
			names := make([]string, len(idx))
			for k, i := range idx {
				names[k] = rows[i].name
			}
			findings = append(findings, fmt.Sprintf("07-test-plan: test %s is in more than one milestone row: %s", id, strings.Join(names, ", ")))
		}
		if !declared[id] {
			findings = append(findings, fmt.Sprintf("07-test-plan: milestone table lists %s, which no test table declares", id))
		}
	}
	return findings
}

// skipDir reports whether the walk skips a directory. The go tool ignores
// a directory with a name that starts with "." or "_".
func skipDir(name string) bool {
	return name == "testdata" || name == "vendor" ||
		strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_")
}

// isNestedModule reports whether dir has its own go.mod. The go tool does
// not build such a directory as part of the module above it. A go.mod that
// is a directory or a dangling symlink makes no module.
func isNestedModule(dir string) bool {
	fi, err := os.Stat(filepath.Join(dir, "go.mod"))
	return err == nil && !fi.IsDir()
}

// isBuilt reports whether go test builds the file. The name, the GOOS and
// GOARCH suffix and the build constraints must allow it. Every CI test run
// sets the tag "race", so the check sets it too. The check reads data, the
// same bytes that the parser reads. An error means that the file does not
// count: go test does not run it.
func isBuilt(dir, name string, data []byte) (bool, error) {
	ctxt := build.Default
	ctxt.BuildTags = append(slices.Clone(ctxt.BuildTags), "race")
	ctxt.OpenFile = func(string) (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(data)), nil
	}
	return ctxt.MatchFile(dir, name)
}

// parseTestFile parses one Go file. Each file has its own FileSet: a shared
// set keeps the line table of every file for the whole walk.
func parseTestFile(name string, data []byte) (*ast.File, error) {
	return parser.ParseFile(token.NewFileSet(), name, data, parser.SkipObjectResolution)
}

// findTestFuncs walks root and returns the test IDs that have a Go test.
// It does not follow symlinks. It parses at most maxTestFiles files.
func findTestFuncs(root string) (map[string]bool, []string, error) {
	if err := checkSpecDir(root); err != nil {
		return nil, nil, err
	}
	have := map[string]bool{}
	var findings []string
	parsed := 0
	unreadable := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if path == root {
			return err // an unreadable root is fatal
		}
		if err != nil {
			unreadable++
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if skipDir(d.Name()) || isNestedModule(path) {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() || !strings.HasSuffix(d.Name(), "_test.go") {
			return nil
		}
		if parsed == maxTestFiles {
			findings = append(findings, fmt.Sprintf("tests: more than %d test files; the walk stopped", maxTestFiles))
			return fs.SkipAll
		}
		parsed++
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			rel = d.Name()
		}
		label := printableName(filepath.ToSlash(rel))
		data, readErr := readCapped(path)
		if f := readFinding(label, readErr); f != "" {
			findings = append(findings, "tests: "+f)
			return nil
		}
		if readErr != nil {
			unreadable++
			return nil
		}
		built, buildErr := isBuilt(filepath.Dir(path), d.Name(), data)
		if buildErr != nil {
			findings = append(findings, fmt.Sprintf("tests: %s has a build line that does not parse", label))
			return nil
		}
		if !built {
			return nil
		}
		file, parseErr := parseTestFile(d.Name(), data)
		if parseErr != nil {
			findings = append(findings, fmt.Sprintf("tests: %s does not parse as Go", label))
		}
		if file != nil {
			for _, decl := range file.Decls {
				if id := testFuncID(decl); id != "" {
					have[id] = true
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, nil, errors.New("cannot walk the tree for Go tests")
	}
	if unreadable > 0 {
		findings = append(findings, fmt.Sprintf("tests: %d path(s) could not be read", unreadable))
	}
	return have, findings, nil
}

// testFuncID returns the test ID of a top-level test func. It returns ""
// when the declaration is not a test func with an ID in its name.
func testFuncID(decl ast.Decl) string {
	fn, ok := decl.(*ast.FuncDecl)
	if !ok || fn.Recv != nil || fn.Type.Params.NumFields() != 1 {
		return ""
	}
	return idFromTestName(fn.Name.Name)
}

// idFromTestName maps TestTS16Name to T-S-16. After the two digits, the
// name must end or go on with a character that is not a digit.
func idFromTestName(name string) string {
	const lead = "TestT"
	if len(name) < len(lead)+3 || !strings.HasPrefix(name, lead) {
		return ""
	}
	rest := name[len(lead):]
	letter, d1, d2 := rest[0], rest[1], rest[2]
	if letter < 'A' || letter > 'Z' || d1 < '0' || d1 > '9' || d2 < '0' || d2 > '9' {
		return ""
	}
	if next, _ := utf8.DecodeRuneInString(rest[3:]); unicode.IsDigit(next) {
		return ""
	}
	return fmt.Sprintf("T-%c-%c%c", letter, d1, d2)
}

// findMarkers reads the marker lines of the Makefile. It returns the IDs
// that a marker covers. A missing Makefile has no markers.
func findMarkers(path string) (map[string]bool, []string, error) {
	data, err := readCapped(path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]bool{}, nil, nil
	}
	if f := readFinding("Makefile", err); f != "" {
		return map[string]bool{}, []string{"tests: " + f}, nil
	}
	if err != nil {
		return nil, nil, errors.New("cannot read the Makefile")
	}
	lines := strings.Split(string(data), "\n")
	var markers []marker
	var findings []string
	for i, l := range lines {
		if !strings.HasPrefix(l, "# trace-test:") {
			continue
		}
		m, ok := parseMarker(l)
		if !ok {
			findings = append(findings, fmt.Sprintf("tests: Makefile line %d is a malformed marker; use %q", i+1, markerPrefix+"T-X-nn target"))
			continue
		}
		markers = append(markers, m)
	}
	marked := map[string]bool{}
	for _, m := range markers {
		if !hasRule(lines, m.target) {
			findings = append(findings, fmt.Sprintf("tests: marker for %s names a target that the Makefile does not define", m.id))
			continue
		}
		marked[m.id] = true
	}
	return marked, findings, nil
}

// parseMarker parses "# trace-test: T-P-07 perf": one test ID and one
// target name, with one space between the parts and nothing after them.
func parseMarker(line string) (marker, bool) {
	rest, ok := strings.CutPrefix(line, markerPrefix)
	if !ok {
		return marker{}, false
	}
	id, target, ok := strings.Cut(rest, " ")
	if !ok || !testIDRE.MatchString(id) || !validTarget(target) {
		return marker{}, false
	}
	return marker{id: id, target: target}, true
}

// validTarget accepts a plain target name: letters, digits, "-", "_", ".".
func validTarget(s string) bool {
	if s == "" || s[0] == '.' {
		return false
	}
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_', c == '.':
		default:
			return false
		}
	}
	return true
}

// hasRule reports whether a line starts with "target:" and is a rule. A
// variable assignment is not a rule: "target:=1", "target::=1" and the
// target-specific form "target: X = 1". A line that ends in an odd number
// of backslashes goes on in the next line, as in make.
func hasRule(lines []string, target string) bool {
	for i := 0; i < len(lines); i++ {
		l := lines[i]
		for i+1 < len(lines) && continues(l) {
			i++
			l = l[:len(l)-1] + " " + lines[i]
		}
		rest, ok := strings.CutPrefix(l, target+":")
		if ok && !isAssignment(rest) {
			return true
		}
	}
	return false
}

// continues reports whether a line ends in an odd number of backslashes.
func continues(line string) bool {
	return (len(line)-len(strings.TrimRight(line, `\`)))%2 == 1
}

// isAssignment reports whether the text after a rule colon has a "=" before
// any ";" or "#". A "=" inside "$(...)" or "${...}" does not count.
func isAssignment(rest string) bool {
	depth := 0
	for i := 0; i < len(rest); i++ {
		switch c := rest[i]; {
		case c == '$' && i+1 < len(rest) && (rest[i+1] == '(' || rest[i+1] == '{'):
			depth++
		case depth > 0 && (c == ')' || c == '}'):
			depth--
		case depth > 0:
		case c == ';' || c == '#':
			return false
		case c == '=':
			return true
		}
	}
	return false
}
