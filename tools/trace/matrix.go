// Matrix check: the C10 traceability rules for spec/08-traceability.md.
//
// The matrix must agree with the requirement IDs declared in 01-prd.md and
// the Covers columns of 07-test-plan.md. After the set checks it re-emits
// the matrix in canonical form and requires a byte-exact match with the
// committed file. 01 and 07 decide the row set, the row order, and the
// Tests cell of each row that has tests. A Tests cell lists its test IDs
// in 07 order. A run is IDs that are next to each other in 07, with one
// type letter and consecutive numbers. A run of two or more is one range.
// The trace tool keeps the Design column of the committed file. It keeps the
// text of a cell that has no tests. It keeps the place of each table. It
// keeps the lines that are not rows: text, table headers, and separators.
//
// Findings name IDs and counts only: spec text is PR-controlled, so it
// never reaches a CI log.

package main

import (
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Size caps on spec input. Spec files are small by design; anything
// larger is a finding, not a workload the tool should absorb.
const (
	maxFileBytes = 1 << 20 // 1 MiB per file
	maxFileLines = 10000   // lines per file
	maxLineBytes = 8192    // bytes per line
)

var (
	reqIDRE   = regexp.MustCompile(`^(FR|NFR|SEC)-\d{2}$`)
	goalIDRE  = regexp.MustCompile(`^G\d+$`)
	reqTokRE  = regexp.MustCompile(`^(FR-\d{2}|NFR-\d{2}|SEC-\d{2}|G\d+)$`)
	sepCellRE = regexp.MustCompile(`^-{3,}$`)
	// idLikeRE matches a token that starts like a requirement ID, valid or
	// not, in any case: "FR-O3", "fr-03", "SEC-04a", "FR 01", "C11", "G 2".
	// Prose in Covers ("rotation", "threat A2") does not match.
	idLikeRE = regexp.MustCompile(`(?i)^((fr|nfr|sec)[^a-z]|[cg][- ]?\d)`)

	// Test references, from strictest to loosest.
	testIDRE          = regexp.MustCompile(`^T-([A-Z])-(\d{2})$`)               // one test ID: T-U-01
	testRefRE         = regexp.MustCompile(`^T-([A-Z])-(\d{2})(\.\.(\d{2}))?$`) // a test ID or a range: T-U-01..04
	testRefAnywhereRE = regexp.MustCompile(`T-[A-Z]-\d{2}(?:\.\.\d{2})?`)       // a test reference anywhere in a string
)

// cRuleIDs returns the constitution rule IDs C1..C10 in order.
func cRuleIDs() []string {
	ids := make([]string, 0, 10)
	for i := 1; i <= 10; i++ {
		ids = append(ids, fmt.Sprintf("C%d", i))
	}
	return ids
}

// cRuleSet holds the IDs of cRuleIDs. The package builds it once, at start.
var cRuleSet = func() map[string]bool {
	set := map[string]bool{}
	for _, id := range cRuleIDs() {
		set[id] = true
	}
	return set
}()

// isCRule reports if id is a constitution rule ID.
func isCRule(id string) bool {
	return cRuleSet[id]
}

// req is a requirement or goal declared in 01.
type req struct {
	id     string
	exempt bool // declared under a heading marked "exempt from C10"
}

// test is a test case declared in 07.
type test struct {
	id     string
	covers []string // requirement tokens, in cell order
	order  int      // declaration order within 07
}

// matRow is one committed row of 08.
type matRow struct {
	reqID  string
	design string
	tests  string // Tests cell, as committed
	line   int    // line index in the normalized file
}

// matGroup is one table in 08: header line, separator line, rows.
type matGroup struct {
	header int
	sep    int
	first  int // insertion point: first row line, or sep+1 when rowless
	rows   []matRow
}

// loadSpec reads one spec file, applying the size caps. It returns the
// LF-normalized text, any cap/CRLF findings, and a fatal error for a
// missing or unreadable file.
func loadSpec(path string) (string, []string, error) {
	return loadSpecAs(path, path)
}

// loadSpecAs reads the file at readPath. Findings and errors print path, the
// display name. The read uses readPath only.
func loadSpecAs(readPath, path string) (string, []string, error) {
	data, err := readCapped(readPath)
	if f := readFinding(path, err); f != "" {
		return "", []string{f}, nil
	}
	if err != nil {
		return "", nil, fmt.Errorf("%s: %w", path, err)
	}
	var findings []string
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	if text != string(data) {
		findings = append(findings, fmt.Sprintf("%s: contains CRLF line endings; re-normalize to LF", path))
	}
	lines := strings.Split(text, "\n")
	n := len(lines)
	if n > 0 && lines[n-1] == "" {
		n-- // a final newline ends the last line; it does not start one
	}
	if n > maxFileLines {
		findings = append(findings, fmt.Sprintf("%s: %d lines exceeds the %d line cap", path, n, maxFileLines))
	}
	for _, l := range lines {
		if len(l) > maxLineBytes {
			findings = append(findings, fmt.Sprintf("%s: a line exceeds the %d byte cap", path, maxLineBytes))
			break
		}
	}
	if len(findings) > 0 {
		return "", findings, nil
	}
	return text, nil, nil
}

// runMatrix runs the full C10 check over one spec directory.
func runMatrix(specDir string) ([]string, error) {
	dir, err := resolveSpecDir(specDir)
	if err != nil {
		return nil, err
	}
	prd, f, err := loadSpecAs(filepath.Join(dir, "01-prd.md"), specDir+"/01-prd.md")
	findings := append([]string(nil), f...)
	if err != nil {
		return findings, err
	}
	tp, f, err := loadSpecAs(filepath.Join(dir, "07-test-plan.md"), specDir+"/07-test-plan.md")
	findings = append(findings, f...)
	if err != nil {
		return findings, err
	}
	mat, f, err := loadSpecAs(filepath.Join(dir, "08-traceability.md"), specDir+"/08-traceability.md")
	findings = append(findings, f...)
	if err != nil {
		return findings, err
	}
	if len(findings) > 0 {
		return findings, nil // malformed input: set checks skipped
	}
	return append(findings, checkMatrix(prd, tp, mat)...), nil
}

// splitRow splits a markdown table row into trimmed cells, or returns nil
// for a non-table line.
func splitRow(line string) []string {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "|") {
		return nil
	}
	line = strings.TrimSuffix(line, "|")
	line = strings.TrimPrefix(line, "|")
	cells := strings.Split(line, "|")
	for i, c := range cells {
		cells[i] = strings.TrimSpace(c)
	}
	return cells
}

func isSepRow(cells []string) bool {
	for _, c := range cells {
		if !sepCellRE.MatchString(c) {
			return false
		}
	}
	return true
}

// parsePRD collects requirement and goal IDs in declaration order,
// tracking the nearest heading for the C10 exemption marker.
func parsePRD(text string, findings *[]string) []req {
	var reqs []req
	seen := map[string]bool{}
	heading := ""
	for _, line := range strings.Split(text, "\n") {
		if h := strings.TrimSpace(line); strings.HasPrefix(h, "#") {
			heading = h
			continue
		}
		cells := splitRow(line)
		if cells == nil {
			continue
		}
		id := cells[0]
		if !reqIDRE.MatchString(id) && !goalIDRE.MatchString(id) {
			continue
		}
		if seen[id] {
			*findings = append(*findings, fmt.Sprintf("01-prd: duplicate requirement ID %s", id))
			continue
		}
		seen[id] = true
		reqs = append(reqs, req{id: id, exempt: strings.Contains(heading, "exempt from C10")})
	}
	return reqs
}

// parseTestPlan collects test IDs in declaration order with their Covers
// tokens (cell 2). Rows whose first cell is not a T-ID (layer rows,
// milestone rows) are ignored.
func parseTestPlan(text string, findings *[]string) []test {
	var tests []test
	seen := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		cells := splitRow(line)
		if len(cells) < 2 {
			continue
		}
		if !testIDRE.MatchString(cells[0]) {
			continue
		}
		id := cells[0]
		if seen[id] {
			*findings = append(*findings, fmt.Sprintf("07-test-plan: duplicate test ID %s", id))
			continue
		}
		seen[id] = true
		t := test{id: id, order: len(tests)}
		for i, tok := range strings.Split(cells[1], ",") {
			tok = strings.TrimSpace(tok)
			switch {
			case tok == "":
			case reqTokRE.MatchString(tok) || isCRule(tok):
				t.covers = append(t.covers, tok)
			case idLikeRE.MatchString(tok):
				// Looks like an ID but is not one (FR-1, FR-100, C11):
				// a typo must not drop out of the C10 check.
				*findings = append(*findings, fmt.Sprintf("07-test-plan: test %s Covers item %d is not a valid requirement ID", id, i+1))
			}
		}
		tests = append(tests, t)
	}
	return tests
}

// parseMatrixFile collects the tables, their rows, and line indices from
// the committed 08 file.
func parseMatrixFile(text string, findings *[]string) ([]matRow, []matGroup) {
	lines := strings.Split(text, "\n")
	var all []matRow
	var groups []matGroup
	cur := -1
	rowOpen := false // a row line has appeared since the current header

	isRowID := func(id string) bool {
		return reqIDRE.MatchString(id) || goalIDRE.MatchString(id) || isCRule(id)
	}

	for i, line := range lines {
		cells := splitRow(line)
		switch {
		case len(cells) == 3 && cells[0] == "Req" && cells[1] == "Design" && cells[2] == "Tests":
			groups = append(groups, matGroup{header: i, sep: -1, first: -1})
			cur = len(groups) - 1
			rowOpen = false
		case len(cells) == 3 && isRowID(cells[0]):
			if cur < 0 {
				*findings = append(*findings, fmt.Sprintf("08-traceability: row %s lies outside a table (line %d)", cells[0], i+1))
				continue
			}
			g := &groups[cur]
			if g.first < 0 {
				g.first = i
			}
			r := matRow{reqID: cells[0], design: cells[1], tests: cells[2], line: i}
			g.rows = append(g.rows, r)
			all = append(all, r)
			rowOpen = true
		case len(cells) == 3 && isSepRow(cells):
			if cur >= 0 && groups[cur].sep < 0 {
				groups[cur].sep = i
			}
			rowOpen = false // a separator after rows: the table ended
		case strings.HasPrefix(line, "|"):
			if rowOpen {
				cur = -1 // a non-row table line ends the table
			}
		default:
			cur = -1 // a non-table line ends any open table
		}
	}

	for gi := range groups {
		if groups[gi].first < 0 { // rowless group: insert after the separator
			if groups[gi].sep >= 0 {
				groups[gi].first = groups[gi].sep + 1
			} else {
				groups[gi].first = groups[gi].header + 1
			}
		}
	}
	return all, groups
}

// expectedRows returns the canonical row IDs: 01 requirements in
// declaration order (exempts removed) followed by C1..C10, plus 01 goals
// in declaration order.
func expectedRows(reqs []req) (main, goals []string) {
	for _, r := range reqs {
		if r.exempt {
			continue
		}
		if goalIDRE.MatchString(r.id) {
			goals = append(goals, r.id)
			continue
		}
		main = append(main, r.id)
	}
	main = append(main, cRuleIDs()...)
	return main, goals
}

// expandOne expands one Tests-cell token (a test ID or a contiguous
// range) into test IDs; it returns nil for a malformed token.
func expandOne(tok string) []string {
	m := testRefRE.FindStringSubmatch(tok)
	if m == nil {
		return nil
	}
	lo, _ := strconv.Atoi(m[2])
	if m[3] == "" {
		return []string{fmt.Sprintf("T-%s-%s", m[1], m[2])}
	}
	hi, _ := strconv.Atoi(m[4])
	if hi < lo {
		return nil
	}
	ids := make([]string, 0, hi-lo+1)
	for n := lo; n <= hi; n++ {
		ids = append(ids, fmt.Sprintf("T-%s-%02d", m[1], n))
	}
	return ids
}

// expandToken expands every token in a Tests cell.
func expandToken(cell string) []string {
	var ids []string
	for _, tok := range strings.Split(cell, ",") {
		ids = append(ids, expandOne(strings.TrimSpace(tok))...)
	}
	return ids
}

// setDelta returns sorted (want−got, got−want).
func setDelta(want, got map[string]bool) (missing, extra []string) {
	for id := range want {
		if !got[id] {
			missing = append(missing, id)
		}
	}
	for id := range got {
		if !want[id] {
			extra = append(extra, id)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	return missing, extra
}

// reemitTests writes a Tests cell in canonical form from the set of test
// IDs it names, not from its tokens. The IDs follow their declaration
// order in 07. IDs that are next to each other in 07, with
// one type letter and consecutive numbers, make a run. A run of two or
// more is one range. Other IDs stand alone. Then come the IDs that 07
// does not declare, in ID order, and the prose tokens, in cell order.
// reemitTests joins the tokens with ", ". A prose token in a cell that has
// a test reference is a finding. A cell with no test references (a "no
// tests" marker) stays as it is.
func reemitTests(reqID, cell string, tests []test, findings *[]string) string {
	testPos := make(map[string]int, len(tests))
	for _, t := range tests {
		testPos[t.id] = t.order
	}

	var known []test // IDs that 07 declares, in cell order
	var unknown, prose []string
	// Item numbers of prose tokens that are not malformed references.
	var proseItems []int
	seen := map[string]bool{}
	hasTest := false
	for i, part := range strings.Split(cell, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		ids := expandOne(part)
		if ids == nil {
			if testRefAnywhereRE.MatchString(part) {
				*findings = append(*findings, fmt.Sprintf("08-traceability: %s Tests cell has a malformed test reference (item %d)", reqID, i+1))
			} else {
				proseItems = append(proseItems, i+1)
			}
			prose = append(prose, part)
			continue
		}
		hasTest = true
		contig := true
		prev := -1
		for _, id := range ids {
			p, ok := testPos[id]
			if !ok {
				contig = false
			} else if prev >= 0 && p != prev+1 {
				contig = false
			}
			if ok {
				prev = p
			}
			if seen[id] {
				continue
			}
			seen[id] = true
			if ok {
				known = append(known, test{id: id, order: p})
			} else {
				unknown = append(unknown, id)
			}
		}
		if len(ids) > 1 && !contig {
			*findings = append(*findings, fmt.Sprintf("08-traceability: %s Tests cell range %s is not contiguous in 07 order", reqID, part))
		}
	}
	if !hasTest {
		return cell
	}
	for _, n := range proseItems {
		*findings = append(*findings, fmt.Sprintf("08-traceability: %s Tests cell has an item that is not a test reference (item %d)", reqID, n))
	}

	sort.Slice(known, func(i, j int) bool { return known[i].order < known[j].order })
	sort.Strings(unknown)
	var parts []string
	for i := 0; i < len(known); {
		j := i + 1
		for j < len(known) && nextInRun(known[j-1], known[j]) {
			j++
		}
		if j-i >= 2 {
			parts = append(parts, known[i].id+".."+known[j-1].id[len(known[j-1].id)-2:])
		} else {
			parts = append(parts, known[i].id)
		}
		i = j
	}
	parts = append(parts, unknown...)
	parts = append(parts, prose...)
	return strings.Join(parts, ", ")
}

// nextInRun reports if b continues a range that ends with a. A range
// continues when b is next to a in 07. b must also have the type letter of
// a and the next number.
func nextInRun(a, b test) bool {
	ma := testIDRE.FindStringSubmatch(a.id)
	mb := testIDRE.FindStringSubmatch(b.id)
	if ma == nil || mb == nil || ma[1] != mb[1] || b.order != a.order+1 {
		return false
	}
	na, _ := strconv.Atoi(ma[2])
	nb, _ := strconv.Atoi(mb[2])
	return nb == na+1
}

// tableRows records which kinds of row a committed table holds. A table
// holding both is mixed: a finding, re-emitted as both canonical sets.
type tableRows struct {
	main, goals bool
}

func classifyTable(g matGroup) tableRows {
	var k tableRows
	for _, r := range g.rows {
		if goalIDRE.MatchString(r.reqID) {
			k.goals = true
		} else {
			k.main = true
		}
	}
	return k
}

func (k tableRows) mixed() bool { return k.main && k.goals }

// diffFinding reports where two file texts differ: line numbers and a
// count only: findings name IDs and counts, never file content.
func diffFinding(committed, canonical string) []string {
	cl := strings.Split(committed, "\n")
	nl := strings.Split(canonical, "\n")
	n := len(cl)
	if len(nl) > n {
		n = len(nl)
	}
	at := func(l []string, i int) string {
		if i < len(l) {
			return l[i]
		}
		return "<absent>"
	}
	var out []string
	diffs := 0
	for i := 0; i < n; i++ {
		if at(cl, i) == at(nl, i) {
			continue
		}
		diffs++
		if len(out) < 10 {
			out = append(out, fmt.Sprintf("08-traceability: line %d differs (committed vs canonical)", i+1))
		}
	}
	if diffs == 0 {
		return nil
	}
	header := fmt.Sprintf("08-traceability: re-emitted matrix differs from the committed file at %d line(s):", diffs)
	if diffs > len(out) {
		out = append(out, fmt.Sprintf("… %d more differing line(s)", diffs-len(out)))
	}
	return append([]string{header}, out...)
}

// buildCanonical re-emits the 08 file: non-row lines pass through, row
// lines are replaced by the canonical rows in canonical order.
func buildCanonical(text string, groups []matGroup, expMain, expGoals []string, rows []matRow, tests []test, findings *[]string) string {
	lines := strings.Split(text, "\n")
	committed := make(map[string]matRow, len(rows))
	for _, r := range rows {
		committed[r.reqID] = r
	}

	skip := map[int]bool{}
	insert := map[int][]string{}
	for gi, g := range groups {
		for _, r := range g.rows {
			skip[r.line] = true
		}
		kind := classifyTable(g)
		if kind.mixed() {
			*findings = append(*findings, fmt.Sprintf("08-traceability: table %d mixes goal and requirement rows", gi+1))
		}
		var sets [][]string
		if kind.main || !kind.goals {
			sets = append(sets, expMain)
		}
		if kind.goals {
			sets = append(sets, expGoals)
		}
		var rowLines []string
		for _, set := range sets {
			for _, id := range set {
				cr, ok := committed[id]
				if !ok {
					continue // missing: reported, and the byte compare catches it
				}
				cell := reemitTests(id, cr.tests, tests, findings)
				rowLines = append(rowLines, fmt.Sprintf("| %s | %s | %s |", id, cr.design, cell))
			}
		}
		insert[g.first] = rowLines
	}

	var out []string
	for i, l := range lines {
		if skip[i] {
			if rl, ok := insert[i]; ok {
				out = append(out, rl...) // canonical rows replace the committed row lines
			}
			continue
		}
		if rl, ok := insert[i]; ok {
			out = append(out, rl...) // rowless group: canonical rows precede the following line
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}

// checkMatrix runs all C10 checks; an empty result means the matrix is
// in sync.
func checkMatrix(prd, tp, mat string) []string {
	var findings []string

	reqs := parsePRD(prd, &findings)
	tests := parseTestPlan(tp, &findings)
	rows, groups := parseMatrixFile(mat, &findings)

	expMain, expGoals := expectedRows(reqs)
	expected := make(map[string]bool, len(expMain)+len(expGoals))
	for _, id := range expMain {
		expected[id] = true
	}
	for _, id := range expGoals {
		expected[id] = true
	}
	exempt := map[string]bool{}
	declared := map[string]bool{}
	for _, r := range reqs {
		declared[r.id] = true
		if r.exempt {
			exempt[r.id] = true
		}
	}
	for _, id := range cRuleIDs() {
		declared[id] = true
	}

	// Row set <-> requirement set, in both directions.
	committed := map[string]bool{}
	for _, r := range rows {
		if committed[r.reqID] {
			findings = append(findings, fmt.Sprintf("08-traceability: duplicate row %s", r.reqID))
		}
		committed[r.reqID] = true
	}
	for _, id := range append(append([]string{}, expMain...), expGoals...) {
		if !committed[id] {
			findings = append(findings, fmt.Sprintf("08-traceability: requirement %s has no row", id))
		}
	}
	committedIDs := make([]string, 0, len(committed))
	for id := range committed {
		committedIDs = append(committedIDs, id)
	}
	sort.Strings(committedIDs)
	for _, id := range committedIDs {
		if expected[id] {
			continue
		}
		if exempt[id] {
			findings = append(findings, fmt.Sprintf("08-traceability: row %s is C10-exempt and must not appear", id))
		} else {
			findings = append(findings, fmt.Sprintf("08-traceability: row %s matches no requirement in 01", id))
		}
	}

	// Per-requirement test sets derived from 07.
	byReq := map[string][]string{}
	for _, t := range tests {
		for _, c := range t.covers {
			byReq[c] = append(byReq[c], t.id)
		}
	}

	// Orphan tests; no test may cover C10 (the trace job is the check).
	for _, t := range tests {
		if len(t.covers) == 0 {
			findings = append(findings, fmt.Sprintf("07-test-plan: test %s covers no requirement (orphan)", t.id))
		}
		for _, c := range t.covers {
			if !declared[c] {
				findings = append(findings, fmt.Sprintf("07-test-plan: test %s covers %s, which 01 does not declare", t.id, c))
			}
			if exempt[c] {
				findings = append(findings, fmt.Sprintf("07-test-plan: test %s covers %s, which is exempt from C10 (no v1 tests)", t.id, c))
			}
			if c == "C10" {
				findings = append(findings, fmt.Sprintf("07-test-plan: test %s covers C10; no test may cover the trace check", t.id))
			}
		}
	}

	// Per-row: committed Tests cell vs 07-derived set.
	for _, r := range rows {
		exp := map[string]bool{}
		for _, id := range byReq[r.reqID] {
			exp[id] = true
		}
		if r.reqID == "C10" {
			if testRefAnywhereRE.MatchString(r.tests) {
				findings = append(findings, "08-traceability: C10 Tests cell contains a T-ID; it must be the no-test marker")
			}
			continue
		}
		got := map[string]bool{}
		for _, id := range expandToken(r.tests) {
			got[id] = true
		}
		missing, extra := setDelta(exp, got)
		if len(missing) > 0 || len(extra) > 0 {
			msg := fmt.Sprintf("08-traceability: %s Tests cell disagrees with 07", r.reqID)
			if len(missing) > 0 {
				msg += fmt.Sprintf("; missing: %s", strings.Join(missing, ", "))
			}
			if len(extra) > 0 {
				msg += fmt.Sprintf("; extra: %s", strings.Join(extra, ", "))
			}
			findings = append(findings, msg)
		}
		if expected[r.reqID] && len(exp) == 0 {
			findings = append(findings, fmt.Sprintf("01-prd: requirement %s has no tests (C10)", r.reqID))
		}
	}

	// Byte-exact re-emit.
	canonical := buildCanonical(mat, groups, expMain, expGoals, rows, tests, &findings)
	if canonical != mat {
		findings = append(findings, diffFinding(mat, canonical)...)
	}
	return findings
}
