// Matrix check: the C10 traceability rules for spec/08-traceability.md.
//
// The matrix must agree with the requirement IDs declared in 01-prd.md and
// the Covers columns of 07-test-plan.md. After the set checks it re-emits
// the matrix in canonical form (row order from 01, Tests cells ordered by
// first occurrence in 07) and requires a byte-exact match with the
// committed file, so the file is a pure function of the other two.
//
// Findings name IDs and counts only: spec text is PR-controlled, so it
// never reaches a CI log.

package main

import (
	"fmt"
	"os"
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
	cRuleRE   = regexp.MustCompile(`^C(10|[1-9])$`)
	reqTokRE  = regexp.MustCompile(`^(FR-\d{2}|NFR-\d{2}|SEC-\d{2}|C(10|[1-9])|G\d+)$`)
	sepCellRE = regexp.MustCompile(`^-{3,}$`)

	// Test references, from strictest to loosest.
	testIDRE          = regexp.MustCompile(`^T-([A-Z])-(\d{2})$`)               // one test ID: T-U-01
	testRefRE         = regexp.MustCompile(`^T-([A-Z])-(\d{2})(\.\.(\d{2}))?$`) // a test ID or a range: T-U-01..04
	testRefAnywhereRE = regexp.MustCompile(`T-[A-Z]-\d{2}(?:\.\.\d{2})?`)       // a test reference anywhere in a string
)

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
	data, err := os.ReadFile(path)
	if err != nil {
		return "", nil, fmt.Errorf("%s: %w", path, err)
	}
	var findings []string
	if len(data) > maxFileBytes {
		findings = append(findings, fmt.Sprintf("%s: %d bytes exceeds the %d byte cap", path, len(data), maxFileBytes))
	}
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	if text != string(data) {
		findings = append(findings, fmt.Sprintf("%s: contains CRLF line endings; re-normalize to LF", path))
	}
	lines := strings.Split(text, "\n")
	if len(lines) > maxFileLines {
		findings = append(findings, fmt.Sprintf("%s: %d lines exceeds the %d line cap", path, len(lines), maxFileLines))
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
	prd, f, err := loadSpec(filepath.Join(specDir, "01-prd.md"))
	findings := append([]string(nil), f...)
	if err != nil {
		return findings, err
	}
	tp, f, err := loadSpec(filepath.Join(specDir, "07-test-plan.md"))
	findings = append(findings, f...)
	if err != nil {
		return findings, err
	}
	mat, f, err := loadSpec(filepath.Join(specDir, "08-traceability.md"))
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
	if strings.HasSuffix(line, "|") {
		line = line[:len(line)-1]
	}
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
		if cells == nil || len(cells) < 2 {
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
		for _, tok := range strings.Split(cells[1], ",") {
			tok = strings.TrimSpace(tok)
			if tok != "" && reqTokRE.MatchString(tok) {
				t.covers = append(t.covers, tok)
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
		return reqIDRE.MatchString(id) || goalIDRE.MatchString(id) || cRuleRE.MatchString(id)
	}

	for i, line := range lines {
		cells := splitRow(line)
		switch {
		case cells != nil && len(cells) == 3 && cells[0] == "Req" && cells[1] == "Design" && cells[2] == "Tests":
			groups = append(groups, matGroup{header: i, sep: -1, first: -1})
			cur = len(groups) - 1
			rowOpen = false
		case cells != nil && len(cells) == 3 && isRowID(cells[0]):
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
		case cells != nil && len(cells) == 3 && isSepRow(cells):
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
	for i := 1; i <= 10; i++ {
		main = append(main, fmt.Sprintf("C%d", i))
	}
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

// reemitTests rewrites a committed Tests cell in canonical form: tokens
// ordered by their first member's declaration order in 07, joined with
// ", ". A committed range stays a range. A cell with no test references
// (a "no tests" marker) is returned as-is.
func reemitTests(reqID, cell string, tests []test, findings *[]string) string {
	testPos := make(map[string]int, len(tests))
	for _, t := range tests {
		testPos[t.id] = t.order
	}

	type tok struct {
		orig string
		ids  []string
		pos  int
	}
	var toks []tok
	for _, part := range strings.Split(cell, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		ids := expandOne(part)
		if ids == nil {
			if testRefAnywhereRE.MatchString(part) {
				*findings = append(*findings, fmt.Sprintf("08-traceability: %s Tests cell has a malformed test reference %q", reqID, part))
			}
			toks = append(toks, tok{orig: part, pos: -1}) // prose marker
			continue
		}
		tr := tok{orig: part, ids: ids, pos: -1}
		contig := true
		prev := -1
		for _, id := range ids {
			p, ok := testPos[id]
			if !ok {
				contig = false
				if tr.pos < 0 {
					tr.pos = len(tests) // unknown member: sort last
				}
				continue
			}
			if tr.pos < 0 {
				tr.pos = p
			}
			if prev >= 0 && p != prev+1 {
				contig = false
			}
			prev = p
		}
		if len(ids) > 1 && !contig {
			*findings = append(*findings, fmt.Sprintf("08-traceability: %s Tests cell range %s is not contiguous in 07 order", reqID, part))
		}
		toks = append(toks, tr)
	}

	hasTest := false
	for _, t := range toks {
		if t.ids != nil {
			hasTest = true
		}
	}
	if !hasTest {
		return cell
	}
	sorted := make([]tok, len(toks))
	copy(sorted, toks)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].pos < sorted[j].pos })
	parts := make([]string, len(sorted))
	for i, t := range sorted {
		parts[i] = t.orig
	}
	return strings.Join(parts, ", ")
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
	for _, r := range reqs {
		if r.exempt {
			exempt[r.id] = true
		}
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
