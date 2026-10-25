package main

import (
	"bytes"
	"go/scanner"
	"go/token"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// maxWords is the longest sentence of a comment, in words.
const maxWords = 20

// sentence is a comment sentence that is too long. It runs from the line of
// its first word to the line of its end mark.
type sentence struct{ first, last, words int }

// textLine is one line of comment text and the source line that holds it.
type textLine struct {
	text string
	line int
}

// hasAny reports whether the check covers a sentence that runs from line first
// to line last. It does when a line of the sentence changed. It also does when
// a deletion joined the sentence: lines were deleted after a line from first
// to last-1. The spans and the deletions are in line order, as git prints them.
func (t target) hasAny(first, last int) bool {
	if t.all {
		return true
	}
	i := sort.Search(len(t.spans), func(i int) bool { return t.spans[i].start+t.spans[i].n > first })
	if i < len(t.spans) && t.spans[i].start <= last {
		return true
	}
	j := sort.SearchInts(t.dels, first)
	return j < len(t.dels) && t.dels[j] < last
}

// longSentences returns the sentences of the comments of src that have more
// than maxWords words, in line order.
func longSentences(src []byte) []sentence {
	out, _ := checkedSentences(src, target{all: true})
	return out
}

// checkedSentences returns the sentences of src that have more than maxWords
// words and that the target covers, in line order. A sentence is covered when
// a line of it changed, or a deletion joined it, or a deletion came directly
// before it in the same text. When a changed line of a text is a fence line or
// a blank line, every sentence of the text is covered. scanErr is true when
// go/scanner reported an error for src.
func checkedSentences(src []byte, t target) (out []sentence, scanErr bool) {
	groups, scanErr := commentGroups(src)
	for _, g := range groups {
		whole := t.all || t.changedBreak(g)
		for _, p := range paragraphs(g) {
			for _, s := range p.long() {
				if whole || t.hasAny(s.first, s.last) || t.delBefore(s.first, g[0].line) {
					out = append(out, s)
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].first < out[j].first })
	return out, scanErr
}

// delBefore reports whether a deletion came directly before line first, and
// the line before the deletion is a line of the text that starts at line lo.
func (t target) delBefore(first, lo int) bool {
	if first-1 < lo {
		return false
	}
	j := sort.SearchInts(t.dels, first-1)
	return j < len(t.dels) && t.dels[j] == first-1
}

// changedBreak reports whether a changed line of the text is a fence line or a
// blank line.
func (t target) changedBreak(g []textLine) bool {
	for _, l := range g {
		s := strings.TrimSpace(l.text)
		if (s == "" || strings.HasPrefix(s, "```")) && t.has(l.line) {
			return true
		}
	}
	return false
}

// isASTDirective reports whether a "//" comment has the directive form of
// go/ast: "//line ", "//extern " or "//export " at the start, or "//", a name
// of [a-z0-9], a colon and one of [a-z0-9].
func isASTDirective(lit string) bool {
	for _, p := range []string{"//line ", "//extern ", "//export "} {
		if strings.HasPrefix(lit, p) {
			return true
		}
	}
	s, ok := strings.CutPrefix(lit, "//")
	if !ok {
		return false
	}
	name := func(c byte) bool { return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' }
	i := 0
	for i < len(s) && name(s[i]) {
		i++
	}
	return i > 0 && i+1 < len(s) && s[i] == ':' && name(s[i+1])
}

// commentGroups returns the text of the comments of src. A run of "//"
// comments on adjacent lines is one group, when each starts its line. A "//"
// comment after code is a group of its own. A "//" line that starts its line
// continues the trailing comment on the line before, when it starts at the
// same column. So does each next such line. Each "/* */" comment is a group of
// its own. A directive ends a group. A directive that isDirective does not
// know, but that has the go/ast form, is a group of its own. scanErr is true
// when go/scanner reported an error.
func commentGroups(src []byte) (groups [][]textLine, scanErr bool) {
	lines := strings.Split(string(src), "\n")
	fset := token.NewFileSet()
	file := fset.AddFile("", fset.Base(), len(src))
	var s scanner.Scanner
	s.Init(file, src, func(token.Position, string) {}, scanner.ScanComments)

	var (
		cur      []textLine
		prevEnd  int
		trail    bool // cur starts with a comment after code
		trailCol int
	)
	flush := func() {
		if cur != nil {
			groups = append(groups, cur)
			cur = nil
		}
	}
	for {
		pos, tok, lit := s.Scan()
		if tok == token.EOF {
			break
		}
		if tok != token.COMMENT {
			continue
		}
		if isDirective(lit) {
			flush()
			continue
		}
		p := file.PositionFor(pos, false)
		if !strings.HasPrefix(lit, "//") {
			flush()
			groups = append(groups, blockLines(lit, p.Line))
			continue
		}
		tl := textLine{strings.TrimSuffix(lit[2:], "\r"), p.Line}
		if isASTDirective(lit) {
			flush()
			groups = append(groups, []textLine{tl})
			continue
		}
		before := lines[p.Line-1][:min(p.Column-1, len(lines[p.Line-1]))]
		col := width(before)
		switch {
		case strings.TrimSpace(before) != "":
			flush()
			cur, trail, trailCol = []textLine{tl}, true, col
		case cur != nil && prevEnd == p.Line-1 && (!trail || col == trailCol):
			cur = append(cur, tl)
		default:
			flush()
			cur, trail = []textLine{tl}, false
		}
		prevEnd = p.Line
	}
	flush()
	return groups, s.ErrorCount > 0
}

// blockLines returns the lines of a "/* */" comment. It removes the markers,
// the indent and a "*" at the start of a line. The indent does not count, so
// a block comment has no code block that is found by its indent.
func blockLines(lit string, line int) []textLine {
	inner := strings.TrimSuffix(strings.TrimPrefix(lit, "/*"), "*/")
	var out []textLine
	for i, p := range strings.Split(inner, "\n") {
		p = strings.TrimSpace(p)
		if i > 0 {
			p = strings.TrimPrefix(p, "*")
		}
		out = append(out, textLine{p, line + i})
	}
	return out
}

// Kinds of text in a comment, as paragraphs reads it.
const (
	modeNone = iota
	modePara
	modeList
	modeCode
)

// paragraphs splits the lines of a comment into paragraphs, headings, list
// items and table cells. Each ends a sentence. It leaves out code, separator
// rows and trailer lines. A line is code in a fence of three backticks. A line
// with a tab or two spaces of indent is also code. This holds when no
// paragraph or list item is open. In a code block, each indented line stays
// code.
func paragraphs(g []textLine) []*para {
	var (
		paras []*para
		cur   *para
		mode  int
		fence bool
	)
	end := func() {
		if cur != nil {
			paras = append(paras, cur)
			cur = nil
		}
	}
	add := func(text string, line int) {
		if cur == nil {
			cur = &para{}
		}
		cur.add(text, line)
	}
	for _, l := range g {
		t := strings.TrimSpace(l.text)
		indented := strings.HasPrefix(l.text, "\t") || strings.HasPrefix(l.text, "  ")
		rest, item := listItem(t)
		switch {
		case strings.HasPrefix(t, "```"):
			end()
			fence = !fence
			mode = modeNone
		case fence:
		case t == "":
			end()
			mode = modeNone
		case indented && mode == modeCode:
		case !indented && isHeading(t):
			end()
			add(t, l.line)
			end()
			mode = modeNone
		case isTrailer(t):
			end()
			mode = modeNone
		case strings.HasPrefix(t, "|"):
			end()
			mode = modeNone
			for _, cell := range tableCells(t) {
				add(cell, l.line)
				end()
			}
		case item:
			end()
			add(rest, l.line)
			mode = modeList
		case indented && (mode == modePara || mode == modeList):
			add(t, l.line)
		case indented:
			end()
			mode = modeCode
		default:
			if mode != modePara {
				end()
			}
			mode = modePara
			add(t, l.line)
		}
	}
	end()
	return paras
}

// isTrailer reports whether a trimmed line is a commit trailer line in its full
// form: "Signed-off-by:" or "Co-authored-by:" in any case, a space, a name of 1
// to 20 words, a space, and an address in "<" and ">" at the end of the line.
// The name has no "<" or ">". The address has one "@" and no space, "<" or ">".
func isTrailer(t string) bool {
	for _, p := range []string{"signed-off-by:", "co-authored-by:"} {
		if len(t) < len(p) || !strings.EqualFold(t[:len(p)], p) {
			continue
		}
		rest, ok := strings.CutPrefix(t[len(p):], " ")
		if !ok || !strings.HasSuffix(rest, ">") {
			return false
		}
		i := strings.IndexByte(rest, '<')
		if i < 1 || rest[i-1] != ' ' {
			return false
		}
		name, addr := rest[:i-1], rest[i+1:len(rest)-1]
		words := len(strings.Fields(name))
		return words >= 1 && words <= 20 && strings.TrimSpace(name) == name &&
			!strings.Contains(name, ">") &&
			strings.Count(addr, "@") == 1 && !strings.ContainsAny(addr, "<>") &&
			strings.IndexFunc(addr, unicode.IsSpace) < 0
	}
	return false
}

// tableCells returns the cells of a table row, which starts with "|". A
// separator row, with only "|", "-", ":" and spaces, has no cell.
func tableCells(t string) []string {
	if strings.Trim(t, "|-: ") == "" {
		return nil
	}
	var cells []string
	for _, c := range strings.Split(t, "|") {
		if c = strings.TrimSpace(c); c != "" {
			cells = append(cells, c)
		}
	}
	return cells
}

// isHeading reports whether a trimmed line starts with "#" and a space.
func isHeading(t string) bool {
	h := strings.TrimLeft(t, "#")
	return h != t && strings.HasPrefix(h, " ")
}

// listItem reads a list marker at the start of a trimmed line. The marker is
// "-", "*", "+", "•", or a number with "." or ")". A space follows it. The
// function returns the text after the marker.
func listItem(t string) (rest string, ok bool) {
	if len(t) >= 2 && strings.IndexByte("-*+", t[0]) >= 0 && t[1] == ' ' {
		return t[2:], true
	}
	if r, found := strings.CutPrefix(t, "• "); found {
		return r, true
	}
	n := len(t) - len(strings.TrimLeft(t, "0123456789"))
	if n > 0 && n+1 < len(t) && (t[n] == '.' || t[n] == ')') && t[n+1] == ' ' {
		return t[n+2:], true
	}
	return "", false
}

// para is the text of a paragraph, a heading or a list item. Each line is
// joined to the one before it with a newline. A seg gives the source line
// of the text from the byte off.
type para struct {
	buf  []byte
	segs []seg
}

type seg struct{ off, line int }

func (p *para) add(text string, line int) {
	if len(p.buf) > 0 {
		p.buf = append(p.buf, '\n')
	}
	p.segs = append(p.segs, seg{len(p.buf), line})
	p.buf = append(p.buf, text...)
}

// spaceAt reports whether the rune that starts at byte i of b is a space, as
// unicode.IsSpace reads it.
func spaceAt(b []byte, i int) bool {
	r, _ := utf8.DecodeRune(b[i:])
	return unicode.IsSpace(r)
}

// long returns the sentences of the paragraph that are too long. The scan
// reads each byte once. A search for a closing character starts at the scan
// position. The result is kept for the next search. So the time is linear in
// the length of the text.
func (p *para) long() []sentence {
	var (
		out         []sentence
		b           = p.buf
		cursor      int
		words, from int
		inWord      bool
		open        bool // a "[" is open: it can start a link
		tick, stop  = -1, -1
	)
	lineAt := func(i int) int {
		for cursor+1 < len(p.segs) && p.segs[cursor+1].off <= i {
			cursor++
		}
		return p.segs[cursor].line
	}
	startWord := func(i int) {
		if !inWord {
			inWord = true
			words++
			if words == 1 {
				from = lineAt(i)
			}
		}
	}
	finish := func(i int) {
		if words > maxWords {
			out = append(out, sentence{from, lineAt(i), words})
		}
		words, inWord = 0, false
	}
	// nextTick is the index of the first backtick from index i, or len(b).
	nextTick := func(i int) int {
		if tick < i {
			tick = len(b)
			if j := bytes.IndexByte(b[min(i, len(b)):], '`'); j >= 0 {
				tick = i + j
			}
		}
		return tick
	}
	// nextStop is the index of the first ")" or space from index i, or len(b).
	nextStop := func(i int) int {
		if stop < i {
			stop = i
			for stop < len(b) && b[stop] != ')' && !spaceAt(b, stop) {
				_, n := utf8.DecodeRune(b[stop:])
				stop += n
			}
		}
		return stop
	}
	for i := 0; i < len(b); {
		c, n := utf8.DecodeRune(b[i:])
		switch {
		case unicode.IsSpace(c):
			inWord = false
		case c == '`' && nextTick(i+1) < len(b):
			startWord(i)
			i = nextTick(i+1) + 1
			continue
		case c == '[':
			open = true
			startWord(i)
		case c == ']' && open && i+1 < len(b) && b[i+1] == '(' && nextStop(i+2) < len(b) && b[nextStop(i+2)] == ')':
			// Only the link text counts: skip "](url)".
			startWord(i)
			open = false
			i = nextStop(i+2) + 1
			continue
		case c == '.' || c == '?' || c == '!':
			startWord(i)
			if i+1 == len(b) || spaceAt(b, i+1) {
				finish(i)
			}
		default:
			startWord(i)
		}
		i += n
	}
	if words > 0 {
		finish(len(b) - 1)
	}
	return out
}
