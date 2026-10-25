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
	// noCode is true when the line is in a text that starts after code. Its
	// indent does not make a code block.
	noCode bool
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
// words and that the target covers, in line order. The target covers a
// sentence when a line of it changed. It also does when a deletion joined it,
// or came directly before it in the same text. A fence line or a blank line
// can change a whole text. When one is a changed line, the target covers every
// sentence of the text. scanErr is true when go/scanner reported an error for
// src.
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

// delBefore reports whether a deletion came directly before line first. The
// line before the deletion must be a line of the text that starts at line lo.
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

// isASTDirective reports whether a "//" comment is a go/ast directive token.
// A rune for which isWordBreak is true is ignored at the end. The comment
// starts with "//", a name of a-z and 0-9, and a colon. After the colon, each
// byte is a-z, 0-9, "," or "_", and there is at least one. Any other byte makes
// the comment ordinary text.
func isASTDirective(lit string) bool {
	s, ok := strings.CutPrefix(lit, "//")
	if !ok {
		return false
	}
	s = strings.TrimRightFunc(s, isWordBreak)
	name := func(c byte) bool { return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' }
	i := 0
	for i < len(s) && name(s[i]) {
		i++
	}
	if i == 0 || i+1 >= len(s) || s[i] != ':' {
		return false
	}
	for _, c := range []byte(s[i+1:]) {
		if !name(c) && c != ',' && c != '_' {
			return false
		}
	}
	return true
}

// commentGroups returns the text of the comments of src. A run of "//"
// comments on adjacent lines is one group, when each starts its line. A "//"
// comment after code starts a group. A "//" line that starts its line
// continues it, when the line is directly after the group. The line must start
// at the column of the trailing comment. Each next such line also continues
// the group. A line of a group that starts after code has noCode set. So its
// indent does not make a code block. Each "/* */" comment is a group of its
// own. A directive ends a group. A comment that isDirective does not know, and
// that is only a go/ast directive token, is a token. On a line of its own, a
// token does not end the group. In a group that starts after code, a token at
// another column ends the group. After code, the code ends the group. With more
// text, the comment is ordinary comment text. A token in the middle of a group
// counts as one word. A token at the end adds no words. A run of adjacent token
// lines can start the group. If a "//" text line follows the run directly,
// each token of the run counts.
// scanErr is true when go/scanner reported an error.
func commentGroups(src []byte) (groups [][]textLine, scanErr bool) {
	lines := strings.Split(string(src), "\n")
	fset := token.NewFileSet()
	file := fset.AddFile("", fset.Base(), len(src))
	var s scanner.Scanner
	s.Init(file, src, func(token.Position, string) {}, scanner.ScanComments)

	var (
		cur      []textLine
		tokens   []textLine // tokens after cur, or before it when cur is nil
		prevEnd  int
		trail    bool // cur starts with a comment after code
		trailCol int
	)
	flush := func() {
		if cur != nil {
			groups = append(groups, cur)
			cur = nil
		}
		tokens = nil
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
		tl := textLine{text: strings.TrimSuffix(lit[2:], "\r"), line: p.Line}
		before := lines[p.Line-1][:min(p.Column-1, len(lines[p.Line-1]))]
		col := width(before)
		if isASTDirective(lit) {
			// After code, the code ends the text. On a line of its own, the
			// text goes on past the token. The token counts when it does.
			if strings.TrimSpace(before) != "" {
				flush()
				continue
			}
			adjacent := prevEnd == p.Line-1
			if !adjacent || cur != nil && trail && col != trailCol {
				flush()
			}
			tokens = append(tokens, tl)
			prevEnd = p.Line
			continue
		}
		switch {
		case strings.TrimSpace(before) != "":
			flush()
			tl.noCode = true
			cur, trail, trailCol = []textLine{tl}, true, col
		case cur != nil && prevEnd == p.Line-1 && (!trail || col == trailCol):
			tl.noCode = trail
			cur = append(cur, tokens...)
			tokens = nil
			cur = append(cur, tl)
		default:
			pending := tokens
			if cur != nil || prevEnd != p.Line-1 {
				pending = nil
			}
			flush()
			cur, trail = append(pending, tl), false
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
		out = append(out, textLine{text: p, line: line + i})
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
// code. A line with noCode set never starts a code block by its indent.
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
		case indented && !l.noCode:
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
// form. The line starts with "Signed-off-by:" or "Co-authored-by:", in any
// case. A space, a name of 1 to 20 words, a space and an address in "<" and ">"
// follow. The address ends the line. The name has no "<" or ">". The address
// has one "@", and no word break, "<" or ">".
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
		words := len(strings.FieldsFunc(name, isWordBreak))
		return words >= 1 && words <= 20 && strings.TrimFunc(name, isWordBreak) == name &&
			!strings.Contains(name, ">") &&
			strings.Count(addr, "@") == 1 && !strings.ContainsAny(addr, "<>") &&
			strings.IndexFunc(addr, isWordBreak) < 0
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

// isBlank reports whether a rune is a space for the sentence rule. It is a
// space when unicode.IsSpace is true. It is also a space for U+115F, U+1160,
// U+2800, U+3164, U+FFA0 and U+1D159, which render blank. A sentence end needs
// such a space. isWordBreak is the wider rule for the end of a word.
func isBlank(r rune) bool {
	switch r {
	case '\u115F', '\u1160', '\u2800', '\u3164', '\uFFA0', '\U0001D159':
		return true
	}
	return unicode.IsSpace(r)
}

// isWordBreak reports whether a rune breaks a word. It does for six classes.
// The first is the runes of isBlank. The second is control runes (category
// Cc). The third is format runes (category Cf, for example U+200B). The fourth
// is private-use runes (category Co). The fifth is the variation selectors. The
// sixth is the other default-ignorable runes, for example U+034F. These runes
// render no gap, so they do not join the words around them. A sentence end
// needs a space. For that, isBlank is the rule.
func isWordBreak(r rune) bool {
	return isBlank(r) || unicode.Is(unicode.Cc, r) || unicode.Is(unicode.Cf, r) ||
		unicode.Is(unicode.Co, r) || unicode.Is(unicode.Variation_Selector, r) ||
		unicode.Is(unicode.Other_Default_Ignorable_Code_Point, r)
}

// spaceAt reports whether the rune that starts at byte i of b is a space, as
// isBlank reads it.
func spaceAt(b []byte, i int) bool {
	r, _ := utf8.DecodeRune(b[i:])
	return isBlank(r)
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
	// nextStop is the index of the first ")" or word break from index i. If
	// there is none, it is len(b).
	nextStop := func(i int) int {
		if stop < i {
			stop = i
			for stop < len(b) && b[stop] != ')' {
				r, n := utf8.DecodeRune(b[stop:])
				if isWordBreak(r) {
					break
				}
				stop += n
			}
		}
		return stop
	}
	for i := 0; i < len(b); {
		c, n := utf8.DecodeRune(b[i:])
		switch {
		case isWordBreak(c):
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
