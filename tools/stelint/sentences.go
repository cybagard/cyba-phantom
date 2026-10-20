package main

import (
	"bytes"
	"go/scanner"
	"go/token"
	"sort"
	"strings"
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

// hasAny reports whether the check covers at least one line from first to
// last. The spans are in line order, as git prints them.
func (t target) hasAny(first, last int) bool {
	if t.all {
		return true
	}
	i := sort.Search(len(t.spans), func(i int) bool { return t.spans[i].start+t.spans[i].n > first })
	return i < len(t.spans) && t.spans[i].start <= last
}

// longSentences returns the sentences of the comments of src that have more
// than maxWords words, in line order.
func longSentences(src []byte) []sentence {
	var out []sentence
	for _, g := range commentGroups(src) {
		for _, p := range paragraphs(g) {
			out = append(out, p.long()...)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].first < out[j].first })
	return out
}

// commentGroups returns the text of the comments of src. A run of "//"
// comments on adjacent lines is one group, when each starts its line. A "//"
// comment after code is a group of its own. So is each "/* */" comment. A
// directive ends a group.
func commentGroups(src []byte) [][]textLine {
	lines := strings.Split(string(src), "\n")
	fset := token.NewFileSet()
	file := fset.AddFile("", fset.Base(), len(src))
	var s scanner.Scanner
	s.Init(file, src, func(token.Position, string) {}, scanner.ScanComments)

	var (
		groups  [][]textLine
		cur     []textLine
		prevEnd int
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
		before := lines[p.Line-1][:min(p.Column-1, len(lines[p.Line-1]))]
		full := strings.TrimSpace(before) == ""
		if !full || cur == nil || prevEnd != p.Line-1 {
			flush()
		}
		tl := textLine{strings.TrimSuffix(lit[2:], "\r"), p.Line}
		if !full {
			groups = append(groups, []textLine{tl})
			continue
		}
		cur = append(cur, tl)
		prevEnd = p.Line
	}
	flush()
	return groups
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

// paragraphs splits the lines of a comment into paragraphs, headings and list
// items. Each ends a sentence. It leaves out code. A line is code in a fence
// of three backticks. A line with a tab or two spaces of indent is also code.
// This holds when no paragraph or list item is open.
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
		case !indented && isHeading(t):
			end()
			add(t, l.line)
			end()
			mode = modeNone
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

func isSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }

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
			for stop < len(b) && b[stop] != ')' && !isSpace(b[stop]) {
				stop++
			}
		}
		return stop
	}
	for i := 0; i < len(b); {
		c := b[i]
		switch {
		case isSpace(c):
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
			if i+1 == len(b) || isSpace(b[i+1]) {
				finish(i)
			}
		default:
			startWord(i)
		}
		i++
	}
	if words > 0 {
		finish(len(b) - 1)
	}
	return out
}
