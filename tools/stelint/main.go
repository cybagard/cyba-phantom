// Command stelint checks two limits in Go comments. A comment line has at most
// 80 columns. A comment sentence has at most 20 words.
//
// Usage:
//
//	stelint <base> <head>
//	stelint -all [head]
//
// The first form fails only for text that changed between base and head. The
// changed lines come from "git diff base...head", the same range as the dco
// check. The file text comes from head.
//
// The second form checks the tracked Go files at head, except symbolic links.
// It prints each hit and a total for each rule. It exits 0 unless git or an
// input limit fails.
//
// A comment line is each source line that holds comment text. These are a
// "//" line, a "//" comment after code, and each line of a "/* */" comment.
// go/scanner finds the comments, so "//" in a string literal is not a comment.
//
// A comment is a compiler directive when it starts with "//go:build",
// "//go:generate", "//go:embed" or "//go:linkname", then a space. A "//line "
// comment whose text has no space is also a directive. A directive is not
// prose, so stelint skips it. It checks each other "//go:" or "//line"
// comment.
//
// The count is for the full source line, with the indent. A tab moves to the
// next multiple of 4 columns, as "expand -t4" does. Each other character is
// one column. A comment line that holds only an http:// or https:// URL can
// be longer. stelint skips each file with a testdata directory in its path.
//
// # Sentences
//
// Adjacent "//" lines that each start their line are one text. A blank "//"
// line, a line of code or a directive ends that text. A "//" comment after
// code is a text of its own. Each "/* */" comment is also a text of its own.
// In it the indent does not count. A "*" at the start of a line is removed.
//
// A sentence ends at ".", "?" or "!" before a space, a line end or the end of
// the text. It also ends at a blank line, a heading, a list item, and the
// start of a code block. A colon in a line does not end a sentence. A
// semicolon, a dash and a parenthesis do not end a sentence.
//
// A heading starts with "#" and a space. A list item starts with a marker and
// a space. The marker is "-", "*", "+", "•", or a number with "." or ")". An
// indented line after a list item belongs to the item.
//
// A code block is a run of lines with a tab or two spaces of indent. It
// starts after a blank line or a code block. A fence of three backticks also
// makes a code block. stelint does not count code.
//
// A word is a run of characters between spaces. A code span in backticks is
// one word, also when it has spaces. A "." in a code span does not end a
// sentence. In a Markdown link, only the link text counts. A backtick or a
// link with no closing mark is an ordinary character.
//
// A sentence is checked when at least one line of it is a changed line.
//
// # Output
//
// A long line prints as "path:line: <n> columns (limit 80)". A long sentence
// prints as "path:line: <n> words (limit 20)", with the line of its first
// word. Paths come from a pull request, so stelint prints no raw control
// character.
//
// A file over 1 MiB, or a git output over the output cap, is not parsed. A
// hunk that ends after line 1048576 is not parsed. Each gives an error and
// exit code 2. When base is empty, stelint prints one line that says the
// check did not run, and exits 0.
//
// Not in this change: stelint does not find quoted text, third-party text or
// legal text. The writing standard does not count them. It does not check
// text outside Go comments, such as Markdown files, strings and commit
// messages.
//
// Exit codes:
//
//	0  pass, or the check did not run
//	1  a changed line is too long, or a changed sentence has too many words
//	2  usage, git or input limit error
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"go/scanner"
	"go/token"
	"io"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	maxColumns = 80
	tabWidth   = 4
)

// Input bounds. Both are variables so that the tests can lower them.
var (
	maxFileBytes = 1 << 20 // 1 MiB per file
	maxDiffBytes = 8 << 20 // 8 MiB per git output
)

func main() { os.Exit(run(os.Args[1:], ".", os.Stdout, os.Stderr)) }

// span is a run of n lines that starts at line start.
type span struct{ start, n int }

// target is a file to check. When all is true, every line counts. Otherwise
// only the lines in spans count.
type target struct {
	path  string
	all   bool
	spans []span
}

// has reports whether the line is one that the check covers.
func (t target) has(line int) bool {
	if t.all {
		return true
	}
	for _, s := range t.spans {
		if line >= s.start && line < s.start+s.n {
			return true
		}
	}
	return false
}

// hit is a comment line that is too long.
type hit struct{ line, cols int }

// run is the whole program, with the directory of the repository as input.
func run(args []string, dir string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("stelint", flag.ContinueOnError)
	fs.SetOutput(stderr)
	all := fs.Bool("all", false, "check every tracked file at head and exit 0")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	base, head := "", "HEAD"
	switch {
	case *all && len(rest) <= 1:
		if len(rest) == 1 {
			head = rest[0]
		}
	case !*all && len(rest) == 2:
		base, head = rest[0], rest[1]
	default:
		fmt.Fprintln(stderr, "usage: stelint <base> <head> | stelint -all [head]")
		return 2
	}
	if strings.HasPrefix(base, "-") || strings.HasPrefix(head, "-") || head == "" {
		fmt.Fprintln(stderr, "stelint: a revision must not be empty or start with '-'")
		return 2
	}

	if *all {
		targets, err := listTracked(dir, head)
		if err != nil {
			fmt.Fprintf(stderr, "stelint: %v\n", err)
			return 2
		}
		return report(dir, head, targets, stdout, stderr)
	}
	if base == "" {
		fmt.Fprintln(stdout, "stelint: the check did not run: BASE is empty and the ref origin/main does not exist")
		return 0
	}
	targets, err := listChanged(dir, base, head)
	if err != nil {
		fmt.Fprintf(stderr, "stelint: %v\n", err)
		return 2
	}
	return check(dir, base, head, targets, stdout, stderr)
}

// totals counts the hits of a scan. For each rule it holds the hits and the
// files with a hit.
type totals struct{ lines, lineFiles, sents, sentFiles int }

// report prints every hit of every target and a total for each rule. It
// exits 0, unless an input limit or git fails.
func report(dir, head string, targets []target, stdout, stderr io.Writer) int {
	n, err := scanTargets(dir, head, targets, stdout)
	if err != nil {
		fmt.Fprintf(stderr, "stelint: %v\n", err)
		return 2
	}
	fmt.Fprintf(stdout, "stelint: %d comment line(s) over %d columns in %d file(s)\n", n.lines, maxColumns, n.lineFiles)
	fmt.Fprintf(stdout, "stelint: %d comment sentence(s) over %d words in %d file(s)\n", n.sents, maxWords, n.sentFiles)
	return 0
}

// check fails when a changed comment line is too long. It also fails when a
// comment sentence with a changed line has too many words.
func check(dir, base, head string, targets []target, stdout, stderr io.Writer) int {
	n, err := scanTargets(dir, head, targets, stdout)
	if err != nil {
		fmt.Fprintf(stderr, "stelint: %v\n", err)
		return 2
	}
	if n.lines+n.sents > 0 {
		fmt.Fprintf(stdout, "stelint FAIL: %d changed comment line(s) over %d columns, %d comment sentence(s) over %d words\n",
			n.lines, maxColumns, n.sents, maxWords)
		return 1
	}
	fmt.Fprintf(stdout, "stelint: no changed comment line over %d columns and no changed sentence over %d words in %.12s...%.12s\n",
		maxColumns, maxWords, clean(base), clean(head))
	return 0
}

// scanTargets prints the hits of each target: the long lines, then the long
// sentences. It returns the totals.
func scanTargets(dir, head string, targets []target, stdout io.Writer) (n totals, err error) {
	for _, t := range targets {
		src, tooBig, err := gitOut(dir, maxFileBytes, "show", head+":"+t.path)
		if err != nil {
			return totals{}, fmt.Errorf("git show of %s failed: %w", clean(t.path), err)
		}
		if tooBig {
			return totals{}, fmt.Errorf("%s is over %d bytes: not parsed", clean(t.path), maxFileBytes)
		}
		lines, sents := 0, 0
		for _, h := range longLines(src) {
			if !t.has(h.line) {
				continue
			}
			fmt.Fprintf(stdout, "%s:%d: %d columns (limit %d)\n", clean(t.path), h.line, h.cols, maxColumns)
			lines++
		}
		for _, s := range longSentences(src) {
			if !t.hasAny(s.first, s.last) {
				continue
			}
			fmt.Fprintf(stdout, "%s:%d: %d words (limit %d)\n", clean(t.path), s.first, s.words, maxWords)
			sents++
		}
		n.lines += lines
		n.sents += sents
		if lines > 0 {
			n.lineFiles++
		}
		if sents > 0 {
			n.sentFiles++
		}
	}
	return n, nil
}

// wanted reports whether stelint checks the path: a Go file with no testdata
// directory element.
func wanted(path string) bool {
	if !strings.HasSuffix(path, ".go") {
		return false
	}
	for _, elem := range strings.Split(path, "/") {
		if elem == "testdata" {
			return false
		}
	}
	return true
}

// listTracked lists the Go files of the tree at head.
func listTracked(dir, head string) ([]target, error) {
	out, tooBig, err := gitOut(dir, maxDiffBytes, "ls-tree", "-r", "-z", head)
	if err != nil {
		return nil, fmt.Errorf("git ls-tree %s failed: %w", clean(head), err)
	}
	if tooBig {
		return nil, fmt.Errorf("git ls-tree output is over %d bytes: not parsed", maxDiffBytes)
	}
	var targets []target
	for _, rec := range strings.Split(string(out), "\x00") {
		// Each record is "<mode> <type> <object>\t<path>".
		meta, path, ok := strings.Cut(rec, "\t")
		if !ok || !wanted(path) {
			continue
		}
		if f := strings.Fields(meta); len(f) != 3 || f[1] != "blob" || f[0] == "120000" {
			continue
		}
		targets = append(targets, target{path: path, all: true})
	}
	return targets, nil
}

// listChanged lists the Go files that differ between base and head, with
// their changed line numbers in head. The options --text and --no-textconv
// keep a .gitattributes file from hiding a changed file as binary.
func listChanged(dir, base, head string) ([]target, error) {
	out, tooBig, err := gitOut(dir, maxDiffBytes, "diff", "-U0", "-M", "--no-color", "--text",
		"--no-textconv", "--no-ext-diff", "--src-prefix=a/", "--dst-prefix=b/", base+"..."+head, "--", "*.go")
	if err != nil {
		return nil, fmt.Errorf("git diff %s...%s failed: %w", clean(base), clean(head), err)
	}
	if tooBig {
		return nil, fmt.Errorf("git diff output is over %d bytes: not parsed", maxDiffBytes)
	}
	return parseDiff(string(out))
}

// parseDiff reads the changed line numbers of the new files from a "-U0"
// patch. Hunk headers give the lengths, so a body line that looks like a
// file header is not read as one.
func parseDiff(patch string) ([]target, error) {
	var (
		targets        []target
		cur            *target
		oldLeft, nLeft int
	)
	for _, l := range strings.Split(patch, "\n") {
		if oldLeft > 0 || nLeft > 0 {
			switch {
			case strings.HasPrefix(l, "-"):
				oldLeft--
			case strings.HasPrefix(l, "+"):
				nLeft--
			}
			continue
		}
		switch {
		case strings.HasPrefix(l, "+++ "):
			cur = nil
			path, ok, err := newPath(l[4:])
			if err != nil {
				return nil, err
			}
			if ok && wanted(path) {
				targets = append(targets, target{path: path})
				cur = &targets[len(targets)-1]
			}
		case strings.HasPrefix(l, "@@ "):
			start, oldLen, newLen, ok := parseHunk(l)
			if !ok {
				return nil, errors.New("bad hunk header in git diff output")
			}
			// A file of maxFileBytes bytes has at most that many lines.
			if newLen > 0 && (start > maxFileBytes || newLen > maxFileBytes ||
				start+newLen-1 > maxFileBytes) {
				return nil, fmt.Errorf("a hunk ends after line %d: not parsed", maxFileBytes)
			}
			oldLeft, nLeft = oldLen, newLen
			if cur != nil && newLen > 0 {
				cur.spans = append(cur.spans, span{start, newLen})
			}
		}
	}
	return targets, nil
}

// newPath reads the path of the new file from the text after "+++ ". It
// returns ok false for a deleted file.
func newPath(s string) (path string, ok bool, err error) {
	// Git can end the path with a tab, also after a closing quote.
	s = strings.TrimSuffix(s, "\t")
	if strings.HasPrefix(s, `"`) {
		if s, err = strconv.Unquote(s); err != nil {
			return "", false, errors.New("bad quoted path in git diff output")
		}
	}
	if s == "/dev/null" {
		return "", false, nil
	}
	path, ok = strings.CutPrefix(s, "b/")
	if !ok {
		return "", false, errors.New("bad path in git diff output")
	}
	return path, true, nil
}

// parseHunk reads "@@ -a[,b] +c[,d] @@". A missing length is 1.
func parseHunk(l string) (start, oldLen, newLen int, ok bool) {
	f := strings.Fields(l)
	if len(f) < 4 || !strings.HasPrefix(f[1], "-") || !strings.HasPrefix(f[2], "+") {
		return 0, 0, 0, false
	}
	_, oldLen, ok1 := splitRange(f[1][1:])
	start, newLen, ok2 := splitRange(f[2][1:])
	return start, oldLen, newLen, ok1 && ok2
}

func splitRange(s string) (start, n int, ok bool) {
	a, b, hasLen := strings.Cut(s, ",")
	n = 1
	var err1, err2 error
	start, err1 = strconv.Atoi(a)
	if hasLen {
		n, err2 = strconv.Atoi(b)
	}
	return start, n, err1 == nil && err2 == nil && start >= 0 && n >= 0
}

// longLines returns the comment lines of src that are too long, in line
// order.
func longLines(src []byte) []hit {
	lines := strings.Split(string(src), "\n")
	fset := token.NewFileSet()
	file := fset.AddFile("", fset.Base(), len(src))
	var s scanner.Scanner
	s.Init(file, src, func(token.Position, string) {}, scanner.ScanComments)

	seen := map[int]bool{}
	var hits []hit
	for {
		pos, tok, lit := s.Scan()
		if tok == token.EOF {
			break
		}
		if tok != token.COMMENT || isDirective(lit) {
			continue
		}
		// PositionFor with false ignores "//line" directives.
		p := file.PositionFor(pos, false)
		parts := strings.Split(lit, "\n")
		for i, part := range parts {
			n := p.Line + i
			if n > len(lines) || seen[n] {
				continue
			}
			seen[n] = true
			line := strings.TrimSuffix(lines[n-1], "\r")
			cols := width(line)
			if cols <= maxColumns {
				continue
			}
			before := ""
			if i == 0 {
				before = line[:min(p.Column-1, len(line))]
			}
			after := ""
			if i == len(parts)-1 {
				after = line[min(len(before)+len(part), len(line)):]
			}
			if urlOnly(before, part, after, i == 0, i == len(parts)-1, strings.HasPrefix(lit, "/*")) {
				continue
			}
			hits = append(hits, hit{n, cols})
		}
	}
	sort.Slice(hits, func(i, j int) bool { return hits[i].line < hits[j].line })
	return hits
}

// isDirective reports whether a comment is a compiler directive. These are
// "//go:" with a known name and a space, and "//line" with no space in its
// text.
func isDirective(lit string) bool {
	if name, ok := strings.CutPrefix(lit, "//go:"); ok {
		for _, d := range []string{"build ", "generate ", "embed ", "linkname "} {
			if strings.HasPrefix(name, d) {
				return true
			}
		}
		return false
	}
	text, ok := strings.CutPrefix(lit, "//line ")
	return ok && !strings.Contains(text, " ")
}

// width counts the columns of a line as "expand -t4" does. A tab moves to the
// next multiple of 4. Each other character is one column.
func width(line string) int {
	col := 0
	for _, r := range line {
		if r == '\t' {
			col += tabWidth - col%tabWidth
		} else {
			col++
		}
	}
	return col
}

// urlOnly reports whether a comment line holds only a URL. The text before
// and after the comment on the line must be blank.
func urlOnly(before, part, after string, first, last, block bool) bool {
	if strings.TrimSpace(before) != "" || strings.TrimSpace(after) != "" {
		return false
	}
	t := strings.TrimSpace(part)
	switch {
	case first && strings.HasPrefix(t, "//"):
		t = t[2:]
	case first:
		t = strings.TrimPrefix(t, "/*")
	default:
		t = strings.TrimPrefix(t, "*")
	}
	if block && last {
		t = strings.TrimSuffix(strings.TrimSpace(t), "*/")
	}
	t = strings.TrimSpace(t)
	rest, ok := strings.CutPrefix(t, "https://")
	if !ok {
		rest, ok = strings.CutPrefix(t, "http://")
	}
	return ok && rest != "" && strings.IndexFunc(rest, unicode.IsSpace) < 0
}

// capWriter keeps at most max bytes. It sets over and fails on the next byte.
type capWriter struct {
	buf  bytes.Buffer
	max  int
	over bool
}

func (w *capWriter) Write(p []byte) (int, error) {
	if w.buf.Len()+len(p) > w.max {
		w.over = true
		return 0, errors.New("output over the size limit")
	}
	return w.buf.Write(p)
}

// gitOut runs git in dir and returns its output. When the output is over max
// bytes, git stops and tooBig is true. stelint does not print the stderr of
// git.
func gitOut(dir string, max int, args ...string) (out []byte, tooBig bool, err error) {
	w := &capWriter{max: max}
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Stdout = w
	err = cmd.Run()
	if w.over {
		return nil, true, nil
	}
	return w.buf.Bytes(), false, err
}

// clean makes a string safe to print. It escapes each control character, each
// other non-printing character, and each byte that is not UTF-8.
func clean(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && n == 1:
			fmt.Fprintf(&b, `\x%02x`, s[i])
		case unicode.IsPrint(r):
			b.WriteRune(r)
		default:
			fmt.Fprintf(&b, `\u%04x`, r)
		}
		i += n
	}
	return b.String()
}
