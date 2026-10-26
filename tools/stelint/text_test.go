package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// textFile writes a text file in a new directory and returns its path.
func textFile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, dir, "body.md", content)
	return filepath.Join(dir, "body.md")
}

func TestTextReportsOnlyTheLongSentence(t *testing.T) {
	path := textFile(t, ws(26)+".\n"+ws(25)+".\n")
	code, out, errOut := runLint(t.TempDir(), "-text", path)
	want := path + ":1: 26 words (limit 25)\n" +
		"stelint FAIL: 1 sentence(s) over 25 words in " + path + "\n"
	if code != 1 || out != want || errOut != "" {
		t.Errorf("code = %d, out = %q, err = %q, want 1 and %q", code, out, errOut, want)
	}
}

func TestTextReportsTheFirstLineOfASentence(t *testing.T) {
	path := textFile(t, "Intro.\n\n"+ws(13)+"\n"+ws(13)+".\n")
	_, out, _ := runLint(t.TempDir(), "-text", path)
	if want := path + ":3: 26 words (limit 25)\n"; !strings.HasPrefix(out, want) {
		t.Errorf("out = %q, want the prefix %q", out, want)
	}
}

func TestTextPassPrintsASummary(t *testing.T) {
	path := textFile(t, ws(25)+".\n")
	code, out, _ := runLint(t.TempDir(), "-text", path)
	if want := "stelint: no sentence over 25 words in " + path + "\n"; code != 0 || out != want {
		t.Errorf("code = %d, out = %q, want 0 and %q", code, out, want)
	}
}

func TestTextSentenceBreaks(t *testing.T) {
	for _, tc := range []struct {
		name, src string
		hits      int
	}{
		{"two table cells of 15 words", "| " + ws(15) + " | " + ws(15) + " |\n", 0},
		{"a row after a separator row still counts", "| --- | :-: |\n| " + ws(26) + " |\n", 1},
		{"two list items of 12 words", "- " + ws(12) + "\n- " + ws(12) + "\n", 0},
		{"numbered list items", "1. " + ws(12) + "\n2) " + ws(12) + "\n", 0},
		{"heading then 12 words", "# " + ws(12) + "\n" + ws(12) + "\n", 0},
		{"heading after text", ws(12) + "\n# " + ws(12) + "\n", 0},
		{"30 words in a fence", "```\n" + ws(30) + "\n```\n", 0},
		{"a backtick in a fence", "```\n` " + ws(25) + "\n```\n", 0},
		{"30 words in an indented code block", "Text.\n\n    " + ws(30) + "\n", 0},
		{"text after a fence still counts", "```\nx\n```\n" + ws(26) + "\n", 1},
		{"a trailer line ends the sentence", ws(22) + "\nSigned-off-by: A B <a@example.com>\n", 0},
		{"24 words, a code span and an end mark", ws(24) + " `a b c d`.\n", 0},
		{"25 words and a code span", ws(25) + " `a b c d`.\n", 1},
		{"code span in the middle", ws(12) + " `a. b` " + ws(12) + ".\n", 0},
		{"code span over two lines", ws(12) + " `a\nb` " + ws(12) + ".\n", 0},
		{"code span joined to a word", "x`a b`y " + ws(24) + ".\n", 0},
		{"unclosed backtick is a character at 25", ws(24) + " `a.\n", 0},
		{"unclosed backtick is a character at 26", ws(25) + " `a.\n", 1},
	} {
		path := textFile(t, tc.src)
		code, out, _ := runLint(t.TempDir(), "-text", path)
		want := 0
		if tc.hits > 0 {
			want = 1
		}
		if code != want || strings.Count(out, " words (limit 25)") != tc.hits {
			t.Errorf("%s: code = %d, out = %q, want %d hit(s)", tc.name, code, out, tc.hits)
		}
	}
}

// A code span is one word in a comment and in a text file. The same words give
// the same count in both. The limits differ: 20 for a comment, 25 for a text.
func TestCodeSpanIsOneWordInBothModes(t *testing.T) {
	words := ws(25) + " `a b`.\n"
	if got := sentences("// " + words); len(got) != 1 || got[0].words != 26 {
		t.Errorf("comment: sentences = %v, want one with 26 words", got)
	}
	if got := textSentences([]byte(words)); len(got) != 1 || got[0].words != 26 {
		t.Errorf("text: sentences = %v, want one with 26 words", got)
	}
	if got := sentences("// " + ws(20) + ".\n"); len(got) != 0 {
		t.Errorf("comment at 20 words: sentences = %v, want none", got)
	}
	if got := sentences("// " + ws(21) + ".\n"); len(got) != 1 || got[0].words != 21 {
		t.Errorf("comment at 21 words: sentences = %v, want one with 21 words", got)
	}
	if got := sentences("// " + ws(20) + " `a b`.\n"); len(got) != 1 || got[0].words != 21 {
		t.Errorf("comment with a code span: sentences = %v, want one with 21 words", got)
	}
}

func TestTextRefusesTwentyWordsAndSixCodeSpans(t *testing.T) {
	path := textFile(t, ws(20)+" `a` `b c` `d` `e` `f` `g`.\n")
	code, out, errOut := runLint(t.TempDir(), "-text", path)
	want := path + ":1: 26 words (limit 25)\n" +
		"stelint FAIL: 1 sentence(s) over 25 words in " + path + "\n"
	if code != 1 || out != want || errOut != "" {
		t.Errorf("code = %d, out = %q, err = %q, want 1 and %q", code, out, errOut, want)
	}
}

func TestTextCRLFKeepsLineNumbers(t *testing.T) {
	lf := "Intro.\n\n" + ws(26) + ".\n\n" + ws(27) + ".\n"
	crlf := strings.ReplaceAll(lf, "\n", "\r\n")
	pathLF := textFile(t, lf)
	pathCRLF := textFile(t, crlf)
	_, outLF, _ := runLint(t.TempDir(), "-text", pathLF)
	_, outCRLF, _ := runLint(t.TempDir(), "-text", pathCRLF)
	hits := func(out, path string) string { return strings.ReplaceAll(out, path, "P") }
	if hits(outLF, pathLF) != hits(outCRLF, pathCRLF) ||
		!strings.Contains(outCRLF, ":3: 26 words") || !strings.Contains(outCRLF, ":5: 27 words") {
		t.Errorf("LF output %q differs from CRLF output %q", outLF, outCRLF)
	}
}

func TestTextUsageAndReadErrorsExitTwo(t *testing.T) {
	path := textFile(t, "ok.\n")
	for _, tc := range []struct {
		args  []string
		usage bool
	}{
		{[]string{"-text"}, true},
		{[]string{"-text", path, path}, true},
		{[]string{"-text", "-all", path}, true},
		{[]string{"-text", "-all"}, true},
		{[]string{"-text", filepath.Join(t.TempDir(), "missing.md")}, false},
		{[]string{"-text", t.TempDir()}, false},
	} {
		code, _, errOut := runLint(t.TempDir(), tc.args...)
		if code != 2 || errOut == "" {
			t.Errorf("args %q: code = %d, err = %q, want 2 and a message", tc.args, code, errOut)
		}
		if tc.usage && !strings.Contains(errOut, "usage: stelint -text <file>") {
			t.Errorf("args %q: err = %q, want the usage line", tc.args, errOut)
		}
	}
}

func TestTextEndlessFileIsRefused(t *testing.T) {
	code, _, errOut := runLint(t.TempDir(), "-text", "/dev/zero")
	if code != 2 || !strings.Contains(errOut, "not parsed") {
		t.Errorf("/dev/zero: code = %d, err = %q, want 2 and not parsed", code, errOut)
	}
}

func TestTextFileNameIsEscaped(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a\x1bb.md", ws(26)+".\n")
	path := filepath.Join(dir, "a\x1bb.md")
	esc := strings.ReplaceAll(path, "\x1b", `\u001b`)
	_, out, _ := runLint(t.TempDir(), "-text", path)
	if want := esc + ":1: 26 words (limit 25)\n"; !strings.HasPrefix(out, want) || strings.Contains(out, "\x1b") {
		t.Errorf("out = %q, want the prefix %q and no ESC byte", out, want)
	}
	old := maxFileBytes
	maxFileBytes = 1
	defer func() { maxFileBytes = old }()
	_, _, errOut := runLint(t.TempDir(), "-text", path)
	if want := "stelint: " + esc + " is over"; !strings.HasPrefix(errOut, want) || strings.Contains(errOut, "\x1b") {
		t.Errorf("err = %q, want the prefix %q and no ESC byte", errOut, want)
	}
}

func TestTextFileOverLimitIsRefused(t *testing.T) {
	big := "word.\n"
	path := textFile(t, big)
	old := maxFileBytes
	maxFileBytes = len(big) - 1
	defer func() { maxFileBytes = old }()
	if code, _, errOut := runLint(t.TempDir(), "-text", path); code != 2 || !strings.Contains(errOut, "not parsed") {
		t.Errorf("over the limit: code = %d, err = %q, want 2", code, errOut)
	}
	maxFileBytes = len(big)
	if code, _, _ := runLint(t.TempDir(), "-text", path); code != 0 {
		t.Errorf("at the limit: code = %d, want 0", code)
	}
}
