package main

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// me is the only author and sign-off address the identity rule allows.
const me = "67512030+cybagard@users.noreply.github.com"

// other is an address the identity rule refuses (reserved test domain).
const other = "other@example.com"

// gitEnv runs a git subcommand in dir with extra environment variables
// and fails the test on error.
func gitEnv(t *testing.T, dir string, env []string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return string(out)
}

// git runs a git subcommand in dir and fails the test on error.
func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	return gitEnv(t, dir, nil, args...)
}

func newRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	git(t, dir, "init", "-b", "main")
	return dir
}

// commitWith makes an empty commit by the noreply address; env can set
// another author or committer.
func commitWith(t *testing.T, dir string, env []string, args ...string) {
	t.Helper()
	gitEnv(t, dir, env, append([]string{"-c", "user.name=t", "-c", "user.email=" + me,
		"commit", "--allow-empty"}, args...)...)
}

func commit(t *testing.T, dir, msg string, sign bool) {
	t.Helper()
	args := []string{"-m", msg}
	if sign {
		args = append(args, "-s")
	}
	commitWith(t, dir, nil, args...)
}

// runDCO runs the checker and returns the exit code, the standard output
// and the standard error.
func runDCO(args []string, dir string) (int, string, string) {
	var out, errOut bytes.Buffer
	code := run(args, dir, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestAllSigned(t *testing.T) {
	dir := newRepo(t)
	commit(t, dir, "base", true)
	git(t, dir, "branch", "base")
	commit(t, dir, "signed one", true)
	commit(t, dir, "signed two", true)
	if code, _, _ := runDCO([]string{"base", "HEAD"}, dir); code != 0 {
		t.Fatalf("run = %d, want 0", code)
	}
}

func TestUnsignedFails(t *testing.T) {
	dir := newRepo(t)
	commit(t, dir, "base", true)
	git(t, dir, "branch", "base")
	commit(t, dir, "signed", true)
	commit(t, dir, "unsigned", false)
	code, out, _ := runDCO([]string{"base", "HEAD"}, dir)
	if code != 1 || !strings.Contains(out, "unsigned: ") {
		t.Fatalf("run = %d, want 1 with an unsigned line; output %q", code, out)
	}
}

// A hand-typed trailer (second paragraph) is a valid sign-off.
func TestManualTrailerCounts(t *testing.T) {
	dir := newRepo(t)
	commit(t, dir, "base", true)
	git(t, dir, "branch", "base")
	commitWith(t, dir, nil, "-m", "manual", "-m", "Signed-off-by: t <"+me+">")
	if code, _, _ := runDCO([]string{"base", "HEAD"}, dir); code != 0 {
		t.Fatalf("run = %d, want 0", code)
	}
}

// A sign-off line without an address is not a DCO trailer.
func TestSignoffWithoutEmailFails(t *testing.T) {
	dir := newRepo(t)
	commit(t, dir, "base", true)
	git(t, dir, "branch", "base")
	commitWith(t, dir, nil, "-m", "nope", "-m", "Signed-off-by: t")
	if code, _, _ := runDCO([]string{"base", "HEAD"}, dir); code != 1 {
		t.Fatalf("run = %d, want 1", code)
	}
}

func TestEmptyRangePasses(t *testing.T) {
	dir := newRepo(t)
	commit(t, dir, "only", true)
	if code, _, _ := runDCO([]string{"HEAD", "HEAD"}, dir); code != 0 {
		t.Fatalf("run = %d, want 0", code)
	}
}

func TestBadRefIsUsageError(t *testing.T) {
	dir := newRepo(t)
	commit(t, dir, "only", true)
	if code, _, _ := runDCO([]string{"no-such-ref", "HEAD"}, dir); code != 2 {
		t.Fatalf("run = %d, want 2", code)
	}
}

func TestUsageError(t *testing.T) {
	if code, _, _ := runDCO([]string{"only-one-arg"}, "."); code != 2 {
		t.Fatalf("run = %d, want 2", code)
	}
}

// A sign-off line outside the trailer block (the last paragraph) does
// not count.
func TestSignoffOutsideTrailerFails(t *testing.T) {
	dir := newRepo(t)
	commit(t, dir, "base", true)
	git(t, dir, "branch", "base")
	commitWith(t, dir, nil, "-m", "subject",
		"-m", "Signed-off-by: t <"+me+">",
		"-m", "A closing paragraph after the sign-off.")
	if code, _, _ := runDCO([]string{"base", "HEAD"}, dir); code != 1 {
		t.Fatalf("run = %d, want 1", code)
	}
}

// A subject line alone is not a trailer block.
func TestSignoffAsSubjectFails(t *testing.T) {
	dir := newRepo(t)
	commit(t, dir, "base", true)
	git(t, dir, "branch", "base")
	commitWith(t, dir, nil, "--cleanup=verbatim", "-m", "Signed-off-by: t <"+me+">")
	if code, _, _ := runDCO([]string{"base", "HEAD"}, dir); code != 1 {
		t.Fatalf("run = %d, want 1", code)
	}
}

// runOn commits msg verbatim on top of a signed base. Env sets the author
// and the committer. It returns the exit code of the checker, its standard
// output and the short hash of the new commit. It fails the test if the
// standard output or the standard error holds an "@".
func runOn(t *testing.T, env []string, msg string) (int, string, string) {
	t.Helper()
	dir := newRepo(t)
	commit(t, dir, "base", true)
	git(t, dir, "branch", "base")
	commitWith(t, dir, env, "--cleanup=verbatim", "-m", msg)
	code, out, errOut := runDCO([]string{"base", "HEAD"}, dir)
	for _, s := range []string{out, errOut} {
		if strings.Contains(s, "@") {
			t.Errorf("the output shows an address: %q", s)
		}
	}
	return code, out, strings.TrimSpace(git(t, dir, "rev-parse", "--short=12", "HEAD"))
}

// signoff is a whole message: a subject, a blank line, and a trailer block
// with one sign-off at the noreply address.
const signoff = "subject\n\nSigned-off-by: t <" + me + ">\n"

// failsWith commits msg (by the author and the committer set in env) and
// expects exit 1 with a "<kind>: <hash>" line.
func failsWith(t *testing.T, env []string, msg, kind string) {
	t.Helper()
	code, out, hash := runOn(t, env, msg)
	if code != 1 || !strings.Contains(out, kind+": "+hash+"\n") {
		t.Fatalf("run = %d, want 1 with a %q line for %q; output %q", code, kind, hash, out)
	}
}

// A SOH byte in a trailer value does not split the trailer in two.
func TestSOHInTrailerDoesNotSplit(t *testing.T) {
	t.Run("hidden sign-off", func(t *testing.T) {
		failsWith(t, nil, "subject\n\nFixes: x\x01Signed-off-by: t <"+me+">\n", "unsigned")
	})
	t.Run("hidden co-author", func(t *testing.T) {
		failsWith(t, nil, signoff+"Co-authored-by: Bob\x01<"+other+">\n", "identity")
	})
	t.Run("hidden Claude co-author", func(t *testing.T) {
		failsWith(t, nil, signoff+"Reviewed-by: x\x01Co-authored-by: Claude <noreply@anthropic.com>\n", "identity")
	})
}

// lookAlike differs from me by one letter. U+017F (long s) folds to "s" in
// Unicode, but the address is not the same.
const lookAlike = "67512030+cybagard@uſers.noreply.github.com"

// An address with a non-ASCII byte never matches the noreply address.
func TestLookAlikeAddressFails(t *testing.T) {
	t.Run("author", func(t *testing.T) {
		failsWith(t, []string{"GIT_AUTHOR_EMAIL=" + lookAlike}, signoff, "identity")
	})
	t.Run("committer", func(t *testing.T) {
		failsWith(t, []string{"GIT_COMMITTER_EMAIL=" + lookAlike}, signoff, "identity")
	})
	t.Run("sign-off", func(t *testing.T) {
		failsWith(t, nil, "subject\n\nSigned-off-by: t <"+lookAlike+">\n", "identity")
	})
}

// A trailer key with a non-ASCII byte is not a sign-off key. U+017F (long
// s) folds to "s" in Unicode. Git drops such a line from the trailers, so
// this test also runs the checker on a whole commit.
func TestNonASCIIKeyIsNotSignoff(t *testing.T) {
	failsWith(t, nil, "subject\n\nſigned-off-by: t <"+me+">\n", "unsigned")
	if hasSignoff([]string{"ſigned-off-by: t <" + me + ">"}) {
		t.Error("hasSignoff accepts a key with U+017F")
	}
	if !identityOK(me, me, []string{"ſigned-off-by: t"}) {
		t.Error("identityOK treats a key with U+017F as a sign-off key")
	}
}

// A Co-authored-by key with a non-ASCII byte does not permit the Claude
// address.
func TestNonASCIICoauthorKeyFails(t *testing.T) {
	if identityOK(me, me, []string{"Co-authöred-by: Claude <" + claudeAddr + ">"}) {
		t.Error("identityOK permits the Claude address under a key with a non-ASCII byte")
	}
}

// Every Signed-off-by value has the noreply address, also next to a valid
// sign-off.
func TestSecondSignoffWithoutAddressFails(t *testing.T) {
	failsWith(t, nil, signoff+"Signed-off-by: Bob\n", "identity")
	failsWith(t, nil, signoff+"signed-off-by: Bob\n", "identity")
}

// Addresses and trailer keys compare without case.
func TestCaseInsensitiveCompare(t *testing.T) {
	upper := strings.ToUpper(me)
	cases := []struct {
		name string
		env  []string
		msg  string
	}{
		{"author address in upper case", []string{"GIT_AUTHOR_EMAIL=" + upper}, signoff},
		{"sign-off address in upper case", nil, "subject\n\nSigned-off-by: t <" + upper + ">\n"},
		{"sign-off key in lower case", nil, "subject\n\nsigned-off-by: t <" + me + ">\n"},
		{"committer address in upper case", []string{"GIT_COMMITTER_EMAIL=" + upper}, signoff},
		{"GitHub committer address in upper case", []string{"GIT_COMMITTER_EMAIL=NOREPLY@GITHUB.COM"}, signoff},
		{"Claude address in upper case", nil, signoff + "Co-authored-by: Claude Sonnet 5.5 <NOREPLY@ANTHROPIC.COM>\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if code, out, _ := runOn(t, c.env, c.msg); code != 0 {
				t.Fatalf("run = %d, want 0; output %q", code, out)
			}
		})
	}
}

// The FAIL output gives the sign-off hint only for an unsigned commit.
// It gives the identity hint only for a commit that breaks the identity rule.
func TestFailHintMatchesFailure(t *testing.T) {
	const signHint, idHint = "git commit -s", "noreply address"
	t.Run("identity only", func(t *testing.T) {
		_, out, _ := runOn(t, []string{"GIT_AUTHOR_EMAIL=" + other}, signoff)
		if strings.Contains(out, signHint) || !strings.Contains(out, idHint) {
			t.Errorf("want the identity hint only; output %q", out)
		}
	})
	t.Run("unsigned only", func(t *testing.T) {
		_, out, _ := runOn(t, nil, "subject\n")
		if !strings.Contains(out, signHint) || strings.Contains(out, idHint) {
			t.Errorf("want the sign-off hint only; output %q", out)
		}
	})
	t.Run("both", func(t *testing.T) {
		_, out, _ := runOn(t, []string{"GIT_AUTHOR_EMAIL=" + other}, "subject\n")
		if !strings.Contains(out, signHint) || !strings.Contains(out, idHint) {
			t.Errorf("want both hints; output %q", out)
		}
	})
}

// A record with fewer than five fields is an error. The checker prints a
// fixed line, no part of the record, and never "all N commits pass".
func TestMalformedRecordIsError(t *testing.T) {
	good := "0123456789abcdef\x00" + me + "\x00" + me + "\x00\x00Signed-off-by: t <" + me + ">\x00\n"
	cases := map[string]string{
		"four fields":         "0123456789abcdef\x00SECRET\x00SECRET\x00\x00\n",
		"three fields":        "0123456789abcdef\x00SECRET\x00SECRET\x00\n",
		"one field":           "SECRET\x00\n",
		"good then malformed": good + "SECRET\x00SECRET\x00\n",
	}
	for name, out := range cases {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := check([]byte(out), "base", "HEAD", &stdout, &stderr); code != 2 {
				t.Fatalf("check = %d, want 2; stdout %q", code, stdout.String())
			}
			if got, want := stderr.String(), "dco: malformed git log record\n"; got != want {
				t.Errorf("stderr = %q, want %q", got, want)
			}
			if strings.Contains(stdout.String(), "pass") || strings.Contains(stdout.String()+stderr.String(), "SECRET") {
				t.Errorf("unexpected output: stdout %q, stderr %q", stdout.String(), stderr.String())
			}
		})
	}
}

// A well-formed record passes.
func TestCheckGoodRecord(t *testing.T) {
	good := "0123456789abcdef\x00" + me + "\x00" + me + "\x00\x00Signed-off-by: t <" + me + ">\x00\n"
	var stdout, stderr bytes.Buffer
	if code := check([]byte(good), "base", "HEAD", &stdout, &stderr); code != 0 {
		t.Fatalf("check = %d, want 0; stdout %q, stderr %q", code, stdout.String(), stderr.String())
	}
}

// forgeCommit writes a commit object by hand on top of a signed base. The
// header line extra goes after the committer line. It uses no --literally, so
// git checks the object. It returns the repository and the full hash. The
// branch "base" holds the base commit and the branch "forged" the new one.
func forgeCommit(t *testing.T, extra, msg string) (dir, hash string) {
	t.Helper()
	dir = newRepo(t)
	commit(t, dir, "base", true)
	git(t, dir, "branch", "base")
	tree := strings.TrimSpace(git(t, dir, "rev-parse", "HEAD^{tree}"))
	parent := strings.TrimSpace(git(t, dir, "rev-parse", "HEAD"))
	ident := "t <" + me + "> 1700000000 +0000"
	obj := "tree " + tree + "\nparent " + parent + "\nauthor " + ident + "\ncommitter " + ident + "\n" +
		extra + "\n" + msg
	cmd := exec.Command("git", "-C", dir, "hash-object", "-t", "commit", "-w", "--stdin")
	cmd.Stdin = strings.NewReader(obj)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git hash-object: %v\n%s", err, out)
	}
	hash = strings.TrimSpace(string(out))
	git(t, dir, "update-ref", "refs/heads/forged", hash)
	return dir, hash
}

// Git converts the message to UTF-8 from the encoding header. The bytes of
// an address can then come out as other characters, so dco cannot see the
// address. A commit with any encoding header fails.
func TestEncodingHeaderFails(t *testing.T) {
	const hint = "hint: commits must not set an encoding header\n"
	t.Run("ISO-2022-JP hides an address", func(t *testing.T) {
		// After ESC $ B, the bytes "ma" and "@i" are two kanji. ESC ( B
		// returns to ASCII.
		msg := "subject\n\nSigned-off-by: t <" + me + ">\nCo-authored-by: Bob \x1b$Bma@i\x1b(B.example\n"
		dir, hash := forgeCommit(t, "encoding ISO-2022-JP\n", msg)
		if raw := git(t, dir, "cat-file", "-p", hash); !strings.Contains(raw, "ma@i") {
			t.Fatalf("the raw object lacks the address bytes: %q", raw)
		}
		if shown := git(t, dir, "log", "-1", "--format=%(trailers:key=Co-authored-by,valueonly)", hash); strings.Contains(shown, "@") {
			t.Fatalf("git log shows an address: %q", shown)
		}
		code, out, errOut := runDCO([]string{"base", "forged"}, dir)
		if code != 1 || !strings.Contains(out, "identity: "+hash[:12]+"\n") || !strings.Contains(out, hint) {
			t.Fatalf("run = %d, want 1 with an identity line and the encoding hint; output %q", code, out)
		}
		if strings.Contains(out+errOut, "@") {
			t.Errorf("the output shows an address: %q %q", out, errOut)
		}
	})
	t.Run("UTF-8", func(t *testing.T) {
		dir, hash := forgeCommit(t, "encoding UTF-8\n", signoff)
		code, out, _ := runDCO([]string{"base", "forged"}, dir)
		if code != 1 || !strings.Contains(out, "identity: "+hash[:12]+"\n") || !strings.Contains(out, hint) {
			t.Fatalf("run = %d, want 1 with an identity line and the encoding hint; output %q", code, out)
		}
	})
}

// A line that holds only whitespace separates paragraphs, as in git.
func TestWhitespaceLineSplitsParagraphs(t *testing.T) {
	if code, _, _ := runOn(t, nil, "subject\n\nSigned-off-by: t <"+me+">\n \t\nclosing words\n"); code != 1 {
		t.Fatalf("run = %d, want 1", code)
	}
}

// Git accepts a trailer block that mixes a trailer with other lines, for
// example "cherry picked from". So does dco.
func TestCherryPickBlockPasses(t *testing.T) {
	if code, _, _ := runOn(t, nil, "subject\n\nbody\n\n(cherry picked from commit 0123456789abcdef0123456789abcdef01234567)\nSigned-off-by: t <"+me+">\n"); code != 0 {
		t.Fatalf("run = %d, want 0", code)
	}
}

func TestCRLFMessage(t *testing.T) {
	if code, _, _ := runOn(t, nil, "subject\r\n\r\nbody\r\n\r\nSigned-off-by: t <"+me+">\r\n"); code != 0 {
		t.Fatalf("run = %d, want 0", code)
	}
}

// The identity rule: each case is one commit. A failing commit gets an
// "identity:" line with its 12-character hash. No output holds an address.
func TestIdentityRule(t *testing.T) {
	asOther := func(v string) []string { return []string{v + "=" + other} }
	cases := []struct {
		name string
		env  []string
		msg  string
		want int
	}{
		{"sign-off at another address", nil, "subject\n\nSigned-off-by: t <" + other + ">\n", 1},
		{"author at another address", asOther("GIT_AUTHOR_EMAIL"), signoff, 1},
		{"co-author at another address", nil, signoff + "Co-authored-by: Bob <" + other + ">\n", 1},
		{"committer at another address", asOther("GIT_COMMITTER_EMAIL"), signoff, 1},
		{"committer is the GitHub address", []string{"GIT_COMMITTER_NAME=GitHub", "GIT_COMMITTER_EMAIL=noreply@github.com"}, signoff, 0},
		{"second sign-off at another address", nil, signoff + "Signed-off-by: t <" + other + ">\n", 1},
		{"Claude co-author", []string{"GIT_COMMITTER_EMAIL=noreply@github.com"}, signoff + "Co-authored-by: Claude Sonnet 5.5 <noreply@anthropic.com>\n", 0},
		{"Claude co-author, key in other case", nil, signoff + "Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>\n", 0},
		{"co-author named Bob at the Claude address", nil, signoff + "Co-authored-by: Bob <noreply@anthropic.com>\n", 1},
		{"co-author named exactly Claude", nil, signoff + "Co-authored-by: Claude <noreply@anthropic.com>\n", 0},
		{"Claude co-author without angle brackets", nil, signoff + "Co-authored-by: Claude noreply@anthropic.com\n", 1},
		{"Claude co-author with a second address", nil, signoff + "Co-authored-by: Claude <noreply@anthropic.com>, Bob <noreply@anthropic.com>\n", 1},
		{"co-author named Claudette", nil, signoff + "Co-authored-by: Claudette <noreply@anthropic.com>\n", 1},
		{"Claude address in another key", nil, signoff + "Reviewed-by: Claude <noreply@anthropic.com>\n", 1},
		{"address without angle brackets", nil, signoff + "Reviewed-by: " + other + "\n", 1},
		{"co-author at the noreply address", nil, signoff + "Co-authored-by: t <" + me + ">\n", 0},
		{"trailer without an address", nil, signoff + "Fixes: 12\n", 0},
		{"folded trailer with another address", nil, signoff + "Co-authored-by: Bob\n <" + other + ">\n", 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, out, hash := runOn(t, c.env, c.msg)
			if code != c.want {
				t.Fatalf("run = %d, want %d; output %q", code, c.want, out)
			}
			if strings.Contains(out, "example.com") || strings.Contains(out, "@") {
				t.Errorf("the output shows an address: %q", out)
			}
			if got := strings.Contains(out, "identity: "+hash+"\n"); got != (c.want == 1) {
				t.Errorf("identity line for %q present = %v, want %v; output %q", hash, got, c.want == 1, out)
			}
		})
	}
}
