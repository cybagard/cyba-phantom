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

// runOn commits msg verbatim (by the author and the committer set in env)
// on top of a signed base, and returns the checker's exit code, its output
// and the short hash of the new commit. It fails the test if the standard
// output or the standard error holds an "@".
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

// signoff is a valid trailer block with the sign-off at the noreply address.
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

// A line that holds only whitespace separates paragraphs, as in git.
func TestWhitespaceLineSplitsParagraphs(t *testing.T) {
	if code, _, _ := runOn(t, nil, "subject\n\nSigned-off-by: t <"+me+">\n \t\nclosing words\n"); code != 1 {
		t.Fatalf("run = %d, want 1", code)
	}
}

// git accepts a trailer block that mixes a git-generated trailer with
// other lines (for example "cherry picked from"); so does dco.
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

// The identity rule: each case is one commit; a failing commit gets an
// "identity:" line with its 12-character hash, and no output holds an
// address.
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
		{"co-author named Claudette", nil, signoff + "Co-authored-by: Claudette <noreply@anthropic.com>\n", 1},
		{"Claude address in another key", nil, signoff + "Reviewed-by: Claude <noreply@anthropic.com>\n", 1},
		{"address without angle brackets", nil, signoff + "Reviewed-by: " + other + "\n", 1},
		{"co-author at the noreply address", nil, signoff + "Co-authored-by: t <" + me + ">\n", 0},
		{"trailer without an address", nil, signoff + "Fixes: 12\n", 0},
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
