package main

import (
	"os/exec"
	"testing"
)

// git runs a git subcommand in dir and fails the test on error.
func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return string(out)
}

func newRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	git(t, dir, "init", "-b", "main")
	return dir
}

func commit(t *testing.T, dir, msg string, sign bool) {
	t.Helper()
	args := []string{"-c", "user.name=t", "-c", "user.email=t@example.com",
		"commit", "--allow-empty", "-m", msg}
	if sign {
		args = append(args, "-s")
	}
	git(t, dir, args...)
}

func TestAllSigned(t *testing.T) {
	dir := newRepo(t)
	commit(t, dir, "base", true)
	git(t, dir, "branch", "base")
	commit(t, dir, "signed one", true)
	commit(t, dir, "signed two", true)
	if code := run([]string{"base", "HEAD"}, dir); code != 0 {
		t.Fatalf("run = %d, want 0", code)
	}
}

func TestUnsignedFails(t *testing.T) {
	dir := newRepo(t)
	commit(t, dir, "base", true)
	git(t, dir, "branch", "base")
	commit(t, dir, "signed", true)
	commit(t, dir, "unsigned", false)
	if code := run([]string{"base", "HEAD"}, dir); code != 1 {
		t.Fatalf("run = %d, want 1", code)
	}
}

// A hand-typed trailer (second paragraph) is a valid sign-off.
func TestManualTrailerCounts(t *testing.T) {
	dir := newRepo(t)
	commit(t, dir, "base", true)
	git(t, dir, "branch", "base")
	git(t, dir, "-c", "user.name=t", "-c", "user.email=t@example.com",
		"commit", "--allow-empty", "-m", "manual",
		"-m", "Signed-off-by: t <t@example.com>")
	if code := run([]string{"base", "HEAD"}, dir); code != 0 {
		t.Fatalf("run = %d, want 0", code)
	}
}

// A sign-off line without an address is not a DCO trailer.
func TestSignoffWithoutEmailFails(t *testing.T) {
	dir := newRepo(t)
	commit(t, dir, "base", true)
	git(t, dir, "branch", "base")
	git(t, dir, "-c", "user.name=t", "-c", "user.email=t@example.com",
		"commit", "--allow-empty", "-m", "nope", "-m", "Signed-off-by: t")
	if code := run([]string{"base", "HEAD"}, dir); code != 1 {
		t.Fatalf("run = %d, want 1", code)
	}
}

func TestEmptyRangePasses(t *testing.T) {
	dir := newRepo(t)
	commit(t, dir, "only", true)
	if code := run([]string{"HEAD", "HEAD"}, dir); code != 0 {
		t.Fatalf("run = %d, want 0", code)
	}
}

func TestBadRefIsUsageError(t *testing.T) {
	dir := newRepo(t)
	commit(t, dir, "only", true)
	if code := run([]string{"no-such-ref", "HEAD"}, dir); code != 2 {
		t.Fatalf("run = %d, want 2", code)
	}
}

func TestUsageError(t *testing.T) {
	if code := run([]string{"only-one-arg"}, "."); code != 2 {
		t.Fatalf("run = %d, want 2", code)
	}
}

// A sign-off line outside the trailer block (the last paragraph) does
// not count.
func TestSignoffOutsideTrailerFails(t *testing.T) {
	dir := newRepo(t)
	commit(t, dir, "base", true)
	git(t, dir, "branch", "base")
	git(t, dir, "-c", "user.name=t", "-c", "user.email=t@example.com",
		"commit", "--allow-empty", "-m", "subject",
		"-m", "Signed-off-by: t <t@example.com>",
		"-m", "A closing paragraph after the sign-off.")
	if code := run([]string{"base", "HEAD"}, dir); code != 1 {
		t.Fatalf("run = %d, want 1", code)
	}
}

// A subject line alone is not a trailer block.
func TestSignoffAsSubjectFails(t *testing.T) {
	dir := newRepo(t)
	commit(t, dir, "base", true)
	git(t, dir, "branch", "base")
	git(t, dir, "-c", "user.name=t", "-c", "user.email=t@example.com",
		"commit", "--allow-empty", "--cleanup=verbatim", "-m", "Signed-off-by: t <t@example.com>")
	if code := run([]string{"base", "HEAD"}, dir); code != 1 {
		t.Fatalf("run = %d, want 1", code)
	}
}

// commitMsg makes a commit with an exact message (no cleanup).
func commitMsg(t *testing.T, dir, msg string) {
	t.Helper()
	git(t, dir, "-c", "user.name=t", "-c", "user.email=t@example.com",
		"commit", "--allow-empty", "--cleanup=verbatim", "-m", msg)
}

func runOn(t *testing.T, msg string) int {
	t.Helper()
	dir := newRepo(t)
	commit(t, dir, "base", true)
	git(t, dir, "branch", "base")
	commitMsg(t, dir, msg)
	return run([]string{"base", "HEAD"}, dir)
}

// A line that holds only whitespace separates paragraphs, as in git.
func TestWhitespaceLineSplitsParagraphs(t *testing.T) {
	if code := runOn(t, "subject\n\nSigned-off-by: t <t@example.com>\n \t\nclosing words\n"); code != 1 {
		t.Fatalf("run = %d, want 1", code)
	}
}

// git accepts a trailer block that mixes a git-generated trailer with
// other lines (for example "cherry picked from"); so does dco.
func TestCherryPickBlockPasses(t *testing.T) {
	if code := runOn(t, "subject\n\nbody\n\n(cherry picked from commit 0123456789abcdef0123456789abcdef01234567)\nSigned-off-by: t <t@example.com>\n"); code != 0 {
		t.Fatalf("run = %d, want 0", code)
	}
}

func TestCRLFMessage(t *testing.T) {
	if code := runOn(t, "subject\r\n\r\nbody\r\n\r\nSigned-off-by: t <t@example.com>\r\n"); code != 0 {
		t.Fatalf("run = %d, want 0", code)
	}
}
