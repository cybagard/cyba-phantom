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
const lookAlike = "67512030+cybagard@u\xc5\xbfers.noreply.github.com"

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
// s) folds to "s" in Unicode. Git drops such a line from the trailers, so a
// run on a whole commit does not reach the code that compares keys. The test
// also calls hasSignoff and identityOK directly.
func TestNonASCIIKeyIsNotSignoff(t *testing.T) {
	failsWith(t, nil, "subject\n\n\xc5\xbfigned-off-by: t <"+me+">\n", "unsigned")
	if hasSignoff([]string{"\xc5\xbfigned-off-by: t <" + me + ">"}) {
		t.Error("hasSignoff accepts a key with U+017F")
	}
	if !identityOK(me, me, []string{"\xc5\xbfigned-off-by: t"}) {
		t.Error("identityOK treats a key with U+017F as a sign-off key")
	}
}

// A Co-authored-by key with a non-ASCII byte does not permit the Claude
// address.
func TestNonASCIICoauthorKeyFails(t *testing.T) {
	if identityOK(me, me, []string{"Co-auth\xc3\xb6red-by: Claude <" + claudeAddr + ">"}) {
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

// idHint is the fixed text of the identity hint.
const idHint = "hint: only a commit with the identity of the maintainer passes this check. Maintainer: see the header of tools/dco/main.go for the rule. Outside contribution: see CONTRIBUTING.md.\n"

// oldIDHint is the text of the identity hint before it stopped naming the
// maintainer address. It is a negative fixture: the hint must not return to it.
const oldIDHint = "hint: the author and trailer addresses must be the maintainer noreply address; the committer can also be the GitHub committer address; a Claude co-author trailer can use the Claude co-author address (see tools/dco/main.go)"

// hintFault returns why a hint text is not acceptable, or "" if it is. The
// hint is in a public CI log. It must name no address, give no step to change
// the author, and point to CONTRIBUTING.md.
func hintFault(hint string) string {
	low := strings.ToLower(hint)
	for _, bad := range []string{
		"@", "noreply", "maintainer address", "maintainer noreply", "--author",
		"git_author", "git_committer", "user.email", "git config", "must be", "use the",
	} {
		if strings.Contains(low, bad) {
			return "contains " + bad
		}
	}
	if !strings.Contains(hint, "CONTRIBUTING.md") {
		return "does not point to CONTRIBUTING.md"
	}
	return ""
}

// The identity hint names no address and gives no step to change the author.
func TestIdentityHintNamesNoAddress(t *testing.T) {
	_, out, _ := runOn(t, []string{"GIT_AUTHOR_EMAIL=" + other}, signoff)
	var line string
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "hint: ") && !strings.Contains(l, "git commit -s") {
			line = l
		}
	}
	if line == "" {
		t.Fatalf("the output has no identity hint; output %q", out)
	}
	if why := hintFault(line); why != "" {
		t.Errorf("identity hint %q: %s", line, why)
	}
	if hintFault(oldIDHint) == "" {
		t.Error("the predicate accepts the old hint text")
	}
}

// The FAIL output gives the sign-off hint only for an unsigned commit.
// It gives the identity hint only for a commit with a wrong address.
func TestFailHintMatchesFailure(t *testing.T) {
	const signHint = "git commit -s"
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

// goodRecord is one well-formed git log record. It has the hash, the author
// and committer addresses and names, an empty encoding header and a sign-off
// trailer.
const goodRecord = "0123456789abcdef\x00" + me + "\x00" + me + "\x00t\x00t\x00\x00Signed-off-by: t <" + me + ">\x00\n"

// goodMsgs holds an empty raw message for each hash that the records of these
// tests use.
var goodMsgs = map[string][]byte{"0123456789abcdef": {}, "fedcba9876543210": {}}

// A commit with no raw message fails, and so does one whose message is not
// valid UTF-8. Both are identity failures, never a pass. The output holds no
// address.
func TestCheckFailsClosed(t *testing.T) {
	for name, msgs := range map[string]map[string][]byte{
		"nil map":      nil,
		"other hash":   {"fedcba9876543210": {}},
		"invalid text": {"0123456789abcdef": []byte("a\xffb\n")},
	} {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := check(splitRecords([]byte(goodRecord)), msgs, "base", "HEAD", &stdout, &stderr)
			if code != 1 || !strings.Contains(stdout.String(), "identity: 0123456789ab\n") {
				t.Fatalf("check = %d, want 1 with an identity line; stdout %q", code, stdout.String())
			}
			if strings.Contains(stdout.String()+stderr.String(), "@") {
				t.Errorf("the output shows an address: %q %q", stdout.String(), stderr.String())
			}
		})
	}
}

// A record with fewer than seven fields is an error. The checker prints a
// fixed line, no part of the record, and never "all N commits pass".
func TestMalformedRecordIsError(t *testing.T) {
	cases := map[string]string{
		"four fields":         "0123456789abcdef\x00SECRET\x00SECRET\x00\x00\n",
		"three fields":        "0123456789abcdef\x00SECRET\x00SECRET\x00\n",
		"one field":           "SECRET\x00\n",
		"good then malformed": goodRecord + "SECRET\x00SECRET\x00\n",
	}
	for name, out := range cases {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := check(splitRecords([]byte(out)), goodMsgs, "base", "HEAD", &stdout, &stderr); code != 2 {
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
	var stdout, stderr bytes.Buffer
	if code := check(splitRecords([]byte(goodRecord)), goodMsgs, "base", "HEAD", &stdout, &stderr); code != 0 {
		t.Fatalf("check = %d, want 0; stdout %q, stderr %q", code, stdout.String(), stderr.String())
	}
}

// The last record is a record even when it lacks the NUL and LF that end it.
func TestCheckKeepsLastRecordWithoutEnd(t *testing.T) {
	unsigned := "0123456789abcdef\x00" + me + "\x00" + me + "\x00t\x00t\x00\x00\x00"
	var stdout, stderr bytes.Buffer
	if code := check(splitRecords([]byte(unsigned)), goodMsgs, "base", "HEAD", &stdout, &stderr); code != 1 || !strings.Contains(stdout.String(), "unsigned: 0123456789ab\n") {
		t.Errorf("check = %d, want 1 with an unsigned line; stdout %q, stderr %q", code, stdout.String(), stderr.String())
	}
}

// The summary line counts the records.
func TestCheckCountsRecords(t *testing.T) {
	unsigned := "fedcba9876543210\x00" + me + "\x00" + me + "\x00t\x00t\x00\x00\x00\n"
	for _, c := range []struct {
		name, out, want string
		code            int
	}{
		{"all pass", goodRecord + goodRecord, "dco: all 2 commits in base..HEAD", 0},
		{"one unsigned", goodRecord + unsigned, "dco FAIL: of 2 commits in base..HEAD, 1 lack", 1},
	} {
		var stdout, stderr bytes.Buffer
		if code := check(splitRecords([]byte(c.out)), goodMsgs, "base", "HEAD", &stdout, &stderr); code != c.code || !strings.Contains(stdout.String(), c.want) {
			t.Errorf("%s: check = %d, stdout %q, stderr %q; want %d and %q", c.name, code, stdout.String(), stderr.String(), c.code, c.want)
		}
	}
}

// A byte of 0x80 or more never matches, not even in two equal strings.
func TestASCIIEqualFoldRefusesHighByte(t *testing.T) {
	for _, s := range []string{"\x80", "a\x80", "\x7f\x80", "\xff"} {
		if asciiEqualFold(s, s) {
			t.Errorf("asciiEqualFold(%q, %q) = true, want false", s, s)
		}
	}
	if !asciiEqualFold("\x7f", "\x7f") {
		t.Error(`asciiEqualFold("\x7f", "\x7f") = false, want true`)
	}
}

// forgeCommit writes a commit object by hand on top of a signed base. The
// header line extra goes after the committer line. Without flags, git checks
// the object; flags go to git hash-object (for example --literally). It
// returns the repository and the full hash. The branch "base" holds the base
// commit and the branch "forged" the new one.
func forgeCommit(t *testing.T, extra, msg string, flags ...string) (dir, hash string) {
	t.Helper()
	dir = newRepo(t)
	commit(t, dir, "base", true)
	git(t, dir, "branch", "base")
	tree := strings.TrimSpace(git(t, dir, "rev-parse", "HEAD^{tree}"))
	parent := strings.TrimSpace(git(t, dir, "rev-parse", "HEAD"))
	ident := "t <" + me + "> 1700000000 +0000"
	obj := "tree " + tree + "\nparent " + parent + "\nauthor " + ident + "\ncommitter " + ident + "\n" +
		extra + "\n" + msg
	cmd := exec.Command("git", append([]string{"-C", dir, "hash-object", "-t", "commit", "-w", "--stdin"}, flags...)...)
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
// address. A commit with a non-empty encoding header fails. An empty value
// gives an empty %e, and that commit passes.
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
		if strings.Contains(out, idHint) {
			t.Errorf("an encoding-only failure shows the address hint; output %q", out)
		}
	})
	t.Run("empty value", func(t *testing.T) {
		// An empty value gives an empty %e, the same as no header.
		dir, _ := forgeCommit(t, "encoding \n", signoff)
		if code, out, _ := runDCO([]string{"base", "forged"}, dir); code != 0 {
			t.Fatalf("run = %d, want 0; output %q", code, out)
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
		{"Claude co-author at another address", nil, signoff + "Co-authored-by: Claude <" + other + ">\n", 1},
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
			if got := strings.Contains(out, "identity: "+hash+"\n"); got != (c.want == 1) {
				t.Errorf("identity line for %q present = %v, want %v; output %q", hash, got, c.want == 1, out)
			}
		})
	}
}

// body is a message with the free text x between a subject and a valid
// sign-off.
func body(x string) string { return "subject\n\n" + x + "\n\nSigned-off-by: t <" + me + ">\n" }

// midClaude puts the line x in a middle paragraph, then a body paragraph and a
// valid sign-off. Git does not parse x as a trailer there.
func midClaude(x string) string {
	return "subject\n\n" + x + "\n\nbody\n\nSigned-off-by: t <" + me + ">\n"
}

// The message rule: each message has a valid sign-off. Only the character
// list or the at-sign list can fail the commit. Look-alike and invisible
// characters are written as escapes.
func TestMessageFails(t *testing.T) {
	const claude = "Co-authored-by: Claude <noreply@anthropic.com>"
	cases := map[string]string{
		// An address in each place.
		"subject":                  "s " + other + "\n\nSigned-off-by: t <" + me + ">\n",
		"body text":                body("write to " + other),
		"co-author before a body":  midClaude("Co-authored-by: Bob <" + other + ">"),
		"sign-off not last":        midClaude("Signed-off-by: Bob <" + other + ">"),
		"equals sign separator":    signoff + "Co-authored-by = Bob <" + other + ">\n",
		"non-ASCII key":            signoff + "\xc5\xbfigned-off-by: Bob <" + other + ">\n",
		"mixed case":               body("Other@Example.COM"),
		"mailto link":              body("<mailto:" + other + ">"),
		"CRLF line":                "subject\r\n\r\ncontact " + other + "\r\n\r\nSigned-off-by: t <" + me + ">\r\n",
		"Claude address in body":   body("Claude <noreply@anthropic.com>"),
		"Claude line, 2 addresses": signoff + claude + " " + other + "\n",
		"maintainer and another":   body("by " + me + " and " + other),
		// Characters off the list.
		"fullwidth at-sign":          body("other\xef\xbc\xa0example.com"),
		"small at-sign":              body("other\xef\xb9\xabexample.com"),
		"fullwidth maintainer":       body("67512030+cybagard\xef\xbc\xa0users.noreply.github.com"),
		"non-ASCII domain":           body("other@ex\xc3\xa4mple.com"),
		"combining mark in domain":   body("other@exa\xcc\x88mple.com"),
		"fullwidth at-sign, combine": body("other\xef\xbc\xa0exa\xcc\x88mple.com"),
		"U+034F in the last label":   body("other@example.c\xcd\x8fom"),
		"U+FE0F in the last label":   body("other@example.c\xef\xb8\x8fom"),
		"U+20DD in the last label":   body("other@example.c\xe2\x83\x9dom"),
		"U+0301 in the last label":   body("other@example.c\xcc\x81om"),
		"one dot leader":             body("other@example\xe2\x80\xa4com"),
		"small full stop":            body("other@example\xef\xb9\x92com"),
		"fullwidth full stop":        body("other@example\xef\xbc\x8ecom"),
		"halfwidth ideographic stop": body("other@example\xef\xbd\xa1com"),
		"ideographic full stop":      body("other@example\xe3\x80\x82com"),
		"right-to-left override":     body("\xe2\x80\xaemoc.elpmaxe@ecila\xe2\x80\xac"),
		"line separator":             body("alice\xe2\x80\xa8@example.com"),
		"next line":                  body("alice\u0085@example.com"),
		"backspace":                  body("alicex\b@example.com"),
		"delete":                     body("alice\x7f@example.com"),
		"bell":                       body("alice\a@example.com"),
		"CR alone":                   body("     @example.com\ralice"),
		"zero width space in domain": body("other@exa\xe2\x80\x8bmple.com"),
		"zero width space before @":  body("other\xe2\x80\x8b@example.com"),
		"soft hyphen in domain":      body("other@exa\xc2\xad" + "mple.com"),
		"non-ASCII last label":       body("other@example.\xe0\xa4\xad\xe0\xa4\xbe\xe0\xa4\xb0\xe0\xa4\xa4"),
		"character not on the list":  body("a \xc3\xa9 b"),
		"fullwidth Claude line":      signoff + "Co-authored-by: Claude <noreply\xef\xbc\xa0anthropic.com>\n",
		// Address forms that the at-sign list refuses.
		"spaces around the at-sign":   body("alice @ example.com"),
		"at-sign at a line start":     body("alice\n@example.com"),
		"at-sign at a line end":       body("alice@\nexample.com"),
		"quoted local part":           body(`"alice"@example.com`),
		"IP literal":                  body("alice@[192.0.2.1]"),
		"no dot in the domain":        body("alice@localhost"),
		"maintainer then a domain":    body(me + "@other.example.com"),
		"dot before the maintainer":   body("bob." + me),
		"domain after the maintainer": body(me + ".evil.example"),
		"domain that starts with v1":  body("alice#v1.example.com"),
		"domain with v1 and a dash":   body("alice#v1-example.com"),
		"letter-only pre-release":     body("pkg#v1.0.0-beta.rc"),
		// Forms that fail by design (the costs).
		"quote after the at-sign":    body(`REDACTED@"`),
		"quoted prefix":              body(`"//REDACTED@".`),
		"connection string":          body("user:pw@tcp(host)/db"),
		"Claude line, indented":      midClaude("  " + claude),
		"Claude line, space":         midClaude("Co-authored-by : Claude <noreply@anthropic.com>"),
		"Claude address, other key":  midClaude("Reviewed-by: Claude <noreply@anthropic.com>"),
		"Claude line, other address": midClaude("Co-authored-by: Claude <" + other + ">"),
		"Claude line, 2 @ in a body": midClaude(claude + " " + other),
		"maintainer in a mid body":   midClaude("by " + me + " and " + other),
	}
	for name, msg := range cases {
		// "#" stands for "@" in the messages that would look like an address.
		t.Run(name, func(t *testing.T) { failsWith(t, nil, strings.ReplaceAll(msg, "#", "@"), "identity") })
	}
}

// A line in a paragraph that is not the trailer block is not a git trailer.
// The trailer rule does not see it, so only the message rule can fail the
// commit. The test checks with git that the line is no trailer.
func TestMessageRuleAloneFails(t *testing.T) {
	for name, line := range map[string]string{
		"Claude line at another address":    "Co-authored-by: Claude <" + other + ">",
		"Claude address in another key":     "Reviewed-by: Claude <noreply@anthropic.com>",
		"Claude line with a second address": "Co-authored-by: Claude <noreply@anthropic.com> " + other,
		"Claude line, indented":             "  Co-authored-by: Claude <noreply@anthropic.com>",
		"Claude line, space before colon":   "Co-authored-by : Claude <noreply@anthropic.com>",
		"maintainer and another address":    "by " + me + " and " + other,
	} {
		t.Run(name, func(t *testing.T) {
			msg := midClaude(line)
			dir := newRepo(t)
			commitWith(t, dir, nil, "--cleanup=verbatim", "-m", msg)
			if got := git(t, dir, "log", "-1", "--format=%(trailers:only)"); strings.Contains(got, "Claude") || strings.Contains(got, "by "+me) {
				t.Fatalf("git parses the line as a trailer: %q", got)
			}
			failsWith(t, nil, msg, "identity")
		})
	}
}

// The author and committer names follow the character list and hold no "@".
func TestNamesFail(t *testing.T) {
	for name, env := range map[string][]string{
		"author name with an address":    {"GIT_AUTHOR_NAME=alice@example.com"},
		"committer name with an at-sign": {"GIT_COMMITTER_NAME=x@y"},
		"author name with U+200B":        {"GIT_AUTHOR_NAME=al\xe2\x80\x8bice"},
		"committer name with U+00E9":     {"GIT_COMMITTER_NAME=Ren\xc3\xa9"},
		"committer name with U+FF20":     {"GIT_COMMITTER_NAME=x\xef\xbc\xa0y"},
	} {
		t.Run(name, func(t *testing.T) { failsWith(t, env, signoff, "identity") })
	}
}

// Text that the lists allow passes. That is the five extra characters, TAB, CR
// before LF, mentions and versions. It is also the maintainer address and
// Claude co-author lines.
func TestMessagePasses(t *testing.T) {
	const claude = "Co-authored-by: Claude Sonnet 5.5 <noreply@anthropic.com>"
	cases := map[string]string{
		"section sign":              body("see \xc2\xa7 4"),
		"em dash":                   body("a \xe2\x80\x94 b"),
		"en dash":                   body("a \xe2\x80\x93 b"),
		"ellipsis":                  body("a\xe2\x80\xa6"),
		"middle dot":                body("a \xc2\xb7 b"),
		"TAB":                       body("a\tb"),
		"CRLF message":              "subject\r\n\r\nbody\r\n\r\nSigned-off-by: t <" + me + ">\r\n",
		"JSON-LD keyword":           body("the key @context"),
		"mention with a dot":        body("thanks @dependabot."),
		"mention in parentheses":    body("(@cybagard)"),
		"action version":            body("uses actions/checkout@v5.1.0,"),
		"module version":            body("golang.org/x/net@v0.30.0"),
		"version with pre-release":  body("x@v1.2.3-rc.1"),
		"maintainer address":        body("by " + me),
		"maintainer in upper case":  body("by " + strings.ToUpper(me)),
		"maintainer in angle":       body("by t <" + me + ">."),
		"Claude co-author trailer":  signoff + claude + "\n",
		"Claude co-author, 1 word":  midClaude("Co-authored-by: Claude <noreply@anthropic.com>"),
		"Claude key in other case":  signoff + "CO-AUTHORED-BY: Claude <NOREPLY@ANTHROPIC.COM>\n",
		"Claude line with CRLF":     "subject\r\n\r\n" + claude + "\r\n\r\nSigned-off-by: t <" + me + ">\r\n",
		"maintainer and a mention":  body(me + " @cybagard"),
		"no at-sign, plain words":   body("write to alice at example dot com"),
		"percent-encoded at-sign":   body("alice%40example.com"),
		"two mentions":              body("@a and @b-c"),
		"mention of 39 characters":  body("@" + strings.Repeat("a", 39)),
		"version after a slash dot": body("x/y@v0.1"),
	}
	for name, msg := range cases {
		t.Run(name, func(t *testing.T) {
			if code, out, _ := runOn(t, nil, msg); code != 0 {
				t.Fatalf("run = %d, want 0; output %q", code, out)
			}
		})
	}
	for name, env := range map[string][]string{
		"author name with a space":    {"GIT_AUTHOR_NAME=cybagard labs"},
		"GitHub committer":            {"GIT_COMMITTER_NAME=GitHub", "GIT_COMMITTER_EMAIL=noreply@github.com"},
		"names with an en dash":       {"GIT_AUTHOR_NAME=a \xe2\x80\x93 b"},
		"committer name with a quote": {`GIT_COMMITTER_NAME=a"b`},
	} {
		t.Run(name, func(t *testing.T) {
			if code, out, _ := runOn(t, env, signoff); code != 0 {
				t.Fatalf("run = %d, want 0; output %q", code, out)
			}
		})
	}
}

// atSignCases pins each boundary of the four at-sign uses, one line at a time.
func TestAtSignBoundaries(t *testing.T) {
	m := me
	cases := []struct {
		line string
		want bool
	}{
		// Maintainer: the character before.
		{"a" + m, false}, {"Z" + m, false}, {"0" + m, false}, {"." + m, false},
		{"_" + m, false}, {"%" + m, false}, {"+" + m, false}, {"-" + m, false},
		{" " + m, true}, {"<" + m, true}, {"(" + m, true}, {m, true},
		// Maintainer: the character after.
		{m + "a", false}, {m + "Z", false}, {m + "0", false}, {m + "_", false},
		{m + "%", false}, {m + "+", false}, {m + "-", false}, {m + "@", false},
		{m + ".x", false}, {m + ".7", false}, {m + ".", true}, {m + ". x", true},
		{m + ">", true}, {m + ",", true}, {strings.ToUpper(m), true},
		// Mention: the character before.
		{"a@b", false}, {"Z@b", false}, {"0@b", false}, {".@b", false},
		{"_@b", false}, {"%@b", false}, {"+@b", false}, {"-@b", false},
		{" @b", true}, {"(@b", true}, {"@b", true}, {"/@b", true},
		// Mention: the length and the characters.
		{"@", false}, {"@ b", false}, {"@a", true}, {"@A-9", true},
		{"@" + strings.Repeat("a", 39), true}, {"@" + strings.Repeat("a", 40), false},
		{"@a@", false}, {"@a_", false}, {"@a%", false}, {"@a.b", false},
		{"@a.7", false}, {"@a.", true}, {"@a+", true}, {"@a,", true}, {"@a:", true},
		// Version: the character before.
		{"a@v1.2", true}, {"Z@v1.2", true}, {"0@v1.2", true}, {".@v1.2", true},
		{"_@v1.2", true}, {"/@v1.2", true}, {"-@v1.2", true},
		{"%@v1.2", false}, {"+@v1.2", false}, {" @v1.2", false}, {"@v1.2", false},
		// Version: the core.
		{"a@v1", true}, {"a@v", false}, {"a@V1.2", false}, {"a@1.2", false},
		{"a@vx", false}, {"a@v1.2.3", true}, {"a@v1.", true}, {"a@v1.x", false},
		// Version: the character after.
		{"a@v1.2a", false}, {"a@v1.2Z", false}, {"a@v1.2_", false},
		{"a@v1.2%", false}, {"a@v1.2+", false}, {"a@v1.2@", false},
		{"a@v1.2.x", false}, {"a@v1.2,", true}, {"a@v1.2)", true}, {"a@v1.2.", true},
		// Version: the pre-release text.
		{"a@v1-rc.1", true}, {"a@v1-rc", false}, {"a@v1-a", true}, {"a@v1-1", true},
		{"a@v1-", false}, {"a#v1-.x", false}, {"a#v1-beta.rc", false},
		{"a@v1-rc1", true}, {"a@v1-rc.1.", true}, {"a@v1-rc.1-x", false},
		{"a#v1-rc.1a.9", true}, {"a#v1-9.rc", false},
		// Claude line.
		{"Co-authored-by: Claude <noreply@anthropic.com>", true},
		{"co-authored-by: Claude Sonnet <NoReply@Anthropic.com>", true},
		{"Co-authored-by:Claude <noreply@anthropic.com>", true},
		{"Co-authored-by: Claude<noreply@anthropic.com>", true},
		{" Co-authored-by: Claude <noreply@anthropic.com>", false},
		{"Co-authored-by : Claude <noreply@anthropic.com>", false},
		{"Co-authored-by: Claudette <noreply@anthropic.com>", false},
		{"Co-authored-by: Bob <noreply@anthropic.com>", false},
		{"Reviewed-by: Claude <noreply@anthropic.com>", false},
		{"Co-authored-by: Claude noreply@anthropic.com", false},
		{"Co-authored-by: Claude <noreply@anthropic.com> ", false},
		{"Co-authored-by: Claude <noreply@anthropic.com>x", false},
		{"Co-authored-by: Claude <noreply@anthropic.com> @a", false},
		{"Co-authored-by: Claude <noreply#anthropic.org>", false},
		{"Co-authored-by: Claude <" + other + ">", false},
		{"Co-authored-by: Claude <" + other + "> <noreply@anthropic.com>", false},
		{"Co-authored-bz: Claude <noreply@anthropic.com>", false},
		// A second "@" next to a word that is whole only without it.
		{m + "@v1.2", false}, {"@a@v1", false}, {"a@v1@v1", false},
		{"@" + strings.Repeat("a", 39) + "-", false}, {"a@v1.-rc", true},
	}
	for _, c := range cases {
		// "#" stands for "@" in the lines that would look like an address.
		c.line = strings.ReplaceAll(c.line, "#", "@")
		if got := atSignsOK(c.line); got != c.want {
			t.Errorf("atSignsOK(%q) = %v, want %v", c.line, got, c.want)
		}
	}
}

// The character list has each of its elements, and nothing else.
func TestCharList(t *testing.T) {
	for _, r := range []rune{'\t', '\n', ' ', '~', 'a', 0xA7, 0x2014, 0x2013, 0x2026, 0xB7} {
		if !charsOK("a" + string(r) + "b") {
			t.Errorf("charsOK refuses U+%04X", r)
		}
	}
	for _, r := range []rune{0, 1, 7, 8, 0x0b, 0x0c, 0x1b, 0x1f, 0x7f, 0x80, 0x85, 0xa0, 0xa6, 0xa8, 0xad, 0xb6, 0xb8,
		0x2012, 0x2015, 0x2025, 0x2027, 0x200b, 0x2028, 0xfffd, 0x1f600} {
		if charsOK("a" + string(r) + "b") {
			t.Errorf("charsOK accepts U+%04X", r)
		}
	}
	for s, want := range map[string]bool{
		"a\r\nb": true, "a\r": false, "\r": false, "a\rb": false, "a\r\r\nb": false, "": true,
		"a\xffb": false, "a\xc2": false, "a\xe2\x80": false,
	} {
		if got := charsOK(s); got != want {
			t.Errorf("charsOK(%q) = %v, want %v", s, got, want)
		}
	}
	if nameOK("a@b") || !nameOK("cybagard labs") || nameOK("a\x00b") {
		t.Error("nameOK does not apply the name rule")
	}
}

// A message that is not valid UTF-8 fails the character list. The commit
// object is made by hand, with no address in it. The output holds no address.
func TestInvalidUTF8MessageFails(t *testing.T) {
	dir, hash := forgeCommit(t, "", body("a\xffb"))
	code, out, errOut := runDCO([]string{"base", "forged"}, dir)
	if code != 1 || !strings.Contains(out, "identity: "+hash[:12]+"\n") {
		t.Fatalf("run = %d, want 1 with an identity line; output %q %q", code, out, errOut)
	}
	if strings.Contains(out+errOut, "@") {
		t.Errorf("the output shows an address: %q %q", out, errOut)
	}
}

// A failing git cat-file is an error (exit 2) that prints no address, whatever
// git prints. A wrapper on PATH replaces only cat-file.
func TestCatFileFailureIsError(t *testing.T) {
	realGit, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	for name, script := range map[string]string{
		"exit 128 with text":  `echo "fatal: alice@example.com" >&2; exit 128`,
		"bad header":          `echo "alice@example.com commit"`,
		"short object":        `read h; echo "$h commit 999"; echo "alice@example.com"`,
		"empty output":        `read h`,
		"object of the wrong": `read h; echo "$h blob 0"; echo`,
	} {
		t.Run(name, func(t *testing.T) {
			dir := newRepo(t)
			commit(t, dir, "base", true)
			git(t, dir, "branch", "base")
			commit(t, dir, "one", true)
			bin := t.TempDir()
			wrapper := "#!/bin/sh\nfor a; do\n  if [ \"$a\" = cat-file ]; then " + script + "; exit 0; fi\ndone\nexec " + realGit + " \"$@\"\n"
			if err := os.WriteFile(bin+"/git", []byte(wrapper), 0o755); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
			code, out, errOut := runDCO([]string{"base", "HEAD"}, dir)
			if code != 2 || strings.Contains(out, "pass") {
				t.Fatalf("run = %d, want 2; output %q %q", code, out, errOut)
			}
			if s := out + errOut; strings.Contains(s, "@") || strings.Contains(s, "alice") {
				t.Errorf("the output shows text of git: %q", s)
			}
		})
	}
}

// The reader of git cat-file output refuses a malformed header or size.
// rawMessages refuses a repository that git cannot read.
func TestRawMessagesErrors(t *testing.T) {
	for name, out := range map[string]string{
		"no LF":        "abc commit 4",
		"not a commit": "abc blob 4\nxxxx\n",
		"missing":      "abc missing\n",
		"bad size":     "abc commit x\nxxxx\n",
		"negative":     "abc commit -1\n\n",
		"short body":   "abc commit 9\nxxxx\n",
		"one of two":   "abc commit 1\nx\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseBatch([]byte(out), 2); err == nil {
				t.Error("parseBatch accepts the output")
			}
		})
	}
	if _, err := rawMessages(t.TempDir(), []string{strings.Repeat("a", 40)}); err == nil {
		t.Error("rawMessages accepts a directory that is not a repository")
	}
}

// The reader accepts an empty object and an object that ends exactly at the
// output. It refuses a body one byte short of the object and its LF.
func TestParseBatchSizes(t *testing.T) {
	got, err := parseBatch([]byte("a commit 0\n\nb commit 6\nh\n\nmsg\n"), 2)
	if err != nil || len(got) != 2 || len(got["a"]) != 0 || string(got["b"]) != "msg" {
		t.Errorf("parseBatch = %q, %v; want a empty and b msg", got, err)
	}
	if _, err := parseBatch([]byte("a commit 3\nxxx"), 1); err == nil {
		t.Error("parseBatch accepts an object without its LF")
	}
	if _, err := parseBatch([]byte("a commit 3\nxxx\n"), 1); err != nil {
		t.Errorf("parseBatch refuses an object with its LF: %v", err)
	}
}

// git log stops a message at a NUL byte, but the bytes stay in the object.
// An address after the NUL fails the commit.
func TestNULHidesNoAddress(t *testing.T) {
	dir, hash := forgeCommit(t, "", signoff+"\x00hidden "+other+"\n", "--literally")
	if shown := git(t, dir, "log", "-1", "--format=%B", hash); strings.Contains(shown, "hidden") {
		t.Fatalf("git log shows the hidden address: %q", shown)
	}
	code, out, errOut := runDCO([]string{"base", "forged"}, dir)
	if code != 1 || !strings.Contains(out, "identity: "+hash[:12]+"\n") {
		t.Fatalf("run = %d, want 1 with an identity line; output %q", code, out)
	}
	if strings.Contains(out+errOut, "@") {
		t.Errorf("the output shows an address: %q %q", out, errOut)
	}
}
