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

// isolate makes git ignore the user and system configuration, and the
// settings of GIT_CONFIG_COUNT. A user setting then cannot change the output.
var isolate = []string{"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_COUNT=0"}

// TestMain sets isolate for every git that dco runs in the tests. It also
// removes GIT_CONFIG_PARAMETERS.
func TestMain(m *testing.M) {
	for _, kv := range isolate {
		k, v, _ := strings.Cut(kv, "=")
		if err := os.Setenv(k, v); err != nil {
			panic(err)
		}
	}
	if err := os.Unsetenv("GIT_CONFIG_PARAMETERS"); err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}

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

// signoff is a whole message. It has a subject, an empty line, and a trailer
// block with one sign-off at the noreply address.
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

// headerHint is the fixed text of the header hint.
const headerHint = "hint: the header rule fails this commit. A signed commit fails it. See the header of tools/dco/main.go.\n"

// A commit that fails only the header rule gets the header hint and not the
// identity hint. An identity failure gets the identity hint and not the header
// hint. Neither hint holds an address or a name.
func TestHeaderHintMatchesFailure(t *testing.T) {
	t.Run("header only", func(t *testing.T) {
		dir, _ := forgeRaw(t, ghHeader+pgpSig, signoff, "--literally")
		code, out, errOut := runDCO([]string{"base", "forged"}, dir)
		if code != 1 || !strings.Contains(out, headerHint) || strings.Contains(out, idHint) || strings.Contains(out+errOut, "@") {
			t.Errorf("want the header hint only; run = %d, output %q %q", code, out, errOut)
		}
	})
	t.Run("identity", func(t *testing.T) {
		_, out, _ := runOn(t, []string{"GIT_AUTHOR_EMAIL=" + other}, signoff)
		if !strings.Contains(out, idHint) || strings.Contains(out, headerHint) {
			t.Errorf("want the identity hint only; output %q", out)
		}
	})
}

// goodRecord is one well-formed git log record. It has the hash, the author
// and committer addresses and names, an empty encoding and a sign-off
// trailer.
const goodRecord = "0123456789abcdef\x00" + me + "\x00" + me + "\x00t\x00t\x00\x00Signed-off-by: t <" + me + ">\x00\n"

// goodObjs holds a good header and an empty raw message for each hash that the
// records of these tests use.
var goodObjs = map[string]commitObject{
	"0123456789abcdef": {header: []byte(stdHeader)},
	"fedcba9876543210": {header: []byte(stdHeader)},
}

// A commit with no raw object fails. So does a commit with no header, or with
// a message that is not valid UTF-8. All are identity failures, never a pass.
// The output holds no address.
func TestCheckFailsClosed(t *testing.T) {
	for name, objs := range map[string]map[string]commitObject{
		"nil map":      nil,
		"other hash":   {"fedcba9876543210": {header: []byte(stdHeader)}},
		"invalid text": {"0123456789abcdef": {header: []byte(stdHeader), msg: []byte("a\xffb\n")}},
		"no header":    {"0123456789abcdef": {}},
	} {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := check(splitRecords([]byte(goodRecord)), objs, "base", "HEAD", &stdout, &stderr)
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
			if code := check(splitRecords([]byte(out)), goodObjs, "base", "HEAD", &stdout, &stderr); code != 2 {
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
	if code := check(splitRecords([]byte(goodRecord)), goodObjs, "base", "HEAD", &stdout, &stderr); code != 0 {
		t.Fatalf("check = %d, want 0; stdout %q, stderr %q", code, stdout.String(), stderr.String())
	}
}

// The last record is a record even when it lacks the NUL and LF that end it.
func TestCheckKeepsLastRecordWithoutEnd(t *testing.T) {
	unsigned := "0123456789abcdef\x00" + me + "\x00" + me + "\x00t\x00t\x00\x00\x00"
	var stdout, stderr bytes.Buffer
	if code := check(splitRecords([]byte(unsigned)), goodObjs, "base", "HEAD", &stdout, &stderr); code != 1 || !strings.Contains(stdout.String(), "unsigned: 0123456789ab\n") {
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
		if code := check(splitRecords([]byte(c.out)), goodObjs, "base", "HEAD", &stdout, &stderr); code != c.code || !strings.Contains(stdout.String(), c.want) {
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
	return forgeRaw(t, forgeHeader+extra, msg, flags...)
}

// ident is a valid author or committer value. stdHeader is a valid header with
// fixed hashes. forgeHeader is the same header for forgeRaw, and it ends in LF.
const (
	ident       = "t <" + me + "> 1700000000 +0000"
	hex40       = "0123456789abcdef0123456789abcdef01234567"
	stdHeader   = "tree " + hex40 + "\nparent " + hex40 + "\nauthor " + ident + "\ncommitter " + ident
	forgeHeader = "tree TREE\nparent PARENT\nauthor " + ident + "\ncommitter " + ident + "\n"
)

// forgeRaw is forgeCommit with the whole header text. In header, TREE and
// PARENT stand for the tree and the parent of the base commit.
func forgeRaw(t *testing.T, header, msg string, flags ...string) (dir, hash string) {
	t.Helper()
	dir = newRepo(t)
	commit(t, dir, "base", true)
	git(t, dir, "branch", "base")
	tree := strings.TrimSpace(git(t, dir, "rev-parse", "HEAD^{tree}"))
	parent := strings.TrimSpace(git(t, dir, "rev-parse", "HEAD"))
	obj := strings.NewReplacer("TREE", tree, "PARENT", parent).Replace(header) + "\n" + msg
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

// Git converts the message to UTF-8 from the encoding line. The bytes of
// an address can then come out as other characters, so dco cannot see the
// address. A commit with an encoding line fails, also with an empty value.
func TestEncodingLineFails(t *testing.T) {
	const hint = "hint: commits must not set an encoding line\n"
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
	// Git shows an empty %e for an empty value, so only the header shows it.
	// A line with no space makes the parse fail.
	for name, extra := range map[string]string{
		"empty value":                        "encoding \n",
		"two encoding lines":                 "encoding \nencoding UTF-7\n",
		"encoding line and continuation":     "encoding UTF-8\n more\n",
		"empty encoding line, no space line": "encoding \nx\n",
	} {
		t.Run(name, func(t *testing.T) {
			dir, hash := forgeCommit(t, extra, signoff, "--literally")
			code, out, _ := runDCO([]string{"base", "forged"}, dir)
			if code != 1 || !strings.Contains(out, "identity: "+hash[:12]+"\n") || !strings.Contains(out, hint) {
				t.Fatalf("run = %d, want 1 with an identity line and the encoding hint; output %q", code, out)
			}
		})
	}
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
		// A mention or version that an address can follow.
		"mention, middle dot":        body("(alice)@gmail\xc2\xb7com"),
		"mention, space, middle dot": body("alice @gmail\xc2\xb7com"),
		"angle, middle dot":          body("Alice <alice @gmail\xc2\xb7com>"),
		"quote, middle dot":          body("alice'@gmail\xc2\xb7com"),
		"line break, middle dot":     body("alice\n@gmail\xc2\xb7com"),
		"version, middle dot":        body("alice#v1\xc2\xb7example.com"),
		"version 6, middle dot":      body("alice#v6\xc2\xb7mail.example.com"),
		"version, en dash":           body("alice#v1\xe2\x80\x93example.com"),
		"version, ellipsis":          body("alice#v1\xe2\x80\xa6example.com"),
		"spaced dot":                 body("alice @example .com"),
		"double dot":                 body("alice @example..com"),
		"dot on the third line":      body("alice\n@example\n.com"),
		"cybagard, space, dot":       body("alice @cybagard .com"),
		"dependabot, break, dot":     body("alice @dependabot\n  .com"),
		"name not on the list":       body("@someone"),
		"copilot":                    body("thanks @copilot"),
		"maintainer, middle dot":     body(me + "\xc2\xb7evil.example"),
		"version, dot, other text":   body("alice#v1-example.com. Thanks"),
		"mention, CRLF, dot":         "subject\r\n\r\nalice @dependabot\r\n.com\r\n\r\nSigned-off-by: t <" + me + ">\r\n",
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
		"mention, upper case":       body("@CYBAGARD"),
		"mention then a sentence":   body("thanks @dependabot. Next sentence."),
		"version, comma, then text": body("uses actions/checkout@v5.1.0, ok"),
		"version, space, em dash":   body("see x@v1.2 \xe2\x80\x94 note"),
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

// TestAtSignBoundaries pins each boundary of the four at-sign uses, one line
// at a time.
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
		{"a@context", false}, {"Z@context", false}, {"0@context", false},
		{".@context", false}, {"_@context", false}, {"%@context", false},
		{"+@context", false}, {"-@context", false},
		{" @context", true}, {"(@context", true}, {"@context", true}, {"/@context", true},
		// Mention: only the names on the list, without case.
		{"@", false}, {"@ context", false}, {"@b", false}, {"@a", false}, {"@copilot", false},
		{"@someone", false}, {"@contex", false}, {"@contextx", false}, {"@context-", false},
		{"@context-x", false}, {"@Context", true}, {"@DEPENDABOT", true},
		{"@dependabot", true}, {"@cybagard", true}, {"@CYBAGARD", true},
		{"@dependabot[bot]", true}, {"@depend", false}, {"@cyba", false},
		// Mention: the character after.
		{"@context@", false}, {"@context_", false}, {"@context%", false},
		{"@context.b", false}, {"@context.7", false}, {"@context.", true},
		{"@context+", true}, {"@context,", true}, {"@context:", true},
		{"@contexta", false}, {"@contextz", false}, {"@contextA", false},
		{"@contextZ", false}, {"@context0", false}, {"@context9", false},
		{"@context\xc2\xb7x", false}, {"@context\xe2\x80\x93x", false},
		{"@context\xe2\x80\xa6", false}, {"@context \xe2\x80\x94 x", true},
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
		{m + "@v1.2", false}, {"@context@v1", false}, {"a@v1@v1", false},
		{"a@v1.-rc", true},
		// The ends of the letter and digit ranges: A, Z, a, z, 0 and 9.
		{"A" + m, false}, {"z" + m, false}, {"9" + m, false},
		{m + "A", false}, {m + "z", false}, {m + "9", false},
		// A version that ends before a dot and a non-word character.
		{"x@v1._", true}, {"x@v1.@v2", true}, {"x@v1-rc1._", true}, {"x@v1-rc1.-", true},
		{"x#v1.2.", true}, {"alice#v1-example.com. Thanks", false},
		// A version that a byte of 0x80 or more follows.
		{"x@v1.2\xc2\xb7y", false}, {"x@v1.2\xe2\x80\x93y", false},
		{"x@v1.2\xe2\x80\xa6y", false}, {"x@v1-rc1\xc2\xb7y", false},
		{"x@v1.2 \xe2\x80\x94 note", true}, {"x@v1.2", true},
		{m + "\xc2\xb7evil.example", false}, {m + "\xe2\x80\x94", false},
		{m + " \xe2\x80\x94", true},
		// Versions with the digits 0 and 9 in each group, and a dot at the end.
		{"x@v9.9.9", true}, {"x@v1.9", true}, {"x@v19", true}, {"x@v0.0", true},
		{"x#v1.9.example", false}, {"x#v1.9.9.example", false},
		{"uses x@v1.9.", true}, {"x@v1.9.0.", true},
		{"x@v1-rc1.", true}, {"x@v1-rc.", false}, {"x@v1-rc.1.", true},
		// The last pre-release part: digits make it a number, letters do not.
		{"x#v1-rc.00", true}, {"x#v1-rc.99", true}, {"x#v1-rc.a9", true},
		{"x#v1-rc.0a", true}, {"x#v1-rc.9a", true}, {"x#v1-rc.ab", false},
		{"x#v1-rc.zz", false}, {"x#v1-rc.AZ", false},
	}
	for _, c := range cases {
		// "#" stands for "@" in the lines that would look like an address.
		c.line = strings.ReplaceAll(c.line, "#", "@")
		if got := atSignsOK(c.line, ""); got != c.want {
			t.Errorf("atSignsOK(%q) = %v, want %v", c.line, got, c.want)
		}
	}
}

// The known limits of the address rules, as tested facts. dco does not find an
// address with no at-sign character, and it passes a space after the dot.
func TestKnownLimits(t *testing.T) {
	for name, msg := range map[string]string{
		"words for at and dot":  body("write to alice at example dot com"),
		"percent-encoded at":    body("alice%40example.com"),
		"space after the dot":   body("alice @dependabot. com"),
		"space after the dot 2": body("alice @cybagard. com"),
	} {
		t.Run(name, func(t *testing.T) {
			if code, out, _ := runOn(t, nil, msg); code != 0 {
				t.Fatalf("run = %d, want 0; output %q", code, out)
			}
		})
	}
}

// A mention at the very end of the message passes.
func TestMentionAtMessageEnd(t *testing.T) {
	if !messageOK([]byte("thanks @dependabot")) || !messageOK([]byte("thanks @dependabot\r\n")) {
		t.Error("messageOK refuses a mention at the end of the message")
	}
	if messageOK([]byte("alice @dependabot\n.com")) || messageOK([]byte("alice @dependabot\r\n  .com")) {
		t.Error("messageOK accepts a dot and a word on the next line")
	}
}

// After a mention or a version, a "." and a word fail the "@". dco skips
// spaces and TABs, and one line break with the spaces and TABs after it.
func TestNoDotAfter(t *testing.T) {
	for _, c := range []struct {
		line, next string
		want       bool
	}{
		{"@context .com", "", false}, {"@context  .com", "", false},
		{"@context\t.com", "", false}, {"@context \t .7", "", false},
		{"@context", ".com", false}, {"@context", "  .com", false},
		{"@context  ", "\t.com", false}, {"x@v1.2 .com", "", false},
		{"x@v1.2", " .a", false}, {"x@v1.2", ".7", false},
		{"@context . com", "", true}, {"@context ..com", "", true},
		{"@context", ". com", true}, {"@context", "", true}, {"@context", ".", true},
		{"@context", "x .com", true}, {"@context x", ".com", true},
		{"@context", "\n.com", true}, {"@context", "-.com", true},
		{"x@v1.2", " x", true}, {"x@v1.2 ", "", true}, {"x@v1.2", "._", true},
		// The known limit: a space after the dot.
		{"@dependabot. com", "", true}, {"@dependabot.", " com", true},
	} {
		if got := atSignsOK(c.line, c.next); got != c.want {
			t.Errorf("atSignsOK(%q, %q) = %v, want %v", c.line, c.next, got, c.want)
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
		t.Error("nameOK does not apply the character list and the no-at-sign rule")
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
		"exit 128 with text":       `echo "fatal: alice@example.com" >&2; exit 128`,
		"bad header":               `echo "alice@example.com commit"`,
		"short object":             `read h; echo "$h commit 999"; echo "alice@example.com"`,
		"empty output":             `read h`,
		"object of the wrong type": `read h; echo "$h blob 0"; echo`,
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
// rawObjects refuses a repository that git cannot read.
func TestRawObjectsErrors(t *testing.T) {
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
	if _, err := rawObjects(t.TempDir(), []string{strings.Repeat("a", 40)}); err == nil {
		t.Error("rawObjects accepts a directory that is not a repository")
	}
}

// The reader accepts an empty object and an object that ends exactly at the
// output. It splits the header from the message at the first empty line. It
// refuses a body one byte short of the object and its LF.
func TestParseBatchSizes(t *testing.T) {
	got, err := parseBatch([]byte("a commit 0\n\nb commit 6\nh\n\nmsg\n"), 2)
	if err != nil || len(got) != 2 || len(got["a"].msg) != 0 || string(got["b"].msg) != "msg" || string(got["b"].header) != "h" {
		t.Errorf("parseBatch = %q, %v; want a empty and b with header h and msg", got, err)
	}
	if _, err := parseBatch([]byte("a commit 3\nxxx"), 1); err == nil {
		t.Error("parseBatch accepts an object without its LF")
	}
	if _, err := parseBatch([]byte("a commit 3\nxxx\n"), 1); err != nil {
		t.Errorf("parseBatch refuses an object with its LF: %v", err)
	}
}

// hdr is a header with the given author and committer values.
func hdr(author, committer string) string {
	return "tree TREE\nparent PARENT\nauthor " + author + "\ncommitter " + committer + "\n"
}

// armor is a signature field: the key and the first line, then each of lines
// as a continuation line.
func armor(first string, lines ...string) string {
	s := first + "\n"
	for _, l := range lines {
		s += " " + l + "\n"
	}
	return s
}

// pgpSig is the PGP signature form of a commit that GitHub makes. The
// signature does not verify here.
var pgpSig = armor("gpgsig -----BEGIN PGP SIGNATURE-----", "",
	"wsFcBAABCAAQBQJq/wVKCRC1aQ7uu5UhlAAA7RAQAH4d4X1OCFylKz/0zCIFXap1",
	"MbhFsFbCdZPqUual1LYCD7NxxHKdqxLz+Bb+eebqQlwNMYnUwG6iIs7KG1FcwQUK",
	"vTWSYSJ4+DxonYAkYwFu", "=NV1v", "-----END PGP SIGNATURE-----", "")

// ghIdent is a valid committer value with the GitHub committer address.
// ghHeader is forgeHeader with that committer.
const (
	ghIdent  = "GitHub <noreply@github.com> 1700000000 +0000"
	ghHeader = "tree TREE\nparent PARENT\nauthor " + ident + "\ncommitter " + ghIdent + "\n"
)

// githubHeader has the form of the header of a commit that GitHub makes, with
// a PGP signature. The signature is an abridged copy: 3 of its 14 base64 lines.
var githubHeader = hdr("cybagard labs <"+me+"> 1795097930 +0100",
	"GitHub <noreply@github.com> 1795097930 +0100") + pgpSig

// failsHeader forges a commit with the header. Git checks the object unless
// flags has --literally. It expects exit 1, an identity line and no "@" in the
// output.
func failsHeader(t *testing.T, header string, flags ...string) {
	t.Helper()
	dir, hash := forgeRaw(t, header, signoff, flags...)
	code, out, errOut := runDCO([]string{"base", "forged"}, dir)
	if code != 1 || !strings.Contains(out, "identity: "+hash[:12]+"\n") {
		t.Fatalf("run = %d, want 1 with an identity line; output %q %q", code, out, errOut)
	}
	if strings.Contains(out+errOut, "@") {
		t.Errorf("the output shows an address: %q %q", out, errOut)
	}
}

// A header with an extra key, a wrong count or order, or a signature field
// fails, also with the GitHub committer. So does an author name with two
// spaces before the address. Git accepts the forms in the first group.
func TestHeaderFails(t *testing.T) {
	lit := "--literally"
	forged := "cybagard <" + me + "> alice@example.com <x@y.example> 1700000000 +0000"
	sha := strings.Replace(pgpSig, "gpgsig ", "gpgsig-sha256 ", 1)
	for name, header := range map[string]string{
		"x-note key":                    forgeHeader + "x-note <" + other + ">\n",
		"mergetag key":                  forgeHeader + armor("mergetag object TREE", "type commit", "tagger t <"+other+"> 1 +0000", "", "tag"),
		"key in a case":                 forgeHeader + "GPGSIG x\n",
		"second tree":                   forgeHeader + "tree TREE\n",
		"two spaces before the address": hdr("t  <"+me+"> 1700000000 +0000", ident),
		"gpgsig field":                  ghHeader + pgpSig,
		"gpgsig-sha256 field":           ghHeader + sha,
		"both signature fields":         ghHeader + sha + pgpSig,
		"gpgsig field, one line":        ghHeader + "gpgsig x\n",
		"gpgsig-sha256 field, one line": ghHeader + "gpgsig-sha256 x\n",
	} {
		t.Run(name, func(t *testing.T) { failsHeader(t, header) })
	}
	for name, header := range map[string]string{
		"forged author line":       hdr(forged, ident),
		"forged committer line":    hdr(ident, forged),
		"text after the time zone": hdr(ident+" alice@example.com", ident),
		"text before the date":     hdr("t <"+me+"> x 1700000000 +0000", ident),
		"no time zone":             hdr("t <"+me+"> 1700000000", ident),
		"two author lines":         "tree TREE\nparent PARENT\nauthor t <" + other + "> 1700000000 +0000\nauthor " + ident + "\ncommitter " + ident + "\n",
		"two committer lines":      hdr(ident, ident) + "committer " + ident + "\n",
		"committer first":          "tree TREE\nparent PARENT\ncommitter " + ident + "\nauthor " + ident + "\n",
		"no committer":             "tree TREE\nparent PARENT\nauthor " + ident + "\n",
		"parent after author":      "tree TREE\nauthor " + ident + "\nparent PARENT\ncommitter " + ident + "\n",
		"signature before author":  "tree TREE\nparent PARENT\n" + pgpSig + "author " + ident + "\ncommitter " + ident + "\n",
		"continuation":             forgeHeader + " more\n",
		"continuation, author":     hdr(ident+"\n more", ident),
		"upper case hash":          strings.Replace(forgeHeader, "tree TREE", "tree "+strings.ToUpper(hex40), 1),
		"line without a space":     forgeHeader + "x\n",
	} {
		t.Run(name, func(t *testing.T) { failsHeader(t, header, lit) })
	}
}

// These headers pass: an unsigned commit with the GitHub committer, also in
// upper case, a root commit and a merge commit.
func TestHeaderPasses(t *testing.T) {
	for name, header := range map[string]string{
		"GitHub committer":               ghHeader,
		"GitHub committer in upper case": hdr(ident, "GitHub <NOREPLY@GITHUB.COM> 1 +0000"),
		"root commit":                    "tree TREE\nauthor " + ident + "\ncommitter " + ident + "\n",
		"merge commit":                   "tree TREE\nparent PARENT\nparent PARENT\nauthor " + ident + "\ncommitter " + ident + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			dir, _ := forgeRaw(t, header, signoff, "--literally")
			code, out, errOut := runDCO([]string{"base", "forged"}, dir)
			if code != 0 || strings.Contains(out+errOut, "@") {
				t.Fatalf("run = %d, want 0 and no address; output %q %q", code, out, errOut)
			}
		})
	}
}

// The setting log.showSignature in the repository adds gpg text to the output
// of git log for a signed commit. dco asks for no signature, so the output
// holds only the expected lines. The test uses an empty GnuPG home.
func TestShowSignatureSettingChangesNothing(t *testing.T) {
	t.Setenv("GNUPGHOME", t.TempDir())
	dir, hash := forgeRaw(t, githubHeader, signoff, "--literally")
	git(t, dir, "config", "log.showSignature", "true")
	cmd := exec.Command("git", "-C", dir, "log", "-1", "--format=%H", hash)
	shown, err := cmd.Output()
	if err != nil || !strings.Contains(string(shown), "gpg") {
		t.Fatalf("the setting does not put gpg text in the output of git log: %q, %v", shown, err)
	}
	code, out, errOut := runDCO([]string{"base", "forged"}, dir)
	if code != 1 || errOut != "" || strings.Contains(out, "gpg") {
		t.Fatalf("run = %d, want 1 and no gpg text; output %q %q", code, out, errOut)
	}
	for _, l := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
		if !strings.HasPrefix(l, "identity: ") && !strings.HasPrefix(l, "dco FAIL: ") && !strings.HasPrefix(l, "hint: ") {
			t.Errorf("unexpected output line %q", l)
		}
	}
}

// The author and committer values follow the form and the address rule,
// whatever git log shows. The name follows the character list.
func TestIdentLineOK(t *testing.T) {
	const gh = "GitHub <noreply@github.com> 1 -0700"
	for _, c := range []struct {
		value     string
		committer bool
		want      bool
	}{
		{"t <" + me + "> 1 +0000", false, true},
		{"t <" + me + "> 0 +0000", false, true},
		{"t <" + me + "> 1234567890123456 +0000", false, true},
		{"t <" + me + "> 1700000000 -0700", false, true},
		{" <" + me + "> 1 +0000", false, false},
		{"<" + me + "> 1 +0000", false, false},
		{"t  <" + me + "> 1 +0000", false, false},
		{"t\t<" + me + "> 1 +0000", false, false},
		{"t\t <" + me + "> 1 +0000", false, false},
		{" t <" + me + "> 1 +0000", false, false},
		{"\tt <" + me + "> 1 +0000", false, false},
		{"a b <" + me + "> 1 +0000", false, true},
		{"t <" + me + "> 01 +0000", false, false},
		{"t <" + me + "> 00 +0000", false, false},
		{"t <" + me + "> 12345678901234567 +0000", false, false},
		{"t <" + me + ">  +0000", false, false},
		{"t <" + strings.ToUpper(me) + "> 1 +0000", false, true},
		{gh, true, true},
		{gh, false, false},
		{"t <" + other + "> 1 +0000", true, false},
		{"t <" + other + "> 1 +0000", false, false},
		{"a@b <" + me + "> 1 +0000", false, false},
		{"a\xe2\x80\x8bb <" + me + "> 1 +0000", false, false},
		{"t <" + me + "> 1 +00000", false, false},
		{"t <" + me + "> 1 0000", false, false},
		{"t <" + me + "> +0000", false, false},
		{"t <" + me + ">  1 +0000", false, false},
		{"t <" + me + "> 1 +0000 ", false, false},
		{"t<" + me + "> 1 +0000", false, false},
	} {
		if got := identLineOK(c.value, c.committer); got != c.want {
			t.Errorf("identLineOK(%q, %v) = %v, want %v", c.value, c.committer, got, c.want)
		}
	}
}

// A hash of 64 digits passes. These fail: a shorter or longer hash and a parent
// before the tree. A missing tree, author or committer fails, and so does an
// empty header. Git refuses to use such objects, so no repository holds them.
func TestHeaderOKHashes(t *testing.T) {
	h64 := strings.Repeat("ab", 32)
	tail := "\nauthor " + ident + "\ncommitter " + ident
	for header, want := range map[string]bool{
		"tree " + h64 + "\nparent " + h64 + tail:        true,
		"tree " + h64 + "0\nparent " + h64 + tail:       false,
		"tree " + hex40 + "0" + tail:                    false,
		"tree " + hex40 + "\nparent " + h64[:63] + tail: false,
		"parent " + hex40 + "\ntree " + hex40 + tail:    false,
		"tree " + hex40 + "\nauthor " + ident:           false,
		"tree " + hex40 + "\ncommitter " + ident:        false,
		"author " + ident + "\ncommitter " + ident:      false,
		"": false,
		// A header that starts with a continuation line.
		" x\ntree " + hex40 + tail: false,
	} {
		if got, _ := headerOK([]byte(header)); got != want {
			t.Errorf("headerOK(%q) = %v, want %v", header, got, want)
		}
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
