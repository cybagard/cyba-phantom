// Command dco checks the Developer Certificate of Origin sign-off (DCO 1.1)
// and the commit identity. Every commit in base..head must carry a
// "Signed-off-by" trailer. Each commit uses only the permitted addresses
// (below).
//
// Usage:
//
//	dco <base> <head>
//
// dco applies the identity rule to each commit. Addresses and trailer keys
// compare without case. The author and committer come from %ae and %ce, so
// no mailmap applies.
//   - The author address is the maintainer noreply address.
//   - The committer address is that address, or the GitHub committer
//     address. GitHub makes the commit for a web merge.
//   - Every Signed-off-by value has the maintainer address.
//   - Every address in any other trailer is the maintainer address. dco
//     also permits the Claude co-author address, in a Co-authored-by
//     trailer. The name in that trailer is "Claude" or starts with
//     "Claude ". That trailer holds exactly one address.
//   - The author name and the committer name (%an and %cn) pass the
//     character list below, and they hold no "@".
//
// In a trailer, an address is any token of the form x@y with no space, "<"
// or ">". dco skips a trailer without an address. A Signed-off-by trailer
// without an address fails.
//
// dco also checks the whole commit message: subject, body, every paragraph
// and every line. It reads the message from the commit object, so the bytes
// after a NUL byte count too. A commit with no raw message fails. The check
// has two allow lists. A commit that breaks one fails as an identity failure.
//
// The character list. A message holds only these characters:
//   - printable ASCII (0x20 to 0x7E), TAB and LF;
//   - CR, directly before LF;
//   - U+00A7, U+2014, U+2013, U+2026 and U+00B7.
//
// Any other byte or character fails. That includes a byte that is not valid
// UTF-8, a control character and a format character. It includes a combining
// mark. It includes these look-alikes of "@" and ".": U+FF20, U+FE6B, U+2024,
// U+FE52, U+FF0E, U+FF61 and U+3002.
//
// The at-sign list. Each "@" in the message must be one of four uses.
//   - Maintainer: the "@" is inside the maintainer address. The address is
//     whole. The character before it is not a letter or a digit. It is not
//     one of . _ % + - either. The character after it is not a letter or
//     a digit. It is not one of _ % + - @, and not a "." before a letter or
//     a digit. The compare is ASCII only and without case.
//   - Claude: the line starts at column 1 with the key Co-authored-by
//     (without case) and ":". The name is "Claude" or starts with "Claude ".
//     The line ends in <noreply@anthropic.com>. It holds no other "@".
//   - Mention: the "@" starts the line. Or it comes after a character that
//     is not a letter, a digit or one of . _ % + -. The name after it is
//     context, dependabot or cybagard, without case. Then come no "@",
//     letter, digit, "_" or "%".
//   - Version: the "@" comes after a letter, a digit or one of . _ / -. After
//     it come "v", digits, and groups of "." and digits. A "-" and a
//     pre-release text of letters, digits and "." can follow. The last
//     "."-part of that text is not two or more letters only. Then come no
//     "@", letter, digit, "_", "%", "+" or "-".
//
// Word end. After the maintainer address, a mention or a version, the next
// byte is not 0x80 or more. A "." before a letter or a digit is not next.
//
// No dot after. After a mention or a version, dco skips spaces and TABs. It
// skips one line break and the spaces and TABs after it. A "." before a
// letter or a digit then fails the "@". The next line counts.
//
// Costs. These forms fail by design: REDACTED@" (a quote after the "@"),
// and user:pw@tcp(host)/db. A version also fails when the last part of its
// pre-release text is two or more letters, such as -beta.rc.
//
// Known limits. dco does not find an address with no at-sign character. One
// example is an address written with the words "at" and "dot". Another is %40.
// After a mention or a version, the no-dot rule fails only a "." directly
// before an ASCII letter or digit. Any other form of a domain passes there.
// Examples are "@dependabot. com", "@context..io" and "@context[.]io". The
// word "dot" passes too. So does a dot at the end of the line. So does a
// space, a TAB or a line break before a non-ASCII character such as U+00B7.
//
// The header rule. dco reads the header of each commit object: the bytes
// before the first empty line. A header line is "<key> <value>". A line that
// starts with one space is a continuation line. A commit that breaks one of
// these rules fails as an identity failure. A signed commit has a signature
// field, so it fails.
//   - A key compares exactly, with case. The permitted keys are tree, parent,
//     author and committer. Any other key fails, also gpgsig and
//     gpgsig-sha256. So a signed commit fails.
//   - A continuation line fails.
//   - The order is one tree line, any parent lines, one author line and one
//     committer line. Any other count or order fails.
//   - A tree or parent value is a full hash: 40 or 64 lowercase hex digits.
//   - An author or committer value has four parts: the name, the address,
//     the time and the zone. The address is in "<" and ">". One space is
//     between the parts. The name is not empty. It does not start or end
//     with a space or a TAB. The name and the address hold no "<" or ">".
//     The time is "0", or up to 16 digits that do not start with "0". The
//     zone is "+" or "-" and 4 digits. The name passes the character list
//     and holds no "@". The address follows the identity rule above. dco
//     reads both from the raw line.
//   - An encoding line fails, whatever its value, also an empty one.
//
// A commit that fails only the header rule gets its own hint, with its
// identity line. A commit with an encoding line gets its own hint too. It
// gets that hint also when the rest of the header does not parse.
//
// It runs git (the toolchain image ships it). It prints short commit
// hashes and counts only. It never prints an address, a name, a subject or
// a trailer value. A PR author controls these, and a CI log shows them.
// Exit codes: 0 all commits pass or the range is empty. 1 a commit fails.
// 2 usage, git or log format error.
package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	maintainerAddr = "67512030+cybagard@users.noreply.github.com"
	githubAddr     = "noreply@github.com"
	claudeAddr     = "noreply@anthropic.com"
)

// signoffRE matches the value of one Signed-off-by trailer: "Name
// <address>", where address has a local part, an @, and a dotted domain.
var signoffRE = regexp.MustCompile(`^\S.* <[^<>\s]+@[^<>\s]+\.[^<>\s]+>$`)

// addrRE finds each address in a trailer value.
var addrRE = regexp.MustCompile(`[^\s<>]+@[^\s<>]+`)

// hashRE matches a full hash: the %H of a commit, or a tree or parent value.
var hashRE = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)

// identLineRE matches the value of an author or committer line: the name, the
// address, the time and the time zone. The groups are the name and the address.
// The name is not empty and has no space or TAB at its ends. The time is "0" or
// up to 16 digits with no leading zero.
var identLineRE = regexp.MustCompile(`^([^<> \t](?:[^<>]*[^<> \t])?) <([^<>]*)> (?:0|[1-9][0-9]{0,15}) [+-][0-9]{4}$`)

// logFormat asks git for these fields of each commit. They are the hash, the
// author and committer addresses and names, the encoding and the
// trailers. Git's own trailer parser decides what a trailer is. The option
// `only` drops the lines of the trailer block that are not trailers. So dco
// accepts only the sign-offs that git recognizes as trailers.
const logFormat = "--format=%H%x00%ae%x00%ce%x00%an%x00%cn%x00%e%x00%(trailers:only,unfold,separator=%x0a)%x00"

func main() { os.Exit(run(os.Args[1:], ".", os.Stdout, os.Stderr)) }

// run checks the sign-off and identity of every commit in base..head of
// the repository in dir.
func run(args []string, dir string, stdout, stderr io.Writer) int {
	if len(args) != 2 {
		fmt.Fprintln(stderr, "usage: dco <base> <head>")
		return 2
	}
	base, head := args[0], args[1]

	cmd := exec.Command("git", "-C", dir, "log", "--no-show-signature", logFormat, base+".."+head)
	out, err := cmd.Output()
	if err != nil {
		// dco does not print the stderr of git.
		fmt.Fprintf(stderr, "dco: git log %s..%s failed: %v\n", base, head, err)
		return 2
	}
	// git log stops a message at a NUL byte, so dco reads the message from
	// the object. A malformed record gives no hash here, and check reports it.
	records := splitRecords(out)
	var hashes []string
	for _, rec := range records {
		if h, _, _ := bytes.Cut(rec, []byte{0}); hashRE.Match(h) {
			hashes = append(hashes, string(h))
		}
	}
	objs, err := rawObjects(dir, hashes)
	if err != nil {
		fmt.Fprintf(stderr, "dco: git cat-file failed: %v\n", err)
		return 2
	}
	return check(records, objs, base, head, stdout, stderr)
}

// commitObject is a commit as stored in the object: the header and the message.
type commitObject struct{ header, msg []byte }

// rawObjects returns the header and the message of each commit as stored in
// the object, keyed by full hash. The message starts after the first empty line
// of the object. A NUL byte and the bytes after it stay in the message.
func rawObjects(dir string, hashes []string) (map[string]commitObject, error) {
	if len(hashes) == 0 {
		return map[string]commitObject{}, nil
	}
	cmd := exec.Command("git", "-C", dir, "cat-file", "--batch")
	cmd.Stdin = strings.NewReader(strings.Join(hashes, "\n") + "\n")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	return parseBatch(out, len(hashes))
}

// parseBatch reads n objects from the output of git cat-file --batch. Each
// object is a batch line "<hash> commit <size>", the object and one LF.
func parseBatch(out []byte, n int) (map[string]commitObject, error) {
	objs := make(map[string]commitObject, n)
	for range n {
		line, rest, ok := bytes.Cut(out, []byte{'\n'})
		f := strings.Fields(string(line))
		if !ok || len(f) != 3 || f[1] != "commit" {
			return nil, errors.New("cat-file: bad object header")
		}
		size, err := strconv.Atoi(f[2])
		if err != nil || size < 0 {
			return nil, errors.New("cat-file: bad object header")
		}
		if len(rest) < size+1 {
			return nil, errors.New("cat-file: short object")
		}
		// The object is followed by one LF.
		header, msg, _ := bytes.Cut(rest[:size], []byte("\n\n"))
		objs[f[0]] = commitObject{header, msg}
		out = rest[size+1:]
	}
	return objs, nil
}

// splitRecords splits the output of git log into records. Git ends every
// record with its own newline, so records separate on NUL+LF.
func splitRecords(out []byte) [][]byte {
	records := bytes.Split(out, []byte{0, '\n'})
	if last := len(records) - 1; last >= 0 && len(records[last]) == 0 {
		records = records[:last]
	}
	return records
}

// check applies the rules to each record of the output of git log. objs holds
// the raw header and message of each commit, keyed by full hash.
func check(records [][]byte, objs map[string]commitObject, base, head string, stdout, stderr io.Writer) int {
	// A record is the fields H, AE, CE, AN, CN, E and TRAILERS. A NUL ends
	// each field. The NUL+LF that ends the record is not in it. Git joins
	// the trailers with LF. An unfolded trailer holds no LF and no NUL.
	// The checker prints no PR-authored text. It prints only hashes and counts.
	total, unsigned, badID, badEnc, badIdentity, badHeader := 0, 0, 0, 0, 0, 0
	for _, rec := range records {
		f := bytes.SplitN(rec, []byte{0}, 7)
		if len(f) < 7 {
			// dco does not print the record: it is PR-authored content.
			fmt.Fprintln(stderr, "dco: malformed git log record")
			return 2
		}
		full := string(f[0])
		hash := full
		if len(hash) > 12 {
			hash = hash[:12]
		}
		total++
		trailers := strings.Split(string(f[6]), "\n")
		if !hasSignoff(trailers) {
			unsigned++
			fmt.Fprintf(stdout, "unsigned: %s\n", hash)
		}
		// A commit with no raw object fails: dco cannot check it. A non-empty
		// %e needs an encoding line, so it also counts as one.
		obj, haveObj := objs[full]
		headerGood, encoded := headerOK(obj.header)
		encoded = encoded || len(f[5]) > 0
		identityBad := !identityOK(string(f[1]), string(f[2]), trailers) ||
			!nameOK(string(f[3])) || !nameOK(string(f[4])) || !haveObj || !messageOK(obj.msg)
		if encoded || identityBad || !headerGood {
			badID++
			fmt.Fprintf(stdout, "identity: %s\n", hash)
		}
		if encoded {
			badEnc++
		}
		if identityBad {
			badIdentity++
		} else if !headerGood {
			badHeader++
		}
	}

	switch {
	case total == 0:
		fmt.Fprintln(stdout, "dco: no commits in range — nothing to check")
		return 0
	case unsigned > 0 || badID > 0:
		fmt.Fprintf(stdout, "dco FAIL: of %d commits in %s..%s, %d lack a Signed-off-by trailer and %d break the identity rule\n",
			total, base, head, unsigned, badID)
		if unsigned > 0 {
			fmt.Fprintln(stdout, "hint: sign with `git commit -s`")
		}
		if badIdentity > 0 {
			fmt.Fprintln(stdout, "hint: only a commit with the identity of the maintainer passes this check. Maintainer: see the header of tools/dco/main.go for the rule. Outside contribution: see CONTRIBUTING.md.")
		}
		if badHeader > 0 {
			fmt.Fprintln(stdout, "hint: the header rule fails this commit. A signed commit fails it. See the header of tools/dco/main.go.")
		}
		if badEnc > 0 {
			fmt.Fprintln(stdout, "hint: commits must not set an encoding line")
		}
		return 1
	}
	fmt.Fprintf(stdout, "dco: all %d commits in %s..%s carry Signed-off-by and pass the identity rule\n", total, base, head)
	return 0
}

// headerRank gives each permitted key its place in the order of the header.
var headerRank = map[string]int{
	"tree": 0, "parent": 1, "author": 2, "committer": 3,
}

// headerField is one header line: the key and the value.
type headerField struct{ key, value string }

// parseHeader splits a header into fields. It reports false for a line that
// has no space. A continuation line starts with a space, so it has the empty
// key. The key check then fails it.
func parseHeader(header []byte) ([]headerField, bool) {
	var fields []headerField
	for _, line := range strings.Split(string(header), "\n") {
		key, value, ok := strings.Cut(line, " ")
		if !ok {
			return nil, false
		}
		fields = append(fields, headerField{key, value})
	}
	return fields, true
}

// hasEncodingLine reports whether a line of the header has the key "encoding".
// A continuation line has no key.
func hasEncodingLine(header []byte) bool {
	for _, line := range strings.Split(string(header), "\n") {
		if key, _, ok := strings.Cut(line, " "); ok && key == "encoding" {
			return true
		}
	}
	return false
}

// headerOK applies the header rule to the header of a commit object. It also
// reports whether the header has an encoding line, also when the parse fails.
// That line alone does not make the first result false: check reports it with
// its own hint.
func headerOK(header []byte) (ok, encoded bool) {
	encoded = hasEncodingLine(header)
	fields, parsed := parseHeader(header)
	if !parsed {
		return false, encoded
	}
	ok = true
	rank, seen := 0, map[string]int{}
	for _, f := range fields {
		if f.key == "encoding" {
			continue
		}
		r, known := headerRank[f.key]
		if !known || r < rank {
			ok = false
			continue
		}
		rank = r
		seen[f.key]++
		ok = ok && fieldOK(f) && (seen[f.key] == 1 || f.key == "parent")
	}
	return ok && seen["tree"] == 1 && seen["author"] == 1 && seen["committer"] == 1, encoded
}

// fieldOK applies the rule for the value of one permitted header field.
func fieldOK(f headerField) bool {
	switch f.key {
	case "tree", "parent":
		return hashRE.MatchString(f.value)
	case "author":
		return identLineOK(f.value, false)
	case "committer":
		return identLineOK(f.value, true)
	}
	return false
}

// identLineOK reports whether an author or committer value is good. It has the
// right form. Its name passes nameOK. Its address is permitted.
func identLineOK(value string, committer bool) bool {
	m := identLineRE.FindStringSubmatch(value)
	if m == nil {
		return false
	}
	addr := m[2]
	return nameOK(m[1]) && (asciiEqualFold(addr, maintainerAddr) ||
		committer && asciiEqualFold(addr, githubAddr))
}

// splitTrailer splits an unfolded "Key: value" trailer line.
func splitTrailer(t string) (key, value string) {
	k, v, _ := strings.Cut(t, ":")
	return strings.TrimSpace(k), strings.TrimSpace(v)
}

// hasSignoff reports whether any trailer is a valid "Name <address>"
// Signed-off-by sign-off.
func hasSignoff(trailers []string) bool {
	for _, t := range trailers {
		if k, v := splitTrailer(t); asciiEqualFold(k, "Signed-off-by") && signoffRE.MatchString(v) {
			return true
		}
	}
	return false
}

// identityOK applies the identity rule to one commit.
func identityOK(author, committer string, trailers []string) bool {
	if !asciiEqualFold(author, maintainerAddr) ||
		!(asciiEqualFold(committer, maintainerAddr) || asciiEqualFold(committer, githubAddr)) {
		return false
	}
	for _, t := range trailers {
		key, value := splitTrailer(t)
		addrs := addrRE.FindAllString(value, -1)
		if len(addrs) == 0 && asciiEqualFold(key, "Signed-off-by") {
			return false
		}
		for _, a := range addrs {
			if asciiEqualFold(a, maintainerAddr) {
				continue
			}
			if asciiEqualFold(a, claudeAddr) && len(addrs) == 1 && asciiEqualFold(key, "Co-authored-by") && claudeName(value) {
				continue
			}
			return false
		}
	}
	return true
}

// allowedRune reports whether the character list has r: printable ASCII, TAB,
// LF, and U+00A7, U+2014, U+2013, U+2026, U+00B7. CR is not here: charsOK
// allows it only before LF. A byte that is not valid UTF-8 gives U+FFFD, which
// is not on the list.
func allowedRune(r rune) bool {
	switch r {
	case '\t', '\n', 0xA7, 0x2014, 0x2013, 0x2026, 0xB7:
		return true
	}
	return r >= 0x20 && r <= 0x7E
}

// charsOK reports whether every character of s is on the character list.
func charsOK(s string) bool {
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		if r == '\r' {
			if i+1 >= len(s) || s[i+1] != '\n' {
				return false
			}
		} else if !allowedRune(r) {
			return false
		}
		i += n
	}
	return true
}

// nameOK checks an author or committer name: the character list, and no "@".
func nameOK(name string) bool {
	return charsOK(name) && !strings.Contains(name, "@")
}

// messageOK applies both lists to a commit message: the character list, then
// the at-sign list for each line. The rule for a mention or a version also
// looks at the next line.
func messageOK(msg []byte) bool {
	if !charsOK(string(msg)) {
		return false
	}
	lines := strings.Split(string(msg), "\n")
	for k, line := range lines {
		next := ""
		if k+1 < len(lines) {
			next = lines[k+1]
		}
		if !atSignsOK(strings.TrimSuffix(line, "\r"), next) {
			return false
		}
	}
	return true
}

// atSignsOK reports whether each "@" of a line (without its CR) is one of the
// four allowed uses. next is the line after it, for the no-dot rule.
func atSignsOK(line, next string) bool {
	claude := strings.Contains(line, "@") && claudeAt(line)
	for i := 0; i < len(line); i++ {
		if line[i] == '@' && !claude && !maintainerAt(line, i) &&
			!mentionAt(line, i, next) && !versionAt(line, i, next) {
			return false
		}
	}
	return true
}

// isAlnum reports whether c is an ASCII letter or digit.
func isAlnum(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// isLocal reports whether c can be part of the local part of an address.
func isLocal(c byte) bool { return isAlnum(c) || strings.IndexByte("._%+-", c) >= 0 }

// wordEnd reports whether a word that ends before line[j] is whole. The next
// character is not "@", a letter, a digit, "_" or "%", or one of the bytes of
// more. It is not a byte of 0x80 or more. It is not a "." before a letter or
// a digit.
func wordEnd(line string, j int, more string) bool {
	if j >= len(line) {
		return true
	}
	c := line[j]
	if c >= 0x80 || c == '@' || isAlnum(c) || c == '_' || c == '%' || strings.IndexByte(more, c) >= 0 {
		return false
	}
	return !(c == '.' && j+1 < len(line) && isAlnum(line[j+1]))
}

// noDotAfter reports whether no "." and word follow line[j:]. It skips spaces
// and TABs, and at most one line break with the spaces and TABs that start
// next. A "." before a letter or a digit then fails.
func noDotAfter(line string, j int, next string) bool {
	rest := strings.TrimLeft(line[j:], " \t")
	if rest == "" {
		rest = strings.TrimLeft(next, " \t")
	}
	return !(len(rest) >= 2 && rest[0] == '.' && isAlnum(rest[1]))
}

// maintainerAt reports whether the "@" at line[i] is inside the maintainer
// address and the address is whole.
func maintainerAt(line string, i int) bool {
	start := i - strings.IndexByte(maintainerAddr, '@')
	end := start + len(maintainerAddr)
	if start < 0 || end > len(line) || !asciiEqualFold(line[start:end], maintainerAddr) {
		return false
	}
	return (start == 0 || !isLocal(line[start-1])) && wordEnd(line, end, "+-")
}

// claudeAt reports whether the line is a Claude co-author line with one "@".
func claudeAt(line string) bool {
	const key, tail = "Co-authored-by:", "<" + claudeAddr + ">"
	if len(line) < len(key) || !asciiEqualFold(line[:len(key)], key) || strings.Count(line, "@") != 1 {
		return false
	}
	value := line[len(key):]
	return len(value) >= len(tail) && asciiEqualFold(value[len(value)-len(tail):], tail) && claudeName(value)
}

// mentions lists the only names that a mention can have.
var mentions = []string{"context", "dependabot", "cybagard"}

// mentionAt reports whether the "@" at line[i] starts a mention. The name is
// on the list mentions, without case.
func mentionAt(line string, i int, next string) bool {
	if i > 0 && isLocal(line[i-1]) {
		return false
	}
	j := i + 1
	for j < len(line) && (isAlnum(line[j]) || line[j] == '-') {
		j++
	}
	listed := false
	for _, name := range mentions {
		listed = listed || asciiEqualFold(line[i+1:j], name)
	}
	return listed && wordEnd(line, j, "") && noDotAfter(line, j, next)
}

// skipDigits returns the index of the first byte at or after j that is not an
// ASCII digit.
func skipDigits(line string, j int) int {
	for j < len(line) && line[j] >= '0' && line[j] <= '9' {
		j++
	}
	return j
}

// versionAt reports whether the "@" at line[i] comes before a version such as
// v1.2.3 or v1.2.3-rc.1. The last "."-part of a pre-release text is not two or
// more letters only.
func versionAt(line string, i int, next string) bool {
	if i == 0 || !(isAlnum(line[i-1]) || strings.IndexByte("._/-", line[i-1]) >= 0) {
		return false
	}
	j := i + 1
	if j >= len(line) || line[j] != 'v' {
		return false
	}
	j++
	if skipDigits(line, j) == j {
		return false
	}
	j = skipDigits(line, j)
	for j+1 < len(line) && line[j] == '.' && line[j+1] >= '0' && line[j+1] <= '9' {
		j = skipDigits(line, j+1)
	}
	if j < len(line) && line[j] == '-' {
		j++
		start := j
		for j < len(line) && (isAlnum(line[j]) || line[j] == '.' && j+1 < len(line) && isAlnum(line[j+1])) {
			j++
		}
		text := line[start:j]
		if text == "" || !isAlnum(text[0]) {
			return false
		}
		last := text[strings.LastIndexByte(text, '.')+1:]
		letters := true
		for k := 0; k < len(last); k++ {
			letters = letters && !(last[k] >= '0' && last[k] <= '9')
		}
		if len(last) >= 2 && letters {
			return false
		}
	}
	return wordEnd(line, j, "+-") && noDotAfter(line, j, next)
}

// asciiEqualFold reports whether two strings are equal without case. It
// compares addresses and trailer keys. Only ASCII letters fold. A string with
// a byte of 0x80 or more never matches.
func asciiEqualFold(a, b string) bool {
	for _, s := range []string{a, b} {
		for i := 0; i < len(s); i++ {
			if s[i] >= 0x80 {
				return false
			}
		}
	}
	return strings.EqualFold(a, b)
}

// claudeName reports whether the name before the "<" of a trailer value is
// "Claude" or starts with "Claude ".
func claudeName(value string) bool {
	name, _, ok := strings.Cut(value, "<")
	name = strings.TrimSpace(name)
	return ok && (name == "Claude" || strings.HasPrefix(name, "Claude "))
}
