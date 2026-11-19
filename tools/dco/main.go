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
//
// In a trailer, an address is any token of the form x@y with no space, "<"
// or ">". dco skips a trailer without an address. A Signed-off-by trailer
// without an address fails.
//
// dco also checks the whole commit message: subject, body, every paragraph
// and every line. It reads the message from the commit object, so the bytes
// after a NUL byte count too. An address in the message is the maintainer
// address. The Claude address is also allowed, on one line that is a
// Co-authored-by line for Claude by the rules above. Any other address fails
// the commit.
//
// In the message, an address has a local part, an at-sign and a domain.
//   - The local part has letters, digits and the marks . _ % + and -.
//   - The domain has two or more labels of letters, digits and "-". The
//     last label has two or more letters and no digit.
//   - The at-sign is "@", the fullwidth at-sign U+FF20 or the small at-sign
//     U+FE6B.
//   - A letter is any Unicode letter, so a non-ASCII domain is an address.
//   - A dot between labels is ".", U+3002, U+FF0E or U+FF61.
//
// A word such as actions/checkout@v5.1.0, @dependabot or user:pw@tcp(host)/db
// is not an address. It has no local part, or no dotted domain that ends in
// letters. The pattern does not match an address with no dot in the domain.
// It does not match one with a byte that is not valid UTF-8 either.
//
// A commit with a non-empty encoding header fails, whatever its value. An
// empty value gives an empty %e, the same as no header, and dco does not fail
// it. dco reports such a commit as an identity failure ("identity: <hash>"),
// with its own hint.
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

// msgAddrRE finds each address in the free text of a commit message. It is
// narrower than addrRE: a version string or a mention is not an address.
// \p{M} keeps a combining mark inside the domain.
var msgAddrRE = regexp.MustCompile(`[\p{L}\p{M}\p{N}._%+-]+[@\x{FF20}\x{FE6B}](?:[\p{L}\p{M}\p{N}-]+[.\x{3002}\x{FF0E}\x{FF61}])+\p{L}{2,}`)

// logFormat asks git for the hash, author address, committer address,
// encoding header and trailers of each commit. Git's own trailer parser
// decides what a trailer is. The option `only` drops the lines of the
// trailer block that are not trailers. Because git parses the trailers, dco
// accepts only the sign-offs that git recognizes as trailers.
const logFormat = "--format=%H%x00%ae%x00%ce%x00%e%x00%(trailers:only,unfold,separator=%x0a)%x00"

func main() { os.Exit(run(os.Args[1:], ".", os.Stdout, os.Stderr)) }

// run checks the sign-off and identity of every commit in base..head of
// the repository in dir.
func run(args []string, dir string, stdout, stderr io.Writer) int {
	if len(args) != 2 {
		fmt.Fprintln(stderr, "usage: dco <base> <head>")
		return 2
	}
	base, head := args[0], args[1]

	cmd := exec.Command("git", "-C", dir, "log", logFormat, base+".."+head)
	out, err := cmd.Output()
	if err != nil {
		// dco does not print the stderr of git.
		fmt.Fprintf(stderr, "dco: git log %s..%s failed: %v\n", base, head, err)
		return 2
	}
	// git log stops a message at a NUL byte, so dco reads the message from
	// the object. A malformed record gives no hash here, and check reports it.
	var hashes []string
	for _, rec := range splitRecords(out) {
		if h, _, _ := bytes.Cut(rec, []byte{0}); hashRE.Match(h) {
			hashes = append(hashes, string(h))
		}
	}
	msgs, err := rawMessages(dir, hashes)
	if err != nil {
		fmt.Fprintf(stderr, "dco: git cat-file failed: %v\n", err)
		return 2
	}
	return check(out, msgs, base, head, stdout, stderr)
}

// hashRE matches the full hash that %H prints.
var hashRE = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)

// rawMessages returns the message of each commit as stored in the object,
// keyed by full hash. The message starts after the first blank line of the
// object. A NUL byte and the bytes after it stay in the message.
func rawMessages(dir string, hashes []string) (map[string][]byte, error) {
	msgs := make(map[string][]byte, len(hashes))
	if len(hashes) == 0 {
		return msgs, nil
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
// object is a header line "<hash> commit <size>", the object and one LF.
func parseBatch(out []byte, n int) (map[string][]byte, error) {
	msgs := make(map[string][]byte, n)
	for range n {
		line, rest, ok := bytes.Cut(out, []byte{'\n'})
		f := strings.Fields(string(line))
		if !ok || len(f) != 3 || f[1] != "commit" {
			return nil, errors.New("unexpected output")
		}
		size, err := strconv.Atoi(f[2])
		if err != nil || size < 0 || len(rest) < size+1 {
			return nil, errors.New("unexpected output")
		}
		// The object is followed by one LF.
		_, msg, _ := bytes.Cut(rest[:size], []byte("\n\n"))
		msgs[f[0]] = msg
		out = rest[size+1:]
	}
	return msgs, nil
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

// check parses the output of git log and applies the rules to each commit.
// msgs holds the raw message of each commit, keyed by full hash.
func check(out []byte, msgs map[string][]byte, base, head string, stdout, stderr io.Writer) int {
	// Each record is H NUL AE NUL CE NUL E NUL TRAILERS NUL. Git ends every
	// record with its own newline, so records separate on NUL+LF. Git joins
	// the trailers with LF. An unfolded trailer holds no LF and no NUL. The
	// checker prints no PR-authored text, only hashes and counts.
	records := splitRecords(out)
	total, unsigned, badID, badEnc, badAddr := 0, 0, 0, 0, 0
	for _, rec := range records {
		f := bytes.SplitN(rec, []byte{0}, 5)
		if len(f) < 5 {
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
		trailers := strings.Split(string(f[4]), "\n")
		if !hasSignoff(trailers) {
			unsigned++
			fmt.Fprintf(stdout, "unsigned: %s\n", hash)
		}
		encoded := len(f[3]) > 0
		wrongAddr := !identityOK(string(f[1]), string(f[2]), trailers) || !messageOK(msgs[full])
		if encoded || wrongAddr {
			badID++
			fmt.Fprintf(stdout, "identity: %s\n", hash)
		}
		if encoded {
			badEnc++
		}
		if wrongAddr {
			badAddr++
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
		if badAddr > 0 {
			fmt.Fprintln(stdout, "hint: only a commit with the identity of the maintainer passes this check. Maintainer: see the header of tools/dco/main.go for the rule. Outside contribution: see CONTRIBUTING.md.")
		}
		if badEnc > 0 {
			fmt.Fprintln(stdout, "hint: commits must not set an encoding header")
		}
		return 1
	}
	fmt.Fprintf(stdout, "dco: all %d commits in %s..%s carry Signed-off-by and pass the identity rule\n", total, base, head)
	return 0
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

// messageOK applies the address rule to every line of a commit message.
func messageOK(msg []byte) bool {
	for _, line := range strings.Split(string(msg), "\n") {
		addrs := msgAddrRE.FindAllString(line, -1)
		for _, a := range addrs {
			if asciiEqualFold(a, maintainerAddr) {
				continue
			}
			if asciiEqualFold(a, claudeAddr) && len(addrs) == 1 && claudeLine(line) {
				continue
			}
			return false
		}
	}
	return true
}

// claudeLine reports whether a line is a Co-authored-by line for Claude.
func claudeLine(line string) bool {
	key, value := splitTrailer(line)
	return asciiEqualFold(key, "Co-authored-by") && claudeName(value)
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
