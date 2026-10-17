// Command dco checks the Developer Certificate of Origin sign-off (DCO 1.1)
// and the commit identity. Every commit in base..head must carry a
// "Signed-off-by" trailer. Each commit uses only the permitted addresses
// (below).
//
// Usage:
//
//	dco <base> <head>
//
// Identity rule, for each commit. Addresses and trailer keys compare
// without case. The author and committer come from %ae and %ce, so no
// mailmap applies.
//   - The author address is the maintainer noreply address.
//   - The committer address is that address, or the GitHub committer
//     address. GitHub makes the commit for a web merge.
//   - Every Signed-off-by value has the maintainer address.
//   - Every address in any other trailer is the maintainer address. The
//     Claude co-author address is also permitted, in a Co-authored-by
//     trailer. The name in that trailer is "Claude" or starts with
//     "Claude ". That trailer holds exactly one address.
//
// An address is any token of the form x@y with no space, "<" or ">". A
// trailer without an address is not checked. A Signed-off-by trailer
// without an address fails.
//
// A commit with an encoding header fails, whatever its value. Git converts
// the message to UTF-8 from that header. The bytes of an address can then
// come out as other characters, and dco would see no address.
//
// It runs git (the toolchain image ships it). It prints short commit
// hashes and counts only. It never prints an address, a name, a subject or
// a trailer value. A PR author controls these, and a CI log shows them.
// Exit codes: 0 all commits pass (or an empty range), 1 a commit fails a
// check, 2 usage, git or log format error.
package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
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

// logFormat asks git for the hash, author address, committer address,
// encoding header and trailers of each commit. Git's own trailer parser decides what a trailer
// is. The option `only` drops the lines of the trailer block that are not
// trailers. So dco accepts exactly the sign-offs that git recognizes, for
// example the block that cherry-pick -x -s writes. It never accepts the
// subject or a line in the middle of the body.
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
		// git's own error text is not printed: print the exit status only.
		fmt.Fprintf(stderr, "dco: git log %s..%s failed: %v\n", base, head, err)
		return 2
	}
	return check(out, base, head, stdout, stderr)
}

// check parses the output of git log and applies both rules to each commit.
func check(out []byte, base, head string, stdout, stderr io.Writer) int {
	// Each record is H NUL AE NUL CE NUL E NUL TRAILERS NUL. Git ends every
	// record with its own newline, so records separate on NUL+LF. Trailers
	// are joined by LF. An unfolded trailer holds no LF and no NUL. The
	// checker prints no PR-authored text, only hashes and counts.
	records := bytes.Split(out, []byte{0, '\n'})
	if last := len(records) - 1; last >= 0 && len(records[last]) == 0 {
		records = records[:last]
	}
	total, unsigned, badID, badEnc, badAddr := 0, 0, 0, 0, 0
	for _, rec := range records {
		f := bytes.SplitN(rec, []byte{0}, 5)
		if len(f) < 5 {
			// The record is not printed: it is PR-authored content.
			fmt.Fprintln(stderr, "dco: malformed git log record")
			return 2
		}
		hash := string(f[0])
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
		wrongAddr := !identityOK(string(f[1]), string(f[2]), trailers)
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
			fmt.Fprintln(stdout, "hint: author, committer and trailer addresses must be the maintainer noreply address; a Claude co-author trailer may use the Claude co-author address (see tools/dco/main.go)")
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
