// Command dco checks Developer Certificate of Origin sign-off (DCO 1.1):
// every commit in base..head must carry a "Signed-off-by" trailer.
//
// Usage:
//
//	dco <base> <head>
//
// It shells out to git (the toolchain image ships it) and reports commit
// SHAs and counts only — never the (PR-authored) subject, which is
// untrusted content in a CI log. Exit codes: 0 all signed (or an
// empty range), 1 unsigned commits, 2 usage or git error.
package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

// signoffRE matches the value of one Signed-off-by trailer: "Name
// <address>", where address has a local part, an @, and a dotted domain.
var signoffRE = regexp.MustCompile(`^\S.* <[^<>\s]+@[^<>\s]+\.[^<>\s]+>$`)

// logFormat asks git for each commit's hash and the values of its
// Signed-off-by trailers. Git's own trailer parser decides what a trailer
// is, so dco accepts exactly the sign-offs that git recognizes (for
// example the block that cherry-pick -x -s writes), and never the subject
// or a line in the middle of the body.
const logFormat = "--format=%H%x00%(trailers:key=Signed-off-by,valueonly,unfold,separator=%x01)%x00"

func main() { os.Exit(run(os.Args[1:], ".")) }

// run checks that every commit in base..head of the repository in dir
// carries a sign-off trailer.
func run(args []string, dir string) int {
	if len(args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: dco <base> <head>")
		return 2
	}
	base, head := args[0], args[1]

	cmd := exec.Command("git", "-C", dir, "log", logFormat, base+".."+head)
	out, err := cmd.CombinedOutput()
	if err != nil {
		o := string(out)
		if len(o) > 512 {
			o = o[:512] + "…"
		}
		fmt.Fprintf(os.Stderr, "dco: git log %s..%s: %v\n%s", base, head, err, o)
		return 2
	}

	// Each record is H NUL TRAILERS NUL, and git ends every record with
	// its own newline, so records separate on NUL+LF. Trailer values are
	// joined by SOH (0x01) and never hold NUL. No PR-authored text is
	// printed: only hashes and counts.
	records := bytes.Split(out, []byte{0, '\n'})
	if last := len(records) - 1; last >= 0 && len(records[last]) == 0 {
		records = records[:last]
	}
	total, unsigned := 0, 0
	for _, rec := range records {
		f := bytes.SplitN(rec, []byte{0}, 2)
		if len(f) < 2 {
			continue
		}
		hash := string(f[0])
		total++
		if !hasSignoff(string(f[1])) {
			unsigned++
			if len(hash) > 12 {
				hash = hash[:12]
			}
			fmt.Printf("unsigned: %s\n", hash)
		}
	}

	switch {
	case total == 0:
		fmt.Println("dco: no commits in range — nothing to check")
		return 0
	case unsigned > 0:
		fmt.Printf("dco FAIL: %d of %d commits in %s..%s lack a Signed-off-by trailer (sign with `git commit -s`)\n",
			unsigned, total, base, head)
		return 1
	}
	fmt.Printf("dco: all %d commits in %s..%s carry Signed-off-by\n", total, base, head)
	return 0
}

// hasSignoff reports whether any SOH-separated trailer value is a valid
// "Name <address>" sign-off.
func hasSignoff(values string) bool {
	for _, v := range strings.Split(values, "\x01") {
		if signoffRE.MatchString(strings.TrimSpace(v)) {
			return true
		}
	}
	return false
}
