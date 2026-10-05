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
)

// signoffRE matches a DCO trailer line: "Signed-off-by: Name <address>",
// where address has a local part, an @, and a dotted domain.
var signoffRE = regexp.MustCompile(`(?m)^Signed-off-by: \S.* <[^<>\s]+@[^<>\s]+\.[^<>\s]+>\s*$`)

func main() { os.Exit(run(os.Args[1:], ".")) }

// run checks that every commit in base..head of the repository in dir
// carries a sign-off trailer.
func run(args []string, dir string) int {
	if len(args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: dco <base> <head>")
		return 2
	}
	base, head := args[0], args[1]

	cmd := exec.Command("git", "-C", dir, "log", "--format=%H%x00%P%x00%s%x00%B%x00", base+".."+head)
	out, err := cmd.CombinedOutput()
	if err != nil {
		o := string(out)
		if len(o) > 512 {
			o = o[:512] + "…"
		}
		fmt.Fprintf(os.Stderr, "dco: git log %s..%s: %v\n%s", base, head, err, o)
		return 2
	}

	// Each record is H NUL P NUL S NUL B, and git terminates every record
	// with the format's final NUL plus its own record newline, so records
	// separate on NUL+LF. %B (the full body) may contain newlines but
	// never NUL, so splitting each record into four fields is safe.
	records := bytes.Split(out, []byte{0, '\n'})
	if last := len(records) - 1; last >= 0 && len(records[last]) == 0 {
		records = records[:last]
	}
	total, unsigned := 0, 0
	for _, rec := range records {
		f := bytes.SplitN(rec, []byte{0}, 4)
		if len(f) < 4 {
			continue
		}
		// f[2] is the commit subject — PR-authored content, never
		// printed: a planted instruction in a subject would reach any
		// agent reading the CI log.
		hash, body := string(f[0]), string(f[3])
		total++
		if !signoffRE.MatchString(body) {
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
