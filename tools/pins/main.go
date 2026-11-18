// Command pins checks that the copies of the Go version and of the build
// image agree. It uses only the standard library.
//
// Usage:
//
//	pins
//
// Run it in the repository root. It reads four files and finds one line in
// each place. The places are:
//   - go.mod: the "go" line, and the "toolchain" line when there is one.
//   - Makefile: the assignment of GOTOOLCHAIN.
//   - .github/workflows/ci.yml: the key GOTOOLCHAIN, and the key "image:".
//   - .devcontainer/Dockerfile: the FROM line.
//
// The version in go.mod, in the Makefile, in ci.yml and in the Dockerfile
// tag must be the same. The image string of the FROM line must be the same
// as the image string of ci.yml.
//
// The check fails closed. A missing file, a missing line, a second line, or
// a line of another form is a failure. The tool prints one line for each
// failure. It exits 1 when there is a failure, and 0 when there is none.
package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	goModFile  = "go.mod"
	makeFile   = "Makefile"
	ciFile     = ".github/workflows/ci.yml"
	dockerFile = ".devcontainer/Dockerfile"

	versionRE = `[0-9]+\.[0-9]+\.[0-9]+`
	digestRE  = `sha256:[0-9a-f]{64}`

	maxFileBytes = 1 << 20
)

// place is a kind of line that must be in a file exactly once. The target
// selects the lines that count. The form is the one valid text of such a
// line. The want text names that form in a failure message.
type place struct {
	what   string
	target *regexp.Regexp
	form   *regexp.Regexp
	want   string
}

var (
	goPlace = place{"go", regexp.MustCompile(`^go(\s|$)`),
		regexp.MustCompile(`^go (` + versionRE + `)$`), "go <x>.<y>.<z>"}
	toolchainPlace = place{"toolchain", regexp.MustCompile(`^toolchain(\s|$)`),
		regexp.MustCompile(`^toolchain go(` + versionRE + `)$`), "toolchain go<x>.<y>.<z>"}
	makePlace = place{"GOTOOLCHAIN assignment",
		regexp.MustCompile(`^ *((override|export) +)*GOTOOLCHAIN *[:?+!]*=`),
		regexp.MustCompile(`^GOTOOLCHAIN := go(` + versionRE + `)$`), "GOTOOLCHAIN := go<x>.<y>.<z>"}
	ciEnvPlace = place{"GOTOOLCHAIN", regexp.MustCompile(`^ *GOTOOLCHAIN *:`),
		regexp.MustCompile(`^ *GOTOOLCHAIN: go(` + versionRE + `)$`), "GOTOOLCHAIN: go<x>.<y>.<z>"}
	ciImagePlace = place{"image", regexp.MustCompile(`^ *image *:`),
		regexp.MustCompile(`^ *image: (\S+)$`), "image: <image>"}
	fromPlace = place{"FROM", regexp.MustCompile(`(?i)^ *FROM(\s|$)`),
		regexp.MustCompile(`^FROM (golang:(` + versionRE + `)@` + digestRE + `)$`),
		"FROM golang:<x>.<y>.<z>@sha256:<64 hex digits>"}
)

// source is a file after the read. Its lines are nil when the read failed.
type source struct {
	name  string
	lines []string
	ok    bool
}

// spot is the one line that find found. The sub field holds the groups of
// the form. Item 0 is the whole line.
type spot struct {
	file string
	line int
	sub  []string
}

func (s spot) String() string { return fmt.Sprintf("%s:%d", s.file, s.line) }

func main() { os.Exit(run(".", os.Stdout, os.Stderr)) }

// run checks the files below dir. It prints each failure to stderr and
// returns the exit status.
func run(dir string, stdout, stderr io.Writer) int {
	fails := check(dir)
	for _, f := range fails {
		fmt.Fprintln(stderr, f)
	}
	if len(fails) > 0 {
		return 1
	}
	fmt.Fprintln(stdout, "pins: the Go version and the image agree")
	return 0
}

// check returns one text for each failure. An empty result means the copies
// agree.
func check(dir string) []string {
	var fails []string
	goMod := load(dir, goModFile, &fails)
	mk := load(dir, makeFile, &fails)
	ci := load(dir, ciFile, &fails)
	df := load(dir, dockerFile, &fails)

	goLine, goOK := find(goMod, goPlace, false, &fails)
	tcLine, tcOK := find(goMod, toolchainPlace, true, &fails)
	mkLine, mkOK := find(mk, makePlace, false, &fails)
	ciLine, ciOK := find(ci, ciEnvPlace, false, &fails)
	imLine, imOK := find(ci, ciImagePlace, false, &fails)
	dfLine, dfOK := find(df, fromPlace, false, &fails)

	if goOK {
		if tcOK {
			sameVersion(&fails, tcLine, 1, goLine)
		}
		if mkOK {
			sameVersion(&fails, mkLine, 1, goLine)
		}
		if ciOK {
			sameVersion(&fails, ciLine, 1, goLine)
		}
		if dfOK {
			sameVersion(&fails, dfLine, 2, goLine)
		}
	}
	if dfOK && imOK && dfLine.sub[1] != imLine.sub[1] {
		fails = append(fails, fmt.Sprintf("%s: image %q is not the image %q of %s",
			imLine, imLine.sub[1], dfLine.sub[1], dfLine))
	}
	return fails
}

// sameVersion adds a failure when the version of s is not the version of
// the go line. Group i of s holds the version.
func sameVersion(fails *[]string, s spot, i int, goLine spot) {
	if s.sub[i] != goLine.sub[1] {
		*fails = append(*fails, fmt.Sprintf("%s: version %q is not version %q of %s",
			s, s.sub[i], goLine.sub[1], goLine))
	}
}

// load reads one file below dir and splits it into lines. A read failure
// adds one failure, and the source then has ok set to false.
func load(dir, name string, fails *[]string) source {
	data, err := readLimited(filepath.Join(dir, filepath.FromSlash(name)))
	if err != nil {
		*fails = append(*fails, fmt.Sprintf("%s: cannot read the file: %v", name, err))
		return source{name: name}
	}
	return source{name: name, lines: strings.Split(string(data), "\n"), ok: true}
}

// readLimited reads a file and fails when it is larger than maxFileBytes.
func readLimited(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxFileBytes {
		return nil, fmt.Errorf("the file is larger than %d bytes", maxFileBytes)
	}
	return data, nil
}

// find looks for the one line of src that the target of p selects. A comment
// line never counts. It returns false and adds a failure in three cases.
// The first case is no such line. The second is two or more lines. The
// third is a line that is not of the form of p. With optional set, a
// missing line is not a failure. A source that failed to load gives false
// and no failure, because load reported it.
func find(src source, p place, optional bool, fails *[]string) (spot, bool) {
	if !src.ok {
		return spot{}, false
	}
	var hits []int
	for i, l := range src.lines {
		if strings.HasPrefix(strings.TrimLeft(l, " \t"), "#") {
			continue
		}
		if p.target.MatchString(l) {
			hits = append(hits, i+1)
		}
	}
	switch {
	case len(hits) == 0:
		if !optional {
			*fails = append(*fails, fmt.Sprintf("%s: no %s line", src.name, p.what))
		}
		return spot{}, false
	case len(hits) > 1:
		*fails = append(*fails, fmt.Sprintf("%s:%d: %d %s lines (lines %v), one needed",
			src.name, hits[1], len(hits), p.what, hits))
		return spot{}, false
	}
	text := src.lines[hits[0]-1]
	sub := p.form.FindStringSubmatch(text)
	if sub == nil {
		*fails = append(*fails, fmt.Sprintf("%s:%d: %s line %q is not of the form %q",
			src.name, hits[0], p.what, text, p.want))
		return spot{}, false
	}
	return spot{file: src.name, line: hits[0], sub: sub}, true
}
