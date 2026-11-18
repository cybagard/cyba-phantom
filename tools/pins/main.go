// Command pins checks that the copies of the Go version and of the build
// image agree. It uses only the standard library.
//
// Usage:
//
//	pins
//
// Run it in the repository root. It reads four files. In each file, a word
// line is a line that holds a key word. A comment line is not a word line.
// Each word line must be equal to one allowed line of that file. Each
// allowed line must be in the file once. Any other word line is a failure.
//
// The files, the key words, and the allowed lines are:
//   - go.mod: the first field is "go" or "toolchain". The allowed lines are
//     "go <v>" and "toolchain go<v>". The toolchain line is optional.
//   - Makefile: the text GOTOOLCHAIN. The allowed lines are
//     "GOTOOLCHAIN := go<v>" and "export GOTOOLCHAIN". A comment line that
//     ends in a backslash is a failure. Make joins the next line to it.
//   - .github/workflows/ci.yml: GOTOOLCHAIN, "image" in any case,
//     "container", and "docker://". The allowed lines are the top-level key
//     "  GOTOOLCHAIN: go<v>", "container:", and "image: <image>".
//   - .devcontainer/Dockerfile: the first field is FROM in any case, or the
//     text GOTOOLCHAIN. The allowed line is
//     "FROM golang:<v>@sha256:<64 hex digits>".
//
// The version in go.mod, in the Makefile, in ci.yml and in the Dockerfile
// tag must be the same. The image string of the FROM line must be the same
// as the image string of ci.yml.
//
// The check fails closed. A missing file is a failure. A missing allowed
// line is a failure. A second allowed line is a failure. A word line of
// another form is a failure. A missing toolchain line is not a failure.
// The tool prints one line for each
// failure. It exits 1 when there is a failure, and 0 when there is none.
//
// This is a drift check, not a gate. The command make lint runs it from the
// tree of the change. A change can edit the tool and the check together.
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

// allowed is one line that a word line may be. The line must be in the file
// once, or at most once when optional is set. The groups of re hold the
// values that check compares.
type allowed struct {
	what     string
	re       *regexp.Regexp
	optional bool
}

// rule is the allow list of one file. A line that starts with the comment
// text, after spaces and tabs, is a comment line. With joins set, a
// comment line that ends in a backslash fails.
type rule struct {
	comment string
	joins   bool
	word    func(line string) bool
	allowed []allowed
}

// The indexes of the allowed lines in each rule, and of the groups that
// check compares.
const (
	goLine, toolchainLine = 0, 1
	makeAssign            = 0
	ciEnv, ciImage        = 0, 2
	dockerFrom            = 0

	versionGroup     = 1
	imageGroup       = 1
	fromVersionGroup = 2
)

func hasWord(words ...string) func(string) bool {
	return func(l string) bool {
		for _, w := range words {
			if strings.Contains(l, w) {
				return true
			}
		}
		return false
	}
}

func firstField(l string) string {
	if f := strings.Fields(l); len(f) > 0 {
		return f[0]
	}
	return ""
}

var rules = map[string]rule{
	goModFile: {comment: "//",
		word: func(l string) bool {
			f := firstField(l)
			return f == "go" || f == "toolchain"
		},
		allowed: []allowed{
			{"go", regexp.MustCompile(`^go (` + versionRE + `)$`), false},
			{"toolchain", regexp.MustCompile(`^toolchain go(` + versionRE + `)$`), true},
		}},
	makeFile: {comment: "#", joins: true,
		word: hasWord("GOTOOLCHAIN"),
		allowed: []allowed{
			{"GOTOOLCHAIN assignment", regexp.MustCompile(`^GOTOOLCHAIN := go(` + versionRE + `)$`), false},
			{"export GOTOOLCHAIN", regexp.MustCompile(`^export GOTOOLCHAIN$`), false},
		}},
	ciFile: {comment: "#",
		word: func(l string) bool {
			return hasWord("GOTOOLCHAIN", "container", "docker://")(l) ||
				strings.Contains(strings.ToLower(l), "image")
		},
		allowed: []allowed{
			{"GOTOOLCHAIN", regexp.MustCompile(`^  GOTOOLCHAIN: go(` + versionRE + `)$`), false},
			{"container", regexp.MustCompile(`^ +container:$`), false},
			{"image", regexp.MustCompile(`^ +image: (\S+)$`), false},
		}},
	dockerFile: {comment: "#",
		word: func(l string) bool {
			return strings.EqualFold(firstField(l), "FROM") || strings.Contains(l, "GOTOOLCHAIN")
		},
		allowed: []allowed{
			{"FROM", regexp.MustCompile(`^FROM (golang:(` + versionRE + `)@` + digestRE + `)$`), false},
		}},
}

// source is a file after the read. Its lines are nil when the read failed.
type source struct {
	name  string
	lines []string
	ok    bool
}

// spot is the one line that audit found for an allowed line. The sub field
// holds the groups of the allowed line, and is nil when there is no such
// line. Item 0 is the whole line.
type spot struct {
	file string
	line int
	sub  []string
}

func (s spot) String() string { return fmt.Sprintf("%s:%d", s.file, s.line) }

func (s spot) found() bool { return s.sub != nil }

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
	goMod := audit(load(dir, goModFile, &fails), rules[goModFile], &fails)
	mk := audit(load(dir, makeFile, &fails), rules[makeFile], &fails)
	ci := audit(load(dir, ciFile, &fails), rules[ciFile], &fails)
	df := audit(load(dir, dockerFile, &fails), rules[dockerFile], &fails)

	goSpot := goMod[goLine]
	if goSpot.found() {
		sameVersion(&fails, goMod[toolchainLine], versionGroup, goSpot)
		sameVersion(&fails, mk[makeAssign], versionGroup, goSpot)
		sameVersion(&fails, ci[ciEnv], versionGroup, goSpot)
		sameVersion(&fails, df[dockerFrom], fromVersionGroup, goSpot)
	}
	from, image := df[dockerFrom], ci[ciImage]
	if from.found() && image.found() && from.sub[imageGroup] != image.sub[imageGroup] {
		fails = append(fails, fmt.Sprintf("%s: image %q is not the image %q of %s",
			image, image.sub[imageGroup], from.sub[imageGroup], from))
	}
	return fails
}

// sameVersion adds a failure when s is there and its version is not the
// version of the go line. Group i of s holds the version.
func sameVersion(fails *[]string, s spot, i int, goSpot spot) {
	if s.found() && s.sub[i] != goSpot.sub[1] {
		*fails = append(*fails, fmt.Sprintf("%s: version %q is not version %q of %s",
			s, s.sub[i], goSpot.sub[1], goSpot))
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

// audit applies the rule to the lines of src. It returns one spot for each
// allowed line of the rule. A spot is empty when its line is missing, or
// when there are two or more. Each failure adds one text. A source that
// failed to load gives empty spots and no failure, because load reported it.
// A missing line is not reported when the file has a word line of another
// form. That line is the failure.
func audit(src source, r rule, fails *[]string) []spot {
	spots := make([]spot, len(r.allowed))
	if !src.ok {
		return spots
	}
	hits := make([][]spot, len(r.allowed))
	other := false
	for i, l := range src.lines {
		n := i + 1
		if strings.HasPrefix(strings.TrimLeft(l, " \t"), r.comment) {
			if r.joins && strings.HasSuffix(l, `\`) {
				*fails = append(*fails, fmt.Sprintf("%s:%d: comment line %q ends in a backslash",
					src.name, n, l))
			}
			continue
		}
		if !r.word(l) {
			continue
		}
		match := false
		for j, a := range r.allowed {
			if sub := a.re.FindStringSubmatch(l); sub != nil {
				hits[j] = append(hits[j], spot{src.name, n, sub})
				match = true
				break
			}
		}
		if !match {
			other = true
			*fails = append(*fails, fmt.Sprintf("%s:%d: line %q is not an allowed line",
				src.name, n, l))
		}
	}
	for j, a := range r.allowed {
		switch {
		case len(hits[j]) == 0:
			if !a.optional && !other {
				*fails = append(*fails, fmt.Sprintf("%s: no %s line", src.name, a.what))
			}
		case len(hits[j]) > 1:
			lines := make([]int, len(hits[j]))
			for k, h := range hits[j] {
				lines[k] = h.line
			}
			*fails = append(*fails, fmt.Sprintf("%s:%d: %d %s lines (lines %v), one allowed",
				src.name, lines[1], len(lines), a.what, lines))
		default:
			spots[j] = hits[j][0]
		}
	}
	return spots
}
