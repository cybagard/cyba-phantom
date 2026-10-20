package bundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

// listing is what one tar reader lists for an archive: one line "<type> <size>
// <name>" for each entry. The type is f for a regular file and d for a
// directory. Another type byte stays as the reader gives it. A directory name
// loses one trailing slash. The readers only list; none of them extracts a
// file. A reader output that does not parse sets failed.
type listing struct {
	lines  []string
	failed bool
}

func (l listing) String() string {
	s := strings.Join(l.lines, "; ")
	if len(s) > 300 {
		s = s[:300] + "..."
	}
	if l.failed {
		s += " [the reader failed]"
	}
	return s
}

func line(kind byte, size int64, name string) string {
	if kind == 'd' {
		name = strings.TrimSuffix(name, "/")
	}
	return fmt.Sprintf("%c %d %s", kind, size, name)
}

func goListing(raw []byte) listing {
	var l listing
	tr := tar.NewReader(bytes.NewReader(raw))
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return l
		}
		if err != nil {
			l.failed = true
			return l
		}
		kind := byte(hdr.Typeflag)
		if kind == tar.TypeReg || kind == tar.TypeRegA {
			kind = 'f'
		} else if kind == tar.TypeDir {
			kind = 'd'
		}
		l.lines = append(l.lines, line(kind, hdr.Size, hdr.Name))
	}
}

// gnuRow splits a line of tar -tv: the mode, the owner, the size, the date and
// the name. The date is a number when the time is out of range. Else it is a
// day and a time.
var gnuRow = regexp.MustCompile(`^(.)\S*\s+\S+\s+(\d+)\s+(?:@?-?\d+|\S+ \S+) (.*)$`)

// parseGNURow returns the type, the size and the name of a line of tar -tv.
func parseGNURow(s string) (kind byte, size int64, name string, ok bool) {
	m := gnuRow.FindStringSubmatch(s)
	if m == nil {
		return 0, 0, "", false
	}
	size, err := strconv.ParseInt(m[2], 10, 64)
	if err != nil {
		return 0, 0, "", false
	}
	kind = m[1][0]
	if kind == '-' {
		kind = 'f'
	}
	return kind, size, m[3], true
}

func gnuListing(path string) listing {
	out, err := exec.Command("tar", "-tvf", path).Output()
	l := listing{failed: err != nil}
	for _, s := range strings.Split(strings.TrimSuffix(string(out), "\n"), "\n") {
		if s == "" {
			continue
		}
		kind, size, name, ok := parseGNURow(s)
		if !ok {
			l.failed = true
			l.lines = append(l.lines, "? "+s)
			continue
		}
		l.lines = append(l.lines, line(kind, size, name))
	}
	return l
}

// pythonList prints one JSON array [type, size, name] for each entry. The
// output is ASCII, so a name with a newline stays on one line.
const pythonList = `
import json, sys, tarfile
try:
    with tarfile.open(sys.argv[1], "r:") as t:
        for m in t.getmembers():
            k = {b"0": "f", b"\0": "f", b"5": "d"}.get(m.type, m.type.decode("latin1"))
            print(json.dumps([k, m.size, m.name]))
except Exception:
    print("ERROR")
`

// parsePythonLine returns the type, the size and the name of one line of
// pythonList.
func parsePythonLine(s string) (kind byte, size int64, name string, ok bool) {
	var v []json.RawMessage
	var k string
	if json.Unmarshal([]byte(s), &v) != nil || len(v) != 3 ||
		json.Unmarshal(v[0], &k) != nil || json.Unmarshal(v[1], &size) != nil || json.Unmarshal(v[2], &name) != nil {
		return 0, 0, "", false
	}
	r, n := utf8.DecodeRuneInString(k)
	if n == 0 || n != len(k) || r > 0xff {
		return 0, 0, "", false
	}
	return byte(r), size, name, true
}

func pythonListing(path string) listing {
	out, err := exec.Command("python3", "-I", "-c", pythonList, path).Output()
	l := listing{failed: err != nil}
	for _, s := range strings.Split(strings.TrimSuffix(string(out), "\n"), "\n") {
		if s == "" {
			continue
		}
		kind, size, name, ok := parsePythonLine(s)
		if !ok {
			l.failed = true
			if s != "ERROR" {
				l.lines = append(l.lines, "? "+s)
			}
			continue
		}
		l.lines = append(l.lines, line(kind, size, name))
	}
	return l
}

// oracleTool is a tool of the oracle and the first line of its --version
// output. The line is equal to want. When prefix is set, the line only starts
// with want.
type oracleTool struct {
	bin, want string
	prefix    bool
}

var (
	tarTool    = oracleTool{"tar", "tar (GNU tar) 1.35", false}
	pythonTool = oracleTool{"python3", "Python 3.13.", true}
)

func (o oracleTool) matches(found string) bool {
	if o.prefix {
		return strings.HasPrefix(found, o.want)
	}
	return found == o.want
}

// requireOracleTools checks the versions of GNU tar and Python. Outside the
// devcontainer and CI, a missing tool or another version skips the test, with
// the reason. In the devcontainer (IN_DEVCONTAINER=1) and in CI (CI=true), it
// fails the test.
func requireOracleTools(t *testing.T) {
	t.Helper()
	for _, tool := range []oracleTool{tarTool, pythonTool} {
		switch decision, msg := checkTool(os.Getenv, exec.LookPath, tool); decision {
		case "fail":
			t.Fatal(msg)
		case "skip":
			t.Skip(msg)
		default:
			t.Log(msg)
		}
	}
}

// checkTool reads the environment with getenv, finds the tool with lookPath
// and reads the first line of its --version output. It returns the decision of
// toolDecision and a message. The message of a skip or a fail holds the reason
// and the version found. The message of a run names the version found.
func checkTool(getenv func(string) string, lookPath func(string) (string, error), tool oracleTool) (decision, msg string) {
	found := "not found"
	if path, err := lookPath(tool.bin); err == nil {
		out, err := exec.Command(path, "--version").Output()
		found, _, _ = strings.Cut(string(out), "\n")
		if err != nil {
			found = "no version line"
		}
	}
	strict := strictEnv(getenv("IN_DEVCONTAINER"), getenv("CI"))
	decision = toolDecision(strict, tool, found)
	if decision == "run" {
		return decision, fmt.Sprintf("%s: %s", tool.bin, found)
	}
	return decision, fmt.Sprintf("%s: version %q; the oracle needs %q", tool.bin, found, tool.want)
}

// strictEnv reports whether a missing tool must fail the test: the values of
// IN_DEVCONTAINER and CI are "1" and "true".
func strictEnv(inDevcontainer, ci string) bool { return inDevcontainer == "1" || ci == "true" }

// toolDecision returns "run" when the version found matches the tool, else
// "fail" when strict, else "skip".
func toolDecision(strict bool, tool oracleTool, found string) string {
	switch {
	case tool.matches(found):
		return "run"
	case strict:
		return "fail"
	}
	return "skip"
}

// fakeTools makes one executable script for each bin of scripts, in a
// temporary directory. A script prints its text (for printf). fakeTools
// returns a lookPath function that finds these scripts only.
func fakeTools(t *testing.T, scripts map[string]string) func(string) (string, error) {
	t.Helper()
	dir := t.TempDir()
	for bin, text := range scripts {
		if err := os.WriteFile(filepath.Join(dir, bin), []byte("#!/bin/sh\nprintf '"+text+"'\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return func(bin string) (string, error) {
		if _, ok := scripts[bin]; !ok {
			return "", exec.ErrNotFound
		}
		return filepath.Join(dir, bin), nil
	}
}

// T-S-19: checkTool reads the environment, finds the tool, cuts the first
// line of the --version output, and makes the message with the reason and the
// version found.
func TestTS19CheckTool(t *testing.T) {
	env := func(kv ...string) func(string) string {
		return func(k string) string {
			for i := 0; i+1 < len(kv); i += 2 {
				if kv[i] == k {
					return kv[i+1]
				}
			}
			return ""
		}
	}
	py312 := fakeTools(t, map[string]string{"python3": `Python 3.12.3\n`})
	py313 := fakeTools(t, map[string]string{"python3": `Python 3.13.5\nsecond line\n`})
	tar1350 := fakeTools(t, map[string]string{"tar": `tar (GNU tar) 1.350\n`})
	none := fakeTools(t, nil)
	for _, c := range []struct {
		name     string
		getenv   func(string) string
		lookPath func(string) (string, error)
		tool     oracleTool
		decision string
		want     []string
	}{
		{"wrong version outside", env(), py312, pythonTool, "skip", []string{`"Python 3.12.3"`, `"Python 3.13."`}},
		{"wrong version in the devcontainer", env("IN_DEVCONTAINER", "1"), py312, pythonTool, "fail", []string{`"Python 3.12.3"`, `"Python 3.13."`}},
		{"wrong version in CI", env("CI", "true"), py312, pythonTool, "fail", []string{`"Python 3.12.3"`}},
		{"missing tool outside", env("IN_DEVCONTAINER", "0", "CI", "false"), none, pythonTool, "skip", []string{`"not found"`, `"Python 3.13."`}},
		{"missing tool in CI", env("CI", "true"), none, tarTool, "fail", []string{`"not found"`, `"tar (GNU tar) 1.35"`}},
		{"right version, first line only", env(), py313, pythonTool, "run", []string{"python3: Python 3.13.5"}},
		{"tar version with more digits", env(), tar1350, tarTool, "skip", []string{`"tar (GNU tar) 1.350"`}},
	} {
		decision, msg := checkTool(c.getenv, c.lookPath, c.tool)
		if decision != c.decision {
			t.Errorf("%s: decision %q; want %q (message %q)", c.name, decision, c.decision, msg)
		}
		for _, w := range c.want {
			if !strings.Contains(msg, w) {
				t.Errorf("%s: message %q does not hold %s", c.name, msg, w)
			}
		}
		if c.decision == "run" && strings.Contains(msg, "second line") {
			t.Errorf("%s: message %q holds more than the first line", c.name, msg)
		}
	}
}

// T-S-19: the parsers of the reader output give the type, the size and the
// name, and refuse a line that has another form. A name with a newline stays
// one entry.
func TestTS19OracleParsers(t *testing.T) {
	for _, c := range []struct {
		s    string
		kind byte
		size int64
		name string
		ok   bool
	}{
		{"-rw-r--r-- 0/0               1 1970-01-01 00:00 traps/a", 'f', 1, "traps/a", true},
		{"drwxr-xr-x 0/0               0 1970-01-01 00:00 traps/d/", 'd', 0, "traps/d/", true},
		{"-rw-r--r-- 0/0               1 9223372036854775807 traps/a b", 'f', 1, "traps/a b", true},
		{"-rw-r--r-- 0/0               1 -9223372036854775808 traps/a", 'f', 1, "traps/a", true},
		{"crw-r--r-- 0/0             0,0 1970-01-01 00:00 traps/a", 0, 0, "", false},
		{"", 0, 0, "", false},
		{"no spaces", 0, 0, "", false},
	} {
		kind, size, name, ok := parseGNURow(c.s)
		if kind != c.kind || size != c.size || name != c.name || ok != c.ok {
			t.Errorf("GNU %q: %c %d %q %v; want %c %d %q %v", c.s, kind, size, name, ok, c.kind, c.size, c.name, c.ok)
		}
	}
	for _, c := range []struct {
		s    string
		kind byte
		size int64
		name string
		ok   bool
	}{
		{`["f", 1, "traps/a"]`, 'f', 1, "traps/a", true},
		{`["f", 1, "traps/x\nf 1 traps/y"]`, 'f', 1, "traps/x\nf 1 traps/y", true},
		{`["é", 0, "traps/a"]`, 0xe9, 0, "traps/a", true},
		{`["f", 1]`, 0, 0, "", false},
		{`["f", 1.5, "traps/a"]`, 0, 0, "", false},
		{`["ff", 1, "traps/a"]`, 0, 0, "", false},
		{`["", 1, "traps/a"]`, 0, 0, "", false},
		{`[1, 1, "traps/a"]`, 0, 0, "", false},
		{`f 1 traps/a`, 0, 0, "", false},
		{`ERROR`, 0, 0, "", false},
		{``, 0, 0, "", false},
	} {
		kind, size, name, ok := parsePythonLine(c.s)
		if kind != c.kind || size != c.size || name != c.name || ok != c.ok {
			t.Errorf("Python %q: %c %d %q %v; want %c %d %q %v", c.s, kind, size, name, ok, c.kind, c.size, c.name, c.ok)
		}
	}
}

// T-S-19: the oracle test runs with the right versions, skips outside the
// devcontainer and CI, and fails inside them. The version of GNU tar must be
// equal to the line, and the version of Python must start with it.
func TestTS19OracleToolDecision(t *testing.T) {
	for _, c := range []struct {
		tool                 oracleTool
		dev, ci, found, want string
	}{
		{tarTool, "", "", "tar (GNU tar) 1.35", "run"},
		{tarTool, "", "", "tar (GNU tar) 1.350", "skip"},
		{tarTool, "1", "", "tar (GNU tar) 1.350", "fail"},
		{tarTool, "", "true", "tar (GNU tar) 1.36", "fail"},
		{tarTool, "", "", "tar (GNU tar) 1.3", "skip"},
		{pythonTool, "", "", "Python 3.13.5", "run"},
		{pythonTool, "1", "true", "Python 3.13.5", "run"},
		{pythonTool, "", "", "Python 3.12.3", "skip"},
		{pythonTool, "", "", "not found", "skip"},
		{pythonTool, "0", "false", "not found", "skip"},
		{pythonTool, "yes", "1", "Python 3.12.3", "skip"},
		{pythonTool, "1", "", "Python 3.12.3", "fail"},
		{pythonTool, "1", "", "not found", "fail"},
		{pythonTool, "", "true", "Python 3.12.3", "fail"},
		{pythonTool, "", "true", "not found", "fail"},
		{pythonTool, "1", "true", "not found", "fail"},
	} {
		got := toolDecision(strictEnv(c.dev, c.ci), c.tool, c.found)
		if got != c.want {
			t.Errorf("%s, IN_DEVCONTAINER=%q CI=%q found %q: %s; want %s", c.tool.bin, c.dev, c.ci, c.found, got, c.want)
		}
	}
}

// oracle lists the archive gz with the three readers, in this order: Go, GNU
// tar and Python.
func oracle(t *testing.T, dir string, gzBytes []byte) [3]listing {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(gzBytes))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "archive.tar")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return [3]listing{goListing(raw), gnuListing(path), pythonListing(path)}
}

// differs reports whether one reader fails or two readers list other entries.
func differs(ls [3]listing) bool {
	for _, l := range ls[1:] {
		if l.failed != ls[0].failed || !slices.Equal(l.lines, ls[0].lines) {
			return true
		}
	}
	return false
}

// logListings logs the lists of the three readers. The lists are on one line
// when the readers list the same.
func logListings(t *testing.T, what, name string, ls [3]listing) {
	t.Helper()
	if !differs(ls) {
		t.Logf("%s %q\n  go, gnu, python: %v", what, name, ls[0])
		return
	}
	t.Logf("%s %q\n  go:     %v\n  gnu:    %v\n  python: %v", what, name, ls[0], ls[1], ls[2])
}

// differential marks each refused form of rawFormCases. The mark is true when
// the readers list other entries, or when one of them fails. The mark is false
// when the three readers list the same entries. The rule of such a form guards
// a reader outside the three.
var differential = map[string]bool{
	"type NUL regular file":                                                        false,
	"type NUL directory":                                                           false,
	"type NUL directory behind a PAX mtime record":                                 true,
	"type NUL directory behind a PAX path record":                                  true,
	"type NUL with a prefix and an empty name field":                               true,
	"chksum field with a leading NUL in the second entry":                          true,
	"chksum field with a leading NUL in a PAX header that is not the first header": true,
	"chksum field with a leading space":                                            false,
	"PAX mtime record with a plus sign":                                            true,
	"size field with a trailing space":                                             false,
	"size field with a leading NUL":                                                true,
	"size field of the PAX header with a leading NUL":                              true,
	"size field with a leading space":                                              false,
	"size field with a non-octal byte":                                             false,
	"size field in base-256 form":                                                  false,
	"PAX size record with a plus sign":                                             true,
	"size field with fewer digits":                                                 false,
	"PAX path in the padding of the PAX header":                                    true,
	"PAX path of the manifest in the padding of the PAX header":                    true,
	"PAX size in the padding of the PAX header":                                    true,
	"PAX header with a repeated key in one block":                                  false,
	"PAX record length with a leading zero in one block":                           false,
	"PAX path record with an empty value":                                          true,
	"PAX mtime record with an empty value":                                         true,
	"PAX size record with an empty value":                                          true,
	"PAX size record and ustar size field that differ":                             false,
	"PAX size record with a leading zero":                                          false,
	"PAX path over the ustar name ../x":                                            false,
	"PAX path that starts the ustar name":                                          false,
	"PAX path with a ustar prefix":                                                 false,
	"PAX path over 100 bytes with another ustar name":                              false,
	"long name with a cut that ends in a slash and a file":                         false,
	"long name with a cut that differs from a file only in case":                   false,
	"long name with the cut of another file":                                       false,
	"long name with a cut that ends in a slash and a directory":                    false,
	"no end blocks": false,
	"one end block": false,
}

// T-S-19: for each archive that ReadArchive accepts, the three readers list
// the same entries, and the regular files are the names and sizes of
// ReadArchive. For each refused form marked as differential, the readers list
// other entries or one fails.
func TestTS19ReaderOracle(t *testing.T) {
	requireOracleTools(t)
	dir := t.TempDir()
	_, pass := fixtures()
	for _, f := range pass {
		a, err := ReadArchive(f.b)
		if err != nil {
			t.Errorf("%s: %v", f.name, err)
			continue
		}
		ls := oracle(t, dir, f.b)
		logListings(t, "accepted", f.name, ls)
		var want, got []string
		for _, name := range a.Names() {
			b, _ := a.File(name)
			want = append(want, line('f', int64(len(b)), name))
		}
		for _, s := range ls[0].lines {
			if s[0] == 'f' {
				got = append(got, s)
			} else if s[0] != 'd' {
				t.Errorf("%s: Go lists the type %q", f.name, s[:1])
			}
		}
		slices.Sort(want)
		slices.Sort(got)
		if differs(ls) || ls[0].failed || !slices.Equal(got, want) {
			t.Errorf("%s: the readers list other entries than ReadArchive %q", f.name, want)
		}
	}
	marked := 0
	for _, c := range entryCases() {
		if a, err := ReadArchive(c.bad); a != nil || err != ErrArchiveInvalid {
			t.Errorf("%s: archive %v, error %v", c.name, a != nil, err)
		}
		ls := oracle(t, dir, c.bad)
		want, ok := differential[c.name]
		mark := "not marked"
		if ok {
			mark = fmt.Sprintf("marked differential %v", want)
		}
		logListings(t, "refused, "+mark+",", c.name, ls)
		if ok {
			marked++
			if got := differs(ls); got != want {
				t.Errorf("%s: readers differ %v; marked differential %v", c.name, got, want)
			}
		}
	}
	for _, c := range rawFormCases() {
		if _, ok := differential[c.name]; !ok {
			t.Errorf("%s: not marked", c.name)
		}
	}
	if marked != len(differential) {
		t.Errorf("%d marks name a form that does not exist; %d marks", len(differential)-marked, len(differential))
	}
}
