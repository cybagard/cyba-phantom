package bundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// listing is what one tar reader lists for an archive: one line "<type> <size>
// <name>" for each entry, where the type is f for a regular file and d for a
// directory. A directory name loses one trailing slash. The readers only list;
// none of them extracts a file.
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

// gnuRow splits a line of tar -tv: the mode, owner, size, date, time and name.
var gnuRow = regexp.MustCompile(`^(.)\S*\s+\S+\s+(\d+)\s+\S+\s+\S+ (.*)$`)

func gnuListing(path string) listing {
	out, err := exec.Command("tar", "-tvf", path).Output()
	l := listing{failed: err != nil}
	for _, s := range strings.Split(strings.TrimSuffix(string(out), "\n"), "\n") {
		m := gnuRow.FindStringSubmatch(s)
		switch {
		case s == "":
		case m == nil:
			l.lines = append(l.lines, "? "+s)
		default:
			kind := m[1][0]
			if kind == '-' {
				kind = 'f'
			}
			var size int64
			fmt.Sscan(m[2], &size)
			l.lines = append(l.lines, line(kind, size, m[3]))
		}
	}
	return l
}

const pythonList = `
import sys, tarfile
sys.stdout.reconfigure(errors="backslashreplace")
try:
    with tarfile.open(sys.argv[1], "r:") as t:
        for m in t.getmembers():
            k = {b"0": "f", b"\0": "f", b"5": "d"}.get(m.type, m.type.decode("latin1"))
            print(k, m.size, m.name)
except Exception as e:
    print("ERROR")
`

func pythonListing(path string) listing {
	out, err := exec.Command("python3", "-I", "-c", pythonList, path).Output()
	var l listing
	for _, s := range strings.Split(strings.TrimSuffix(string(out), "\n"), "\n") {
		switch {
		case s == "":
		case s == "ERROR":
			l.failed = true
		default:
			var kind byte
			var size int64
			var name string
			fmt.Sscanf(s[:1], "%c", &kind)
			fmt.Sscan(strings.SplitN(s, " ", 3)[1], &size)
			name = strings.SplitN(s, " ", 3)[2]
			l.lines = append(l.lines, line(kind, size, name))
		}
	}
	l.failed = l.failed || err != nil
	return l
}

// requireOracleTools checks the versions of GNU tar and Python. Outside the
// devcontainer and CI, a missing tool or another version skips the test, with
// the reason. In the devcontainer (IN_DEVCONTAINER=1) and in CI (CI=true), it
// fails the test.
func requireOracleTools(t *testing.T) {
	t.Helper()
	strict := os.Getenv("IN_DEVCONTAINER") == "1" || os.Getenv("CI") == "true"
	for _, c := range []struct{ bin, want string }{{"tar", "tar (GNU tar) 1.35"}, {"python3", "Python 3.13."}} {
		found := "not found"
		if path, err := exec.LookPath(c.bin); err == nil {
			out, _ := exec.Command(path, "--version").Output()
			found, _, _ = strings.Cut(string(out), "\n")
		}
		if !strings.HasPrefix(found, c.want) {
			msg := fmt.Sprintf("%s: version %q; the oracle needs %q", c.bin, found, c.want)
			if strict {
				t.Fatal(msg)
			}
			t.Skip(msg)
		}
		t.Logf("%s: %s", c.bin, found)
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

// differential marks each refused form of rawFormCases: true when the readers
// list other entries, or one of them fails. The rule of a form marked false
// guards a reader outside the three (the forms that no reader of the oracle
// shows), or the readers agree on the entries that the form hides.
var differential = map[string]bool{
	"size field with a leading NUL":                             true,
	"size field of the PAX header with a leading NUL":           true,
	"size field with a leading space":                           false,
	"size field with fewer digits":                              false,
	"PAX path in the padding of the PAX header":                 true,
	"PAX path of the manifest in the padding of the PAX header": true,
	"PAX size in the padding of the PAX header":                 true,
	"PAX header with a repeated key in one block":               false,
	"PAX record length with a leading zero in one block":        false,
	"PAX path record with an empty value":                       true,
	"PAX mtime record with an empty value":                      true,
	"PAX size record with an empty value":                       true,
	"PAX size record and ustar size field that differ":          false,
	"PAX size record with a leading zero":                       false,
	"PAX path over the ustar name ../x":                         false,
	"PAX path that starts the ustar name":                       false,
	"PAX path with a ustar prefix":                              false,
	"PAX path over 100 bytes with another ustar name":           false,
	"two long names with the same cut":                          false,
	"long name with the cut of another file":                    false,
	"long name with a cut that ends in a slash and a directory": false,
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
		logListings(t, fmt.Sprintf("refused, marked differential %v (marked %v),", want, ok), c.name, ls)
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
