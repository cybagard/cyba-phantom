package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/cybagard/cyba-phantom/internal/safefile/safefiletest"
)

// sepRule is the fixed error text for a raw U+0085, U+2028 or U+2029.
const sepRule = "contains U+0085, U+2028 or U+2029"

// crRule is the fixed error text for a CR without an LF after it.
const crRule = "contains a CR without an LF after it"

func TestTS10_Read(t *testing.T) {
	type row struct {
		name   string
		input  string
		isFile bool
		mode   os.FileMode
		// otherOwner makes the check see the file as a file of another owner.
		otherOwner bool
		wantRule   string
		wantPath   string
		// ceiling is the allocation limit. Each ceiling is at least 1.25
		// times the count that go test -race measured in the devcontainer.
		ceiling int
		// size is the expected input length for a file row. 0 means no check.
		size int
		// noEcho is text of the input that the error must not hold.
		noEcho string
	}

	rows := []row{
		{name: "Valid", input: "foo: bar", ceiling: 94},
		{name: "EmptyKey", input: "\"\": 1", wantRule: keyRule, wantPath: "(root)", ceiling: 88},
		{name: "MergeKey", input: "a: 1\n<<: {b: 2}", wantRule: "merge keys are rejected", wantPath: "(root)", ceiling: 126},
		{name: "DottedKey", input: "foo.bar: 1", wantRule: keyRule, wantPath: "(root)", ceiling: 96},
		{name: "UnknownAlias", input: "foo: *a", wantRule: "invalid YAML", ceiling: 98},
		{name: "AliasExpansion", input: "a: &a [x, x]\nb: [*a, *a]", wantRule: "anchors are rejected", wantPath: "\"a\"", ceiling: 142},
		{name: "Anchor", input: "anchor: &a value", wantRule: "anchors are rejected", wantPath: "\"anchor\"", ceiling: 106},
		{name: "CustomTag", input: "foo: !!custom value", wantRule: scalarTagRule, wantPath: "\"foo\"", ceiling: 112},
		{name: "MapTagOnScalar", input: "a: !!map x", wantRule: scalarTagRule, wantPath: "\"a\"", ceiling: 74},
		{name: "StrTagOnMapping", input: "a: !!str {b: 1}", wantRule: mapTagRule, wantPath: "\"a\"", ceiling: 86},
		{name: "StrTagOnSequence", input: "a: !!str [1]", wantRule: seqTagRule, wantPath: "\"a\"", ceiling: 80},
		{name: "DuplicateKey", input: "foo: 1\nfoo: 2", wantRule: "duplicate key", wantPath: "\"foo\"", ceiling: 116},
		{name: "DuplicateKeyPath", input: "outer: { inner: 1 }\nouter: { inner: 2 }", wantRule: "duplicate key", wantPath: "\"outer\"", ceiling: 154},
		{name: "Depth8", input: "a:\n  b:\n    c:\n      d:\n        e:\n          f:\n            g:\n              h: 1", ceiling: 206},
		{name: "Depth9", input: "a:\n  b:\n    c:\n      d:\n        e:\n          f:\n            g:\n              h:\n                i: 1", wantRule: "nesting exceeds limit of 8", wantPath: "\"a.b.c.d.e.f.g.h.i\"", ceiling: 238},
		{name: "InvalidUTF8", input: "\xff\xfe\xfd", wantRule: "invalid UTF-8 encoding", ceiling: 2},
		{name: "NULByte", input: "foo: bar\x00baz", wantRule: "contains NUL byte", ceiling: 2},
		{name: "BOM", input: "\xef\xbb\xbffoo: bar", wantRule: "contains UTF-8 BOM", ceiling: 2},
		{name: "NEL", input: "foo: bar\u0085baz", wantRule: sepRule, ceiling: 2},
		{name: "LineSeparator", input: "foo: bar\u2028baz", wantRule: sepRule, ceiling: 2},
		{name: "ParagraphSeparator", input: "foo: bar\u2029baz", wantRule: sepRule, ceiling: 2},
		{name: "HiddenKey", input: "acme:\n  email: a@b.example\u2028  ca: x\n", wantRule: sepRule, ceiling: 2},
		{name: "LoneCR", input: "foo: bar\rbaz: qux\n", wantRule: crRule, ceiling: 2},
		{name: "CRFirstByte", input: "\rfoo: bar\n", wantRule: crRule, ceiling: 2},
		{name: "CRAfterCRLFLine", input: "foo: bar\r\n\rbaz: qux\n", wantRule: crRule, ceiling: 2},
		{name: "CRAfterBlankCRLF", input: "foo: bar\r\n\r\n\rbaz: qux\n", wantRule: crRule, ceiling: 2},
		{name: "CRLast", input: "foo: bar\r", wantRule: crRule, ceiling: 2},
		{name: "CRCRLF", input: "foo: bar\r\r\nbaz: qux\n", wantRule: crRule, ceiling: 2},
		{name: "CRAfterCRLF", input: "foo: bar\r\nbaz: qux\rx: y\n", wantRule: crRule, ceiling: 2},
		{name: "HiddenKeyCR", input: "acme:\n  email: a@b.example\r  ca: x\n", wantRule: crRule, noEcho: "a@b.example", ceiling: 2},
		{name: "CRLF", input: "foo: bar\r\nbaz: qux\r\n", ceiling: 75},
		{name: "SecondDocument", input: "foo: bar\n---\nbaz: qux", wantRule: "contains more than one document", ceiling: 120},
		{name: "EmptyDocument", input: " ", wantRule: "empty document", ceiling: 2},
		{name: "CommentsOnly", input: "# only a comment\n", wantRule: "empty document", ceiling: 34},
		{name: "NotAMapping", input: "- foo: bar", wantRule: "root must be a mapping", ceiling: 94},
		{name: "LargeFile", input: padded(128 * 1024), isFile: true, wantRule: "the file is larger than 64 KiB", ceiling: 54},
		{name: "Exactly64KiB", input: padded(64 * 1024), isFile: true, ceiling: 174, size: 65536},
		{name: "Over64KiB", input: padded(64*1024 + 1), isFile: true, wantRule: "the file is larger than 64 KiB", ceiling: 54, size: 65537},
		{name: "OtherWritable", input: "foo: bar", isFile: true, mode: 0602, wantRule: "group or other writable", ceiling: 20},
		{name: "GroupWritable", input: "foo: bar", isFile: true, mode: 0620, wantRule: "group or other writable", ceiling: 20},
		{name: "WrongOwner", input: "foo: bar", isFile: true, mode: 0644, otherOwner: true, wantRule: "the owner must be root or the current user", ceiling: 20},
		{name: "FIFO", input: "foo: bar", isFile: true, wantRule: "not a regular file", ceiling: 20},
		{name: "MissingFile", input: "foo: bar", isFile: true, wantRule: "no such file", ceiling: 18},
		{name: "Unreadable", input: "foo: bar", isFile: true, wantRule: "permission denied", ceiling: 18},
		{name: "ValidFile", input: "foo: bar", isFile: true, mode: 0644, ceiling: 106},
		{name: "KeyAnchor", input: "&k foo: 1", wantRule: "mapping key anchor is rejected", wantPath: "(root)", ceiling: 98},
		{name: "KeyTagCustom", input: "!custom foo: 1", wantRule: "mapping key tag is rejected", wantPath: "(root)", ceiling: 104},
		{name: "KeyTagBinary", input: "!!binary Zm9v: 1", wantRule: keyRule, wantPath: "(root)", ceiling: 102},
		{name: "KeyTagTilde", input: "~: 1", wantRule: keyRule, wantPath: "(root)", ceiling: 92},
		{name: "KeyTagTrue", input: "true: 1", wantRule: "mapping key tag is rejected", wantPath: "(root)", ceiling: 94},
		{name: "KeyBrackets", input: "\"sinks[0]\": {type: x}", wantRule: keyRule, wantPath: "(root)", ceiling: 116},
		{name: "DupListEmpty", input: "a: []\na: []", wantRule: "duplicate key", wantPath: "\"a\"", ceiling: 110},
		{name: "DupListScalar", input: "a: [1]\na: 1", wantRule: "duplicate key", wantPath: "\"a\"", ceiling: 126},
		{name: "DupListScalarX", input: "a: []\na: x", wantRule: "duplicate key", wantPath: "\"a\"", ceiling: 114},
		{name: "DupListMapping", input: "a: [x]\na: {b: 1}", wantRule: "duplicate key", wantPath: "\"a\"", ceiling: 140},
		{name: "ScalarList", input: "a: [1, 2]", ceiling: 114},
		{name: "MappingList", input: "s: [{t: 1}, {t: 2}]", ceiling: 146},
		{name: "LiteralEnv", input: "foo: ${HOME}", ceiling: 94},
		{name: "ParseErrorLine", input: "a: 1\nb: [\n", wantRule: "line 2", ceiling: 118},
		{name: "UnknownAnchor", input: "a: *marker_XYZ", wantRule: "invalid YAML", ceiling: 98},
		{name: "KeyDigits", input: "1: x", wantRule: "a key must be a string, not a number", wantPath: "(root)", ceiling: 98},
		{name: "PlainDate", input: "a: 2001-12-14", wantRule: plainTagRule, wantPath: "\"a\"", ceiling: 112},
		{name: "TaggedDate", input: "a: !!timestamp 2001-12-14", wantRule: scalarTagRule, wantPath: "\"a\"", ceiling: 112},
		{name: "ValidLarge", input: padded(64*1024 - 3), ceiling: 132},
	}

	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			var err error
			var doc *Doc
			var path string

			if r.isFile {
				tmpDir := t.TempDir()
				path = filepath.Join(tmpDir, "config.yaml")

				if r.size != 0 && len(r.input) != r.size {
					t.Fatalf("input has %d bytes, want %d", len(r.input), r.size)
				}
				if err := os.WriteFile(path, []byte(r.input), 0644); err != nil {
					t.Fatal(err)
				}

				if r.mode != 0 {
					if err := os.Chmod(path, r.mode); err != nil {
						t.Fatal(err)
					}
				}

				if r.name == "FIFO" {
					fifoPath := filepath.Join(tmpDir, "fifo")
					if err := syscall.Mkfifo(fifoPath, 0666); err != nil {
						t.Fatal(err)
					}
					path = fifoPath
				} else if r.name == "MissingFile" {
					path = filepath.Join(tmpDir, "missing.yaml")
				} else if r.name == "Unreadable" {
					if os.Geteuid() == 0 {
						t.Skip("skipping unreadable test as root")
					}
					path = filepath.Join(tmpDir, "unreadable.yaml")
					if err := os.WriteFile(path, []byte("foo: bar"), 0644); err != nil {
						t.Fatal(err)
					}
					if err := os.Chmod(path, 0000); err != nil {
						t.Fatal(err)
					}
				}

				if r.otherOwner {
					otherOwner(t, path)
				}

				doc, err = ReadFile(path)
			} else {
				doc, err = ReadBytes([]byte(r.input))
			}

			if r.wantRule == "" {
				if err != nil {
					t.Errorf("expected no error, got %v", err)
				} else if doc == nil {
					t.Error("expected doc, got nil")
				} else {
					if r.name == "ScalarList" {
						if _, ok := doc.Leaves["a[0]"]; !ok {
							t.Error("missing path a[0]")
						}
						if _, ok := doc.Leaves["a[1]"]; !ok {
							t.Error("missing path a[1]")
						}
						if !doc.Sequences["a"] {
							t.Error("expected path a to be a sequence")
						}
					} else if r.name == "MappingList" {
						if _, ok := doc.Leaves["s[0].t"]; !ok {
							t.Error("missing path s[0].t")
						}
						if _, ok := doc.Leaves["s[1].t"]; !ok {
							t.Error("missing path s[1].t")
						}
						if !doc.Sequences["s"] {
							t.Error("expected path s to be a sequence")
						}
					} else if r.name == "CRLF" {
						if doc.Leaves["foo"].Value != "bar" || doc.Leaves["baz"].Value != "qux" {
							t.Errorf("expected keys foo and baz, got %v", doc.Leaves)
						}
					} else if r.name == "LiteralEnv" {
						if doc.Leaves["foo"].Value != "${HOME}" {
							t.Errorf("expected value %q, got %q", "${HOME}", doc.Leaves["foo"].Value)
						}
					}
				}
			} else {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", r.wantRule)
				} else {
					if !strings.Contains(err.Error(), r.wantRule) {
						t.Errorf("expected error containing %q, got %q", r.wantRule, err.Error())
					}
					if r.isFile && !strings.Contains(err.Error(), fmt.Sprintf("%q", path)) {
						t.Errorf("expected error containing the quoted file path %q, got %q", path, err.Error())
					}
					if r.noEcho != "" && strings.Contains(err.Error(), r.noEcho) {
						t.Errorf("error should not contain %q, got %q", r.noEcho, err.Error())
					}
					if r.wantPath != "" && !strings.Contains(err.Error(), r.wantPath) {
						t.Errorf("expected error containing path %q, got %q", r.wantPath, err.Error())
					}
					if r.name == "ParseErrorLine" {
						if !strings.Contains(err.Error(), "invalid YAML") {
							t.Errorf("expected error containing %q, got %q", "invalid YAML", err.Error())
						}
					} else if r.name == "UnknownAnchor" {
						if strings.Contains(err.Error(), "marker_XYZ") {
							t.Errorf("error should not contain %q, got %q", "marker_XYZ", err.Error())
						}
					} else if r.name == "MissingFile" {
						if !errors.Is(err, fs.ErrNotExist) {
							t.Errorf("expected error to be fs.ErrNotExist, got %v", err)
						}
					}
				}
			}

			input := []byte(r.input)
			allocs := testing.AllocsPerRun(10, func() {
				if r.isFile {
					_, _ = ReadFile(path)
				} else {
					_, _ = ReadBytes(input)
				}
			})

			if allocs > float64(r.ceiling) {
				t.Errorf("too many allocations in %s: %v (ceiling %d)", r.name, allocs, r.ceiling)
			}
		})
	}
}

func TestReadBytesSizeLimit(t *testing.T) {
	data := make([]byte, 64*1024+1)
	_, err := ReadBytes(data)
	if err == nil || !strings.Contains(err.Error(), "the input is larger than 64 KiB") {
		t.Errorf("expected size limit error, got %v", err)
	}
}

// TestTS10_ReadErrorText checks the exact text of each form of ReadError.Error.
func TestTS10_ReadErrorText(t *testing.T) {
	long := strings.Repeat("k", 70)
	for _, r := range []struct {
		e    ReadError
		want string
	}{
		{ReadError{Path: "a.b", Line: 3, Column: 4, Detail: "duplicate key"}, `config: "a.b": line 3 column 4: duplicate key`},
		{ReadError{Line: 1, Column: 1, Detail: "x"}, `config: (root): line 1 column 1: x`},
		{ReadError{Path: long, Line: 1, Column: 1, Detail: "x"}, `config: "` + long[:64] + `": line 1 column 1: x`},
		{ReadError{Line: 2, Detail: "invalid YAML"}, `config: line 2: invalid YAML`},
		{ReadError{Detail: "empty document"}, `config: empty document`},
		{ReadError{File: "/c.yaml", Detail: "not a regular file"}, `config: "/c.yaml": not a regular file`},
		{ReadError{File: "/c.yaml", Err: syscall.ENOENT}, `config: "/c.yaml": no such file or directory`},
		{ReadError{Err: syscall.ENOENT}, `config: "": no such file or directory`},
	} {
		if got := r.e.Error(); got != r.want {
			t.Errorf("got %q, want %q", got, r.want)
		}
	}
}

// TestTS10_ReadErrorFields checks that a reader error is a *ReadError.
// The error holds the key path, the line, the column, and the detail as fields.
// The text of a file error escapes the path (T-S-10).
func TestTS10_ReadErrorFields(t *testing.T) {
	rows := []struct {
		name, input string
		want        ReadError
	}{
		{"node", "a:\n  b: 1\n  b: 2", ReadError{Path: "a.b", Line: 3, Column: 3, Detail: "duplicate key"}},
		{"root", "\"\": 1", ReadError{Line: 1, Column: 1, Detail: keyRule}},
		{"YAML", "a: 1\nb: [\n", ReadError{Line: 2, Detail: "invalid YAML"}},
		{"fixed text", "- a", ReadError{Detail: "root must be a mapping"}},
	}
	for _, r := range rows {
		_, err := ReadBytes([]byte(r.input))
		var got *ReadError
		if !errors.As(err, &got) || *got != r.want {
			t.Errorf("%s: got %#v, want %#v", r.name, got, r.want)
		}
	}
	_, err := ReadFile(filepath.Join(t.TempDir(), "\x1b[31m"))
	var got *ReadError
	if !errors.As(err, &got) || !errors.Is(err, fs.ErrNotExist) || strings.Contains(err.Error(), "\x1b") {
		t.Errorf("file error: got %q (%#v)", err, got)
	}
}

// TestTS10_DuplicateKeyPosition checks that the duplicate-key error gives the
// line and column of the second key, not of its value (T-S-10).
func TestTS10_DuplicateKeyPosition(t *testing.T) {
	rows := []struct{ name, input, want string }{
		{"value on next line", "foo: 1\nfoo:\n  2", "line 2 column 1: duplicate key"},
		{"nested, value in other column", "a:\n  foo: 1\n  foo: 2", "line 3 column 3: duplicate key"},
		{"value after a longer key", "a: 1\nlong_key_name: 1\nlong_key_name: 2", "line 3 column 1: duplicate key"},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			_, err := ReadBytes([]byte(r.input))
			if err == nil || !strings.Contains(err.Error(), r.want) {
				t.Errorf("got %v, want text %q", err, r.want)
			}
		})
	}
}

// padded returns "foo: " and then enough "a" to make n bytes.
func padded(n int) string {
	return "foo: " + strings.Repeat("a", n-len("foo: "))
}

func FuzzRead(f *testing.F) {
	// Seed with table inputs
	inputs := []string{
		"foo: bar",
		"a: 1\n<<: {b: 2}",
		"foo.bar: 1",
		"anchor: &a value\nalias: *a",
		"anchor: &a value",
		"foo: !!custom value",
		"foo: 1\nfoo: 2",
		"outer: { inner: 1 }\nouter: { inner: 2 }",
		"a: { b: { c: { d: { e: { f: { g: { h: 1 } } } } } } }",
		"a: { b: { c: { d: { e: { f: { g: { h: { i: 1 } } } } } } }",
		"\xff\xfe\xfd",
		"foo: bar\x00baz",
		"\xef\xbb\xbffoo: bar",
		"foo: bar\u0085baz",
		"foo: bar\xe2\x80\xa8baz",
		"foo: bar\xe2\x80\xa9baz",
		"foo: bar\n---\nbaz: qux",
		"foo: bar\rbaz: qux",
		"foo: bar\r\nbaz: qux\r\n",
		"",
		"foo: bar\n- baz",
		"\"\": 1",
		"&k foo: 1",
		"!custom foo: 1",
		"!!binary Zm9v: 1",
		"~: 1",
		"true: 1",
		"\"sinks[0]\": {type: x}",
		"a: []\na: []",
		"a: [1]\na: 1",
		"a: []\na: x",
		"a: [x]\na: {b: 1}",
		"a: [1, 2]",
		"s: [{t: 1}, {t: 2}]",
		"foo: ${HOME}",
		"foo: : bar",
		"a: *marker_XYZ",
		// Seeds for boundaries and rejected patterns.
		"a: 1\nb: [\n",
		"a: &a [x, x]\nb: [*a, *a]",
	}

	for _, in := range inputs {
		f.Add([]byte(in))
	}
	f.Add([]byte("large: " + strings.Repeat("a", 65537)))

	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = ReadBytes(b)
	})
}

// writeFile writes body to a new file in a private directory and sets its
// mode. The mode call follows the write, so the umask does not change it.
func writeFile(t *testing.T, dir, name, body string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

// afterCheckCount counts the calls of the hook that runs between the check and
// the open. A refusal before the open does not call it.
func afterCheckCount(t *testing.T) *int {
	t.Helper()
	n := new(int)
	safefiletest.Set(t, safefiletest.Hooks{AfterCheck: func(string) { *n++ }})
	return n
}

// loadDetail loads path as the config file, as --check does. The Net has no
// network. It gives the detail of the file error.
func loadDetail(t *testing.T, path string) string {
	t.Helper()
	useTestKeys(t)
	_, err := LoadWith(path, []string{tokenVar + "=token"}, testNet)
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("got %v, want an *Error", err)
	}
	return e.Detail
}

// TestTS10_ConfigNotRegular checks that a FIFO and a device node as the config
// path are refused before the open (T-S-10).
func TestTS10_ConfigNotRegular(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Lstat("/dev/null"); err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		t.Fatalf("/dev/null is not a character device: %v", err)
	}
	for _, r := range []struct{ name, path string }{
		{"FIFO", fifo}, {"device node", "/dev/null"}, {"directory", dir},
	} {
		t.Run(r.name, func(t *testing.T) {
			opened := afterCheckCount(t)
			_, err := ReadFile(r.path)
			if want := fmt.Sprintf("config: %q: not a regular file", r.path); err == nil || err.Error() != want {
				t.Errorf("got %v, want %q", err, want)
			}
			if *opened != 0 {
				t.Error("the file was opened")
			}
			if got := loadDetail(t, r.path); got != "not a regular file" {
				t.Errorf("Load: got detail %q", got)
			}
			if *opened != 0 {
				t.Error("Load opened the file")
			}
		})
	}
}

// TestTS10_ConfigSwap checks that a file that replaces the config file between
// the check and the open is refused (T-S-10). The new file can be a regular
// file or a FIFO.
func TestTS10_ConfigSwap(t *testing.T) {
	const want = "the file changed during the read"
	for _, r := range []struct {
		name string
		swap func(t *testing.T, dir, p string)
	}{
		{"other file", func(t *testing.T, dir, p string) {
			if err := os.Rename(writeFile(t, dir, "new.yaml", "foo: bar", 0o600), p); err != nil {
				t.Fatal(err)
			}
		}},
		{"FIFO", func(t *testing.T, dir, p string) {
			fifo := filepath.Join(dir, "new-fifo")
			if err := syscall.Mkfifo(fifo, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(fifo, p); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		for _, viaLoad := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s load %v", r.name, viaLoad), func(t *testing.T) {
				dir := t.TempDir()
				p := writeFile(t, dir, "config.yaml", "foo: bar", 0o600)
				swapped := false
				safefiletest.Set(t, safefiletest.Hooks{AfterCheck: func(name string) {
					if name == p && !swapped {
						swapped = true
						r.swap(t, dir, p)
					}
				}})
				var got string
				if viaLoad {
					got = loadDetail(t, p)
				} else {
					_, err := ReadFile(p)
					var re *ReadError
					if !errors.As(err, &re) {
						t.Fatalf("got %v", err)
					}
					got = re.Detail
				}
				if !swapped || got != want {
					t.Errorf("swapped %v, detail %q, want %q", swapped, got, want)
				}
			})
		}
	}
}

// TestTS10_ConfigSymlink checks that a symlink to a regular file loads
// (T-S-10).
func TestTS10_ConfigSymlink(t *testing.T) {
	useTestKeys(t)
	dir := t.TempDir()
	real := writeFile(t, dir, "real.yaml", base, 0o600)
	abs := filepath.Join(dir, "abs.yaml")
	rel := filepath.Join(dir, "rel.yaml")
	chain := filepath.Join(dir, "chain.yaml")
	for link, target := range map[string]string{abs: real, rel: "real.yaml", chain: abs} {
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range []string{abs, rel, chain} {
		if _, err := ReadFile(p); err != nil {
			t.Errorf("ReadFile(%s): %v", filepath.Base(p), err)
		}
		if _, err := LoadWith(p, []string{tokenVar + "=token"}, testNet); err != nil {
			t.Errorf("LoadWith(%s): %v", filepath.Base(p), err)
		}
	}
	// A link to a file that is group-writable gets the rule of the target.
	bad := writeFile(t, dir, "bad.yaml", base, 0o620)
	link := filepath.Join(dir, "bad-link.yaml")
	if err := os.Symlink(bad, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFile(link); err == nil || !strings.Contains(err.Error(), "group or other writable") {
		t.Errorf("link to a group-writable file: got %v", err)
	}
	// A link loop keeps the system cause.
	loop := filepath.Join(dir, "loop.yaml")
	if err := os.Symlink(loop, loop); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFile(loop); !errors.Is(err, syscall.ELOOP) {
		t.Errorf("link loop: got %v", err)
	}
}

// TestTS10_ConfigRelativePath checks that a relative config path loads and that
// an error shows the path as the user gave it.
func TestTS10_ConfigRelativePath(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "c.yaml", "foo: bar", 0o600)
	writeFile(t, dir, "wide.yaml", "foo: bar", 0o666)
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	for _, p := range []string{"c.yaml", "./c.yaml", "sub/../c.yaml", "sub/../sub/../c.yaml"} {
		if _, err := ReadFile(p); err != nil {
			t.Errorf("ReadFile(%q): %v", p, err)
		}
	}
	for _, r := range []struct{ path, want string }{
		{"wide.yaml", `config: "wide.yaml": group or other writable`},
		{"missing.yaml", `config: "missing.yaml": no such file or directory`},
		{"sub/missing.yaml", `config: "sub/missing.yaml": no such file or directory`},
		{"", `config: "": no such file or directory`},
		{"sub/.", `config: "sub/.": not a regular file`},
		{"sub/", `config: "sub/": not a regular file`},
		{"sub/..", `config: "sub/..": not a regular file`},
		{"c.yaml/x", `config: "c.yaml/x": not a directory`},
	} {
		if _, err := ReadFile(r.path); err == nil || err.Error() != r.want {
			t.Errorf("ReadFile(%q): got %v, want %q", r.path, err, r.want)
		}
	}
}

// TestTS10_ConfigModeOwner checks the mode and owner rules of the config
// file (T-S-10). It also runs them through LoadWith, as --check does.
func TestTS10_ConfigModeOwner(t *testing.T) {
	const (
		writable = "group or other writable"
		owner    = "the owner must be root or the current user"
	)
	dir := t.TempDir()
	for _, r := range []struct {
		name       string
		mode       os.FileMode
		otherOwner bool
		want       string // "" is for a file that loads
	}{
		{"0600", 0o600, false, ""},
		{"0644", 0o644, false, ""},
		{"group write 0620", 0o620, false, writable},
		{"other write 0602", 0o602, false, writable},
		{"other owner", 0o600, true, owner},
		// The owner rule runs before the mode rule.
		// A file with both faults gets the owner text.
		{"other owner and group write", 0o660, true, owner},
	} {
		t.Run(r.name, func(t *testing.T) {
			p := writeFile(t, dir, strings.ReplaceAll(r.name, " ", "_")+".yaml", base, r.mode)
			if r.otherOwner {
				otherOwner(t, p)
			}
			_, err := ReadFile(p)
			var re *ReadError
			switch {
			case r.want == "" && err != nil:
				t.Errorf("ReadFile: %v", err)
			case r.want != "" && (!errors.As(err, &re) || re.Detail != r.want || re.File != p || err.Error() != fmt.Sprintf("config: %q: %s", p, r.want)):
				t.Errorf("ReadFile: got %v, want %q", err, r.want)
			}
			useTestKeys(t)
			_, err = LoadWith(p, []string{tokenVar + "=token"}, testNet)
			var e *Error
			switch {
			case r.want == "" && err != nil:
				t.Errorf("LoadWith: %v", err)
			case r.want != "" && (!errors.As(err, &e) || e.Detail != r.want || e.Source != p):
				t.Errorf("LoadWith: got %v, want the detail %q", err, r.want)
			}
		})
	}
}

// TestTS10_ConfigTooLarge checks that the size text is fixed and that the size
// is measured on the open file.
func TestTS10_ConfigTooLarge(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "big.yaml", padded(64*1024+1), 0o600)
	_, err := ReadFile(p)
	if want := fmt.Sprintf("config: %q: the file is larger than 64 KiB", p); err == nil || err.Error() != want {
		t.Errorf("got %v, want %q", err, want)
	}
	if got := loadDetail(t, p); got != "the file is larger than 64 KiB" {
		t.Errorf("Load: got detail %q", got)
	}
}
