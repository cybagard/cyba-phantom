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
)

// sepRule is the fixed error text for a raw U+0085, U+2028 or U+2029.
const sepRule = "contains U+0085, U+2028 or U+2029"

func TestTS10_Read(t *testing.T) {
	type row struct {
		name     string
		input    string
		isFile   bool
		mode     os.FileMode
		uid      uint32
		wantRule string
		wantPath string
		// ceiling is the allocation limit. Each ceiling is at least 1.25
		// times the count that go test -race measured in the devcontainer.
		ceiling int
		// size is the expected input length for a file row. 0 means no check.
		size int
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
		{name: "SecondDocument", input: "foo: bar\n---\nbaz: qux", wantRule: "contains more than one document", ceiling: 120},
		{name: "EmptyDocument", input: " ", wantRule: "empty document", ceiling: 2},
		{name: "CommentsOnly", input: "# only a comment\n", wantRule: "empty document", ceiling: 34},
		{name: "NotAMapping", input: "- foo: bar", wantRule: "root must be a mapping", ceiling: 94},
		{name: "LargeFile", input: padded(128 * 1024), isFile: true, wantRule: "the file is larger than 64 KiB", ceiling: 54},
		{name: "Exactly64KiB", input: padded(64 * 1024), isFile: true, ceiling: 174, size: 65536},
		{name: "Over64KiB", input: padded(64*1024 + 1), isFile: true, wantRule: "the file is larger than 64 KiB", ceiling: 54, size: 65537},
		{name: "OtherWritable", input: "foo: bar", isFile: true, mode: 0602, wantRule: "group or other writable", ceiling: 20},
		{name: "GroupWritable", input: "foo: bar", isFile: true, mode: 0620, wantRule: "group or other writable", ceiling: 20},
		{name: "WrongOwner", input: "foo: bar", isFile: true, mode: 0644, uid: 12345, wantRule: "the owner must be root or the current user", ceiling: 20},
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

				origGetUid := getUid
				if r.uid != 0 {
					getUid = func(info os.FileInfo) (uint32, error) {
						return r.uid, nil
					}
					defer func() { getUid = origGetUid }()
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
		"foo: bar\n---\nbaz: qux",
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
