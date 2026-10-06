package config

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestTS10_Read(t *testing.T) {
	type row struct {
		name     string
		input    string
		isFile   bool
		mode     os.FileMode
		uid      uint32
		wantRule string
		wantPath string
		ceiling  int
	}

	rows := []row{
		{"Valid", "foo: bar", false, 0, 0, "", "", 94},
		{"EmptyKey", "\"\": 1", false, 0, 0, "mapping key is invalid", "(root)", 88},
		{"MergeKey", "a: 1\n<<: {b: 2}", false, 0, 0, "merge keys are rejected", "(root)", 126},
		{"DottedKey", "foo.bar: 1", false, 0, 0, "mapping key is invalid", "(root)", 96},
		{"UnknownAlias", "foo: *a", false, 0, 0, "invalid YAML", "", 98},
		{"AliasExpansion", "a: &a [x, x]\nb: [*a, *a]", false, 0, 0, "anchors are rejected", "\"a\"", 142},
		{"Anchor", "anchor: &a value", false, 0, 0, "anchors are rejected", "\"anchor\"", 106},
		{"CustomTag", "foo: !!custom value", false, 0, 0, "is outside the core schema", "\"foo\"", 112},
		{"DuplicateKey", "foo: 1\nfoo: 2", false, 0, 0, "duplicate key", "\"foo\"", 116},
		{"DuplicateKeyPath", "outer: { inner: 1 }\nouter: { inner: 2 }", false, 0, 0, "duplicate key", "\"outer\"", 154},
		{"Depth8", "a:\n  b:\n    c:\n      d:\n        e:\n          f:\n            g:\n              h: 1", false, 0, 0, "", "", 206},
		{"Depth9", "a:\n  b:\n    c:\n      d:\n        e:\n          f:\n            g:\n              h:\n                i: 1", false, 0, 0, "nesting exceeds limit of 8", "\"a.b.c.d.e.f.g.h.i\"", 238},
		{"InvalidUTF8", "\xff\xfe\xfd", false, 0, 0, "invalid UTF-8 encoding", "", 2},
		{"NULByte", "foo: bar\x00baz", false, 0, 0, "contains NUL byte", "", 2},
		{"BOM", "\xef\xbb\xbffoo: bar", false, 0, 0, "contains UTF-8 BOM", "", 2},
		{"SecondDocument", "foo: bar\n---\nbaz: qux", false, 0, 0, "contains more than one document", "", 120},
		{"EmptyDocument", " ", false, 0, 0, "empty document", "", 2},
		{"CommentsOnly", "# only a comment\n", false, 0, 0, "empty document", "", 34},
		{"NotAMapping", "- foo: bar", false, 0, 0, "root must be a mapping", "", 94},
		{"LargeFile", "foo: bar", true, 0, 0, "the file is larger than 64 KiB", "", 54},
		{"Exactly64KiB", "foo: bar", true, 0, 0, "", "", 174},
		{"Over64KiB", "foo: bar", true, 0, 0, "the file is larger than 64 KiB", "", 54},
		{"OtherWritable", "foo: bar", true, 0602, 0, "group or other writable", "", 20},
		{"GroupWritable", "foo: bar", true, 0620, 0, "group or other writable", "", 20},
		{"WrongOwner", "foo: bar", true, 0644, 12345, "the owner must be root or the current user", "", 20},
		{"FIFO", "foo: bar", true, 0, 0, "not a regular file", "", 20},
		{"MissingFile", "foo: bar", true, 0, 0, "no such file", "", 18},
		{"Unreadable", "foo: bar", true, 0000, 0, "permission denied", "", 18},
		{"ValidFile", "foo: bar", true, 0644, 0, "", "", 106},
		{"KeyAnchor", "&k foo: 1", false, 0, 0, "mapping key anchor is rejected", "(root)", 98},
		{"KeyTagCustom", "!custom foo: 1", false, 0, 0, "mapping key tag is rejected", "(root)", 104},
		{"KeyTagBinary", "!!binary Zm9v: 1", false, 0, 0, "mapping key is invalid", "(root)", 102},
		{"KeyTagTilde", "~: 1", false, 0, 0, "mapping key is invalid", "(root)", 92},
		{"KeyTagTrue", "true: 1", false, 0, 0, "mapping key tag is rejected", "(root)", 94},
		{"KeyBrackets", "\"sinks[0]\": {type: x}", false, 0, 0, "mapping key is invalid", "(root)", 116},
		{"DupListEmpty", "a: []\na: []", false, 0, 0, "duplicate key", "\"a\"", 110},
		{"DupListScalar", "a: [1]\na: 1", false, 0, 0, "duplicate key", "\"a\"", 126},
		{"DupListScalarX", "a: []\na: x", false, 0, 0, "duplicate key", "\"a\"", 114},
		{"DupListMapping", "a: [x]\na: {b: 1}", false, 0, 0, "duplicate key", "\"a\"", 140},
		{"ScalarList", "a: [1, 2]", false, 0, 0, "", "", 114},
		{"MappingList", "s: [{t: 1}, {t: 2}]", false, 0, 0, "", "", 146},
		{"LiteralEnv", "foo: ${HOME}", false, 0, 0, "", "", 94},
		{"ParseErrorLine", "a: 1\nb: [\n", false, 0, 0, "line 2", "", 118},
		{"UnknownAnchor", "a: *marker_XYZ", false, 0, 0, "invalid YAML", "", 98},
		{"ValidLarge", "large: value", false, 0, 0, "", "", 132},
	}

	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			var err error
			var doc *Doc
			var path string

			if r.isFile {
				tmpDir := t.TempDir()
				path = filepath.Join(tmpDir, "config.yaml")

				input := r.input
				if r.name == "LargeFile" {
					input = "large: " + strings.Repeat("a", 64*1024)
				} else if r.name == "Exactly64KiB" {
					input = "foo: " + strings.Repeat("a", 64*1024-5)
					// adjust to be exactly 65536 bytes. "foo: " is 5 bytes.
					// input = "foo: aaaa...a" where len(input) == 65536
					// current: "foo: " (5) + strings.Repeat("a", 64*1024-5) (65531) = 65536
					input = "foo: " + strings.Repeat("a", 64*1024-5)
				} else if r.name == "Over64KiB" {
					input = "large: " + strings.Repeat("a", 64*1024)
				}

				if err := os.WriteFile(path, []byte(input), 0644); err != nil {
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
				input := r.input
				if r.name == "ValidLarge" {
					// Generate a valid YAML mapping <= 64 KiB.
					var b strings.Builder
					b.WriteString("large: ")
					for i := 0; i < 64*1024-10; i++ {
						b.WriteByte('a')
					}
					input = b.String()
				}
				doc, err = ReadBytes([]byte(input))
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

			// Allocation check
			var input []byte
			if r.isFile {
				input = []byte(r.input)
				if r.name == "LargeFile" {
					input = []byte("large: " + strings.Repeat("a", 64*1024))
				}
			} else {
				if r.name == "ValidLarge" {
					var b strings.Builder
					b.WriteString("large: ")
					for i := 0; i < 64*1024-10; i++ {
						b.WriteByte('a')
					}
					input = []byte(b.String())
				} else {
					input = []byte(r.input)
				}
			}

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
	if err == nil || !strings.Contains(err.Error(), "the file is larger than 64 KiB") {
		t.Errorf("expected size limit error, got %v", err)
	}
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
