package config

import (
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
	}

	rows := []row{
		{"Valid", "foo: bar", false, 0, 0, "", ""},
		{"EmptyKey", "\"\": 1", false, 0, 0, "mapping key", "\"\""},
		{"MergeKey", "a: 1\n<<: {b: 2}", false, 0, 0, "merge keys are rejected", ""},
		{"DottedKey", "foo.bar: 1", false, 0, 0, "mapping key", "\"foo.bar\""},
		{"Alias", "foo: *a", false, 0, 0, "invalid YAML", ""},
		{"Anchor", "anchor: &a value", false, 0, 0, "anchors are rejected", "\"anchor\""},
		{"CustomTag", "foo: !!custom value", false, 0, 0, "custom tag", "\"foo\""},
		{"DuplicateKey", "foo: 1\nfoo: 2", false, 0, 0, "duplicate key", "\"foo\""},
		{"DuplicateKeyPath", "outer: { inner: 1 }\nouter: { inner: 2 }", false, 0, 0, "duplicate key", "\"outer\""},
		{"Depth8", "a:\n  b:\n    c:\n      d:\n        e:\n          f:\n            g:\n              h: 1", false, 0, 0, "", ""},
		{"Depth9", "a:\n  b:\n    c:\n      d:\n        e:\n          f:\n            g:\n              h:\n                i: 1", false, 0, 0, "nesting exceeds limit of 8", "\"a.b.c.d.e.f.g.h.i\""},
		{"InvalidUTF8", "\xff\xfe\xfd", false, 0, 0, "invalid UTF-8 encoding", ""},
		{"NULByte", "foo: bar\x00baz", false, 0, 0, "contains NUL byte", ""},
		{"BOM", "\xef\xbb\xbffoo: bar", false, 0, 0, "contains UTF-8 BOM", ""},
		{"SecondDocument", "foo: bar\n---\nbaz: qux", false, 0, 0, "contains more than one document", ""},
		{"EmptyDocument", " ", false, 0, 0, "empty document", ""},
		{"NotAMapping", "- foo: bar", false, 0, 0, "root must be a mapping", ""},
		{"LargeFile", "foo: bar", true, 0, 0, "config file exceeds 64 KiB limit", ""},
		{"OtherWritable", "foo: bar", true, 0602, 0, "group or other writable", ""},
		{"WrongOwner", "foo: bar", true, 0644, 12345, "owner must be root or current user", ""},
		{"FIFO", "foo: bar", true, 0, 0, "not a regular file", ""},
		{"ValidFile", "foo: bar", true, 0644, 0, "", ""},
		{"KeyAnchor", "&k foo: 1", false, 0, 0, "mapping key anchor is rejected", "(root)"},
		{"KeyTagCustom", "!custom foo: 1", false, 0, 0, "mapping key tag \"!custom\" is rejected", "(root)"},
		{"KeyTagBinary", "!!binary Zm9v: 1", false, 0, 0, "mapping key", "\"Zm9v\""},
		{"KeyTagTilde", "~: 1", false, 0, 0, "mapping key", "\"~\""},
		{"KeyTagTrue", "true: 1", false, 0, 0, "mapping key tag \"!!bool\" is rejected", "(root)"},
		{"KeyBrackets", "\"sinks[0]\": {type: x}", false, 0, 0, "mapping key", "\"sinks[0]\""},
		{"DupListEmpty", "a: []\na: []", false, 0, 0, "duplicate key \"a\"", "\"a\""},
		{"DupListScalar", "a: [1]\na: 1", false, 0, 0, "duplicate key \"a\"", "\"a\""},
		{"DupListScalarX", "a: []\na: x", false, 0, 0, "duplicate key \"a\"", "\"a\""},
		{"DupListMapping", "a: [x]\na: {b: 1}", false, 0, 0, "duplicate key \"a\"", "\"a\""},
		{"ScalarList", "a: [1, 2]", false, 0, 0, "", ""},
		{"MappingList", "s: [{t: 1}, {t: 2}]", false, 0, 0, "", ""},
		{"LiteralEnv", "foo: ${HOME}", false, 0, 0, "", ""},
		{"ParseErrorLine", "foo: : bar", false, 0, 0, "invalid YAML", ""},
		{"UnknownAnchor", "a: *marker_XYZ", false, 0, 0, "invalid YAML", ""},
		{"ValidLarge", "large: value", false, 0, 0, "", ""},
	}

	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			var err error
			var doc *Doc

			if r.isFile {
				tmpDir := t.TempDir()
				path := filepath.Join(tmpDir, "config.yaml")

				input := r.input
				if r.name == "LargeFile" {
					input = string(make([]byte, 64*1024+1))
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
				}
			}

			// Allocation check
			var input []byte
			if r.isFile {
				tmpDir := t.TempDir()
				path := filepath.Join(tmpDir, "config.yaml")
				input = []byte(r.input)
				if r.name == "LargeFile" {
					input = make([]byte, 64*1024+1)
				}
				_ = os.WriteFile(path, input, 0644) // not used but for consistency
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
					_, _ = ReadFile("nonexistent") // just to check allocs of the call
				} else {
					_, _ = ReadBytes(input)
				}
			})

			if allocs > 2000 { // Baseline bound
				t.Errorf("too many allocations in %s: %v", r.name, allocs)
			}
		})
	}
}

func TestReadBytesSizeLimit(t *testing.T) {
	data := make([]byte, 64*1024+1)
	_, err := ReadBytes(data)
	if err == nil || !strings.Contains(err.Error(), "config file exceeds 64 KiB limit") {
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
	}

	for _, in := range inputs {
		f.Add([]byte(in))
	}

	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = ReadBytes(b)
	})
}
