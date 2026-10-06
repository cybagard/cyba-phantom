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
		{"EmptyKey", "\"\": 1", false, 0, 0, "mapping key cannot be empty", ""},
		{"MergeKey", "a: 1\n<<: {b: 2}", false, 0, 0, "mapping key tag \"!!merge\" is rejected", ""},
		{"DottedKey", "foo.bar: 1", false, 0, 0, "cannot contain dot", ""},
		{"Alias", "anchor: &a value\nalias: *a", false, 0, 0, "anchors are rejected", ""},
		{"Anchor", "anchor: &a value", false, 0, 0, "anchors are rejected", ""},
		{"CustomTag", "foo: !!custom value", false, 0, 0, "custom tag", ""},
		{"DuplicateKey", "foo: 1\nfoo: 2", false, 0, 0, "duplicate key", ""},
		{"DuplicateKeyPath", "outer: { inner: 1 }\nouter: { inner: 2 }", false, 0, 0, "duplicate key", ""},
		{"Depth8", "a:\n  b:\n    c:\n      d:\n        e:\n          f:\n            g:\n              h: 1", false, 0, 0, "", ""},
		{"Depth9", "a:\n  b:\n    c:\n      d:\n        e:\n          f:\n            g:\n              h:\n                i: 1", false, 0, 0, "nesting exceeds limit of 8", ""},
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

				doc, err = ReadFile(path, ReadOptions{})
			} else {
				doc, err = ReadBytes([]byte(r.input))
			}

			if r.wantRule == "" {
				if err != nil {
					t.Errorf("expected no error, got %v", err)
				} else if doc == nil {
					t.Error("expected doc, got nil")
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
		})
	}
}

func TestAllocs(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{"Size", "foo: bar"}, // We'll use a large input here
		{"Depth", "a: { b: { c: { d: { e: { f: { g: { h: 1 } } } } } } }"},
		{"Alias", "anchor: &a value\nalias: *a"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var input []byte
			if c.name == "Size" {
				input = make([]byte, 64*1024)
				copy(input, "foo: bar") // just some content
			} else {
				input = []byte(c.input)
			}

			allocs := testing.AllocsPerRun(10, func() {
				_, _ = ReadBytes(input)
			})

			if allocs > 1000 { // Arbitrary bound, should be checked
				t.Errorf("too many allocations: %v", allocs)
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

	// Check that ReadBytes doesn't read more than 64KiB + 1
	// This is harder to test without a custom reader, but ReadFile uses LimitReader.
}

func FuzzRead(f *testing.F) {
	// Seed with table inputs
	inputs := []string{
		"foo: bar",
		" : 1",
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
	}

	for _, in := range inputs {
		f.Add([]byte(in))
	}

	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = ReadBytes(b)
	})
}
