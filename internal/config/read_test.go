package config
import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

type mockFileInfo struct {
	name    string
	size    int64
	mode    os.FileMode
	uid     uint32
}

func (m *mockFileInfo) Name() string       { return m.name }
func (m *mockFileInfo) Size() int64        { return m.size }
func (m *mockFileInfo) Mode() os.FileMode  { return m.mode }
func (m *mockFileInfo) ModTime() time.Time { return time.Time{} }
func (m *mockFileInfo) IsDir() bool        { return m.mode.IsDir() }
func (m *mockFileInfo) Sys() interface{}   { return nil }
func (m *mockFileInfo) Uid() uint32        { return m.uid }


func TestTS10_FileSize(t *testing.T) {
	// T-S-10: > 64 KiB (rejected before parse)
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "large.yaml")
	data := make([]byte, 64*1024+1)
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}

	_, err := ReadFile(path, ReadOptions{})
	if err == nil || err.Error() != fmt.Sprintf("config file %q: config file exceeds 64 KiB limit", path) {
		t.Errorf("expected size error, got %v", err)
	}
}

func TestTS10_UTF8(t *testing.T) {
	// T-S-10: invalid UTF-8
	data := []byte{0xff, 0xfe, 0xfd}
	_, err := ReadBytes(data)
	if err == nil || err.Error() != "config: invalid UTF-8 encoding" {
		t.Errorf("expected utf8 error, got %v", err)
	}
}

func TestTS10_NUL(t *testing.T) {
	// T-S-10: NUL byte
	data := []byte("foo: bar\x00baz")
	_, err := ReadBytes(data)
	if err == nil || err.Error() != "config: contains NUL byte" {
		t.Errorf("expected nul error, got %v", err)
	}
}

func TestTS10_BOM(t *testing.T) {
	// T-S-10: BOM
	data := []byte("\xef\xbb\xbffoo: bar")
	_, err := ReadBytes(data)
	if err == nil || err.Error() != "config: contains UTF-8 BOM" {
		t.Errorf("expected bom error, got %v", err)
	}
}

func TestTS10_Alias(t *testing.T) {
	// T-S-10: alias
	data := []byte("anchor: &a value\nalias: *a")
	_, err := ReadBytes(data)
	if err == nil {
		t.Fatal("expected error for alias")
	}
}

func TestTS10_Anchor(t *testing.T) {
	// T-S-10: anchor
	data := []byte("anchor: &a value")
	_, err := ReadBytes(data)
	if err == nil {
		t.Fatal("expected error for anchor")
	}
}

func TestTS10_MergeKey(t *testing.T) {
	// T-S-10: merge key
	data := []byte("base: { a: 1 }\nchild: { <<: *base }") // Also uses alias
	_, err := ReadBytes(data)
	if err == nil {
		t.Fatal("expected error for merge key")
	}
}

func TestTS10_CustomTag(t *testing.T) {
	// T-S-10: custom tag
	data := []byte("foo: !!custom value")
	_, err := ReadBytes(data)
	if err == nil {
		t.Fatal("expected error for custom tag")
	}
}

func TestTS10_SecondDocument(t *testing.T) {
	// T-S-10: second document
	data := []byte("foo: bar\n---\nbaz: qux")
	_, err := ReadBytes(data)
	if err == nil {
		t.Fatal("expected error for second document")
	}
}

func TestTS10_Depth(t *testing.T) {
	// T-S-10: depth 9
	data := []byte("a: { b: { c: { d: { e: { f: { g: { h: { i: 1 } } } } } } } }")
	_, err := ReadBytes(data)
	if err == nil {
		t.Fatal("expected error for depth > 8")
	}
}

func TestTS10_DuplicateKey(t *testing.T) {
	// T-S-10: duplicate key
	data := []byte("foo: 1\nfoo: 2")
	_, err := ReadBytes(data)
	if err == nil {
		t.Fatal("expected error for duplicate key")
	}
}

func TestTS10_DuplicateKeyPath(t *testing.T) {
	// T-S-10: duplicate key by full path
	data := []byte("outer: { inner: 1 }\nouter: { inner: 2 }")
	_, err := ReadBytes(data)
	if err == nil {
		t.Fatal("expected error for duplicate key path")
	}
}

func TestTS10_DottedKey(t *testing.T) {
	// T-S-10: dotted key
	data := []byte("foo.bar: 1")
	_, err := ReadBytes(data)
	if err == nil {
		t.Fatal("expected error for dotted key")
	}
}

func TestTS10_EmptyKey(t *testing.T) {
	// T-S-10: empty key
	data := []byte(" : 1")
	_, err := ReadBytes(data)
	if err == nil {
		t.Fatal("expected error for empty key")
	}
}

func TestTS10_LiteralVariable(t *testing.T) {
	// T-S-10: ${HOME} stays literal
	data := []byte("foo: ${HOME}")
	doc, err := ReadBytes(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if doc.Leaves["foo"].Value != "${HOME}" {
		t.Errorf("expected ${HOME}, got %q", doc.Leaves["foo"].Value)
	}
}

func TestTS10_FIFO(t *testing.T) {
	// T-S-10: FIFO path (does not block)
	tmpDir := t.TempDir()
	fifoPath := filepath.Join(tmpDir, "fifo")
	err := syscall.Mkfifo(fifoPath, 0666)
	if err != nil {
		t.Fatalf("failed to create fifo: %v", err)
	}

	_, err = ReadFile(fifoPath, ReadOptions{})
	if err == nil {
		t.Fatal("expected error for FIFO")
	}
}

func TestTS10_GroupWritable(t *testing.T) {
	// T-S-10: group-writable file
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(path, []byte("foo: bar"), 0664); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0664); err != nil {
		t.Fatal(err)
	}

	_, err := ReadFile(path, ReadOptions{})
	if err == nil {
		t.Fatal("expected error for group-writable file")
	}
}

func TestTS10_WrongOwner(t *testing.T) {
	// T-S-10: wrong owner (via the fake stat)
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(path, []byte("foo: bar"), 0644); err != nil {
		t.Fatal(err)
	}

	mock := &mockFileInfo{
		name: "config.yaml",
		size: 8,
		mode: 0, // Regular file
		uid:  12345, // Not 0 and not euid usually
	}


	_, err := ReadFile(path, ReadOptions{
		Stat: func(p string) (os.FileInfo, error) {
			return mock, nil
		},
	})

	if err == nil {
		t.Fatal("expected error for wrong owner")
	}
}

func FuzzRead(f *testing.F) {
	// Seed with fixed cases
	f.Add([]byte("foo: bar"))
	f.Add([]byte("anchor: &a value\nalias: *a"))
	f.Add([]byte("foo: 1\nfoo: 2"))
	f.Add([]byte("\xef\xbb\xbffoo: bar"))

	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = ReadBytes(b)
	})
}
