package safefile

import (
	"errors"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

const testHelperPath = "github.com/cybagard/cyba-phantom/internal/safefile/safefiletest"

// walkError gives the error that stops the walk of dir at p. An entry that
// another test removes during the walk is not an error. The dir itself must
// exist.
func walkError(dir, p string, err error) error {
	if err != nil && p != dir && errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

// importers gives the .go files below dir that do not end in _test.go and
// import path. It reads only the imports of each file. It reads a file with
// a build constraint too. It skips an entry that is removed during the walk.
func importers(dir, path string) ([]string, error) {
	var found []string
	fset := token.NewFileSet()
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return walkError(dir, p, err)
		}
		if d.IsDir() && d.Name() == ".git" {
			return filepath.SkipDir
		}
		name := d.Name()
		if d.IsDir() || !strings.HasSuffix(name, ".go") ||
			strings.HasSuffix(name, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, p, nil, parser.ImportsOnly)
		if err != nil {
			return walkError(dir, p, err)
		}
		for _, imp := range f.Imports {
			if s, err := strconv.Unquote(imp.Path.Value); err == nil && s == path {
				rel, err := filepath.Rel(dir, p)
				if err != nil {
					return err
				}
				found = append(found, filepath.ToSlash(rel))
				break
			}
		}
		return nil
	})
	return found, err
}

func TestTS23_NoNonTestFileImportsSafefiletest(t *testing.T) {
	top := filepath.Join("..", "..")
	mod, err := os.ReadFile(filepath.Join(top, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	const line = "module github.com/cybagard/cyba-phantom"
	if !slices.ContainsFunc(strings.Split(string(mod), "\n"), func(l string) bool {
		return strings.TrimSpace(l) == line
	}) {
		t.Fatalf("%s is not the module root: no line %q", top, line)
	}
	found, err := importers(top, testHelperPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 0 {
		t.Errorf("non-test files import safefiletest: %v", found)
	}
}

func TestTS23_ImportersFindsPlantedFiles(t *testing.T) {
	dir := t.TempDir()
	for _, d := range []string{"pkg/deep", "pkg/node_modules/dep"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	plant := func(rel, src string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, rel), []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	plant("pkg/named.go", "package pkg\n\nimport st \""+testHelperPath+"\"\n\nvar _ = st.Set\n")
	plant("pkg/deep/blank.go", "package deep\n\nimport _ \""+testHelperPath+"\"\n")
	plant("pkg/node_modules/dep/vendored.go",
		"package dep\n\nimport \""+testHelperPath+"\"\n")
	plant("ignored.go", "//go:build ignore\n\npackage x\n\nimport \""+testHelperPath+"\"\n")
	plant("grouped.go", "package x\n\nimport (\n\t\"os\"\n\t\""+testHelperPath+"\"\n)\n")
	plant("pkg/clean.go", "package pkg\n\nimport \"os\"\n\nvar _ = os.Args\n")
	plant("pkg/planted_test.go", "package pkg\n\nimport \""+testHelperPath+"\"\n")
	plant("pkg/notgo.txt", "import \""+testHelperPath+"\"\n")

	found, err := importers(dir, testHelperPath)
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(found)
	want := []string{"grouped.go", "ignored.go", "pkg/deep/blank.go", "pkg/named.go",
		"pkg/node_modules/dep/vendored.go"}
	if !slices.Equal(found, want) {
		t.Errorf("found %v, want %v", found, want)
	}
}

func TestTS23_ImportersReportsMissingDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "none")
	if _, err := importers(dir, testHelperPath); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("err = %v, want fs.ErrNotExist", err)
	}
}

func TestTS23_WalkErrorSkipsRemovedEntry(t *testing.T) {
	gone := &fs.PathError{Op: "open", Path: "x/y", Err: fs.ErrNotExist}
	if err := walkError("x", "x/y", gone); err != nil {
		t.Errorf("removed entry: err = %v, want nil", err)
	}
	if err := walkError("x", "x", gone); err == nil {
		t.Error("missing dir: no error")
	}
	other := &fs.PathError{Op: "open", Path: "x/y", Err: fs.ErrPermission}
	if err := walkError("x", "x/y", other); err == nil {
		t.Error("other error: no error")
	}
}

func TestTS23_ImportersReportsUnreadableFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bad.go"), []byte("not go"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := importers(dir, testHelperPath); err == nil {
		t.Error("no error for a file that does not parse")
	}
}
