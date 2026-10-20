package safefile

import (
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

// importers gives the .go files below dir that do not end in _test.go and
// import path. It reads only the imports of each file. It reads a file with
// a build constraint too.
func importers(dir, path string) ([]string, error) {
	var found []string
	fset := token.NewFileSet()
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == "node_modules") {
			return filepath.SkipDir
		}
		name := d.Name()
		if d.IsDir() || !strings.HasSuffix(name, ".go") ||
			strings.HasSuffix(name, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, p, nil, parser.ImportsOnly)
		if err != nil {
			return err
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
	sub := filepath.Join(dir, "pkg", "deep")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	plant := func(rel, src string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, rel), []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	plant("pkg/named.go", "package pkg\n\nimport st \""+testHelperPath+"\"\n\nvar _ = st.Set\n")
	plant("pkg/deep/blank.go", "package deep\n\nimport _ \""+testHelperPath+"\"\n")
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
	want := []string{"grouped.go", "ignored.go", "pkg/deep/blank.go", "pkg/named.go"}
	if !slices.Equal(found, want) {
		t.Errorf("found %v, want %v", found, want)
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
