package config

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// TestTS10_NoSystemNetwork checks that the non-test files of this package use the system
// network only in SystemNet (SEC-11). A rule violation is net.Dial*, net.Lookup*,
// net.DefaultResolver, net.Resolver, or an import of net/http. The interface
// declarations use net.Conn only, so they are allowed.
func TestTS10_NoSystemNetwork(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range f.Imports {
			if imp.Path.Value == `"net/http"` {
				t.Errorf("%s: imports net/http", fset.Position(imp.Pos()))
			}
		}
		for _, decl := range f.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == "SystemNet" && fn.Recv == nil {
				continue // SystemNet builds the system Net.
			}
			ast.Inspect(decl, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if id, ok := sel.X.(*ast.Ident); ok && id.Name == "net" {
					s := sel.Sel.Name
					if strings.HasPrefix(s, "Dial") || strings.HasPrefix(s, "Lookup") || s == "DefaultResolver" || s == "Resolver" {
						t.Errorf("%s: uses net.%s", fset.Position(sel.Pos()), s)
					}
				}
				return true
			})
		}
	}
}
