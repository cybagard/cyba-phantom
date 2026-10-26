package config

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// TestTS10_NoSystemNetwork (SEC-11) parses the non-test files of internal/config and fails
// on the forms below. The local name of an import is its alias, if any.
// So in nn "net", the local name of the import of the package net is nn.
// The test fails on:
//   - a selector X.Y outside the declaration of the function SystemNet.
//     X is the local name of the import of the package net, and Y is not
//     Conn. One exemption: net.SplitHostPort in the file validate.go.
//     It parses a string and opens no socket;
//   - a call expression whose function is the identifier SystemNet, outside the declaration
//     of the function Load;
//   - a dot import of net or syscall;
//   - an import of net/http, net/smtp, net/rpc, crypto/tls, golang.org/x/net, or a path
//     below one of them;
//   - a selector X.Y where X is the local name of the import of the package
//     syscall. Y is Socket, Socketpair, Connect, Bind, Listen, Sendto, or
//     Sendmsg.
//
// The test does not detect every way to use the network. It misses, for
// example, a parenthesised call (SystemNet)() and a function value of
// SystemNet. It also misses the packages net/textproto, log/syslog and
// os/exec, and the function syscall.Syscall.
// The proof that --check uses no network is the injected-network tests:
// TestTS10_CheckNoDial and TestTS10_CheckWiring.
func TestTS10_NoSystemNetwork(t *testing.T) {
	sockets := []string{"Socket", "Socketpair", "Connect", "Bind", "Listen", "Sendto", "Sendmsg"}
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
		// local holds the local names of the packages net and syscall.
		local := map[string]string{}
		for _, imp := range f.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			for _, b := range []string{"net/http", "net/smtp", "net/rpc", "crypto/tls", "golang.org/x/net"} {
				if p == b || strings.HasPrefix(p, b+"/") {
					t.Errorf("%s: imports %s", fset.Position(imp.Pos()), p)
				}
			}
			if p != "net" && p != "syscall" {
				continue
			}
			n := path.Base(p)
			if imp.Name != nil {
				n = imp.Name.Name
			}
			if n == "." {
				t.Errorf("%s: dot import of %s", fset.Position(imp.Pos()), p)
			}
			local[n] = p
		}
		for _, decl := range f.Decls {
			fn, _ := decl.(*ast.FuncDecl)
			in := func(name string) bool { return fn != nil && fn.Recv == nil && fn.Name.Name == name }
			ast.Inspect(decl, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.CallExpr:
					if id, ok := x.Fun.(*ast.Ident); ok && id.Name == "SystemNet" && !in("Load") {
						t.Errorf("%s: calls SystemNet outside Load", fset.Position(x.Pos()))
					}
				case *ast.SelectorExpr:
					id, ok := x.X.(*ast.Ident)
					if !ok {
						return true
					}
					switch s := x.Sel.Name; local[id.Name] {
					case "net":
						parseOnly := name == "validate.go" && s == "SplitHostPort"
						if s != "Conn" && !parseOnly && !in("SystemNet") {
							t.Errorf("%s: uses net.%s", fset.Position(x.Pos()), s)
						}
					case "syscall":
						if slices.Contains(sockets, s) {
							t.Errorf("%s: uses syscall.%s", fset.Position(x.Pos()), s)
						}
					}
				}
				return true
			})
		}
	}
}

// stubNet is a Dialer and a Resolver. No test calls a method of it.
type stubNet struct {
	Dialer
	Resolver
}

// TestTS10_ZeroNet (SEC-11): LoadWith returns an error that names the missing field if
// the Dialer or the Resolver of the Net is nil.
func TestTS10_ZeroNet(t *testing.T) {
	for want, n := range map[string]Net{"Dialer": {Resolver: stubNet{}}, "Resolver": {Dialer: stubNet{}}} {
		if _, err := LoadWith("unused.yaml", nil, n); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("error %v does not name %s", err, want)
		}
	}
}
