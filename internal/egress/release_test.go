package egress_test

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

const modPath = "github.com/cybagard/cyba-phantom"

// moduleRoot gives the module root and fails t when it is not the module.
func moduleRoot(t *testing.T) string {
	t.Helper()
	top := filepath.Join("..", "..")
	mod, err := os.ReadFile(filepath.Join(top, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	line := "module " + modPath
	if !slices.ContainsFunc(strings.Split(string(mod), "\n"), func(l string) bool {
		return strings.TrimSpace(l) == line
	}) {
		t.Fatalf("%s is not the module root: no line %q", top, line)
	}
	return top
}

// goCommand makes a go tool command that runs in dir. GOFLAGS stops the tool
// from changing go.mod. Each entry of env replaces the entry of the test.
func goCommand(t *testing.T, dir string, env []string, args ...string) *exec.Cmd {
	t.Helper()
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("the go tool is not on PATH: %v", err)
	}
	cmd := exec.Command(goTool, args...)
	cmd.Dir = dir
	cmd.Env = append(append(os.Environ(), "GOFLAGS=-mod=readonly"), env...)
	return cmd
}

func TestTS21ReleaseCommandsDoNotListTestSeam(t *testing.T) {
	root := moduleRoot(t)
	commands := []string{modPath + "/cmd/phantom", modPath + "/cmd/phantom-verify"}
	seams := []string{
		modPath + "/internal/egress/egresstest",
		modPath + "/internal/egress/internal/seam",
	}
	// The empty GOOS is the GOOS of the host.
	for _, goos := range []string{"linux", ""} {
		name, env := "default", []string(nil)
		if goos != "" {
			name, env = goos, []string{"GOOS=" + goos}
		}
		t.Run(name, func(t *testing.T) {
			cmd := goCommand(t, root, env, append([]string{"list", "-deps"}, commands...)...)
			out, err := cmd.Output()
			if err != nil {
				var exitErr *exec.ExitError
				if errors.As(err, &exitErr) {
					t.Fatalf("go list -deps: %v\n%s", err, exitErr.Stderr)
				}
				t.Fatalf("go list -deps: %v", err)
			}
			deps := strings.Fields(string(out))
			for _, c := range commands {
				if !slices.Contains(deps, c) {
					t.Errorf("go list -deps did not list %s", c)
				}
			}
			for _, s := range seams {
				if slices.Contains(deps, s) {
					t.Errorf("a release command depends on %s", s)
				}
			}
		})
	}
}

// The notest command calls egresstest in a binary that is not a test binary.
func TestTS21EgresstestFailsOutsideTestBinary(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "notest")
	build := goCommand(t, moduleRoot(t), nil,
		"build", "-o", bin, "./internal/egress/testdata/notest")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	out, err := exec.Command(bin).CombinedOutput()
	if err != nil {
		t.Fatalf("notest: %v\n%s", err, out)
	}
	for _, want := range []string{
		"testing.Testing=false", "Dialer failed=true", "NewNames failed=true",
	} {
		if !slices.Contains(strings.Split(string(out), "\n"), want) {
			t.Errorf("notest output lacks %q:\n%s", want, out)
		}
	}
}

// finding is one use of a banned form in one file.
type finding struct {
	File string // slash path relative to the scan root
	Line int
	Form string
}

func (f finding) String() string {
	return fmt.Sprintf("%s:%d: %s", f.File, f.Line, f.Form)
}

// banned lists, for each import path, the names that make or use a dialer
// with no address rule.
var banned = map[string][]string{
	"net":        {"Dial", "DialTimeout", "DialTCP", "DialUDP", "DialIP", "DialUnix"},
	"crypto/tls": {"Dial", "DialWithDialer"},
	"net/http": {"DefaultClient", "DefaultTransport", "Get", "Post", "PostForm",
		"Head"},
	"net/smtp":   {"Dial", "SendMail"},
	"log/syslog": {"Dial"},
}

// noRuleTypes lists the types whose value, with no pointer, dials with no
// address rule. The pointer type *T only holds a dialer that code made
// elsewhere.
var noRuleTypes = map[string][]string{
	"net":        {"Dialer"},
	"crypto/tls": {"Dialer"},
	"net/http":   {"Transport"},
}

// egressImports are the packages that code in internal/egress must not import.
var egressImports = []string{"os", "flag", "os/exec"}

// dialerHooks are the fields of net.Dialer that hold the address rule.
var dialerHooks = []string{"ControlContext", "Control"}

// scan parses each .go file below root, except test files. It skips what the
// go tool skips. Those are testdata directories and directories with a name
// that starts with "." or "_". It gives the findings, with paths relative to
// root.
func scan(root string) ([]finding, error) {
	var out []finding
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := d.Name()
		if d.IsDir() {
			if p != root && (name == "testdata" ||
				strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, p, nil, parser.ParseComments)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		for _, x := range scanFile(fset, f, strings.HasPrefix(rel, "internal/egress/")) {
			x.File = rel
			out = append(out, x)
		}
		return nil
	})
	slices.SortFunc(out, func(a, b finding) int {
		if c := strings.Compare(a.File, b.File); c != 0 {
			return c
		}
		if a.Line != b.Line {
			return a.Line - b.Line
		}
		return strings.Compare(a.Form, b.Form)
	})
	return out, err
}

// scanFile gives the findings in f, with no File. inEgress is true for a file
// in internal/egress or below. The syntax tree has no types. Thus the scan
// reads the package of a selector from the imports of the file. It finds the
// fields ControlContext and Control by name only.
func scanFile(fset *token.FileSet, f *ast.File, inEgress bool) []finding {
	var out []finding
	add := func(p token.Pos, form string) {
		out = append(out, finding{Line: fset.Position(p).Line, Form: form})
	}
	local := map[string]string{} // local package name to import path
	for _, imp := range f.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			continue
		}
		if inEgress && slices.Contains(egressImports, p) {
			add(imp.Pos(), "import "+p)
		}
		name := path.Base(p)
		if imp.Name != nil {
			name = imp.Name.Name
		}
		switch {
		case name == "_":
		case name == ".":
			if _, ok := banned[p]; ok && !inEgress {
				add(imp.Pos(), "dot import "+p)
			}
		default:
			local[name] = p
		}
	}
	for _, g := range f.Comments {
		for _, c := range g.List {
			if strings.HasPrefix(c.Text, "//go:linkname") {
				add(c.Pos(), "go:linkname directive")
			}
		}
	}
	if inEgress {
		return out
	}

	// pointed holds the types that follow a star. lits holds the type of each
	// composite literal.
	pointed := map[ast.Expr]bool{}
	lits := map[ast.Expr]*ast.CompositeLit{}
	ast.Inspect(f, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.StarExpr:
			pointed[n.X] = true
		case *ast.CompositeLit:
			if n.Type != nil {
				lits[n.Type] = n
			}
		}
		return true
	})
	// pkgName gives the import path and the name that n selects. An identifier
	// that the file declares locally is not a package.
	pkgName := func(n ast.Node) (pkg, name string) {
		s, ok := n.(*ast.SelectorExpr)
		if !ok {
			return "", ""
		}
		if id, ok := s.X.(*ast.Ident); ok && id.Obj == nil {
			return local[id.Name], s.Sel.Name
		}
		return "", ""
	}
	ast.Inspect(f, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.SelectorExpr:
			p, name := pkgName(n)
			form := path.Base(p) + "." + name
			switch {
			case slices.Contains(banned[p], name):
				add(n.Pos(), form)
			case slices.Contains(noRuleTypes[p], name) && !pointed[n]:
				lit := lits[n]
				switch {
				case lit == nil:
					add(n.Pos(), form+" used with no pointer")
				case p == "net/http":
					for _, form := range transportForms(lit) {
						add(n.Pos(), form)
					}
				default:
					add(n.Pos(), form+" literal")
				}
			case p == "net/http" && name == "Client" && lits[n] != nil:
				if !hasKey(lits[n], "Transport") {
					add(n.Pos(), "http.Client literal without Transport")
				}
			}
		case *ast.CallExpr:
			// new(http.Client) uses http.DefaultTransport.
			if id, ok := n.Fun.(*ast.Ident); ok && id.Name == "new" &&
				id.Obj == nil && len(n.Args) == 1 {
				if p, name := pkgName(n.Args[0]); p == "net/http" && name == "Client" {
					add(n.Pos(), "new(http.Client)")
				}
			}
		case *ast.AssignStmt:
			for _, l := range n.Lhs {
				if s, ok := l.(*ast.SelectorExpr); ok &&
					slices.Contains(dialerHooks, s.Sel.Name) {
					add(s.Pos(), "write to "+s.Sel.Name)
				}
			}
		case *ast.UnaryExpr:
			if s, ok := n.X.(*ast.SelectorExpr); ok && n.Op == token.AND &&
				slices.Contains(dialerHooks, s.Sel.Name) {
				add(n.Pos(), "address of "+s.Sel.Name)
			}
		}
		return true
	})
	return out
}

// hasKey tells if lit has an element with the field name key.
func hasKey(lit *ast.CompositeLit, key string) bool {
	for _, e := range lit.Elts {
		if kv, ok := e.(*ast.KeyValueExpr); ok {
			if id, ok := kv.Key.(*ast.Ident); ok && id.Name == key {
				return true
			}
		}
	}
	return false
}

// transportForms gives the findings for an http.Transport literal.
func transportForms(lit *ast.CompositeLit) []string {
	var out []string
	if !hasKey(lit, "DialContext") {
		out = append(out, "http.Transport literal without DialContext")
	}
	for _, k := range []string{"DialTLSContext", "DialTLS"} {
		if hasKey(lit, k) {
			out = append(out, "http.Transport literal with "+k)
		}
	}
	return out
}

func TestTS21SourceHasNoDialerOutsideGuard(t *testing.T) {
	found, err := scan(moduleRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range found {
		t.Error(f)
	}
}

func TestTS21ScanFindsPlantedFiles(t *testing.T) {
	dir := t.TempDir()
	plant := func(rel, src string) {
		t.Helper()
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// file gives a file with the imports and the body.
	file := func(imports, body string) string {
		return "package p\n\nimport (\n" + imports + ")\n\n" + body + "\n"
	}
	want := map[string][]string{} // file to the forms that the scan must find
	plantWant := func(rel, src string, forms ...string) {
		t.Helper()
		plant(rel, src)
		want[rel] = forms
	}

	// Each banned name, with the package named by its own import.
	for p, names := range banned {
		for _, name := range names {
			rel := "banned_" + path.Base(p) + "_" + name + ".go"
			plantWant(rel, file("\t\""+p+"\"\n", "var _ = "+path.Base(p)+"."+name),
				path.Base(p)+"."+name)
		}
	}
	// An import alias does not hide the package.
	plantWant("alias.go", file("\tn \"net\"\n\tt \"crypto/tls\"\n\th \"net/http\"\n",
		"var _ = n.DialTimeout\nvar _ = t.Dialer{}\nvar _ = h.DefaultClient"),
		"net.DialTimeout", "tls.Dialer literal", "http.DefaultClient")
	plantWant("aliased_dialer.go", file("\tn \"net\"\n", "var _ = &n.Dialer{}"),
		"net.Dialer literal")
	plantWant("dial.go", file("\t\"net\"\n", "var _, _ = net.Dial(\"tcp\", \"a:1\")"),
		"net.Dial")

	// A dialer, a transport or a client with no rule.
	plantWant("net_dialer_lit.go", file("\t\"net\"\n", "var _ = &net.Dialer{}"),
		"net.Dialer literal")
	plantWant("net_dialer_new.go", file("\t\"net\"\n", "var _ = new(net.Dialer)"),
		"net.Dialer used with no pointer")
	plantWant("net_dialer_var.go", file("\t\"net\"\n", "var d net.Dialer"),
		"net.Dialer used with no pointer")
	plantWant("net_dialer_field.go", file("\t\"net\"\n",
		"type a struct{ d net.Dialer }\ntype b struct{ net.Dialer }"),
		"net.Dialer used with no pointer", "net.Dialer used with no pointer")
	plantWant("tls_dialer_lit.go", file("\t\"crypto/tls\"\n", "var _ = &tls.Dialer{}"),
		"tls.Dialer literal")
	plantWant("tls_dialer_new.go", file("\t\"crypto/tls\"\n", "var _ = new(tls.Dialer)"),
		"tls.Dialer used with no pointer")
	plantWant("transport_none.go", file("\t\"net/http\"\n", "var _ = &http.Transport{}"),
		"http.Transport literal without DialContext")
	plantWant("transport_tls_context.go", file("\t\"net/http\"\n",
		"var _ = &http.Transport{DialContext: nil, DialTLSContext: nil}"),
		"http.Transport literal with DialTLSContext")
	plantWant("transport_tls.go", file("\t\"net/http\"\n",
		"var _ = &http.Transport{DialContext: nil, DialTLS: nil}"),
		"http.Transport literal with DialTLS")
	plantWant("transport_new.go", file("\t\"net/http\"\n", "var _ = new(http.Transport)"),
		"http.Transport used with no pointer")
	plantWant("transport_var.go", file("\t\"net/http\"\n", "var t http.Transport"),
		"http.Transport used with no pointer")
	plantWant("client_lit.go", file("\t\"net/http\"\n", "var _ = &http.Client{}"),
		"http.Client literal without Transport")
	plantWant("client_new.go", file("\t\"net/http\"\n", "var _ = new(http.Client)"),
		"new(http.Client)")

	// A write to the hook of a dialer.
	for _, tc := range []struct{ src, form string }{
		{"d.ControlContext = nil", "write to ControlContext"},
		{"d.Control = nil", "write to Control"},
		{"_ = &d.ControlContext", "address of ControlContext"},
		{"_ = &d.Control", "address of Control"},
	} {
		name := strings.NewReplacer(" ", "_", ".", "_", "=", "", "&", "").Replace(tc.src)
		plantWant("write_"+name+".go",
			file("", "type dialer struct{ Control, ControlContext func() }\n"+
				"func f(d *dialer) {\n\t"+tc.src+"\n}"),
			tc.form)
	}

	// A dot import of a package that makes dialers.
	for p := range banned {
		plantWant("dot_"+path.Base(p)+".go", file("\t. \""+p+"\"\n", ""),
			"dot import "+p)
	}

	// A directive, and code in internal/egress.
	plantWant("link.go", "package p\n\n//go:linkname f runtime.f\nfunc f()\n",
		"go:linkname directive")
	plantWant("internal/egress/link.go", "package egress\n\n//go:linkname f runtime.f\nfunc f()\n",
		"go:linkname directive")
	for _, imp := range egressImports {
		plantWant("internal/egress/deep/"+path.Base(imp)+".go",
			file("\t\""+imp+"\"\n", "var _ = "+path.Base(imp)+".Args"), "import "+imp)
	}

	// The scan finds nothing in these files.
	plant("x_test.go", file("\t\"net\"\n", "var _, _ = net.Dial(\"tcp\", \"a:1\")"))
	plant("testdata/x.go", file("\t\"net\"\n", "var _, _ = net.Dial(\"tcp\", \"a:1\")"))
	plant(".hidden/x.go", file("\t\"net\"\n", "var _, _ = net.Dial(\"tcp\", \"a:1\")"))
	plant("_skipped/x.go", file("\t\"net\"\n", "var _, _ = net.Dial(\"tcp\", \"a:1\")"))
	plant("comment.go", "package p\n\n// the text //go:linkname is not a directive\n"+
		"/* //go:linkname is not a directive */\n")
	plant("pointer.go", file("\t\"net\"\n", "type s struct{ d *net.Dialer }\n"+
		"func f(d *net.Dialer) *net.Dialer { return d }"))
	plant("transport_ok.go", file("\t\"net/http\"\n",
		"var _ = &http.Transport{DialContext: nil}"))
	plant("client_ok.go", file("\t\"net/http\"\n", "var _ = &http.Client{Transport: nil}"))
	plant("shadow.go", file("\t\"net\"\n", "func f(net struct{ Dial func() }) {\n"+
		"\tnet.Dial()\n}"))
	plant("not_hook.go", file("", "type c struct{ Control func() }\n"+
		"func f(x c) func() { return x.Control }"))
	plant("internal/egress/write.go", file("\t\"net\"\n",
		"func f(d *net.Dialer) { d.ControlContext = nil; d.Control = nil\n"+
			"\t_ = &d.Control; _ = &net.Dialer{} }"))
	plant("internal/egress/egresstest/write.go", file("\t\"net\"\n",
		"func f(d *net.Dialer) { d.ControlContext = nil }"))

	got, err := scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	gotForms := map[string][]string{}
	for _, f := range got {
		gotForms[f.File] = append(gotForms[f.File], f.Form)
	}
	for rel, forms := range want {
		slices.Sort(forms)
		g := gotForms[rel]
		slices.Sort(g)
		if !slices.Equal(g, forms) {
			t.Errorf("%s: found %q, want %q", rel, g, forms)
		}
		delete(gotForms, rel)
	}
	for rel, forms := range gotForms {
		t.Errorf("%s: unexpected findings %q", rel, forms)
	}
	// The finding names the line.
	for _, f := range got {
		if f.File == "dial.go" && f.String() != "dial.go:7: net.Dial" {
			t.Errorf("finding is %q, want %q", f, "dial.go:7: net.Dial")
		}
	}
}

func TestTS21ScanReportsFileThatDoesNotParse(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bad.go"), []byte("not go"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := scan(dir); err == nil {
		t.Error("no error for a file that does not parse")
	}
}
