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
	"runtime"
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

// buildConfig is a platform for the release build. An empty field is the
// value of the host.
type buildConfig struct{ goos, goarch string }

// releaseConfigs are the platforms of the release build: each linux target of
// go tool dist list. The Makefile sets no GOARCH, so the host platform counts.
var releaseConfigs = []buildConfig{
	{"linux", "386"}, {"linux", "amd64"}, {"linux", "arm"}, {"linux", "arm64"},
	{"linux", "loong64"}, {"linux", "mips"}, {"linux", "mips64"},
	{"linux", "mips64le"}, {"linux", "mipsle"}, {"linux", "ppc64"},
	{"linux", "ppc64le"}, {"linux", "riscv64"}, {"linux", "s390x"}, {"", ""},
}

func (c buildConfig) name() string {
	if c.goos == "" {
		return "default"
	}
	return c.goos + "/" + c.goarch
}

// env gives the environment entries for the platform, with cgo off. The
// release build of the Makefile does the same.
func (c buildConfig) env() []string {
	env := []string{"CGO_ENABLED=0"}
	if c.goos != "" {
		env = append(env, "GOOS="+c.goos, "GOARCH="+c.goarch)
	}
	return env
}

// contextError gives an error when got is not the build context of c with cgo
// off. got has the form GOOS/GOARCH/CgoEnabled.
func contextError(got string, c buildConfig) error {
	goos, goarch := c.goos, c.goarch
	if goos == "" {
		goos, goarch = runtime.GOOS, runtime.GOARCH
	}
	if want := goos + "/" + goarch + "/false"; got != want {
		return fmt.Errorf("go list used the build context %s, want %s", got, want)
	}
	return nil
}

// listedDep is one package that go list -deps finds.
type listedDep struct {
	Path           string // import path
	Dir            string // folder of the package
	Module         string // path of the module, empty for the standard library
	Replace        string // path of the replacement of the module, if any
	ReplaceVersion string // version of the replacement, empty for a folder
}

// depFormat is the go list format. Each line has seven fields, split by tabs.
// The last field is the error of the package, quoted.
const depFormat = "{{context.GOOS}}/{{context.GOARCH}}/{{context.CgoEnabled}}\t" +
	"{{.ImportPath}}\t{{.Dir}}\t{{with .Module}}{{.Path}}{{end}}\t" +
	"{{with .Module}}{{with .Replace}}{{.Path}}{{end}}{{end}}\t" +
	"{{with .Module}}{{with .Replace}}{{.Version}}{{end}}{{end}}\t" +
	"{{with .Error}}{{printf \"%q\" .Err}}{{end}}"

// completeList tells if the list for c must have no package error. Other
// platforms can list a dependency that has no Go file for them.
func completeList(c buildConfig) bool {
	return c == buildConfig{"linux", "amd64"} || c == buildConfig{"linux", "arm64"} ||
		c == buildConfig{}
}

// listProblem tells why the list for a platform with a complete list is not
// good. It gives "" for a package with no error and a folder.
func listProblem(dir, errText string) string {
	switch {
	case errText != "":
		return "go list reports the error " + errText
	case dir == "":
		return "go list gives no folder"
	}
	return ""
}

// listDeps gives the build context and the packages that go list -deps finds
// for pkgs in the platform c. The context is the same for each package. The
// flag -e keeps the list for a platform where a dependency has no Go file.
// On a platform with completeList, a package error or no folder fails t.
func listDeps(t *testing.T, root string, c buildConfig, pkgs ...string) (string, []listedDep) {
	t.Helper()
	args := append([]string{"list", "-e", "-deps", "-f", depFormat}, pkgs...)
	out, err := goCommand(t, root, c.env(), args...).Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			t.Fatalf("go list -deps: %v\n%s", err, exitErr.Stderr)
		}
		t.Fatalf("go list -deps: %v", err)
	}
	ctx, deps, problems, err := parseDeps(string(out), c)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range problems {
		t.Error(p)
	}
	return ctx, deps
}

// parseDeps reads the output of go list with depFormat for the platform c. It
// gives the build context and the packages. It also gives one text for each
// package that listProblem refuses on a platform with completeList.
func parseDeps(out string, c buildConfig) (string, []listedDep, []string, error) {
	var ctx string
	var deps []listedDep
	var problems []string
	for _, line := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
		f := strings.Split(line, "\t")
		if len(f) != 7 || (ctx != "" && f[0] != ctx) {
			return "", nil, nil, fmt.Errorf("unexpected go list line %q", line)
		}
		ctx = f[0]
		if why := listProblem(f[2], f[6]); why != "" && completeList(c) {
			problems = append(problems, fmt.Sprintf("%s on %s: %s", f[1], c.name(), why))
		}
		deps = append(deps, listedDep{f[1], f[2], f[3], f[4], f[5]})
	}
	return ctx, deps, problems, nil
}

// workspaceError gives an error when got, the value of go env GOWORK, shows a
// workspace. A workspace can add a module folder that the module test misses.
func workspaceError(got string) error {
	if got = strings.TrimSpace(got); got != "" && got != "off" {
		return fmt.Errorf("go env GOWORK is %q, want empty or off", got)
	}
	return nil
}

// realPath gives the absolute path of p with each symbolic link resolved.
func realPath(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(abs)
}

// depProblem tells why a release command must not depend on d. It gives "" for
// a package that a command may import. realRoot is the real module root.
func depProblem(realRoot string, d listedDep) string {
	if why := releaseDepProblem(d.Path); why != "" {
		return why
	}
	if d.Replace != "" && d.ReplaceVersion == "" {
		return "its module " + d.Module + " has a replace with a local folder"
	}
	resolved, err := realPath(d.Dir)
	if err != nil {
		return "its folder " + d.Dir + " does not resolve: " + err.Error()
	}
	rel, err := filepath.Rel(realRoot, resolved)
	inside := err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
	switch {
	case !inside && d.Module == modPath:
		return "its real folder " + resolved + " is outside the module root"
	case !inside:
		return ""
	case d.Module != modPath:
		return "its module " + d.Module + " has a folder inside the module root"
	}
	imp := modPath
	if rel != "." {
		imp += "/" + filepath.ToSlash(rel)
	}
	if why := releaseDepProblem(imp); why != "" {
		return "its real path is " + imp + ": " + why
	}
	return ""
}

// releaseDepProblem tells why a release command must not depend on the
// package imp. It gives "" for a package that a command may import. Only the
// packages of this module have a problem.
func releaseDepProblem(imp string) string {
	rel, ok := strings.CutPrefix(imp, modPath+"/")
	if !ok {
		return ""
	}
	// A file system that ignores case maps internal/EGRESS to internal/egress.
	if strings.HasPrefix(strings.ToLower(rel), "internal/egress/") {
		return "it is below internal/egress"
	}
	for _, el := range strings.Split(rel, "/") {
		if strings.EqualFold(el, "testdata") || strings.HasPrefix(el, "_") ||
			strings.HasPrefix(el, ".") {
			return "its path has the element " + el
		}
	}
	return ""
}

// TestTS21ReleaseCommandsDoNotListTestSeam lists the dependencies of the
// release commands for each platform in releaseConfigs, with cgo off. It
// fails on each dependency that depProblem names, and on a go workspace.
func TestTS21ReleaseCommandsDoNotListTestSeam(t *testing.T) {
	root := moduleRoot(t)
	realRoot, err := realPath(root)
	if err != nil {
		t.Fatal(err)
	}
	work, err := goCommand(t, root, nil, "env", "GOWORK").Output()
	if err != nil {
		t.Fatalf("go env GOWORK: %v", err)
	}
	if err := workspaceError(string(work)); err != nil {
		t.Fatal(err)
	}
	commands := []string{modPath + "/cmd/phantom", modPath + "/cmd/phantom-verify"}
	for _, c := range releaseConfigs {
		t.Run(c.name(), func(t *testing.T) {
			ctx, deps := listDeps(t, root, c, commands...)
			if err := contextError(ctx, c); err != nil {
				t.Fatal(err)
			}
			for _, cmd := range commands {
				if !slices.ContainsFunc(deps, func(d listedDep) bool { return d.Path == cmd }) {
					t.Errorf("go list -deps did not list %s", cmd)
				}
			}
			for _, d := range deps {
				if why := depProblem(realRoot, d); why != "" {
					t.Errorf("a release command depends on %s: %s", d.Path, why)
				}
			}
		})
	}
}

// TestTS21ReleaseDependencyRule checks releaseDepProblem on the two test-seam
// paths, on other paths with a problem and on permitted paths.
func TestTS21ReleaseDependencyRule(t *testing.T) {
	for imp, bad := range map[string]bool{
		modPath + "/internal/egress/egresstest":        true,
		modPath + "/internal/egress/internal/seam":     true,
		modPath + "/internal/egress/other":             true,
		modPath + "/internal/EGRESS/egresstest":        true,
		modPath + "/internal/Egress/egresstest":        true,
		modPath + "/internal/zz/testdata/d":            true,
		modPath + "/internal/zz/TESTDATA/d":            true,
		modPath + "/internal/zz/TestData/d":            true,
		modPath + "/TESTDATA":                          true,
		modPath + "/internal/zz/_d":                    true,
		modPath + "/internal/zz/.d":                    true,
		modPath + "/testdata":                          true,
		modPath + "/internal/egress":                   false,
		modPath + "/internal/egressx":                  false,
		modPath + "/internal/zz/data":                  false,
		modPath + "/cmd/phantom":                       false,
		"example.org/other/testdata/d":                 false,
		"example.org/other/internal/egress/egresstest": false,
		"net/http": false,
	} {
		if got := releaseDepProblem(imp) != ""; got != bad {
			t.Errorf("releaseDepProblem(%q) has a problem: %t, want %t", imp, got, bad)
		}
	}
}

// TestTS21ReleaseDepProblem checks depProblem on a planted module root. It
// plants symbolic links, a local replace and a second module in the root. It
// checks workspaceError too.
func TestTS21ReleaseDepProblem(t *testing.T) {
	top := t.TempDir()
	root := filepath.Join(top, "mod")
	outside := filepath.Join(top, "cache", "lib")
	for _, d := range []string{
		filepath.Join(root, "internal", "egress", "egresstest"),
		filepath.Join(root, "internal", "zz", ".real"),
		filepath.Join(root, "internal", "zz", "ok"),
		filepath.Join(root, "internal", "zz", "testdata", "x"),
		outside,
	} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for name, target := range map[string]string{
		"zzseam": filepath.Join("egress", "egresstest"),
		"zzlink": filepath.Join("zz", ".real"),
		"zzfine": filepath.Join("zz", "ok"),
		"zzout":  outside,
	} {
		if err := os.Symlink(target, filepath.Join(root, "internal", name)); err != nil {
			t.Fatal(err)
		}
	}
	realRoot, err := realPath(root)
	if err != nil {
		t.Fatal(err)
	}
	in := func(rel string) string { return filepath.Join(root, filepath.FromSlash(rel)) }
	for _, tc := range []struct {
		name string
		d    listedDep
		bad  bool
	}{
		{"package of the module", listedDep{modPath + "/internal/zz/ok", in("internal/zz/ok"), modPath, "", ""}, false},
		{"module root", listedDep{modPath, root, modPath, "", ""}, false},
		{"link to a folder with no problem", listedDep{modPath + "/internal/zzfine", in("internal/zzfine"), modPath, "", ""}, false},
		{"link to the test seam", listedDep{modPath + "/internal/zzseam", in("internal/zzseam"), modPath, "", ""}, true},
		{"link to a dot folder", listedDep{modPath + "/internal/zzlink", in("internal/zzlink"), modPath, "", ""}, true},
		{"link out of the root", listedDep{modPath + "/internal/zzout", in("internal/zzout"), modPath, "", ""}, true},
		{"upper-case test seam path", listedDep{modPath + "/internal/EGRESS/egresstest", in("internal/zz/ok"), modPath, "", ""}, true},
		{"mixed-case test seam path", listedDep{modPath + "/internal/Egress/egresstest", in("internal/zz/ok"), modPath, "", ""}, true},
		{"upper-case testdata path", listedDep{modPath + "/internal/zz/TESTDATA/x", in("internal/zz/ok"), modPath, "", ""}, true},
		{"mixed-case testdata path", listedDep{modPath + "/internal/zz/TestData/x", in("internal/zz/ok"), modPath, "", ""}, true},
		{"folder that does not exist", listedDep{modPath + "/internal/gone", in("internal/gone"), modPath, "", ""}, true},
		{"local replace", listedDep{"example.org/zzx", in("internal/zz/testdata/x"), "example.org/zzx", "./internal/zz/testdata/x", ""}, true},
		{"local replace outside the root", listedDep{"example.org/zzx", outside, "example.org/zzx", outside, ""}, true},
		{"other module inside the root", listedDep{"example.org/zzx", in("internal/zz/ok"), "example.org/zzx", "", ""}, true},
		{"replace with a module version", listedDep{"example.org/fork", outside, "example.org/lib", "example.org/fork", "v1.0.0"}, false},
		{"other module outside the root", listedDep{"example.org/lib", outside, "example.org/lib", "", ""}, false},
		{"standard library", listedDep{"net/http", outside, "", "", ""}, false},
	} {
		if got := depProblem(realRoot, tc.d) != ""; got != tc.bad {
			t.Errorf("%s: depProblem has a problem: %t, want %t", tc.name, got, tc.bad)
		}
	}
	for got, bad := range map[string]bool{
		"": false, "\n": false, "off\n": false, top + "/go.work\n": true, "on": true,
	} {
		if has := workspaceError(got) != nil; has != bad {
			t.Errorf("workspaceError(%q) has an error: %t, want %t", got, has, bad)
		}
	}
}

// TestTS21ReleaseContextCheck checks that contextError fails when go list
// ignores GOOS, GOARCH or CGO_ENABLED.
func TestTS21ReleaseContextCheck(t *testing.T) {
	c := buildConfig{"linux", "amd64"}
	if err := contextError("linux/amd64/false", c); err != nil {
		t.Errorf("same context: %v", err)
	}
	for _, got := range []string{
		"linux/arm64/false", "darwin/amd64/false", "linux/amd64/true",
	} {
		if contextError(got, c) == nil {
			t.Errorf("no error for the context %s", got)
		}
	}
}

// TestTS21ReleaseListRealError runs go list on a path that has no package.
// parseDeps must report a problem for linux/amd64 and none for linux/386.
func TestTS21ReleaseListRealError(t *testing.T) {
	root := moduleRoot(t)
	missing := modPath + "/internal/egress/testdata/nosuchpkg"
	for _, tc := range []struct {
		c    buildConfig
		want int
	}{{buildConfig{"linux", "amd64"}, 1}, {buildConfig{"linux", "386"}, 0}} {
		args := []string{"list", "-e", "-deps", "-f", depFormat, missing}
		out, err := goCommand(t, root, tc.c.env(), args...).Output()
		if err != nil {
			t.Fatalf("go list on %s: %v", tc.c.name(), err)
		}
		_, deps, problems, err := parseDeps(string(out), tc.c)
		if err != nil {
			t.Fatal(err)
		}
		if len(problems) != tc.want {
			t.Errorf("%s: %d problems %q, want %d (deps %v)",
				tc.c.name(), len(problems), problems, tc.want, deps)
		}
	}
}

// TestTS21ReleaseListCheck checks that listProblem fails on a package error
// and on an empty folder. It checks that completeList names three platforms.
func TestTS21ReleaseListCheck(t *testing.T) {
	for name, tc := range map[string]struct {
		dir, errText string
		bad          bool
	}{
		"package with a folder":  {"/src/p", "", false},
		"package error":          {"/src/p", `"no Go files"`, true},
		"empty folder":           {"", "", true},
		"error and empty folder": {"", `"import cycle"`, true},
	} {
		if got := listProblem(tc.dir, tc.errText) != ""; got != tc.bad {
			t.Errorf("%s: listProblem has a problem: %t, want %t", name, got, tc.bad)
		}
	}
	for _, c := range releaseConfigs {
		want := c.name() == "linux/amd64" || c.name() == "linux/arm64" || c.name() == "default"
		if completeList(c) != want {
			t.Errorf("completeList(%s) is %t, want %t", c.name(), !want, want)
		}
	}
}

// TestTS21EgresstestFailsOutsideTestBinary builds the notest command and runs
// it. The command calls egresstest in a binary that is not a test binary.
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

// String gives the finding as file:line: form.
func (f finding) String() string {
	return fmt.Sprintf("%s:%d: %s", f.File, f.Line, f.Form)
}

// banned lists, for each import path, the names that make or use a dialer
// with no address rule.
var banned = map[string][]string{
	"net": {"Dial", "DialTimeout", "DialTCP", "DialUDP", "DialIP", "DialUnix",
		"ListenPacket", "ListenUDP", "ListenIP", "ListenUnixgram",
		"ListenMulticastUDP", "FileConn", "FilePacketConn"},
	"crypto/tls": {"Dial", "DialWithDialer"},
	"net/http": {"DefaultClient", "DefaultTransport", "Get", "Post", "PostForm",
		"Head", "ProxyFromEnvironment", "ProxyURL"},
	"net/http/httputil": {"NewSingleHostReverseProxy"},
	"net/smtp":          {"Dial", "SendMail"},
	"log/syslog":        {"Dial"},
	"net/textproto":     {"Dial"},
	"net/rpc":           {"Dial", "DialHTTP", "DialHTTPPath"},
	"net/rpc/jsonrpc":   {"Dial"},
	"syscall": {"Socket", "Connect", "Syscall", "Syscall6", "RawSyscall",
		"RawSyscall6"},
	"golang.org/x/sys/unix": {"Socket", "Connect", "Syscall", "Syscall6",
		"RawSyscall", "RawSyscall6"},
}

// noRuleTypes lists the types whose value, with no pointer, dials with no
// address rule. The pointer type *T only holds a dialer that code made
// elsewhere. A net.ListenConfig sends datagrams with ListenPacket.
var noRuleTypes = map[string][]string{
	"net":               {"Dialer", "ListenConfig"},
	"crypto/tls":        {"Dialer"},
	"net/http":          {"Transport", "Client"},
	"net/http/httputil": {"ReverseProxy"},
}

// egressImports are the packages that code in internal/egress must not import.
var egressImports = []string{"os", "flag", "os/exec"}

// egressBanned lists the names that code in internal/egress must not use. They
// read the environment, as the packages of egressImports do.
var egressBanned = map[string][]string{
	"syscall":               {"Getenv", "Environ"},
	"golang.org/x/sys/unix": {"Getenv", "Environ"},
}

// dialImports are the packages that dial through a proxy or with no address
// rule. Code outside internal/egress must not import them.
var dialImports = []string{
	"golang.org/x/net/proxy", "golang.org/x/net/http2", "golang.org/x/net/icmp",
	"golang.org/x/net/websocket", "golang.org/x/crypto/ssh", "github.com/miekg/dns",
	"golang.org/x/net/quic", "golang.org/x/crypto/acme",
	"golang.org/x/crypto/acme/autocert",
}

// dialerHooks are the fields of net.Dialer, http.Transport, http.Client and
// httputil.ReverseProxy that hold the address rule or the proxy. Code outside
// internal/egress must not write them.
var dialerHooks = []string{
	"ControlContext", "Control", "DialContext", "DialTLSContext", "DialTLS",
	"Proxy", "Transport",
}

// walkError gives the error that stops the walk of root at p. An entry that
// another test removes during the walk is not an error. The root must exist.
func walkError(root, p string, err error) error {
	if err != nil && p != root && errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

// skippedDir tells if rel is in a folder that scan skips. The path rel is below
// the scan root. A skipped folder is testdata or starts with "." or "_".
func skippedDir(rel string) bool {
	dir := path.Dir(rel)
	if dir == "." {
		return false
	}
	return slices.ContainsFunc(strings.Split(dir, "/"), func(el string) bool {
		return el == "testdata" || strings.HasPrefix(el, ".") || strings.HasPrefix(el, "_")
	})
}

// scan parses the .go files below root and gives the findings, with paths
// relative to root. It finds each symbolic link below root. It skips test
// files and files in testdata and in folders that start with "." or "_". The
// dependency test covers an import of a skipped folder, a symlink and a
// replace.
func scan(root string) ([]finding, error) {
	return scanWith(root, filepath.WalkDir)
}

// scanWith is scan with the function walk, which walks the tree of root.
func scanWith(root string, walk func(string, fs.WalkDirFunc) error) ([]finding, error) {
	var out []finding
	err := walk(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return walkError(root, p, err)
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		name := d.Name()
		if p != root && d.Type()&fs.ModeSymlink != 0 {
			out = append(out, finding{File: rel, Line: 1, Form: "symbolic link"})
			return nil
		}
		if d.IsDir() || skippedDir(rel) {
			return nil
		}
		if strings.HasSuffix(name, ".s") || strings.HasSuffix(name, ".S") {
			out = append(out, finding{File: rel, Line: 1, Form: "assembly file"})
			return nil
		}
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, p, nil, parser.ParseComments)
		if err != nil {
			return walkError(root, p, err)
		}
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
// fields of dialerHooks by name only.
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
		if p == "C" {
			add(imp.Pos(), "import C")
		}
		if inEgress && slices.Contains(egressImports, p) {
			add(imp.Pos(), "import "+p)
		}
		if !inEgress && slices.Contains(dialImports, p) {
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
	if inEgress {
		ast.Inspect(f, func(n ast.Node) bool {
			if p, name := pkgName(n); slices.Contains(egressBanned[p], name) {
				add(n.Pos(), path.Base(p)+"."+name)
			}
			return true
		})
		return out
	}

	// pointed holds the types that follow a star. lits holds the type of each
	// composite literal. newCall holds the type in each call of new. elided
	// holds the literals with no type. Each one gets the element type or the
	// key type of the slice, array or map literal that holds it.
	pointed := map[ast.Expr]bool{}
	lits := map[ast.Expr]*ast.CompositeLit{}
	newCall := map[ast.Expr]*ast.CallExpr{}
	elided := map[ast.Expr][]*ast.CompositeLit{}
	// resolve follows the type names that this file declares and gives the type
	// that they stand for. A type from another file stays a name.
	resolve := func(typ ast.Expr) ast.Expr {
		for range 10 {
			id, ok := typ.(*ast.Ident)
			if !ok || id.Obj == nil || id.Obj.Kind != ast.Typ {
				break
			}
			spec, ok := id.Obj.Decl.(*ast.TypeSpec)
			if !ok {
				break
			}
			typ = spec.Type
		}
		return typ
	}
	var elide func(typ ast.Expr, lit *ast.CompositeLit)
	// elideIn notes lit as a literal with no type of the element type typ.
	elideIn := func(typ ast.Expr, lit *ast.CompositeLit) {
		typ = resolve(typ)
		if s, ok := typ.(*ast.StarExpr); ok {
			typ = resolve(s.X)
		}
		switch typ.(type) {
		case *ast.ArrayType, *ast.MapType:
			elide(typ, lit)
		default:
			elided[typ] = append(elided[typ], lit)
		}
	}
	// elide notes the elements of lit that have no type, for the literal type
	// typ.
	elide = func(typ ast.Expr, lit *ast.CompositeLit) {
		var elem, key ast.Expr
		typ = resolve(typ)
		switch t := typ.(type) {
		case *ast.ArrayType:
			elem = t.Elt
		case *ast.MapType:
			elem, key = t.Value, t.Key
		default:
			return
		}
		for _, e := range lit.Elts {
			if kv, ok := e.(*ast.KeyValueExpr); ok {
				if k, ok := kv.Key.(*ast.CompositeLit); ok && k.Type == nil && key != nil {
					elideIn(key, k)
				}
				e = kv.Value
			}
			if c, ok := e.(*ast.CompositeLit); ok && c.Type == nil {
				elideIn(elem, c)
			}
		}
	}
	ast.Inspect(f, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.StarExpr:
			pointed[n.X] = true
		case *ast.CompositeLit:
			if n.Type != nil {
				lits[n.Type] = n
				elide(n.Type, n)
			}
		case *ast.CallExpr:
			if id, ok := n.Fun.(*ast.Ident); ok && id.Name == "new" &&
				id.Obj == nil && len(n.Args) == 1 {
				newCall[n.Args[0]] = n
			}
		}
		return true
	})
	ast.Inspect(f, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.SelectorExpr:
			p, name := pkgName(n)
			form := path.Base(p) + "." + name
			switch {
			case slices.Contains(banned[p], name):
				add(n.Pos(), form)
			case !slices.Contains(noRuleTypes[p], name):
			case pointed[n]:
				for _, lit := range elided[n] {
					for _, x := range literalForms(p, name, lit) {
						add(lit.Pos(), x)
					}
				}
			case newCall[n] != nil:
				add(newCall[n].Pos(), "new("+form+")")
			case lits[n] == nil:
				add(n.Pos(), form+" used with no pointer")
			default:
				for _, x := range literalForms(p, name, lits[n]) {
					add(n.Pos(), x)
				}
			}
		case *ast.AssignStmt:
			for _, l := range n.Lhs {
				if s, ok := ast.Unparen(l).(*ast.SelectorExpr); ok &&
					slices.Contains(dialerHooks, s.Sel.Name) {
					add(s.Pos(), "write to "+s.Sel.Name)
				}
			}
		case *ast.UnaryExpr:
			if s, ok := ast.Unparen(n.X).(*ast.SelectorExpr); ok && n.Op == token.AND &&
				slices.Contains(dialerHooks, s.Sel.Name) {
				add(n.Pos(), "address of "+s.Sel.Name)
			}
		}
		return true
	})
	return out
}

// literalForms gives the findings for lit, a literal of the type name in the
// package p. The type is one of noRuleTypes.
func literalForms(p, name string, lit *ast.CompositeLit) []string {
	switch {
	case p == "net/http" && name == "Transport":
		return transportForms(lit)
	case p == "net/http" && name == "Client":
		if !hasKey(lit, "Transport") {
			return []string{"http.Client literal without Transport"}
		}
		return nil
	case p == "net/http/httputil" && name == "ReverseProxy":
		if !hasKey(lit, "Transport") {
			return []string{"httputil.ReverseProxy literal without Transport"}
		}
		return nil
	}
	return []string{path.Base(p) + "." + name + " literal"}
}

// hasKey tells if lit has an element with the field name key and a value
// other than nil. A key with the value nil is the same as no key.
func hasKey(lit *ast.CompositeLit, key string) bool {
	for _, e := range lit.Elts {
		if kv, ok := e.(*ast.KeyValueExpr); ok {
			if id, ok := kv.Key.(*ast.Ident); ok && id.Name == key {
				v, isIdent := kv.Value.(*ast.Ident)
				return !(isIdent && v.Name == "nil" && v.Obj == nil)
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
	if hasKey(lit, "Proxy") {
		out = append(out, "http.Transport literal with Proxy")
	}
	return out
}

// TestTS21SourceHasNoDialerOutsideGuard scans the non-test files of the
// module. The scan finds only the forms that the tables and cases of scanFile
// list. A child process (os/exec) is not in the scan. A command can open a
// connection that the scan does not see.
func TestTS21SourceHasNoDialerOutsideGuard(t *testing.T) {
	found, err := scan(moduleRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range found {
		t.Error(f)
	}
}

// TestTS21ScanFindsPlantedFiles plants files in a temp directory. It checks
// the forms that scan finds in each file, and the files that it skips.
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

	// The tables name the QUIC and ACME packages and the inherited sockets.
	for _, p := range []string{"golang.org/x/net/quic", "golang.org/x/crypto/acme",
		"golang.org/x/crypto/acme/autocert"} {
		if !slices.Contains(dialImports, p) {
			t.Errorf("dialImports lacks %s", p)
		}
	}
	for _, name := range []string{"FileConn", "FilePacketConn"} {
		if !slices.Contains(banned["net"], name) {
			t.Errorf("banned lacks net.%s", name)
		}
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
		"new(net.Dialer)")
	plantWant("net_dialer_var.go", file("\t\"net\"\n", "var d net.Dialer"),
		"net.Dialer used with no pointer")
	plantWant("net_dialer_field.go", file("\t\"net\"\n",
		"type a struct{ d net.Dialer }\ntype b struct{ net.Dialer }"),
		"net.Dialer used with no pointer", "net.Dialer used with no pointer")
	plantWant("tls_dialer_lit.go", file("\t\"crypto/tls\"\n", "var _ = &tls.Dialer{}"),
		"tls.Dialer literal")
	plantWant("tls_dialer_new.go", file("\t\"crypto/tls\"\n", "var _ = new(tls.Dialer)"),
		"new(tls.Dialer)")
	plantWant("transport_none.go", file("\t\"net/http\"\n", "var _ = &http.Transport{}"),
		"http.Transport literal without DialContext")
	plantWant("transport_nil.go", file("\t\"net/http\"\n",
		"var _ = &http.Transport{DialContext: nil}"),
		"http.Transport literal without DialContext")
	plantWant("transport_tls_context.go", file("\t\"net/http\"\n",
		"var _ = &http.Transport{DialContext: f, DialTLSContext: f}"),
		"http.Transport literal with DialTLSContext")
	plantWant("transport_tls.go", file("\t\"net/http\"\n",
		"var _ = &http.Transport{DialContext: f, DialTLS: f}"),
		"http.Transport literal with DialTLS")
	plantWant("transport_new.go", file("\t\"net/http\"\n", "var _ = new(http.Transport)"),
		"new(http.Transport)")
	plantWant("transport_var.go", file("\t\"net/http\"\n", "var t http.Transport"),
		"http.Transport used with no pointer")
	plantWant("tls_dialer_var.go", file("\t\"crypto/tls\"\n", "var d tls.Dialer"),
		"tls.Dialer used with no pointer")
	plantWant("tls_dialer_field.go", file("\t\"crypto/tls\"\n",
		"type a struct{ d tls.Dialer }\ntype b struct{ tls.Dialer }"),
		"tls.Dialer used with no pointer", "tls.Dialer used with no pointer")
	plantWant("transport_field.go", file("\t\"net/http\"\n",
		"type a struct{ t http.Transport }\ntype b struct{ http.Transport }"),
		"http.Transport used with no pointer", "http.Transport used with no pointer")
	plantWant("transport_proxy.go", file("\t\"net/http\"\n",
		"var _ = &http.Transport{DialContext: f, Proxy: g}"),
		"http.Transport literal with Proxy")
	plantWant("listen_config_lit.go", file("\t\"net\"\n", "var _ = &net.ListenConfig{}"),
		"net.ListenConfig literal")
	plantWant("listen_config_var.go", file("\t\"net\"\n", "var lc net.ListenConfig"),
		"net.ListenConfig used with no pointer")
	plantWant("reverse_proxy_lit.go", file("\t\"net/http/httputil\"\n",
		"var _ = &httputil.ReverseProxy{}"),
		"httputil.ReverseProxy literal without Transport")
	plantWant("reverse_proxy_nil.go", file("\t\"net/http/httputil\"\n",
		"var _ = &httputil.ReverseProxy{Transport: nil}"),
		"httputil.ReverseProxy literal without Transport")
	plantWant("reverse_proxy_new.go", file("\t\"net/http/httputil\"\n",
		"var _ = new(httputil.ReverseProxy)"),
		"new(httputil.ReverseProxy)")
	plantWant("reverse_proxy_var.go", file("\t\"net/http/httputil\"\n",
		"var p httputil.ReverseProxy"),
		"httputil.ReverseProxy used with no pointer")
	plantWant("client_lit.go", file("\t\"net/http\"\n", "var _ = &http.Client{}"),
		"http.Client literal without Transport")
	plantWant("client_nil.go", file("\t\"net/http\"\n",
		"var _ = &http.Client{Transport: nil}"),
		"http.Client literal without Transport")
	plantWant("client_new.go", file("\t\"net/http\"\n", "var _ = new(http.Client)"),
		"new(http.Client)")
	plantWant("client_var.go", file("\t\"net/http\"\n", "var c http.Client"),
		"http.Client used with no pointer")
	plantWant("client_field.go", file("\t\"net/http\"\n",
		"type a struct{ c http.Client }\ntype b struct{ http.Client }"),
		"http.Client used with no pointer", "http.Client used with no pointer")

	// A literal with no type, in a slice, an array or a map.
	plantWant("elided_dialer_slice.go", file("\t\"net\"\n", "var _ = []*net.Dialer{{}}"),
		"net.Dialer literal")
	plantWant("elided_dialer_array.go", file("\t\"net\"\n",
		"var _ = [...]*net.Dialer{{}, {}}"),
		"net.Dialer literal", "net.Dialer literal")
	plantWant("elided_dialer_nested.go", file("\t\"net\"\n",
		"var _ = [][]*net.Dialer{{{}}}"),
		"net.Dialer literal")
	plantWant("elided_dialer_value.go", file("\t\"net\"\n", "var _ = []net.Dialer{{}}"),
		"net.Dialer used with no pointer")
	plantWant("elided_transport_map.go", file("\t\"net/http\"\n",
		"var _ = map[string]*http.Transport{\"a\": {}}"),
		"http.Transport literal without DialContext")
	plantWant("elided_client_slice.go", file("\t\"net/http\"\n",
		"var _ = []*http.Client{{}}"),
		"http.Client literal without Transport")

	// A literal with no type, in a type that the same file declares.
	plantWant("elided_named_slice.go", file("\t\"net\"\n",
		"type ds []*net.Dialer\n\nvar _ = ds{{}}"),
		"net.Dialer literal")
	plantWant("elided_named_map.go", file("\t\"net/http\"\n",
		"type ts map[string]*http.Transport\n\nvar _ = ts{\"a\": {}}"),
		"http.Transport literal without DialContext")
	plantWant("elided_alias.go", file("\t\"net\"\n",
		"type PD = *net.Dialer\n\nvar _ = []PD{{}}"),
		"net.Dialer literal")
	plantWant("elided_pointer_named.go", file("\t\"net\"\n",
		"type ds []*net.Dialer\n\nvar _ = []*ds{{{}}}"),
		"net.Dialer literal")
	plantWant("elided_named_nested.go", file("\t\"net/http\"\n",
		"type cs []*http.Client\ntype ncs [][]cs\n\nvar _ = ncs{{{{}}}}"),
		"http.Client literal without Transport")

	// A write to a field that holds the address rule or the proxy.
	for i, tc := range []struct{ src, form string }{
		{"d.ControlContext = nil", "write to ControlContext"},
		{"d.Control = nil", "write to Control"},
		{"d.DialContext = nil", "write to DialContext"},
		{"d.DialTLSContext = nil", "write to DialTLSContext"},
		{"d.DialTLS = nil", "write to DialTLS"},
		{"d.Proxy = nil", "write to Proxy"},
		{"d.Transport = nil", "write to Transport"},
		{"(d.ControlContext) = nil", "write to ControlContext"},
		{"((d.Transport)) = nil", "write to Transport"},
		{"_ = &d.ControlContext", "address of ControlContext"},
		{"_ = &d.Control", "address of Control"},
		{"_ = &d.DialContext", "address of DialContext"},
		{"_ = &d.DialTLSContext", "address of DialTLSContext"},
		{"_ = &d.DialTLS", "address of DialTLS"},
		{"_ = &d.Proxy", "address of Proxy"},
		{"_ = &d.Transport", "address of Transport"},
		{"_ = &(d.Control)", "address of Control"},
	} {
		plantWant("write_"+strconv.Itoa(i)+".go",
			file("", "type dialer struct{ Control, ControlContext, DialContext,\n"+
				"\tDialTLSContext, DialTLS, Proxy, Transport func() }\n"+
				"func f(d *dialer) {\n\t"+tc.src+"\n}"),
			tc.form)
	}

	// A dot import of a package that makes dialers.
	for p := range banned {
		plantWant("dot_"+strings.ReplaceAll(p, "/", "_")+".go",
			file("\t. \""+p+"\"\n", ""), "dot import "+p)
	}

	// A directive, a proxy package, cgo, assembly, and code in internal/egress.
	plantWant("link.go", "package p\n\n//go:linkname f runtime.f\nfunc f()\n",
		"go:linkname directive")
	for _, p := range dialImports {
		plantWant("import_"+strings.ReplaceAll(p, "/", "_")+".go",
			file("\t\""+p+"\"\n", ""), "import "+p)
		plant("internal/egress/import_"+strings.ReplaceAll(p, "/", "_")+".go",
			file("\t\""+p+"\"\n", ""))
	}
	plantWant("cgo.go", file("\t\"C\"\n", ""), "import C")
	plantWant("internal/egress/cgo.go", file("\t\"C\"\n", ""), "import C")
	plantWant("asm.s", "TEXT ·f(SB),0,$0\n\tRET\n", "assembly file")
	plantWant("internal/egress/asm.S", "TEXT ·f(SB),0,$0\n\tRET\n", "assembly file")
	plantWant("internal/egress/link.go", "package egress\n\n//go:linkname f runtime.f\nfunc f()\n",
		"go:linkname directive")
	for _, imp := range egressImports {
		plantWant("internal/egress/deep/"+path.Base(imp)+".go",
			file("\t\""+imp+"\"\n", "var _ = "+path.Base(imp)+".Args"), "import "+imp)
	}
	plantWant("internal/egress/env.go", file("\t\"syscall\"\n",
		"var _, _ = syscall.Getenv(\"X\")\nvar _ = syscall.Environ()"),
		"syscall.Getenv", "syscall.Environ")
	plantWant("internal/egress/unix_env.go",
		file("\t\"golang.org/x/sys/unix\"\n",
			"var _, _ = unix.Getenv(\"X\")\nvar _ = unix.Environ()"),
		"unix.Getenv", "unix.Environ")

	// The scan finds nothing in these files.
	plant("x_test.go", file("\t\"net\"\n", "var _, _ = net.Dial(\"tcp\", \"a:1\")"))
	plant("testdata/x.go", file("\t\"net\"\n", "var _, _ = net.Dial(\"tcp\", \"a:1\")"))
	plant("testdata/x.s", "TEXT ·f(SB),0,$0\n\tRET\n")
	plant(".hidden/x.go", file("\t\"net\"\n", "var _, _ = net.Dial(\"tcp\", \"a:1\")"))
	plant("_skipped/x.go", file("\t\"net\"\n", "var _, _ = net.Dial(\"tcp\", \"a:1\")"))
	plant("comment.go", "package p\n\n// the text //go:linkname is not a directive\n"+
		"/* //go:linkname is not a directive */\n")
	plant("pointer.go", file("\t\"net\"\n\t\"net/http\"\n",
		"type s struct{ d *net.Dialer; t *http.Transport; c *http.Client }\n"+
			"func f(d *net.Dialer) *net.Dialer { return d }"))
	plant("elided_ok.go", file("\t\"net/http\"\n",
		"var _ = []*http.Transport{{DialContext: f}}\n"+
			"var _ = []*http.Client{{Transport: t}}"))
	plant("transport_ok.go", file("\t\"net/http\"\n",
		"var _ = &http.Transport{DialContext: f, DialTLSContext: nil, Proxy: nil}"))
	plant("reverse_proxy_ok.go", file("\t\"net/http/httputil\"\n",
		"var _ = &httputil.ReverseProxy{Transport: t}"))
	plant("client_ok.go", file("\t\"net/http\"\n", "var _ = &http.Client{Transport: t}"))
	plant("shadow.go", file("\t\"net\"\n", "func f(net struct{ Dial func() }) {\n"+
		"\tnet.Dial()\n}"))
	plant("not_hook.go", file("", "type c struct{ Control func() }\n"+
		"func f(x c) func() { return x.Control }"))
	plant("internal/egress/raw.go", file("\t\"syscall\"\n",
		"func f(c syscall.RawConn) syscall.RawConn { return c }"))
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

// TestTS21ScanReportsFileThatDoesNotParse checks that scan gives an error for
// a file that does not parse.
func TestTS21ScanReportsFileThatDoesNotParse(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bad.go"), []byte("not go"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := scan(dir); err == nil {
		t.Error("no error for a file that does not parse")
	}
}

// TestTS21ScanFindsSymlinks plants symbolic links to a folder and to a file.
// It plants them in a folder that scan checks and in folders that it skips.
func TestTS21ScanFindsSymlinks(t *testing.T) {
	dir := t.TempDir()
	for _, d := range []string{"sub", "testdata", ".hidden", "_skipped"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "sub", "a.txt"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	var want []string
	for _, d := range []string{".", "testdata", ".hidden", "_skipped"} {
		for name, target := range map[string]string{
			"link_dir":  "sub",
			"link_file": filepath.Join("sub", "a.txt"),
		} {
			// Targets are relative to the folder of the link.
			if d != "." {
				target = filepath.Join("..", target)
			}
			if err := os.Symlink(target, filepath.Join(dir, d, name)); err != nil {
				t.Fatal(err)
			}
			want = append(want, path.Join(d, name)+":1: symbolic link")
		}
	}
	got, err := scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	var gotText []string
	for _, f := range got {
		gotText = append(gotText, f.String())
	}
	slices.Sort(want)
	slices.Sort(gotText)
	if !slices.Equal(gotText, want) {
		t.Errorf("found %q, want %q", gotText, want)
	}
}

// TestTS21ScanWalkError checks that scan ignores only an entry that is gone.
// It does not ignore the root, and it does not ignore another error.
func TestTS21ScanWalkError(t *testing.T) {
	dir := t.TempDir()
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	root := fs.FileInfoToDirEntry(info)
	for name, tc := range map[string]struct {
		p       string
		err     error
		wantErr bool
	}{
		"entry that is gone": {filepath.Join(dir, "x"), fs.ErrNotExist, false},
		"root that is gone":  {dir, fs.ErrNotExist, true},
		"other error":        {filepath.Join(dir, "x"), errors.New("other"), true},
	} {
		// The fake walk reports tc.err for tc.p. When tc.p is not the root, it
		// visits the root first.
		walk := func(r string, fn fs.WalkDirFunc) error {
			if tc.p != r {
				if err := fn(r, root, nil); err != nil {
					return err
				}
			}
			return fn(tc.p, nil, &fs.PathError{Op: "lstat", Path: tc.p, Err: tc.err})
		}
		if _, err := scanWith(dir, walk); (err != nil) != tc.wantErr {
			t.Errorf("%s: scan gave the error %v, want an error: %t", name, err, tc.wantErr)
		}
	}
}

// TestTS21WalkError checks that walkError ignores only an entry that is gone.
// It does not ignore the root, and it does not ignore another error.
func TestTS21WalkError(t *testing.T) {
	gone := &fs.PathError{Op: "lstat", Path: "root/x", Err: fs.ErrNotExist}
	other := errors.New("other")
	if err := walkError("root", "root/x", gone); err != nil {
		t.Errorf("entry that is gone: %v", err)
	}
	if err := walkError("root", "root", gone); err != gone {
		t.Errorf("root that is gone: got %v", err)
	}
	if err := walkError("root", "root/x", other); err != other {
		t.Errorf("other error: got %v", err)
	}
	if err := walkError("root", "root/x", nil); err != nil {
		t.Errorf("no error: got %v", err)
	}
}
