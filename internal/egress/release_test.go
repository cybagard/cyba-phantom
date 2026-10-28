package egress_test

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"maps"
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
func goCommand(t testing.TB, dir string, env []string, args ...string) *exec.Cmd {
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

// wantContext gives the build context of c with cgo off, in the form
// GOOS/GOARCH/CgoEnabled.
func wantContext(c buildConfig) string {
	goos, goarch := c.goos, c.goarch
	if goos == "" {
		goos, goarch = runtime.GOOS, runtime.GOARCH
	}
	return goos + "/" + goarch + "/false"
}

// contextError gives an error when got is not the build context of c with cgo
// off. got has the form GOOS/GOARCH/CgoEnabled.
func contextError(got string, c buildConfig) error {
	if want := wantContext(c); got != want {
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
func listDeps(t testing.TB, root string, c buildConfig, pkgs ...string) (string, []listedDep) {
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
	if inModule(d.Path) && d.Module == "" {
		return "it has no module, and its path is in this module"
	}
	if inModule(d.Path) && d.Module != modPath {
		return "its module " + d.Module + " is not this module"
	}
	if inModuleFold(d.Path) && !inModule(d.Path) {
		return "its path differs from the module path only in case"
	}
	if d.Replace != "" {
		return "its module " + d.Module + " has a replace"
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

// usesDepList tells if the dependency list covers the platform c. A host that
// is not linux has other std packages. Thus only the linux targets use it.
func usesDepList(c buildConfig) bool { return c.goos == "linux" }

// readList gives the lines of the list file name in testdata.
func readList(name string) ([]string, error) {
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		return nil, err
	}
	return strings.Split(strings.TrimSuffix(string(b), "\n"), "\n"), nil
}

// listProblems gives one text for each problem of a line. A line has a
// problem when it is empty or the same as the line before it. A line also has
// a problem when it sorts before the line before it in byte order. A line that
// is not in used has a problem too.
func listProblems(lines []string, used map[string]bool) []string {
	var out []string
	for i, l := range lines {
		switch {
		case l == "":
			out = append(out, fmt.Sprintf("line %d is empty", i+1))
		case i > 0 && l == lines[i-1]:
			out = append(out, fmt.Sprintf("line %d repeats %s", i+1, l))
		case i > 0 && l < lines[i-1]:
			out = append(out, fmt.Sprintf("line %d, %s, is out of order", i+1, l))
		}
		if l != "" && !used[l] {
			out = append(out, fmt.Sprintf("line %d, %s, is not used", i+1, l))
		}
	}
	return out
}

// loadList gives the lines of the list file name in testdata.
func loadList(t *testing.T, name string) []string {
	t.Helper()
	lines, err := readList(name)
	if err != nil {
		t.Fatal(err)
	}
	return lines
}

// lineSet gives the set of lines.
func lineSet(lines []string) map[string]bool {
	set := map[string]bool{}
	for _, l := range lines {
		set[l] = true
	}
	return set
}

// TestTS21ReleaseCommandsDoNotListTestSeam gets the dependencies of the
// release commands for each platform in releaseConfigs, with cgo off. It
// fails on each dependency that depProblem names, and on a go workspace. On a
// platform with usesDepList, it fails on each package that is not on
// release-deps.txt. It also fails on a line of the file that is not a
// dependency on a linux platform.
// The loop has no subtests. Thus the union of the platforms does not depend on
// the -run filter.
// Each program has the package runtime. Thus a list without runtime fails,
// for example a list cut to the two commands. A cut list that keeps runtime
// and the commands still passes.
// Three other changes of this function stay live. Here is why for each one:
//   - The deps of linux/amd64 go to linux/s390x. The two platforms list
//     the same packages, so the data does not change.
//   - The context is replaced by wantContext. A right go list gives that
//     same value, so only a wrong go list differs. The wrong context case of
//     TestTS21CheckDepListReports covers it.
//   - The commands are nil or cut. The same variable feeds listDeps, so a
//     test has no value to compare with. The not listed cases cover the check.
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
	var all []platformDeps
	for _, c := range releaseConfigs {
		ctx, deps := listDeps(t, root, c, commands...)
		all = append(all, platformDeps{c, ctx, deps})
	}
	for _, pd := range all {
		if !slices.ContainsFunc(pd.deps, func(d listedDep) bool { return d.Path == "runtime" }) {
			t.Errorf("%s: go list -deps did not list runtime", pd.c.name())
		}
	}
	checkDepList(t, realRoot, loadList(t, "release-deps.txt"), commands, all)
}

// platformDeps are the build context and the packages that go list -deps
// finds for one platform.
type platformDeps struct {
	c    buildConfig
	ctx  string
	deps []listedDep
}

// configNames gives the names of the platforms cs.
func configNames(cs []buildConfig) []string {
	var out []string
	for _, c := range cs {
		out = append(out, c.name())
	}
	return out
}

// checkDepList fails t on each dependency that depProblem names. It builds
// the list from lines. It also fails when the platforms of all are not the
// platforms of releaseConfigs, in the same order. The list check and the used
// lines cover only the packages of other modules, on the platforms with
// usesDepList. It also fails on each problem that listProblems finds in lines.
// It fails when the build context of a platform is wrong (contextError). It
// also fails when a platform does not list each path of cmds.
func checkDepList(t testing.TB, realRoot string, lines []string, cmds []string, all []platformDeps) {
	t.Helper()
	list := lineSet(lines)
	cs := make([]buildConfig, len(all))
	for i, pd := range all {
		cs[i] = pd.c
	}
	if !slices.Equal(cs, releaseConfigs) {
		t.Errorf("platforms %q, want %q", configNames(cs), configNames(releaseConfigs))
	}
	used := map[string]bool{}
	for _, pd := range all {
		if err := contextError(pd.ctx, pd.c); err != nil {
			t.Errorf("%s: %v", pd.c.name(), err)
		}
		for _, cmd := range cmds {
			if !slices.ContainsFunc(pd.deps, func(d listedDep) bool { return d.Path == cmd }) {
				t.Errorf("%s: go list -deps did not list %s", pd.c.name(), cmd)
			}
		}
		for _, d := range pd.deps {
			if why := depProblem(realRoot, d); why != "" {
				t.Errorf("%s: a release command depends on %s: %s", pd.c.name(), d.Path, why)
			}
			if !usesDepList(pd.c) || d.Module == modPath {
				continue
			}
			used[d.Path] = true
			if !list[d.Path] {
				t.Errorf("%s: %s is not on release-deps.txt", pd.c.name(), d.Path)
			}
		}
	}
	for _, p := range listProblems(lines, used) {
		t.Errorf("release-deps.txt: %s", p)
	}
}

// record runs f with a recorder in a new goroutine and gives the errors that
// f records. A call to Fatal in f ends only that goroutine. A method that the
// recorder does not override goes to t. FailNow and SkipNow are not
// overridden, so they act on the real test from another goroutine. A panic in
// f is recorded as an error.
func record(t testing.TB, f func(testing.TB)) []string {
	r := &recorder{TB: t}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() {
			if p := recover(); p != nil {
				r.Error("panic: ", p)
			}
		}()
		f(r)
	}()
	<-done
	return r.errs
}

// TestTS21RecordPassesOtherMethods calls TempDir and Log, which the recorder
// does not override, through record. They must work and record no error.
func TestTS21RecordPassesOtherMethods(t *testing.T) {
	var dir string
	got := record(t, func(tb testing.TB) {
		dir = tb.TempDir()
		tb.Log("record passes Log to the test")
	})
	if len(got) != 0 {
		t.Errorf("errors %q, want none", got)
	}
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		t.Errorf("TempDir gave %q, want a folder: %v", dir, err)
	}
}

// TestTS21CheckDepListReports calls checkDepList on planted packages. The
// input adds the command package to the deps of each platform. The platform
// linux/amd64 has a package that is not on the list and a package with a
// replace. A host platform has no list check. The host platform has a package
// of the test seam, which depProblem names. It also has a listed package that
// only the host lists, which is not used. Each case changes the input:
//   - "not on the list" keeps the input.
//   - "line not used" leaves only the replace package on linux/amd64.
//   - "platform dropped" drops the host platform.
//   - "order swapped" swaps the first two platforms.
//   - "platform replaced" gives the s390x slot the name linux/amd64.
//   - "wrong context" gives linux/386 the context of a build with cgo on.
//   - "command not listed" gives linux/386 no deps, not even the command.
//   - "command missing" cuts the command from linux/amd64, which still lists
//     other packages.
func TestTS21CheckDepListReports(t *testing.T) {
	root, err := realPath(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	cmd := modPath + "/cmd/x"
	lines := []string{"example.org/lib/h", "example.org/lib/z", "example.org/rep/b"}
	amd := []listedDep{
		{"example.org/lib/a", outside, "example.org/lib", "", ""},
		{"example.org/rep/b", outside, "example.org/rep", outside, ""},
		{"example.org/lib/z", outside, "example.org/lib", "", ""},
	}
	host := []listedDep{
		{modPath + "/internal/egress/egresstest", root, modPath, "", ""},
		{"example.org/lib/h", outside, "example.org/lib", "", ""},
	}
	input := func(amdDeps []listedDep) []platformDeps {
		var all []platformDeps
		for _, c := range releaseConfigs {
			pd := platformDeps{c: c, ctx: wantContext(c)}
			switch c {
			case buildConfig{"linux", "amd64"}:
				pd.deps = amdDeps
			case buildConfig{}:
				pd.deps = host
			}
			pd.deps = append(pd.deps[:len(pd.deps):len(pd.deps)], listedDep{cmd, root, modPath, "", ""})
			all = append(all, pd)
		}
		return all
	}
	replace := "linux/amd64: a release command depends on example.org/rep/b: " +
		"its module example.org/rep has a replace"
	seam := "default: a release command depends on " + modPath +
		"/internal/egress/egresstest: it is below internal/egress"
	unused := "release-deps.txt: line 1, example.org/lib/h, is not used"
	notListed := "linux/amd64: example.org/lib/a is not on release-deps.txt"
	with := func(f func([]platformDeps)) []platformDeps {
		all := input(amd)
		f(all)
		return all
	}
	platforms := func(cs []buildConfig) string {
		return fmt.Sprintf("platforms %q, want %q", configNames(cs), configNames(releaseConfigs))
	}
	swapped, relabelled := slices.Clone(releaseConfigs), slices.Clone(releaseConfigs)
	swapped[0], swapped[1] = swapped[1], swapped[0]
	relabelled[12] = buildConfig{"linux", "amd64"}
	for name, tc := range map[string]struct {
		all  []platformDeps
		want []string
	}{
		"not on the list": {input(amd), []string{
			"linux/amd64: example.org/lib/a is not on release-deps.txt", replace, seam, unused}},
		"line not used": {input(amd[1:2]), []string{replace, seam, unused,
			"release-deps.txt: line 2, example.org/lib/z, is not used"}},
		"platform dropped": {input(amd)[:len(releaseConfigs)-1], []string{
			fmt.Sprintf("platforms %q, want %q", configNames(releaseConfigs[:len(releaseConfigs)-1]),
				configNames(releaseConfigs)),
			"linux/amd64: example.org/lib/a is not on release-deps.txt", replace, unused}},
		"order swapped": {with(func(a []platformDeps) { a[0], a[1] = a[1], a[0] }), []string{
			platforms(swapped), notListed, replace, seam, unused}},
		"platform replaced": {with(func(a []platformDeps) {
			a[12].c, a[12].ctx = relabelled[12], wantContext(relabelled[12])
		}), []string{platforms(relabelled), notListed, replace, seam, unused}},
		"wrong context": {with(func(a []platformDeps) { a[0].ctx = "linux/386/true" }), []string{
			"linux/386: go list used the build context linux/386/true, want linux/386/false",
			notListed, replace, seam, unused}},
		"command not listed": {with(func(a []platformDeps) { a[0].deps = nil }), []string{
			"linux/386: go list -deps did not list " + cmd, notListed, replace, seam, unused}},
		"command missing": {with(func(a []platformDeps) { a[1].deps = a[1].deps[:len(a[1].deps)-1] }), []string{
			"linux/amd64: go list -deps did not list " + cmd, notListed, replace, seam, unused}},
	} {
		got := record(t, func(tb testing.TB) { checkDepList(tb, root, lines, []string{cmd}, tc.all) })
		if !slices.Equal(got, tc.want) {
			t.Errorf("%s: errors %q, want %q", name, got, tc.want)
		}
	}
}

// TestTS21ReleaseConfigsAreLinuxTargets checks that the linux platforms of
// releaseConfigs are the linux targets of go tool dist list. The host platform
// is the only one that does not use the dependency list.
func TestTS21ReleaseConfigsAreLinuxTargets(t *testing.T) {
	out, err := goCommand(t, moduleRoot(t), nil, "tool", "dist", "list").Output()
	if err != nil {
		t.Fatalf("go tool dist list: %v", err)
	}
	checkLinuxTargets(t, string(out), releaseConfigs)
}

// checkLinuxTargets fails t when the linux platforms of configs differ from
// the linux targets in dist. Here dist is the output of go tool dist list. It
// also fails unless the host is the only platform with no dependency list.
func checkLinuxTargets(t testing.TB, dist string, configs []buildConfig) {
	t.Helper()
	var want, got, other []string
	for _, l := range strings.Fields(dist) {
		if strings.HasPrefix(l, "linux/") {
			want = append(want, l)
		}
	}
	for _, c := range configs {
		if usesDepList(c) {
			got = append(got, c.name())
		} else {
			other = append(other, c.name())
		}
	}
	slices.Sort(want)
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("releaseConfigs has the linux targets %q, want %q", got, want)
	}
	if !slices.Equal(other, []string{"default"}) {
		t.Errorf("platforms with no dependency list: %q, want the host only", other)
	}
}

// TestTS21CheckLinuxTargetsReports calls checkLinuxTargets on planted input.
// It must record a missing linux target and a second platform with no list.
func TestTS21CheckLinuxTargetsReports(t *testing.T) {
	dist := "darwin/arm64\nlinux/amd64\nlinux/arm64\n"
	amd, arm := buildConfig{"linux", "amd64"}, buildConfig{"linux", "arm64"}
	for name, tc := range map[string]struct {
		configs []buildConfig
		want    []string
	}{
		"complete": {[]buildConfig{amd, arm, {}}, nil},
		"missing target": {[]buildConfig{amd, {}}, []string{
			`releaseConfigs has the linux targets ["linux/amd64"], want ["linux/amd64" "linux/arm64"]`}},
		"no host": {[]buildConfig{amd, arm}, []string{
			`platforms with no dependency list: [], want the host only`}},
		"second host": {[]buildConfig{amd, arm, {}, {"darwin", "arm64"}}, []string{
			`platforms with no dependency list: ["default" "darwin/arm64"], want the host only`}},
	} {
		got := record(t, func(tb testing.TB) { checkLinuxTargets(tb, dist, tc.configs) })
		if !slices.Equal(got, tc.want) {
			t.Errorf("%s: errors %q, want %q", name, got, tc.want)
		}
	}
}

// TestTS21ReleaseListFormRules checks the text of each problem that
// listProblems gives. The lists have a wrong order, a repeat, an empty line or
// a line that is not used.
func TestTS21ReleaseListFormRules(t *testing.T) {
	used := map[string]bool{"a": true, "a/b": true, "b": true, "c": true, "B": true}
	for name, tc := range map[string]struct {
		lines []string
		want  []string
	}{
		"sorted":            {[]string{"a", "a/b", "b"}, nil},
		"swapped":           {[]string{"b", "a", "c"}, []string{"line 2, a, is out of order"}},
		"doubled":           {[]string{"a", "b", "b"}, []string{"line 3 repeats b"}},
		"repeat at line 2":  {[]string{"a", "a", "b"}, []string{"line 2 repeats a"}},
		"empty line":        {[]string{"a", "", "b"}, []string{"line 2 is empty"}},
		"empty first line":  {[]string{"", "a"}, []string{"line 1 is empty"}},
		"empty last line":   {[]string{"a", "b", ""}, []string{"line 3 is empty"}},
		"byte order":        {[]string{"B", "a"}, nil},
		"upper after lower": {[]string{"a", "B"}, []string{"line 2, B, is out of order"}},
		"line not used":     {[]string{"a", "b", "z"}, []string{"line 3, z, is not used"}},
		"first not used":    {[]string{"0", "a"}, []string{"line 1, 0, is not used"}},
		"all not used": {[]string{"x", "y"},
			[]string{"line 1, x, is not used", "line 2, y, is not used"}},
	} {
		if got := listProblems(tc.lines, used); !slices.Equal(got, tc.want) {
			t.Errorf("%s: problems %q, want %q", name, got, tc.want)
		}
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
	below := listedDep{modPath + "/x/p", outside, modPath + "/x", "", ""}
	variant := listedDep{"github.com/cybagard/Cyba-Phantom/egress/egresstest", outside,
		"github.com/cybagard/Cyba-Phantom", "", ""}
	variantRoot := "github.com/cybagard/Cyba-Phantom"
	sameReplace := listedDep{"example.org/lib", outside, "example.org/lib", "example.org/lib", "v1.1.0"}
	noModule := listedDep{modPath + "/x/q", outside, "", "", ""}
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
		{"replace with a module version", listedDep{"example.org/fork", outside, "example.org/lib", "example.org/fork", "v1.0.0"}, true},
		{"other module outside the root", listedDep{"example.org/lib", outside, "example.org/lib", "", ""}, false},
		{"module below the module path", below, true},
		{"case variant of the module path", variant, true},
		{"case variant of the module root path", listedDep{variantRoot, outside, variantRoot, "", ""}, true},
		{"replace to the same path with a version", sameReplace, true},
		{"module path with no module", noModule, true},
		{"module that starts with the module path", listedDep{modPath + "-x/p", outside, modPath + "-x", "", ""}, false},
		{"standard library", listedDep{"net/http", outside, "", "", ""}, false},
	} {
		if got := depProblem(realRoot, tc.d) != ""; got != tc.bad {
			t.Errorf("%s: depProblem has a problem: %t, want %t", tc.name, got, tc.bad)
		}
	}
	for name, tc := range map[string]struct {
		d    listedDep
		want string
	}{
		"module below the module path": {below, "its module " + modPath + "/x is not this module"},
		"case variant of the module path": {variant,
			"its path differs from the module path only in case"},
		"replace to the same path with a version": {sameReplace,
			"its module example.org/lib has a replace"},
		"module path with no module": {noModule,
			"it has no module, and its path is in this module"},
	} {
		if why := depProblem(realRoot, tc.d); why != tc.want {
			t.Errorf("%s: reason %q, want %q", name, why, tc.want)
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

// TestTS21ReleaseListErrorWithFolder runs go list on a package that has an
// error and a folder. On linux/amd64, parseDeps must report the error text.
func TestTS21ReleaseListErrorWithFolder(t *testing.T) {
	c := buildConfig{"linux", "amd64"}
	pkg := modPath + "/internal/egress/testdata/excludedpkg"
	args := []string{"list", "-e", "-deps", "-f", depFormat, pkg}
	out, err := goCommand(t, moduleRoot(t), c.env(), args...).Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	_, deps, problems, err := parseDeps(string(out), c)
	if err != nil {
		t.Fatal(err)
	}
	i := slices.IndexFunc(deps, func(d listedDep) bool { return d.Path == pkg })
	if i < 0 || deps[i].Dir == "" {
		t.Fatalf("go list gave %v, want the package %s with a folder", deps, pkg)
	}
	if len(problems) != 1 || !strings.Contains(problems[0], "build constraints exclude all Go files") {
		t.Errorf("problems %q, want one with the error text of go list", problems)
	}
}

// TestTS21ReleaseListNoFolder gives parseDeps a line with no folder and no
// error. On linux/amd64 it must report that go list gives no folder.
func TestTS21ReleaseListNoFolder(t *testing.T) {
	c := buildConfig{"linux", "amd64"}
	line := "linux/amd64/false\tx/p\t\t\t\t\t\n"
	_, _, problems, err := parseDeps(line, c)
	if err != nil {
		t.Fatal(err)
	}
	if len(problems) != 1 || !strings.Contains(problems[0], "x/p on linux/amd64: go list gives no folder") {
		t.Errorf("problems %q, want x/p with no folder", problems)
	}
}

// recorder is a testing.TB that records the errors instead of failing a test.
// A call to Fatal or Fatalf records the error and ends the goroutine.
type recorder struct {
	testing.TB
	errs []string
}

func (r *recorder) Helper() {}

func (r *recorder) Error(args ...any) { r.errs = append(r.errs, fmt.Sprint(args...)) }

func (r *recorder) Errorf(f string, args ...any) {
	r.errs = append(r.errs, fmt.Sprintf(f, args...))
}

func (r *recorder) Fatal(args ...any) {
	r.Error(args...)
	runtime.Goexit()
}

func (r *recorder) Fatalf(f string, args ...any) {
	r.Errorf(f, args...)
	runtime.Goexit()
}

// TestTS21ReleaseListDepsReports calls listDeps with a recorder on a path that
// has no package. It must record an error for linux/amd64 and none for
// linux/386.
func TestTS21ReleaseListDepsReports(t *testing.T) {
	root := moduleRoot(t)
	missing := modPath + "/internal/egress/testdata/nosuchpkg"
	for _, tc := range []struct {
		c    buildConfig
		want bool
	}{{buildConfig{"linux", "amd64"}, true}, {buildConfig{"linux", "386"}, false}} {
		errs := record(t, func(tb testing.TB) { listDeps(tb, root, tc.c, missing) })
		if got := len(errs) > 0; got != tc.want {
			t.Errorf("%s: errors %q, want an error: %t", tc.c.name(), errs, tc.want)
		}
		if tc.want && (len(errs) != 1 || !strings.Contains(errs[0], missing+" on linux/amd64: go list reports the error ")) {
			t.Errorf("%s: errors %q, want one that names %s and the reason", tc.c.name(), errs, missing)
		}
	}
}

// TestTS21ReleaseListCheck checks that listProblem gives a problem for a
// package error and for a package with no folder. It checks that completeList
// names three platforms.
func TestTS21ReleaseListCheck(t *testing.T) {
	for name, tc := range map[string]struct {
		dir, errText string
		bad          bool
	}{
		"package with a folder": {"/src/p", "", false},
		"package error":         {"/src/p", `"no Go files"`, true},
		"no folder":             {"", "", true},
		"error and no folder":   {"", `"import cycle"`, true},
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
// replace. When allowed is not nil, scan finds each import from outside the
// module that is not in allowed. It also gives the set of all imports from
// outside the module.
func scan(root string, allowed map[string]bool) ([]finding, map[string]bool, error) {
	return scanWith(root, allowed, filepath.WalkDir)
}

// notOnImportList ends the form of a finding for an import that is not listed.
const notOnImportList = " is not on the import list"

// inModule tells if the import path p is the module or is below it.
func inModule(p string) bool {
	return p == modPath || strings.HasPrefix(p, modPath+"/")
}

// inModuleFold is inModule with no regard to case.
func inModuleFold(p string) bool {
	n := len(modPath)
	return len(p) >= n && strings.EqualFold(p[:n], modPath) && (len(p) == n || p[n] == '/')
}

// scanWith is scan with the function walk, which walks the tree of root.
func scanWith(root string, allowed map[string]bool,
	walk func(string, fs.WalkDirFunc) error) ([]finding, map[string]bool, error) {
	var out []finding
	seen := map[string]bool{}
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
		for _, x := range scanFile(fset, f, strings.HasPrefix(rel, "internal/egress/"),
			allowed, seen) {
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
	return out, seen, err
}

// scanFile gives the findings in f, with no File. inEgress is true for a file
// in internal/egress or below. The syntax tree has no types. Thus the scan
// reads the package of a selector from the imports of the file. It finds the
// fields of dialerHooks by name only. It adds each import from outside the
// module to seen. When allowed is not nil, it finds each one not in allowed.
func scanFile(fset *token.FileSet, f *ast.File, inEgress bool,
	allowed, seen map[string]bool) []finding {
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
		if p != "C" && !inModule(p) {
			seen[p] = true
			if allowed != nil && !allowed[p] {
				add(imp.Pos(), "import "+p+notOnImportList)
			}
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
// list. A child process is not in the scan: os/exec, os.StartProcess or
// syscall.ForkExec. A command can open a connection that the scan does not
// see. The test also fails on each import from outside the module that is not
// on release-imports.txt. It fails on each form problem of that file too.
func TestTS21SourceHasNoDialerOutsideGuard(t *testing.T) {
	checkImportList(t, moduleRoot(t), loadList(t, "release-imports.txt"))
}

// checkImportList scans the non-test files below root with the import list
// that it builds from lines. It fails t on each finding and on a file that does
// not parse. It also fails on each problem that listProblems finds in lines.
// The used lines are the imports that the scan saw.
func checkImportList(t testing.TB, root string, lines []string) {
	t.Helper()
	found, seen, err := scan(root, lineSet(lines))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range found {
		t.Error(f)
	}
	for _, p := range listProblems(lines, seen) {
		t.Errorf("release-imports.txt: %s", p)
	}
}

// TestTS21CheckImportListReports calls checkImportList on a planted folder and
// a planted list. It must record an import that is not on the list and a line
// that no file imports.
func TestTS21CheckImportListReports(t *testing.T) {
	dir := t.TempDir()
	plantFile(t, dir, "p/a.go", "package p\n\nimport (\n\t\"net\"\n\t\"example.org/a\"\n)\n")
	lines := []string{"example.org/z", "net"}
	want := []string{
		"p/a.go:5: import example.org/a" + notOnImportList,
		"release-imports.txt: line 1, example.org/z, is not used",
	}
	got := record(t, func(tb testing.TB) { checkImportList(tb, dir, lines) })
	if !slices.Equal(got, want) {
		t.Errorf("errors %q, want %q", got, want)
	}
}

// TestTS21CheckImportListParseError plants a file that does not parse. The
// helper must record one error that names the file.
func TestTS21CheckImportListParseError(t *testing.T) {
	dir := t.TempDir()
	plantFile(t, dir, "p/bad.go", "package p\n\nimport (\n")
	got := record(t, func(tb testing.TB) { checkImportList(tb, dir, []string{"net"}) })
	if len(got) != 1 || !strings.Contains(got[0], "bad.go") {
		t.Errorf("errors %q, want one that names bad.go", got)
	}
}

// TestTS21ImportListFindsPlantedImports plants files that import a package
// that is not on the list. The scan must find each one, in a folder outside
// internal/egress and in internal/egress, for each form of the import. A path
// that only starts with the module path is not in the module.
func TestTS21ImportListFindsPlantedImports(t *testing.T) {
	dir := t.TempDir()
	list := map[string]bool{"net": true}
	want := map[string]string{} // file to the path that the scan must find
	for i, p := range []string{
		"golang.org/x/net/context/ctxhttp", "github.com/mholt/acmez/v3/acme",
		"golang.org/x/net/nettest", "net/http/httptest",
		"github.com/letsencrypt/pebble/v2/va", "github.com/miekg/dns",
		modPath + "-x/p", modPath + "x",
	} {
		for _, sub := range []string{"pkg", "internal/egress"} {
			rel := sub + "/p" + strconv.Itoa(i) + ".go"
			want[rel] = p
			plantFile(t, dir, rel, "package p\n\nimport \""+p+"\"\n")
		}
	}
	for form, imp := range map[string]string{
		"blank": "_ \"example.org/a\"", "dot": ". \"example.org/b\"",
		"alias": "x \"example.org/c\"",
	} {
		want["form_"+form+".go"] = strings.Trim(strings.Fields(imp)[1], `"`)
		plantFile(t, dir, "form_"+form+".go", "package p\n\nimport "+imp+"\n")
	}
	plantFile(t, dir, "ok.go", "package p\n\nimport (\n\t\"net\"\n\t\""+modPath+
		"\"\n\t\""+modPath+"/internal/x\"\n\t\"C\"\n)\n")
	found, seen, err := scan(dir, list)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, f := range found {
		if f.Form == "import C" {
			continue
		}
		got[f.File] = strings.TrimSuffix(strings.TrimPrefix(f.Form, "import "),
			notOnImportList)
	}
	if !maps.Equal(got, want) {
		t.Errorf("found %q, want %q", got, want)
	}
	if seen["C"] || seen[modPath] || seen[modPath+"/internal/x"] || !seen["net"] {
		t.Errorf("seen imports %v", seen)
	}
}

// plantFile writes src to the file rel below dir.
func plantFile(t *testing.T, dir, rel, src string) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestTS21ScanFindsPlantedFiles plants files in a temp directory. It checks
// the forms that scan finds in each file, and the files that it skips.
func TestTS21ScanFindsPlantedFiles(t *testing.T) {
	dir := t.TempDir()
	plant := func(rel, src string) {
		t.Helper()
		plantFile(t, dir, rel, src)
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

	// The table names the inherited sockets.
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

	// A directive, cgo, assembly, and code in internal/egress.
	plantWant("link.go", "package p\n\n//go:linkname f runtime.f\nfunc f()\n",
		"go:linkname directive")
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

	got, _, err := scan(dir, nil)
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
	if _, _, err := scan(dir, nil); err == nil {
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
	got, _, err := scan(dir, nil)
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
		if _, _, err := scanWith(dir, nil, walk); (err != nil) != tc.wantErr {
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
