package config

import (
	"cmp"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
)

// testDir holds a valid htpasswd file: the default path of the production table does not exist here.
// It is below the package directory, not the system temporary directory.
// The htpasswd rule refuses a parent with a group or other write bit.
// The system temporary directory can have mode 1777.
// TestMain removes testDir.
var testDir = func() string {
	d, err := os.MkdirTemp(".", "config-test-")
	if err == nil {
		d, err = filepath.Abs(d)
	}
	if err == nil {
		err = os.WriteFile(filepath.Join(d, "htpasswd"), nil, 0o600)
	}
	if err != nil {
		panic(err)
	}
	return d
}()

func TestMain(m *testing.M) {
	code := m.Run()
	os.RemoveAll(testDir)
	os.Exit(code)
}

// testKeys uses the htpasswd file in testDir and adds kinds that the production table does not have yet.
var testKeys = append(withHtpasswd(keys, filepath.Join(testDir, "htpasswd")), []key{
	{path: "a.flag", kind: kindBool, def: "false"},
	{path: "a.port", kind: kindUint, def: "8"},
	{path: "a.delta", kind: kindInt, def: "-1"},
	{path: "a.size", kind: kindBytes, def: "65536"},
	{path: "a.every", kind: kindDuration, def: "6h"},
	{path: "a.token", kind: kindString, secret: true},
	{path: "a.pin", kind: kindInt, def: "0", secret: true},
}...)

func withHtpasswd(table []key, path string) []key {
	out := append([]key{}, table...)
	for i := range out {
		if out[i].path == "ops.basic_auth_htpasswd" {
			out[i].def = path
		}
	}
	return out
}

// cfg has 64 bytes: esc does not cut it. TestTS10_LeftCut cuts a longer path.
var cfg = filepath.Join(strings.Repeat("d", 52), "config.yaml")

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	t.Chdir(t.TempDir())
	if err := cmp.Or(os.Mkdir(filepath.Dir(cfg), 0o700), os.WriteFile(cfg, []byte(body), 0o600)); err != nil {
		t.Fatal(err)
	}
	return cfg
}

// base has 4 lines. Thus, a section line that a test adds after base is on line 5, and its first key is on line 6.
// The acme section has three lines (with acmeNames). The tlog section has one line, and its publisher names
// the variable tokenVar. tlogOrigin adds an empty line after the tlog section; base does not.
const (
	tokenVar   = "CKPT_TOKEN"
	tlogLine   = "tlog: {origin: test/origin, publish: [{type: https-put, url: \"https://ckpt.example/put\", token_env: " + tokenVar + "}]}\n"
	tlogOrigin = tlogLine + "\n"
	acmeNames  = "  names: [decoy.host.zz]\n"
	base       = "acme:\n  email: sec@example.com\n" + acmeNames + tlogLine
)

// loadTest is Load with one entry for tokenVar before env. If the file names
// tokenVar in a *_env key, an entry for tokenVar in env makes two entries.
// Load then fails with the text of envMany.
func loadTest(path string, env []string) (*Config, error) {
	return Load(path, append([]string{tokenVar + "=" + strings.Repeat("t", 32)}, env...))
}

// testNet is a Net with a stub in each field. LoadWith accepts it.
var testNet = Net{Dialer: stubNet{}, Resolver: stubNet{}}

// TestTU10_Precedence checks default < file < env and the source of each value.
func TestTU10_Precedence(t *testing.T) {
	useTestKeys(t)
	rows := []struct {
		name, file, env, key string
		want                 Value
	}{
		{"default", base, "", "listen.http", Value{Str: ":80", Source: "default"}},
		{"file", base + "listen:\n  http: \":8080\"\n", "", "listen.http", Value{Str: ":8080", Source: cfg, Line: 6}},
		{"env", base + "listen:\n  http: \":8080\"\n", "PHANTOM_LISTEN_HTTP=:81", "listen.http", Value{Str: ":81", Source: "PHANTOM_LISTEN_HTTP"}},
		{"htpasswd default", base, "", "ops.basic_auth_htpasswd", Value{Str: filepath.Join(testDir, "htpasswd"), Source: "default"}},
		{"int default", base, "", "a.delta", Value{Int: -1, Source: "default"}},
		{"int file", base + "a:\n  delta: -7\n", "", "a.delta", Value{Int: -7, Source: cfg, Line: 6}},
		{"int env", base + "a:\n  delta: -7\n", "PHANTOM_A_DELTA=9", "a.delta", Value{Int: 9, Source: "PHANTOM_A_DELTA"}},
		{"bool env", base + "a:\n  flag: false\n", "PHANTOM_A_FLAG=true", "a.flag", Value{Bool: true, Source: "PHANTOM_A_FLAG"}},
		{"duration file", base + "a:\n  every: 15m\n", "", "a.every", Value{Dur: 15 * time.Minute, Source: cfg, Line: 6}},
		{"bytes env", base, "PHANTOM_A_SIZE=1024", "a.size", Value{Int: 1024, Source: "PHANTOM_A_SIZE"}},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			c, err := LoadWith(writeConfig(t, r.file), append(strings.Fields(r.env), tokenVar+"=token"), testNet)
			if err != nil {
				t.Fatal(err)
			}
			if v, _ := c.Get(r.key); v != r.want {
				t.Errorf("got %+v, want %+v", v, r.want)
			}
		})
	}
}

// TestTU10_EffectiveValueCheck uses the production key table. It checks that each check runs on
// the effective value only: a default that the file or the environment replaces is not checked.
func TestTU10_EffectiveValueCheck(t *testing.T) {
	const def = "/etc/phantom/htpasswd"
	if _, err := os.Lstat(def); err == nil {
		t.Skip("the default htpasswd file exists on this host")
	}
	good := filepath.Join(testDir, "htpasswd")
	t.Run("file", func(t *testing.T) {
		c, err := loadTest(writeConfig(t, base+"ops:\n  basic_auth_htpasswd: "+good+"\n"), nil)
		if err != nil {
			t.Fatal(err)
		}
		if v, _ := c.Get("ops.basic_auth_htpasswd"); v.Str != good || v.Source != cfg || v.Line != 6 {
			t.Errorf("got %+v", v)
		}
	})
	t.Run("env", func(t *testing.T) {
		c, err := loadTest(writeConfig(t, base), []string{"PHANTOM_OPS_BASIC_AUTH_HTPASSWD=" + good})
		if err != nil {
			t.Fatal(err)
		}
		if v, _ := c.Get("ops.basic_auth_htpasswd"); v.Str != good || v.Source != "PHANTOM_OPS_BASIC_AUTH_HTPASSWD" {
			t.Errorf("got %+v", v)
		}
	})
	t.Run("env over bad file value", func(t *testing.T) {
		bad := filepath.Join(testDir, "missing")
		_, err := loadTest(writeConfig(t, base+"ops:\n  basic_auth_htpasswd: "+bad+"\n"), []string{"PHANTOM_OPS_BASIC_AUTH_HTPASSWD=" + good})
		if err != nil {
			t.Errorf("a file value that the environment replaces is checked: %v", err)
		}
	})
	t.Run("default fails", func(t *testing.T) {
		_, err := loadTest(writeConfig(t, base), nil)
		if err == nil || !strings.Contains(err.Error(), "ops.basic_auth_htpasswd at default: the htpasswd file cannot be resolved") {
			t.Errorf("got %v", err)
		}
	})
	t.Run("file value fails", func(t *testing.T) {
		bad := filepath.Join(testDir, "missing")
		_, err := loadTest(writeConfig(t, base+"ops:\n  basic_auth_htpasswd: "+bad+"\n"), nil)
		if err == nil || !strings.Contains(err.Error(), "ops.basic_auth_htpasswd at "+cfg[len(cfg)-64:]+":6: ") || strings.Contains(err.Error(), "default") {
			t.Errorf("got %v", err)
		}
	})
}

// TestTU10_EnvNames checks that each key in the key table has its own variable name.
func TestTU10_EnvNames(t *testing.T) {
	seen := make(map[string]string)
	for _, k := range keys {
		if p, ok := seen[envName(k.path)]; ok {
			t.Errorf("%s and %s have the same variable name", p, k.path)
		}
		seen[envName(k.path)] = k.path
	}
}

// TestTU10_Errors checks unknown keys, wrong shapes, and error collection.
func TestTU10_Errors(t *testing.T) {
	useTestKeys(t)
	p := writeConfig(t, "zz: 1\nlisten:\n  http: \":1\"\n  bogus: 1\nfoo:\n  bar: 1\nops: [x]\nacme:\n  email: [a]\n")
	_, err := loadTest(p, []string{"PHANTOM_LISTEN_HTTPS=:2", "PHANTOM_NOPE=1", "HOME=/x"})
	want := strings.Join([]string{
		`config: zz at ` + p + `:1: unknown key`,
		`config: listen.bogus at ` + p + `:4: unknown key`,
		`config: foo at ` + p + `:5: unknown key`,
		`config: ops at ` + p + `:7: the section needs a mapping`,
		`config: acme.email at ` + p + `:9: the key needs a scalar value`,
		`config: PHANTOM_NOPE: unknown PHANTOM variable`,
		`config: tlog.origin at ` + p + `: the key is required`,
		`config: tlog.publish at ` + p + `: the key is required`,
		`config: acme.names at ` + p + `: acme.names and tls.certs need 1 to 16 names in total`,
	}, "\n")
	if err.Error() != want {
		t.Errorf("got\n%v\nwant\n%v", err, want)
	}
	for _, body := range []string{"", "a: [\n"} {
		if _, err := loadTest(writeConfig(t, body), nil); err == nil {
			t.Errorf("Load(%q) returned no error", body)
		}
	}
	_, err = loadTest(filepath.Join(t.TempDir(), "missing.yaml"), nil)
	if err == nil || !strings.HasSuffix(err.Error(), ": the file does not exist") {
		t.Errorf("missing file: got %v", err)
	}
}

// TestTU10_ReaderErrorValues checks the load after a reader error. It also
// shows the parse errors and the check errors of each known variable. It
// runs no cross-check.
func TestTU10_ReaderErrorValues(t *testing.T) {
	useTestKeys(t)
	_, err := loadTest(filepath.Join(t.TempDir(), "missing.yaml"), []string{"PHANTOM_A_PORT=017", "PHANTOM_A_FLAG=true", "PHANTOM_LIMITS_MAX_CONNS=2001"})
	if err == nil {
		t.Fatal("got no error")
	}
	for _, want := range []string{
		": the file does not exist",
		"a.port at PHANTOM_A_PORT: an integer is a decimal literal only",
		"limits.max_conns at PHANTOM_LIMITS_MAX_CONNS: the value must be in the range 1 to 2000",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("got %v, want %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "a.flag") {
		t.Errorf("a good value gives an error: %v", err)
	}
}

// TestTU10_RequiredParseError checks a required key that is set but does not
// parse. It gets the parse error only. It gets no required-key error.
func TestTU10_RequiredParseError(t *testing.T) {
	useTestKeys(t)
	_, err := loadTest(writeConfig(t, "acme:\n  email: 5\n"+acmeNames+tlogLine), nil)
	if err == nil || !strings.Contains(err.Error(), "acme.email at "+cfg[len(cfg)-64:]+":2: the value is not a valid string") {
		t.Fatalf("got %v, want the parse error", err)
	}
	if strings.Contains(err.Error(), "required") {
		t.Errorf("the key is set, but the error says it is required: %v", err)
	}
}

// TestTU10_UnknownTwice checks that an unknown PHANTOM_ name that is in env
// two times gives one error.
func TestTU10_UnknownTwice(t *testing.T) {
	useTestKeys(t)
	_, err := loadTest(writeConfig(t, base), []string{"PHANTOM_NOPE=1", "PHANTOM_NOPE=2"})
	if err == nil || strings.Count(err.Error(), "PHANTOM_NOPE") != 1 {
		t.Errorf("got %v, want one error for PHANTOM_NOPE", err)
	}
}

// TestTU10_NoReload checks that the package exports no reload function.
func TestTU10_NoReload(t *testing.T) {
	names, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	parsed := 0
	for _, name := range names {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		parsed++
		ast.Inspect(file, func(n ast.Node) bool {
			if fn, ok := n.(*ast.FuncDecl); ok && fn.Name.IsExported() && strings.Contains(strings.ToLower(fn.Name.Name), "reload") {
				t.Errorf("exported reload function %s", fn.Name.Name)
			}
			return true
		})
	}
	if parsed == 0 {
		t.Error("no non-test .go file found")
	}
}

// useTestKeys sets the key table to testKeys until the test ends, so Load also checks the
// test keys. A test that calls it must not run in parallel.
func useTestKeys(t *testing.T) {
	old := keys
	keys = testKeys
	t.Cleanup(func() { keys = old })
}

// TestTS10_Scalars checks strict scalars, unknown PHANTOM variables, and
// escaped values through Load.
func TestTS10_Scalars(t *testing.T) {
	useTestKeys(t)
	rows := []struct{ name, file, env, want string }{
		{"YAML 1.1 bool yes", "a:\n  flag: yes\n", "", "the value is not a valid bool"},
		{"YAML 1.1 bool on", "a:\n  flag: on\n", "", "the value is not a valid bool"},
		{"octal", "a:\n  port: 017\n", "", "decimal literal only"},
		{"hex", "a:\n  port: 0x1F\n", "", "decimal literal only"},
		{"underscore", "a:\n  size: 1_000\n", "", "decimal literal only"},
		{"sign on uint", "a:\n  port: -1\n", "", "decimal literal only"},
		{"float into int", "a:\n  delta: 1.5\n", "", "the value is not a valid int"},
		{"quoted int", "a:\n  port: \"8080\"\n", "", "the value is not a valid uint"},
		{"tagged int", "a:\n  port: !!int x\n", "", "decimal literal only"},
		{"plus sign", "a:\n  delta: +5\n", "", "decimal literal only"},
		{"0o prefix", "a:\n  delta: 0o17\n", "", "decimal literal only"},
		{"minus zero", "a:\n  delta: -0\n", "", "decimal literal only"},
		{"null", "a:\n  every: ~\n", "", "the value is not a valid duration"},
		{"duration number", "a:\n  every: 5\n", "", "the value is not a valid duration"},
		{"env octal", "", "PHANTOM_A_PORT=017", "decimal literal only"},
		{"env bool", "", "PHANTOM_A_FLAG=on", "true or false only"},
		{"env range", "", "PHANTOM_A_SIZE=99999999999999999999", "out of range"},
		{"bool into string", "listen:\n  https: true\n", "", "the value is not a valid string"},
		{"octal into string", "listen:\n  http: 017\n", "", "the value is not a valid string"},
		{"unknown env", "", "PHANTOM_LISTEN_HTTPX=:1", "PHANTOM_LISTEN_HTTPX: unknown PHANTOM variable"},
		{"lower case env", "", "phantom_listen_http=:1", "phantom_listen_http: unknown PHANTOM variable"},
		{"mixed case env", "", "Phantom_Listen_Http=:1", "Phantom_Listen_Http: unknown PHANTOM variable"},
		{"dash env", "", "PHANTOM-LISTEN-HTTP=:1", "PHANTOM-LISTEN-HTTP: unknown PHANTOM variable"},
		{"name of another program", "", "PHANTOMJS_BIN=x", "PHANTOMJS_BIN: unknown PHANTOM variable"},
		{"ESC in env name", "", "PHANTOM_X\x1b[2J=1", `PHANTOM_X\x1b[2J: unknown PHANTOM variable`},
		{"URL text to the last @", "", "PHANTOM_A_EVERY=https://user:p/w@host", `: value "https://REDACTED@host"`},
		{"URL form without //", "", "PHANTOM_A_EVERY=https:u:SECRET@h", `: value "REDACTED@h"`},
		{"reader key not printed", "listen:\n  \"\\e[2J\": 1\n", "", `/config.yaml:6: listen: column 3: ` + keyRule},
		{"known env name twice", "", "PHANTOM_A_FLAG=true PHANTOM_A_FLAG=false", "PHANTOM_A_FLAG: the variable occurs more than one time"},
		{"known env name twice, reader error", "a: [\n", "PHANTOM_A_FLAG=true PHANTOM_A_FLAG=false", "PHANTOM_A_FLAG: the variable occurs more than one time"},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			_, err := loadTest(writeConfig(t, base+r.file), strings.Fields(r.env))
			if err == nil || !strings.Contains(err.Error(), r.want) {
				t.Errorf("got %v, want %q", err, r.want)
			}
		})
	}
}

// TestTS10_EnvNameForms checks the names that envFold reads as PHANTOM names.
// They have no "_", a ".", leading white space, or invisible, control,
// combining or full-width characters. PHANTOMJS_BIN shows that the rule also
// refuses a name of another program. A character next to the full-width range
// is not a form.
func TestTS10_EnvNameForms(t *testing.T) {
	useTestKeys(t)
	for _, name := range []string{
		"PHANTOMX", "PHANTOM.X", " PHANTOM_X", "\tPHANTOM_X", "PHANTOM", "PHANTOMJS_BIN",
		"PHANTOM\u200b_X", "\u200bPHANTOM_X", "\uff30HANTOM_X", "\uff30\uff28\uff21\uff2e\uff34\uff2f\uff2d_X",
		"PHANTOM\uff3fX",
		"\u3164PHANTOM_A_PORT", "\uffa0PHANTOM_A_PORT", "\u115fPHANTOM_A_PORT",
		"PHANTOM\u034f_A_PORT", "P\u0301HANTOM_A_PORT", "P\u20ddHANTOM_A_PORT",
		"PHANTOM\ufe0f_A_PORT", "\x1bPHANTOM_A_PORT", "\x01PHANTOM_A_PORT",
	} {
		_, err := loadTest(writeConfig(t, base), []string{name + "=1"})
		if err == nil || !strings.Contains(err.Error(), "unknown PHANTOM variable") {
			t.Errorf("%q: got %v, want the unknown-name error", name, err)
		}
	}
	for _, name := range []string{"PHANTO_X", "XPHANTOM_X", "!PHANTOM_X", "\uff00PHANTOM_X", "\uff5fPHANTOM_X"} {
		if _, err := loadTest(writeConfig(t, base), []string{name + "=1"}); err != nil {
			t.Errorf("%q: got %v, want no error", name, err)
		}
	}
}

// TestTS10_WrittenTag checks the YAML tags of a file value through Load.
// The tag "!" gives an error that names the key. So does a tag other than
// "!!str" on a quoted or block scalar. The kind tag of the key on a plain
// scalar stays valid, for example "!!int 80" on an int key.
// So does "!!str" on a quoted or block scalar.
func TestTS10_WrittenTag(t *testing.T) {
	useTestKeys(t)
	rows := []struct{ name, file, key, detail string }{
		{"bare tag, int", "a:\n  delta: ! 80\n", "a.delta", "the value is not a valid int"},
		{"bare tag, flow", "a: {delta: ! 80}\n", "a.delta", "the value is not a valid int"},
		{"bare tag, quoted int", "a:\n  port: ! \"80\"\n", "a.port", "the value is not a valid uint"},
		{"bare tag, string", "listen:\n  http: ! \":1\"\n", "listen.http", "the value is not a valid string"},
		{"bare tag, plain string", "listen:\n  http: ! x\n", "listen.http", "the value is not a valid string"},
		{"bare tag, bool", "a:\n  flag: ! true\n", "a.flag", "the value is not a valid bool"},
		{"quoted int tag", "a:\n  delta: !!int \"80\"\n", "a.delta", "the value is not a valid int"},
		{"quoted bool tag", "a:\n  flag: !!bool 'true'\n", "a.flag", "the value is not a valid bool"},
		{"quoted int tag, string", "listen:\n  http: !!int \"80\"\n", "listen.http", "the value is not a valid string"},
		{"literal int tag", "a:\n  delta: !!int |-\n    80\n", "a.delta", "the value is not a valid int"},
		{"folded int tag", "a:\n  delta: !!int >-\n    80\n", "a.delta", "the value is not a valid int"},
		{"literal bool tag", "a:\n  flag: !!bool |-\n    true\n", "a.flag", "the value is not a valid bool"},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			_, err := loadTest(writeConfig(t, base+r.file), nil)
			joined, ok := err.(interface{ Unwrap() []error })
			if !ok {
				t.Fatalf("got %v, want a join of errors", err)
			}
			found := false
			for _, e := range joined.Unwrap() {
				if e, ok := e.(*Error); ok && e.Key == r.key && e.Detail == r.detail {
					found = true
				}
			}
			if !found {
				t.Errorf("got %v, want an error for %s: %s", err, r.key, r.detail)
			}
		})
	}
	c, err := loadTest(writeConfig(t, base+"a:\n  delta: !!int 80\nlisten:\n  http: !!str \":1\"\n"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := c.Get("a.delta"); v.Int != 80 {
		t.Errorf("a.delta = %+v, want 80", v)
	}
	for _, body := range []string{"!!str |-\n    :1\n", "|-\n    :1\n", "!!str >-\n    :1\n", "':1'\n"} {
		c, err := loadTest(writeConfig(t, base+"listen:\n  http: "+body), nil)
		if err != nil {
			t.Fatalf("%q: %v", body, err)
		}
		if v, _ := c.Get("listen.http"); v.Str == "" {
			t.Errorf("%q: listen.http is empty", body)
		}
	}
}

// hasKeyError reports whether err is a join with an *Error for key.
func hasKeyError(err error, key string) bool {
	joined, ok := err.(interface{ Unwrap() []error })
	if !ok {
		return false
	}
	for _, e := range joined.Unwrap() {
		if e, ok := e.(*Error); ok && e.Key == key {
			return true
		}
	}
	return false
}

// TestTS10_BareTagPosition checks the bare tag "!" on line 1, on the last
// line without an LF, and at column 1. The reader gives the tag "!" and Load
// refuses the key. An empty value at the end of a line gives an error, not a
// panic.
func TestTS10_BareTagPosition(t *testing.T) {
	useTestKeys(t)
	rows := []struct {
		name, file, leaf, key string
		bare                  bool
	}{
		{"line 1", "a: {delta: ! 80}\n", "a.delta", "a.delta", true},
		{"last line, no LF", "a:\n  delta: ! 80", "a.delta", "a.delta", true},
		{"column 1, flow sequence", "a: [\n! 80]\n", "a[0]", "", true},
		{"column 1, flow mapping", "a: {delta:\n! 80}\n", "a.delta", "a.delta", true},
		{"empty value, no LF", "a:\n  delta:", "a.delta", "a.delta", false},
		{"empty value, next key", "a:\n  delta:\n  flag: true\n", "a.delta", "a.delta", false},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			doc, err := ReadBytes([]byte(r.file))
			if err != nil {
				t.Fatal(err)
			}
			if got := doc.Leaves[r.leaf].Tag == "!"; got != r.bare {
				t.Errorf("Leaf %s = %+v, want the bare tag: %v", r.leaf, doc.Leaves[r.leaf], r.bare)
			}
			if r.key == "" {
				return
			}
			_, err = loadTest(writeConfig(t, r.file), nil)
			if !hasKeyError(err, r.key) {
				t.Errorf("got %v, want an error for %s", err, r.key)
			}
		})
	}
}

// TestTS10_BareTagAlloc checks that the reader does not copy the line for each
// scalar. A flow line of about 64 000 bytes stays in a small byte budget.
// A copy for each scalar needs gigabytes.
func TestTS10_BareTagAlloc(t *testing.T) {
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, err := ReadBytes([]byte("a: [" + strings.Repeat("1,", 32000) + "1]\n"))
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatal(err)
	}
	const budget = 128 << 20
	if got := after.TotalAlloc - before.TotalAlloc; got > budget {
		t.Errorf("ReadBytes allocated %d bytes, want at most %d", got, budget)
	}
}

// TestTS10_BareTagSteps checks that the rune reads of bareTag on one line
// stay linear. A flow line with many scalars gives at most twice its length
// in steps. A read from the line start for each scalar gives a square.
func TestTS10_BareTagSteps(t *testing.T) {
	line := "a: [" + strings.Repeat("1,", 32000) + "1]"
	var node yaml.Node
	if err := yaml.Unmarshal([]byte(line), &node); err != nil {
		t.Fatal(err)
	}
	doc := &Doc{Leaves: map[string]Leaf{}, Mappings: map[string]bool{}, Sequences: map[string]bool{}, Lines: map[string]int{}}
	src := &lineCursor{lines: [][]byte{[]byte(line)}}
	if err := walkNode(node.Content[0], nil, "", doc, 0, src); err != nil {
		t.Fatal(err)
	}
	if src.steps > 2*len(line) {
		t.Errorf("bareTag read %d runes of a line of %d bytes", src.steps, len(line))
	}
}

// TestTS10_SecretEnvPrefix checks that a *_env key refuses each name that
// the environment check refuses, with or without "_".
func TestTS10_SecretEnvPrefix(t *testing.T) {
	for _, name := range []string{"PHANTOMTOKEN", "PHANTOM_TOKEN", "PHANTOM"} {
		file := strings.Replace(base, "token_env: "+tokenVar, "token_env: "+name, 1)
		_, err := loadTest(writeConfig(t, file), []string{name + "=" + strings.Repeat("t", 32)})
		if !hasKeyError(err, "tlog.publish[0].token_env") {
			t.Errorf("%s: got %v, want an error for tlog.publish[0].token_env", name, err)
		}
	}
}

// TestTS10_Unreadable checks the detail for a file that the loader cannot
// read because of its mode.
func TestTS10_Unreadable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a file with mode 0000: no permission error")
	}
	p := writeConfig(t, base)
	if err := os.Chmod(p, 0); err != nil {
		t.Fatal(err)
	}
	_, err := loadTest(p, nil)
	var e *Error
	if !errors.As(err, &e) || e.Detail != "permission denied" {
		t.Errorf("got %v, want the detail %q", err, "permission denied")
	}
}

// TestTS10_NetReachesLoader checks that LoadWith gives its Net to the loader,
// not a zero Net. A test key check reads the Net.
func TestTS10_NetReachesLoader(t *testing.T) {
	var got Net
	old := keys
	keys = append(slices.Clone(testKeys), key{path: "a.probe", kind: kindString, def: "x",
		check: func(l *loader, _ string) string { got = l.net; return "" }})
	t.Cleanup(func() { keys = old })
	if _, err := LoadWith(writeConfig(t, base), []string{tokenVar + "=token"}, testNet); err != nil {
		t.Fatal(err)
	}
	if got != testNet {
		t.Errorf("the loader has %+v, want %+v", got, testNet)
	}
}

// TestTS10_OldPrefixIgnored checks that a variable with the old prefix is not special: Load
// ignores it, even when its name is a known key, and the value does not reach the config.
func TestTS10_OldPrefixIgnored(t *testing.T) {
	useTestKeys(t)
	c, err := loadTest(writeConfig(t, base+"listen:\n  http: \":8080\"\n"), []string{"CANARY_LISTEN_HTTP=:81", "CANARY_NOPE=1"})
	if err != nil {
		t.Fatalf("Load returned an error for variables with the old prefix: %v", err)
	}
	if v, _ := c.Get("listen.http"); v.Str != ":8080" || v.Source == "CANARY_LISTEN_HTTP" {
		t.Errorf("listen.http = %+v, want the file value", v)
	}
}

// TestTS10_Secret checks that no error shows the secret. The secret is in a
// YAML value, a tag, a mapping key, or a key below a secret key.
// The joined text of the errors holds want.
func TestTS10_Secret(t *testing.T) {
	useTestKeys(t)
	const marker = "secret_marker_7f3a"
	for _, r := range []struct{ body, want string }{
		{"token: " + marker + "\n  pin: " + marker + "\n  port: x", "a.pin"},
		{"token: !" + marker, "a.token"}, {"pin: !" + marker, "a.pin"},
		{"token: !<" + marker + "> x", "a.token"}, {"token: [!" + marker + "]", "invalid YAML"},
		{"token: {" + strings.ToUpper(marker) + ": 1}", "a.token"},
		{"token:\n    " + marker + ":\n      x: !t 1", "a.token"}, {"token: [" + marker + ": !t 1]", "a.token"},
	} {
		_, err := loadTest(writeConfig(t, base+"a:\n  "+r.body+"\n"), []string{"PHANTOM_A_TOKEN=" + marker, "PHANTOM_A_PIN=" + marker})
		// Load joins the *Error values.
		joined, ok := err.(interface{ Unwrap() []error })
		if !ok {
			t.Fatalf("%q: got %v, want a join of errors", r.body, err)
		}
		if !strings.Contains(err.Error(), r.want) {
			t.Errorf("%q: the error does not hold %q: %v", r.body, r.want, err)
		}
		for _, e := range joined.Unwrap() {
			if s := fmt.Sprintf("%v %#v", e, e); strings.Contains(strings.ToLower(s), marker) {
				t.Errorf("%q: the error shows a secret value: %s", r.body, s)
			}
		}
	}
}

// TestTS10_NoUserName checks that each value loses its user name. No value
// has a URL scheme before the ":" and 2 or more slashes or backslashes after.
func TestTS10_NoUserName(t *testing.T) {
	useTestKeys(t)
	for _, v := range []struct{ in, user string }{
		{"user:SECRET@tcp(h)/db", "user"},
		{"ops@corp.example:SECRET@tcp(h)/db", "ops@corp.example"},
		{"user:/pw@tcp(h)/db", "user"}, {"ops@corp.example:/pw@h", "ops@corp.example"},
		{"user: pw@h", "user"}, {"user:\tpw@h", "user"}, {`user:\pw@h`, "user"},
		{"user//x:pw@h", "user"}, {"mysql:user:pw@h", "user"},
	} {
		for _, name := range []string{"PHANTOM_BUNDLE_FETCH_URL", "PHANTOM_A_EVERY"} {
			_, err := loadTest(writeConfig(t, base), []string{name + "=" + v.in})
			if err == nil {
				t.Fatalf("%s=%s: Load returned no error", name, v.in)
			}
			for _, s := range []string{"SECRET", "pw", v.user} {
				if strings.Contains(err.Error(), s) {
					t.Errorf("%s=%s: the error shows %q: %v", name, v.in, s, err)
				}
			}
			if want := `value "REDACTED@` + v.in[strings.LastIndex(v.in, "@")+1:] + `"`; name == "PHANTOM_A_EVERY" && !strings.Contains(err.Error(), want) {
				t.Errorf("%s=%s: the error does not show the redacted value: %v", name, v.in, err)
			}
		}
	}
}

// TestTS10_LeftCut checks that a Source that esc cuts on the left starts
// with the cut marker. It checks a long file path and a long variable name.
func TestTS10_LeftCut(t *testing.T) {
	useTestKeys(t)
	dir := filepath.Join(t.TempDir(), strings.Repeat("d", 70))
	path := filepath.Join(dir, "config.yaml")
	if err := cmp.Or(os.Mkdir(dir, 0o700), os.WriteFile(path, []byte(base+"zz: 1\n"), 0o600)); err != nil {
		t.Fatal(err)
	}
	name := "PHANTOM_" + strings.Repeat("X", 70)
	_, err := loadTest(path, []string{name + "=1"})
	for _, want := range []string{
		"zz at ..." + path[len(path)-61:] + ":5: unknown key",
		"config: ..." + name[len(name)-61:] + ": unknown PHANTOM variable",
	} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("got %v, want %q", err, want)
		}
	}
}

// TestTS10_ReaderError checks that a reader error gives its line in Error.Line.
// The loader still checks the variable names, and returns no config.
func TestTS10_ReaderError(t *testing.T) {
	useTestKeys(t)
	rows := []struct {
		name, file string
		line       int
		detail     string
	}{
		{"node", base + "listen:\n  http: \":1\"\n  http: \":2\"\n", 7, "listen.http: column 3: duplicate key"},
		{"YAML", "a: 1\nb: [\n", 2, "invalid YAML"},
	}
	for _, r := range rows {
		c, err := loadTest(writeConfig(t, r.file), []string{"PHANTOM_NOPE=1"})
		var e *Error // The first error in the join is the reader error.
		if !errors.As(err, &e) || e.Line != r.line || e.Detail != r.detail || c != nil ||
			!strings.Contains(err.Error(), "PHANTOM_NOPE: unknown PHANTOM variable") {
			t.Errorf("%s: got config %v and error %v, want line %d, detail %q, the unknown variable error, and no config", r.name, c, err, r.line, r.detail)
		}
	}
}

// TestTS10_ReaderErrorFields checks that readError uses the fields of a
// ReadError and does not parse text.
func TestTS10_ReaderErrorFields(t *testing.T) {
	err := &ReadError{Path: `a."b" x`, Line: 3, Column: 4, Detail: `d "q"`}
	e := readError("f", err, testKeys, lists).(*Error)
	if want := `a."b" x: column 4: d "q"`; e.Detail != want || e.Line != 3 {
		t.Errorf("got detail %q line %d, want %q line 3", e.Detail, e.Line, want)
	}
}

// TestTS10_Escape checks the escaper on control bytes, the URL user information, and the cut.
func TestTS10_Escape(t *testing.T) {
	rows := []struct{ in, want string }{
		{"a\x1b[31mb\n", `a\x1b[31mb\n`},
		{"https://u:SECRET@h", "https://REDACTED@h"},
		{"https://user:p/w@h", "https://REDACTED@h"},
		{"https://u:a?b@h/x", "https://REDACTED@h/x"},
		{"https://u:a#b@h", "https://REDACTED@h"},
		{"https://u:a b@h", "https://REDACTED@h"},
		{"https://ops@corp.example:pa/ss@smtp.corp.example", "https://REDACTED@smtp.corp.example"},
		{"https://a b:SECRET@h", "https://REDACTED@h"},
		{"https://u@p@h/x?to=ops@corp.example", "https://REDACTED@corp.example"},
		{"HTTP://U:SECRET@h", "HTTP://REDACTED@h"},
		{"//u:SECRET@h", "//REDACTED@h"},
		{"x //u:a b\tc@host", "REDACTED@host"},
		{"https://h/x", "https://h/x"},
		{`https:\\u:SECRET@h`, `https:\\\\REDACTED@h`},
		{`https:/\/u:SECRET@h`, `https:/\\/REDACTED@h`},
		{"https:/u:SECRET@h", "REDACTED@h"},
		{"https:u:SECRET@h", "REDACTED@h"},
		{"https:/\t/u:SECRET@h", `https:/\t/REDACTED@h`},
		{"user:SECRET@tcp(h:3306)/db", "REDACTED@tcp(h:3306)/db"},
		{"ops@corp.example:SECRET@tcp(h)/db", "REDACTED@tcp(h)/db"},
		{"user:/pw@tcp(h)/db", "REDACTED@tcp(h)/db"}, {"ops@corp.example:/pw@h", "REDACTED@h"}, {"ops@corp.example://pw@h", "REDACTED@h"},
		{"user: pw@h", "REDACTED@h"}, {"user:\tpw@h", "REDACTED@h"}, {`user:\pw@h`, "REDACTED@h"}, {"1user://pw@h", "REDACTED@h"},
		{"user//x:pw@h", "REDACTED@h"}, {"mysql:user:pw@h", "REDACTED@h"}, {"ht tps://u:pw@h", "REDACTED@h"}, {"x.y://u:pw@h", "x.y://REDACTED@h"},
		{"\u202e" + strings.Repeat("é", 40), `\u202e` + strings.Repeat(`\u00e9`, 9)},
		{"bad\xff", `bad\xff`},
	}
	for _, r := range rows {
		got := esc(r.in, 64)
		if got != r.want {
			t.Errorf("esc(%q) = %q, want %q", r.in, got, r.want)
		}
		if strings.Contains(r.in, "SECRET") && (strings.Contains(got, "SECRET") || !strings.Contains(got, "REDACTED@")) {
			t.Errorf("esc(%q) = %q: the password is not removed", r.in, got)
		}
	}
}

// TestTS10_EscapeCut checks the cut for these max values. The result is not
// empty and has at most |max| bytes. Only a left cut starts with the marker.
func TestTS10_EscapeCut(t *testing.T) {
	for _, in := range []string{
		strings.Repeat("\x80", 100), strings.Repeat("\U0010ffff", 100), strings.Repeat("\x1b", 100), strings.Repeat("a", 100),
	} {
		for _, max := range []int{10, 11, 64, 256, -4, -5, -11, -64, -256} {
			got := esc(in, max)
			if got == "" || len(got) > max && max > 0 || len(got) > -max && max < 0 {
				t.Errorf("esc(%.8q, %d) has %d bytes: %q", in, max, len(got), got)
			}
			if strings.HasPrefix(got, cutMarker) != (max < 0 && len(esc(in, 1<<20)) > -max) {
				t.Errorf("esc(%.8q, %d) = %q: wrong cut marker", in, max, got)
			}
		}
	}
	if got, want := esc(strings.Repeat("a", 100), -64), cutMarker+strings.Repeat("a", 61); got != want {
		t.Errorf("left cut = %q, want %q", got, want)
	}
	// With the marker removed, each result is a whole prefix or suffix of
	// the full escape. The loops put each token at each offset near the cut.
	for _, tok := range []string{`\`, "\n", `"`, "\x1b", "é", "\U0010ffff"} {
		for p := 50; p <= 70; p++ {
			for n := 0; n <= 70; n++ {
				in := strings.Repeat("a", p) + tok + strings.Repeat("a", n)
				full := esc(in, 1<<20)
				for _, max := range []int{64, -64} {
					got := strings.TrimPrefix(esc(in, max), cutMarker)
					if _, err := strconv.Unquote(`"` + got + `"`); err != nil ||
						max > 0 && !strings.HasPrefix(full, got) || max < 0 && !strings.HasSuffix(full, got) {
						t.Fatalf("esc(%d a, %q, %d a, %d) = %q: not a whole part of %q", p, tok, n, max, got, full)
					}
				}
			}
		}
	}
	// A small max gives no panic. The bound holds if max >= 0 or max <= -3.
	for _, in := range []string{"", "a", "aaaa", "\x1bé\\\"", "\U0010ffff", strings.Repeat("a", 30)} {
		for max := -20; max <= 20; max++ {
			if got := esc(in, max); max >= 0 && len(got) > max || max <= -3 && len(got) > -max {
				t.Errorf("esc(%q, %d) = %q: more than |max| bytes", in, max, got)
			}
		}
	}
}
