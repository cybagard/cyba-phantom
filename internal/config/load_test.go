package config

import (
	"cmp"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testDir holds a valid htpasswd file: the default path of the production table does not exist here.
var testDir = func() string {
	d, err := os.MkdirTemp("", "config-test")
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

// cfg is longer than 64 bytes, so each error shows the cut source.
var cfg = filepath.Join(strings.Repeat("d", 60), "config.yaml")

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	t.Chdir(t.TempDir())
	if err := cmp.Or(os.Mkdir(filepath.Dir(cfg), 0o700), os.WriteFile(cfg, []byte(body), 0o600)); err != nil {
		t.Fatal(err)
	}
	return cfg
}

const base = "acme:\n  email: sec@example.com\n"

// TestTU10_Precedence checks default < file < env and the source of each value.
func TestTU10_Precedence(t *testing.T) {
	rows := []struct {
		name, file, env, key string
		want                 Value
	}{
		{"default", base, "", "listen.http", Value{Str: ":80", Source: "default"}},
		{"file", base + "listen:\n  http: \":8080\"\n", "", "listen.http", Value{Str: ":8080", Source: cfg, Line: 4}},
		{"env", base + "listen:\n  http: \":8080\"\n", "CANARY_LISTEN_HTTP=:81", "listen.http", Value{Str: ":81", Source: "CANARY_LISTEN_HTTP"}},
		{"htpasswd default", base, "", "ops.basic_auth_htpasswd", Value{Str: filepath.Join(testDir, "htpasswd"), Source: "default"}},
		{"int default", base, "", "a.delta", Value{Int: -1, Source: "default"}},
		{"int file", base + "a:\n  delta: -7\n", "", "a.delta", Value{Int: -7, Source: cfg, Line: 4}},
		{"int env", base + "a:\n  delta: -7\n", "CANARY_A_DELTA=9", "a.delta", Value{Int: 9, Source: "CANARY_A_DELTA"}},
		{"bool env", base + "a:\n  flag: false\n", "CANARY_A_FLAG=true", "a.flag", Value{Bool: true, Source: "CANARY_A_FLAG"}},
		{"duration file", base + "a:\n  every: 15m\n", "", "a.every", Value{Dur: 15 * time.Minute, Source: cfg, Line: 4}},
		{"bytes env", base, "CANARY_A_SIZE=1024", "a.size", Value{Int: 1024, Source: "CANARY_A_SIZE"}},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			c, err := load(writeConfig(t, r.file), strings.Fields(r.env), testKeys)
			if err != nil {
				t.Fatal(err)
			}
			if v, _ := c.Get(r.key); v != r.want {
				t.Errorf("got %+v, want %+v", v, r.want)
			}
		})
	}
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
	_, err := Load(p, []string{"CANARY_LISTEN_HTTPS=:2", "CANARY_NOPE=1", "HOME=/x"})
	p = p[len(p)-64:] // The error keeps the end of a long path: the file name and the line.
	want := strings.Join([]string{
		`config: zz at ` + p + `:1: unknown key`,
		`config: listen.bogus at ` + p + `:4: unknown key`,
		`config: foo at ` + p + `:5: unknown key`,
		`config: ops at ` + p + `:7: the section needs a mapping`,
		`config: acme.email at ` + p + `:9: the key needs a scalar value`,
		`config: CANARY_NOPE: unknown CANARY_ variable`,
		`config: acme.email at ` + p + `: the key is required`,
	}, "\n")
	if err.Error() != want {
		t.Errorf("got\n%v\nwant\n%v", err, want)
	}
	for _, body := range []string{"", "a: [\n"} {
		if _, err := Load(writeConfig(t, body), nil); err == nil {
			t.Errorf("Load(%q) returned no error", body)
		}
	}
	_, err = Load(filepath.Join(t.TempDir(), "missing.yaml"), nil)
	if err == nil || !strings.HasSuffix(err.Error(), ": the file does not exist") {
		t.Errorf("missing file: got %v", err)
	}
}

// TestTU10_NoReload checks that the package exports no reload function.
func TestTU10_NoReload(t *testing.T) {
	pkgs, err := parser.ParseDir(token.NewFileSet(), ".", func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, pkg := range pkgs {
		ast.Inspect(pkg, func(n ast.Node) bool {
			if fn, ok := n.(*ast.FuncDecl); ok && fn.Name.IsExported() && strings.Contains(strings.ToLower(fn.Name.Name), "reload") {
				t.Errorf("exported reload function %s", fn.Name.Name)
			}
			return true
		})
	}
}

// useTestKeys sets the key table to testKeys until the test ends, so Load also checks the
// test keys. A test that calls it must not run in parallel.
func useTestKeys(t *testing.T) {
	old := keys
	keys = testKeys
	t.Cleanup(func() { keys = old })
}

// TestTS10_Scalars checks strict scalars, unknown CANARY_ variables, and escaped values through Load.
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
		{"null", "a:\n  every: ~\n", "", "the value is not a valid duration"},
		{"duration number", "a:\n  every: 5\n", "", "the value is not a valid duration"},
		{"env octal", "", "CANARY_A_PORT=017", "decimal literal only"},
		{"env bool", "", "CANARY_A_FLAG=on", "true or false only"},
		{"env range", "", "CANARY_A_SIZE=99999999999999999999", "out of range"},
		{"bool into string", "listen:\n  https: true\n", "", "the value is not a valid string"},
		{"octal into string", "listen:\n  http: 017\n", "", "the value is not a valid string"},
		{"unknown env", "", "CANARY_LISTEN_HTTPX=:1", "CANARY_LISTEN_HTTPX: unknown CANARY_ variable"},
		{"lower case env", "", "canary_listen_http=:1", "canary_listen_http: unknown CANARY_ variable"},
		{"mixed case env", "", "Canary_Listen_Http=:1", "Canary_Listen_Http: unknown CANARY_ variable"},
		{"dash env", "", "CANARY-LISTEN-HTTP=:1", "CANARY-LISTEN-HTTP: unknown CANARY_ variable"},
		{"ESC in env name", "", "CANARY_X\x1b[2J=1", `CANARY_X\x1b[2J: unknown CANARY_ variable`},
		{"URL text to the last @", "", "CANARY_A_EVERY=https://user:p/w@host", `: value "https://REDACTED@host"`},
		{"reader key not printed", "listen:\n  \"\\e[2J\": 1\n", "", `/config.yaml: listen: line 4 column 3: mapping key is invalid`},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			_, err := Load(writeConfig(t, base+r.file), strings.Fields(r.env))
			if err == nil || !strings.Contains(err.Error(), r.want) {
				t.Errorf("got %v, want %q", err, r.want)
			}
		})
	}
}

// TestTS10_Secret checks that a secret value never appears in an error: as a value,
// as a YAML tag, as a mapping key, or as a key below a secret key.
func TestTS10_Secret(t *testing.T) {
	useTestKeys(t)
	const marker = "secret_marker_7f3a"
	for _, body := range []string{
		"token: " + marker + "\n  pin: " + marker + "\n  port: x",
		"token: !" + marker, "pin: !" + marker, "token: !<" + marker + "> x", "token: [!" + marker + "]",
		"token: {" + strings.ToUpper(marker) + ": 1}", "token:\n    " + marker + ":\n      x: !t 1", "token: [" + marker + ": !t 1]",
	} {
		_, err := Load(writeConfig(t, base+"a:\n  "+body+"\n"), []string{"CANARY_A_TOKEN=" + marker, "CANARY_A_PIN=" + marker})
		for _, e := range err.(interface{ Unwrap() []error }).Unwrap() { // Each *Error in the join.
			if s := fmt.Sprintf("%v %#v", e, e); strings.Contains(strings.ToLower(s), marker) {
				t.Errorf("%q: the error shows a secret value: %s", body, s)
			}
		}
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
		{"https://ops@corp.com:pa/ss@smtp.corp.com", "https://REDACTED@smtp.corp.com"},
		{"https://a b:SECRET@h", "https://REDACTED@h"},
		{"https://u@p@h/x?to=ops@corp.com", "https://REDACTED@corp.com"},
		{"HTTP://U:SECRET@h", "HTTP://REDACTED@h"},
		{"//u:SECRET@h", "//REDACTED@h"},
		{"x //u:a b\tc@host", "x //REDACTED@host"},
		{"https://h/x", "https://h/x"},
		{`https:\\u:SECRET@h`, `https:\\\\REDACTED@h`},
		{`https:/\/u:SECRET@h`, `https:/\\/REDACTED@h`},
		{"https:/u:SECRET@h", "https:/REDACTED@h"},
		{"https:u:SECRET@h", "https:REDACTED@h"},
		{"https:/\t/u:SECRET@h", `https:/\t/REDACTED@h`},
		{"user:SECRET@tcp(h:3306)/db", "user:REDACTED@tcp(h:3306)/db"},
		{"\u202e" + strings.Repeat("é", 40), `\u202e` + strings.Repeat(`\u00e9`, 30)},
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
