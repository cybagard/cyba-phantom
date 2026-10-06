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

// testKeys adds kinds that the production table does not have yet.
var testKeys = append(append([]key{}, keys...), []key{
	{path: "a.flag", kind: kindBool, def: "false"},
	{path: "a.port", kind: kindUint, def: "8"},
	{path: "a.delta", kind: kindInt, def: "-1"},
	{path: "a.size", kind: kindBytes, def: "65536"},
	{path: "a.every", kind: kindDuration, def: "6h"},
	{path: "a.token", kind: kindString, secret: true},
	{path: "a.pin", kind: kindInt, def: "0", secret: true},
}...)

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
		{"htpasswd default", base, "", "ops.basic_auth_htpasswd", Value{Str: "/etc/agent-canary/htpasswd", Source: "default"}},
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

// TestTS10_Scalars checks strict scalars, unknown CANARY_ variables, and escaped values.
func TestTS10_Scalars(t *testing.T) {
	rows := []struct {
		name, file, env, want string
		prod                  bool
	}{
		{"YAML 1.1 bool yes", "a:\n  flag: yes\n", "", "the value is not a valid bool", false},
		{"YAML 1.1 bool on", "a:\n  flag: on\n", "", "the value is not a valid bool", false},
		{"octal", "a:\n  port: 017\n", "", "decimal literal only", false},
		{"hex", "a:\n  port: 0x1F\n", "", "decimal literal only", false},
		{"underscore", "a:\n  size: 1_000\n", "", "decimal literal only", false},
		{"sign on uint", "a:\n  port: -1\n", "", "decimal literal only", false},
		{"float into int", "a:\n  delta: 1.5\n", "", "the value is not a valid int", false},
		{"quoted int", "a:\n  port: \"8080\"\n", "", "the value is not a valid uint", false},
		{"tagged int", "a:\n  port: !!int x\n", "", "decimal literal only", false},
		{"null", "a:\n  every: ~\n", "", "the value is not a valid duration", false},
		{"duration number", "a:\n  every: 5\n", "", "the value is not a valid duration", false},
		{"env octal", "", "CANARY_A_PORT=017", "decimal literal only", false},
		{"env bool", "", "CANARY_A_FLAG=on", "true or false only", false},
		{"env range", "", "CANARY_A_SIZE=99999999999999999999", "out of range", false},
		{"bool into string", "listen:\n  https: true\n", "", "the value is not a valid string", true},
		{"octal into string", "listen:\n  http: 017\n", "", "the value is not a valid string", true},
		{"unknown env", "", "CANARY_LISTEN_HTTPX=:1", "CANARY_LISTEN_HTTPX: unknown CANARY_ variable", true},
		{"lower case env", "", "canary_listen_http=:1", "canary_listen_http: unknown CANARY_ variable", true},
		{"mixed case env", "", "Canary_Listen_Http=:1", "Canary_Listen_Http: unknown CANARY_ variable", true},
		{"dash env", "", "CANARY-LISTEN-HTTP=:1", "CANARY-LISTEN-HTTP: unknown CANARY_ variable", true},
		{"ESC in env name", "", "CANARY_X\x1b[2J=1", `CANARY_X\x1b[2J: unknown CANARY_ variable`, true},
		{"URL user information", "", "CANARY_A_EVERY=https://user:p/w@host", `: value "https://host"`, false},
		{"reader key not printed", "listen:\n  \"\\e[2J\": 1\n", "", `/config.yaml: listen: line 4 column 3: mapping key is invalid`, true},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			p := writeConfig(t, base+r.file)
			var err error
			if r.prod {
				_, err = Load(p, strings.Fields(r.env))
			} else {
				_, err = load(p, strings.Fields(r.env), testKeys)
			}
			if err == nil || !strings.Contains(err.Error(), r.want) {
				t.Errorf("got %v, want %q", err, r.want)
			}
		})
	}
}

// TestTS10_Secret checks that a secret value never appears in an error: as a value,
// as a YAML tag, as a mapping key, or as a key below a secret key.
func TestTS10_Secret(t *testing.T) {
	const marker = "secret_marker_7f3a"
	for _, body := range []string{
		"token: " + marker + "\n  pin: " + marker + "\n  port: x",
		"token: !" + marker, "pin: !" + marker, "token: !<" + marker + "> x", "token: [!" + marker + "]",
		"token: {" + strings.ToUpper(marker) + ": 1}", "token:\n    " + marker + ":\n      x: !t 1",
	} {
		_, err := load(writeConfig(t, base+"a:\n  "+body+"\n"), []string{"CANARY_A_TOKEN=" + marker, "CANARY_A_PIN=" + marker}, testKeys)
		for _, e := range err.(interface{ Unwrap() []error }).Unwrap() { // Each *Error in the join.
			if s := fmt.Sprintf("%v %#v", e, e); strings.Contains(strings.ToLower(s), marker) {
				t.Errorf("%q: the error shows a secret value: %s", body, s)
			}
		}
	}
}

// TestTS10_Escape checks the escaper on control bytes, URL user information, and the cut.
func TestTS10_Escape(t *testing.T) {
	rows := []struct{ in, want string }{
		{"a\x1b[31mb\n", `a\x1b[31mb\n`},
		{"https://user:pw@host/x", "https://host/x"},
		{"https://user:p/w@host", "https://host"},
		{"https://u:a?b#c@host", "https://host"},
		{"https://u@p@h/x?to=ops@corp.com", "https://h/x?to=ops@corp.com"},
		{"https://x/y?to=ops@corp.com", "https://x/y?to=ops@corp.com"},
		{"x //u:a b\tc@host", "x //host"},
		{"\u202e" + strings.Repeat("é", 40), `\u202e` + strings.Repeat(`\u00e9`, 30)},
		{"bad\xff", `bad\xff`},
	}
	for _, r := range rows {
		if got := esc(r.in, 64); got != r.want {
			t.Errorf("esc(%q) = %q, want %q", r.in, got, r.want)
		}
	}
}
