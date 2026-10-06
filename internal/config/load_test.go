package config

import (
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
	{path: "a.url", kind: kindURL},
	{path: "a.token", kind: kindString, secret: true},
	{path: "a.pin", kind: kindInt, def: "0", secret: true},
	{path: "a.sinks", kind: kindList},
}...)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	t.Chdir(t.TempDir())
	p := "config.yaml"
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const base = "acme:\n  email: sec@example.com\n"

// TestTU10_Precedence checks default < file < env for each kind.
func TestTU10_Precedence(t *testing.T) {
	rows := []struct {
		name, file, env, key, src string
		want                      Value
	}{
		{"default", base, "", "listen.http", "default", Value{Str: ":80"}},
		{"file", base + "listen:\n  http: \":8080\"\n", "", "listen.http", ":4", Value{Str: ":8080"}},
		{"env", base + "listen:\n  http: \":8080\"\n", "CANARY_LISTEN_HTTP=:81", "listen.http", "CANARY_LISTEN_HTTP", Value{Str: ":81"}},
		{"htpasswd default", base, "", "ops.basic_auth_htpasswd", "default", Value{Str: "/etc/agent-canary/htpasswd"}},
		{"int default", base, "", "a.delta", "default", Value{Int: -1}},
		{"int file", base + "a:\n  delta: -7\n", "", "a.delta", ":4", Value{Int: -7}},
		{"int env", base + "a:\n  delta: -7\n", "CANARY_A_DELTA=9", "a.delta", "CANARY_A_DELTA", Value{Int: 9}},
		{"bool env", base + "a:\n  flag: false\n", "CANARY_A_FLAG=true", "a.flag", "CANARY_A_FLAG", Value{Bool: true}},
		{"duration file", base + "a:\n  every: 15m\n", "", "a.every", ":4", Value{Dur: 15 * time.Minute}},
		{"bytes env", base, "CANARY_A_SIZE=1024", "a.size", "CANARY_A_SIZE", Value{Int: 1024}},
		{"list file", base + "a:\n  sinks: [x]\n", "", "a.sinks", ":4", Value{}},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			c, err := load(writeConfig(t, r.file), strings.Fields(r.env), testKeys)
			if err != nil {
				t.Fatal(err)
			}
			v, _ := c.Get(r.key)
			src := v.Source
			v.Source = ""
			if v != r.want || !strings.HasSuffix(src, r.src) {
				t.Errorf("got %+v from %q, want %+v from %q", v, src, r.want, r.src)
			}
		})
	}
}

// TestTU10_Errors checks unknown keys, wrong shapes, and error collection.
func TestTU10_Errors(t *testing.T) {
	p := writeConfig(t, "listen:\n  http: \":1\"\n  bogus: 1\nfoo:\n  bar: 1\nops: x\nacme:\n  email: [a]\n")
	_, err := Load(p, []string{"CANARY_LISTEN_HTTPS=:2", "CANARY_NOPE=1", "HOME=/x"})
	if err == nil {
		t.Fatal("Load returned no error")
	}
	for _, want := range []string{
		`listen.bogus at ` + p + `:3: unknown key`,
		`foo at ` + p + `:4: unknown key`,
		`ops at ` + p + `:6: the section needs a mapping`,
		`acme.email at ` + p + `:8: the key needs a scalar value`,
		`config: CANARY_NOPE: unknown CANARY_ variable`,
		`acme.email at ` + p + `: the key is required`,
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "foo.bar") || strings.Contains(err.Error(), "email[0]") {
		t.Errorf("error %q reports a key under an unknown key", err)
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
		for _, f := range pkg.Files {
			for _, d := range f.Decls {
				if fn, ok := d.(*ast.FuncDecl); ok && fn.Name.IsExported() &&
					strings.Contains(strings.ToLower(fn.Name.Name), "reload") {
					t.Errorf("exported reload function %s", fn.Name.Name)
				}
			}
		}
	}
}

// TestTS10_Scalars checks strict scalars and unknown CANARY_ variables.
func TestTS10_Scalars(t *testing.T) {
	rows := []struct {
		name, file, env, want string
		prod                  bool
	}{
		{"YAML 1.1 bool yes", "a:\n  flag: yes\n", "", "a.flag at", false},
		{"YAML 1.1 bool on", "a:\n  flag: on\n", "", "the value is not a valid bool", false},
		{"octal", "a:\n  port: 017\n", "", "decimal literal only", false},
		{"hex", "a:\n  port: 0x1F\n", "", "decimal literal only", false},
		{"underscore", "a:\n  size: 1_000\n", "", "a.size at", false},
		{"sign on uint", "a:\n  port: -1\n", "", "decimal literal only", false},
		{"float into int", "a:\n  delta: 1.5\n", "", "the value is not a valid int", false},
		{"quoted int", "a:\n  port: \"8080\"\n", "", "the value is not a valid uint", false},
		{"tagged int", "a:\n  port: !!int x\n", "", "decimal literal only", false},
		{"null", "a:\n  every: ~\n", "", "the value is not a valid duration", false},
		{"duration number", "a:\n  every: 5\n", "", "the value is not a valid duration", false},
		{"env octal", "", "CANARY_A_PORT=017", "decimal literal only", false},
		{"env bool", "", "CANARY_A_FLAG=on", "true or false only", false},
		{"env range", "", "CANARY_A_SIZE=99999999999999999999", "out of range", false},
		{"bool into string", "listen:\n  https: true\n", "", "listen.https at", true},
		{"octal into string", "listen:\n  http: 017\n", "", "the value is not a valid string", true},
		{"unknown env", "", "CANARY_LISTEN_HTTPX=:1", "CANARY_LISTEN_HTTPX: unknown CANARY_ variable", true},
		{"list env", "", "CANARY_A_SINKS=x", "CANARY_A_SINKS: unknown CANARY_ variable", false},
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

// TestTS10_Secret checks that a secret value never appears in an error.
func TestTS10_Secret(t *testing.T) {
	const marker = "SECRET_MARKER_7f3a"
	p := writeConfig(t, base+"a:\n  token: "+marker+"\n  pin: "+marker+"\n  port: x\n")
	env := []string{"CANARY_A_TOKEN=" + marker, "CANARY_A_PIN=" + marker, "CANARY_" + marker + "=" + marker}
	_, err := load(p, env, testKeys)
	if err == nil || !strings.Contains(err.Error(), `a.port at`) || !strings.Contains(err.Error(), `a.pin at CANARY_A_PIN`) {
		t.Fatalf("got %v", err)
	}
	if strings.Count(err.Error(), marker) != 1 || !strings.Contains(err.Error(), "CANARY_"+marker+": unknown") {
		t.Errorf("error shows a secret value: %v", err)
	}
}

// TestTS10_Escape checks the escaper on control bytes, URL user information, and the cut.
func TestTS10_Escape(t *testing.T) {
	rows := []struct{ in, want string }{
		{"a\x1b[31mb\n", `a\x1b[31mb\n`},
		{"https://user:pw@host/x", "https://host/x"},
		{"\u202e" + strings.Repeat("é", 40), `\u202e` + strings.Repeat(`\u00e9`, 30)},
		{"bad\xff", `bad\xff`},
	}
	for _, r := range rows {
		if got := esc(r.in, 64); got != r.want {
			t.Errorf("esc(%q) = %q, want %q", r.in, got, r.want)
		}
	}
	p := writeConfig(t, base+"listen:\n  bad: 1\n")
	_, err := Load(p, []string{"CANARY_X\x1b[2J=1"})
	if err == nil || strings.ContainsRune(err.Error(), 0x1b) {
		t.Errorf("got %q", err)
	}
}
