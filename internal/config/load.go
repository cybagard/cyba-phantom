package config

import (
	"cmp"
	"context"
	"errors"
	"io/fs"
	"maps"
	"net"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

type kind int

const (
	kindString kind = iota
	kindBool
	kindInt
	kindUint
	kindBytes
	kindDuration
	kindPath
)

var kindNames = [...]string{"string", "bool", "int", "uint", "byte size", "duration", "path"}
var kindTags = [...]string{"!!str", "!!bool", "!!int", "!!int", "!!int", "!!str", "!!str"}

// key is one row of the key table.
type key struct {
	path   string
	kind   kind
	def    string // def is the default value, parsed like an override.
	req    bool   // req marks a required key: the file or the environment must set it.
	secret bool   // secret marks a key whose value is never printed.
}

// keys is the production key table (04 section 3). Later changes add the
// other sections. Only the kind is checked here.
var keys = []key{
	{path: "listen.http", kind: kindString, def: ":80"},
	{path: "listen.https", kind: kindString, def: ":443"},
	{path: "ops.listen", kind: kindString, def: "127.0.0.1:9443"},
	{path: "ops.basic_auth_htpasswd", kind: kindPath, def: "/etc/agent-canary/htpasswd"},
	{path: "acme.email", kind: kindString, req: true},
	{path: "acme.ca", kind: kindString, def: "letsencrypt"},
	{path: "acme.cache_dir", kind: kindPath, def: "/var/lib/agent-canary/certs"},
}

// Value is one effective config value.
type Value struct {
	Str    string
	Int    int64
	Bool   bool
	Dur    time.Duration
	Source string // Source is "default", the file, or the variable name.
	Line   int    // Line is the line in the file, or 0.
}

// Config is the effective configuration.
type Config struct{ values map[string]Value }

// Get returns the effective value of the key at path.
func (c *Config) Get(path string) (Value, bool) {
	v, ok := c.values[path]
	return v, ok
}

// Error is one config error. It never holds a secret value: Value is empty for a secret key.
// A reader error holds no file text other than key paths. If a key path is below a secret key,
// the loader cuts it to the secret key. Error() escapes each part.
type Error struct {
	Key, Source, Detail, Value string
	Line                       int
}

func (e *Error) Error() string {
	s := "config: "
	if e.Key != "" {
		s += esc(e.Key, 64) + " at "
	}
	s += esc(e.Source, -64) // Keep the end of a long path: the file name.
	if e.Line > 0 {
		s += ":" + strconv.Itoa(e.Line)
	}
	s += ": " + esc(e.Detail, 256)
	if e.Value != "" {
		s += ": value \"" + esc(e.Value, 64) + "\""
	}
	return s
}

// Dialer opens connections. The loader checks a URL value for syntax only (SEC-11),
// so no key uses a Dialer yet.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// Resolver looks up host names. No key uses a Resolver yet, for the same reason.
type Resolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// Net is the network access of the load path.
type Net struct {
	Dialer   Dialer
	Resolver Resolver
}

// Load is LoadWith with the system dialer and resolver.
func Load(path string, env []string) (*Config, error) {
	return LoadWith(path, env, Net{Dialer: &net.Dialer{}, Resolver: net.DefaultResolver})
}

// LoadWith reads the config file at path one time. It applies the CANARY_*
// overrides in env (use os.Environ()). Precedence: default < file < env.
// LoadWith returns all errors together and never returns a partial config.
// It uses the network only through n.
func LoadWith(path string, env []string, _ Net) (*Config, error) {
	return load(path, env, keys)
}

func envName(path string) string {
	return "CANARY_" + strings.ToUpper(strings.ReplaceAll(path, ".", "_"))
}

func load(path string, env []string, table []key) (*Config, error) {
	doc, err := ReadFile(path)
	if err != nil {
		return nil, errors.Join(readError(path, err, table))
	}
	byPath := make(map[string]key, len(table))
	byEnv := make(map[string]key, len(table))
	for _, k := range table {
		byPath[k.path] = k
		byEnv[envName(k.path)] = k
	}
	vals := make(map[string]Value)
	var errs []error
	set := func(k key, raw, tag, src string, line int) {
		v, detail := parse(k, raw, tag)
		if detail == "" {
			v.Source, v.Line = src, line
			vals[k.path] = v
			return
		}
		if k.secret {
			raw = "" // An Error never holds a secret value.
		}
		errs = append(errs, &Error{Key: k.path, Source: src, Line: line, Detail: detail, Value: raw})
	}
	for _, k := range table {
		if !k.req {
			set(k, k.def, "", "default", 0)
		}
	}

	// File: each node must be a known key or section. Errors come in file order.
	paths := slices.Collect(maps.Keys(doc.Lines))
	slices.SortFunc(paths, func(a, b string) int {
		return cmp.Or(cmp.Compare(doc.Lines[a], doc.Lines[b]), cmp.Compare(a, b))
	})
	for _, p := range paths {
		line := doc.Lines[p]
		k, isKey := byPath[p]
		leaf, isLeaf := doc.Leaves[p]
		switch {
		case isKey && isLeaf:
			set(k, leaf.Value, leaf.Tag, path, line)
		case isKey:
			errs = append(errs, &Error{Key: p, Source: path, Line: line, Detail: "the key needs a scalar value"})
		case isSection(p, table):
			if !doc.Mappings[p] {
				errs = append(errs, &Error{Key: p, Source: path, Line: line, Detail: "the section needs a mapping"})
			}
		case doc.Mappings[parent(p)] && isSection(parent(p), table):
			errs = append(errs, &Error{Key: p, Source: path, Line: line, Detail: "unknown key"})
		}
	}

	// Env: if a name, in upper case and with "-" changed to "_", starts with CANARY_,
	// the key table must contain it.
	seen := make(map[string]bool)
	for _, kv := range env {
		name, raw, _ := strings.Cut(kv, "=")
		if !strings.HasPrefix(strings.ToUpper(strings.ReplaceAll(name, "-", "_")), "CANARY_") {
			continue
		}
		k, ok := byEnv[name]
		switch {
		case !ok:
			errs = append(errs, &Error{Source: name, Detail: "unknown CANARY_ variable"})
		case seen[name]:
			errs = append(errs, &Error{Source: name, Detail: "the variable occurs more than one time"})
		default:
			set(k, raw, "", name, 0)
		}
		seen[name] = true
	}

	for _, k := range table {
		if _, ok := vals[k.path]; k.req && !ok {
			errs = append(errs, &Error{Key: k.path, Source: path, Detail: "the key is required"})
		}
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return &Config{values: vals}, nil
}

// parse checks the YAML tag of a file value (tag is "" for a default or an override),
// then parses raw for the kind of k. It returns a fixed detail on an error.
func parse(k key, raw, tag string) (Value, string) {
	var v Value
	if tag != "" && tag != kindTags[k.kind] {
		return v, "the value is not a valid " + kindNames[k.kind]
	}
	switch k.kind {
	case kindBool:
		if raw != "true" && raw != "false" {
			return v, "a bool is true or false only"
		}
		v.Bool = raw == "true"
	case kindInt, kindUint, kindBytes:
		if !decimal.MatchString(raw) || (k.kind != kindInt && raw[0] == '-') {
			return v, "an integer is a decimal literal only"
		}
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return v, "the integer is out of range"
		}
		v.Int = n
	case kindDuration:
		d, err := time.ParseDuration(raw)
		if err != nil {
			return v, "the value is not a valid duration"
		}
		v.Dur = d
	default:
		v.Str = raw
	}
	return v, ""
}

// decimal matches a decimal literal: no "+", no leading 0, no "-0", no base prefix, no "_".
var decimal = regexp.MustCompile(`^(0|-?[1-9][0-9]*)$`)

// isSection reports whether p is the root or a section of the table.
func isSection(p string, table []key) bool {
	return p == "" || slices.ContainsFunc(table, func(k key) bool { return strings.HasPrefix(k.path, p+".") })
}

func parent(p string) string {
	if i := strings.LastIndexAny(p, ".["); i >= 0 {
		return p[:i]
	}
	return ""
}

// readError changes a reader error into an Error. A wrapped system error becomes
// a fixed message. It removes the reader's quotes, so esc escapes the text one time only.
// A key below a secret key can be the secret value, so readError changes its path to the path of the secret key.
func readError(path string, err error, table []key) error {
	detail := "the loader cannot read the file"
	switch {
	case errors.Is(err, fs.ErrNotExist):
		detail = "the file does not exist"
	case errors.Is(err, fs.ErrPermission):
		detail = "permission denied"
	case errors.Unwrap(err) == nil:
		detail = strings.TrimPrefix(strings.TrimPrefix(err.Error(), "config: "), strconv.Quote(path)+": ")
		detail = quoted.ReplaceAllStringFunc(detail, func(q string) string {
			s, _ := strconv.Unquote(q)
			if i := slices.IndexFunc(table, func(k key) bool {
				return k.secret && (strings.HasPrefix(s, k.path+".") || strings.HasPrefix(s, k.path+"["))
			}); i >= 0 {
				return table[i].path
			}
			return s
		})
	}
	return &Error{Source: path, Detail: detail}
}

var quoted = regexp.MustCompile(`"(?:[^"\\]|\\.)*"`)

// userinfo matches a start and all text after it to the last "@" in the value. The start
// is the first of these in the value: a ":" with all slashes, backslashes, and white space
// after it, or two characters that are each a slash or a backslash. Thus the rule also
// removes a password after a backslash, after one slash or no slash, and in "user:password@host".
// A more precise rule can miss a password form, so the loader accepts that it removes too much.
var userinfo = regexp.MustCompile(`(?s)(:[/\\\s]*|[/\\]{2}).*@`)

// esc is the one escaper for printed text (SEC-07). It keeps the start that userinfo matches
// and replaces the text after it, to the last "@", with "REDACTED@". Then it cuts the text to
// max bytes on a rune boundary (max < 0: keep the last -max bytes), and escapes control
// characters, ANSI sequences, and non-ASCII runes.
func esc(s string, max int) string {
	s = userinfo.ReplaceAllString(s, "${1}REDACTED@")
	if n := len(s) + max; max < 0 && n > 0 {
		for n < len(s) && !utf8.RuneStart(s[n]) {
			n++
		}
		s = s[n:]
	} else if max >= 0 && len(s) > max {
		n := max
		for n > 0 && !utf8.RuneStart(s[n]) {
			n--
		}
		s = s[:n]
	}
	q := strconv.QuoteToASCII(s)
	return q[1 : len(q)-1]
}
