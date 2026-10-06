package config

import (
	"errors"
	"io/fs"
	"net/url"
	"regexp"
	"sort"
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
	kindURL
	kindPath
	kindList
)

var kindNames = [...]string{"string", "bool", "int", "uint", "byte size", "duration", "URL", "path", "list"}

// key is one row of the key table.
type key struct {
	path   string
	kind   kind
	def    string // def is the default value, parsed like an override.
	req    bool   // req marks a key that has no default.
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
	Source string // Source is "default", "<file>:<line>", or the variable name.
}

// Config is the effective configuration.
type Config struct{ values map[string]Value }

// Get returns the effective value of the key at path.
func (c *Config) Get(path string) (Value, bool) {
	v, ok := c.values[path]
	return v, ok
}

// Error is one config error. Error escapes each part and never shows a
// secret value.
type Error struct {
	Key, Source, Detail, Value string
	show                       bool
}

func (e *Error) Error() string {
	s := "config: "
	if e.Key != "" {
		s += esc(e.Key, 64) + " at "
	}
	s += esc(e.Source, 64) + ": " + esc(e.Detail, -1)
	if e.show {
		s += ": value \"" + esc(e.Value, 64) + "\""
	}
	return s
}

// Load reads the config file at path one time. It applies the CANARY_*
// overrides in env (use os.Environ()). Precedence: default < file < env.
// Load returns all errors together and never returns a partial config.
func Load(path string, env []string) (*Config, error) {
	return load(path, env, keys)
}

func envName(path string) string {
	return "CANARY_" + strings.ToUpper(strings.ReplaceAll(path, ".", "_"))
}

func load(path string, env []string, table []key) (*Config, error) {
	doc, err := ReadFile(path)
	if err != nil {
		return nil, readError(path, err)
	}
	byPath := make(map[string]key, len(table))
	byEnv := make(map[string]key, len(table))
	for _, k := range table {
		byPath[k.path] = k
		if k.kind != kindList {
			byEnv[envName(k.path)] = k
		}
	}
	vals := make(map[string]Value)
	var errs []error
	set := func(k key, raw, tag, src string) {
		if v, detail := parse(k, raw, tag); detail != "" {
			errs = append(errs, &Error{Key: k.path, Source: src, Detail: detail, Value: raw, show: !k.secret})
		} else {
			v.Source = src
			vals[k.path] = v
		}
	}
	for _, k := range table {
		if !k.req && k.kind != kindList {
			set(k, k.def, "", "default")
		}
	}

	// File: every node must be a known key, a known section, or an item of a list key.
	paths := make([]string, 0, len(doc.Lines))
	for p := range doc.Lines {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		src := path + ":" + strconv.Itoa(doc.Lines[p])
		k, isKey := byPath[p]
		leaf, isLeaf := doc.Leaves[p]
		switch {
		case isKey && k.kind == kindList:
			if doc.Sequences[p] {
				vals[p] = Value{Source: src}
			} else {
				errs = append(errs, &Error{Key: p, Source: src, Detail: "the key needs a list"})
			}
		case isKey && isLeaf:
			set(k, leaf.Value, leaf.Tag, src)
		case isKey:
			errs = append(errs, &Error{Key: p, Source: src, Detail: "the key needs a scalar value"})
		case within(p, table, false):
			if p != "" && !doc.Mappings[p] {
				errs = append(errs, &Error{Key: p, Source: src, Detail: "the section needs a mapping"})
			}
		case !within(p, table, true) && within(parent(p), table, false):
			errs = append(errs, &Error{Key: p, Source: src, Detail: "unknown key"})
		}
	}

	seen := make(map[string]bool)
	for _, kv := range env {
		name, raw, _ := strings.Cut(kv, "=")
		if !strings.HasPrefix(name, "CANARY_") {
			continue
		}
		k, ok := byEnv[name]
		switch {
		case !ok:
			errs = append(errs, &Error{Source: name, Detail: "unknown CANARY_ variable"})
		case seen[name]:
			errs = append(errs, &Error{Source: name, Detail: "the variable is set more than one time"})
		default:
			set(k, raw, "", name)
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

// parse checks raw against the kind of k. It checks the YAML tag of a file
// value (tag is "" for a default or an override) and then parses the text.
// It returns a fixed detail on an error.
func parse(k key, raw, tag string) (Value, string) {
	var v Value
	want := map[kind]string{kindBool: "!!bool", kindInt: "!!int", kindUint: "!!int", kindBytes: "!!int"}[k.kind]
	if want == "" {
		want = "!!str"
	}
	if tag != "" && tag != want {
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
	case kindURL:
		if _, err := url.Parse(raw); err != nil {
			return v, "the value is not a valid URL"
		}
		v.Str = raw
	default:
		v.Str = raw
	}
	return v, ""
}

// decimal matches a decimal literal: no "+", no leading 0, no "-0", no base prefix, no "_".
var decimal = regexp.MustCompile(`^(0|-?[1-9][0-9]*)$`)

// within reports whether p is the root or a section of the table. With list,
// it reports whether p is an item path under a list key.
func within(p string, table []key, list bool) bool {
	for _, k := range table {
		if list && k.kind == kindList && strings.HasPrefix(p, k.path+"[") ||
			!list && (p == "" || strings.HasPrefix(k.path, p+".")) {
			return true
		}
	}
	return false
}

func parent(p string) string {
	if i := strings.LastIndexAny(p, ".["); i >= 0 {
		return p[:i]
	}
	return ""
}

// readError turns a reader error into an Error. A wrapped system error
// becomes a fixed message.
func readError(path string, err error) error {
	detail := "the file cannot be read"
	switch {
	case errors.Is(err, fs.ErrNotExist):
		detail = "the file does not exist"
	case errors.Is(err, fs.ErrPermission):
		detail = "permission denied"
	case errors.Unwrap(err) == nil:
		detail = strings.TrimPrefix(strings.TrimPrefix(err.Error(), "config: "), strconv.Quote(path)+": ")
	}
	return &Error{Source: path, Detail: detail}
}

var userinfo = regexp.MustCompile(`(?i)([a-z][a-z0-9+.-]*://)[^/?#\s]*@`)

// esc is the one escaper for printed text (SEC-07). It removes URL user
// information, cuts the text to max bytes on a rune boundary (max < 0: no
// cut), and escapes control characters, ANSI sequences, and non-ASCII runes.
func esc(s string, max int) string {
	s = userinfo.ReplaceAllString(s, "$1")
	if max >= 0 && len(s) > max {
		n := max
		for n > 0 && !utf8.RuneStart(s[n]) {
			n--
		}
		s = s[:n]
	}
	q := strconv.QuoteToASCII(s)
	return q[1 : len(q)-1]
}
