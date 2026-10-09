package config

import (
	"cmp"
	"context"
	"errors"
	"io/fs"
	"maps"
	"math"
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
	kindURL // kindURL is a key whose value is never printed in an error: it can hold user information.
)

var kindNames = [...]string{"string", "bool", "int", "uint", "byte size", "duration", "path", "URL"}
var kindTags = [...]string{"!!str", "!!bool", "!!int", "!!int", "!!int", "!!str", "!!str", "!!str"}

// key is one row of the key table.
type key struct {
	path     string
	kind     kind
	def      string                             // def is the default value, parsed like an override.
	req      bool                               // req marks a required key: the file or the environment must set it.
	secret   bool                               // secret marks a key whose value is never printed.
	maxItems int                                // maxItems > 0 marks a key in a list item that holds 1 to maxItems scalars in a list.
	check    func(l *loader, raw string) string // check returns a fixed detail if a parsed value breaks a rule, or "".
}

// keys is the production key table (04 section 3). It holds the scalar keys. The list
// keys are in the table lists. The loader adds the item keys to its table when it reads the lists (expandLists).
var keys = []key{
	{path: "listen.http", kind: kindString, def: ":80", check: checkListen},
	{path: "listen.https", kind: kindString, def: ":443", check: checkListen},
	{path: "ops.listen", kind: kindString, def: "127.0.0.1:9443", check: checkOpsListen},
	{path: "ops.basic_auth_htpasswd", kind: kindPath, def: "/etc/agent-canary/htpasswd", check: checkHtpasswd},
	{path: "acme.email", kind: kindString, req: true, check: checkEmail},
	{path: "acme.ca", kind: kindURL, def: "letsencrypt", check: checkCA},
	{path: "acme.cache_dir", kind: kindPath, def: "/var/lib/agent-canary/certs", check: checkStatePath},
	{path: "bundle.path", kind: kindPath, def: "/var/lib/agent-canary/bundle/current.cbnd", check: checkStatePath},
	{path: "bundle.fetch_url", kind: kindURL, check: checkFetchURL},
	{path: "bundle.fetch_interval", kind: kindDuration, def: "6h", check: checkPositiveDuration}, // The bounds 15m to 7d are a cross-check: they apply if fetch_url is set.
	{path: "limits.max_conns", kind: kindInt, def: "2000", check: intRange(1, 2000)},
	{path: "limits.body_bytes", kind: kindBytes, def: "65536", check: intRange(1, 65536)},
	{path: "limits.header_bytes", kind: kindBytes, def: "16384", check: intRange(1, 16384)},
	{path: "limits.per_ip_rps", kind: kindInt, def: "50", check: intRange(1, 1000)},
	{path: "limits.per_ip_burst", kind: kindInt, def: "200", check: intRange(1, 5000)}, // The lower bound is per_ip_rps: a cross-check.
	{path: "limits.queue_depth", kind: kindInt, def: "4096", check: intRange(1, 8192)},
	{path: "store.path", kind: kindPath, def: "/var/lib/agent-canary/events.db", check: checkStatePath},
	{path: "store.max_bytes", kind: kindBytes, def: "10737418240", check: intRange(268435456, math.MaxInt64)},
	{path: "store.retention_days.ip", kind: kindInt, def: "7", check: intRange(1, 7)},
	{path: "store.retention_days.raw", kind: kindInt, def: "30", check: intRange(1, 30)},
	{path: "store.retention_days.events", kind: kindInt, def: "90", check: intRange(1, 90)}, // The lower bound is retention_days.raw: a cross-check.
	{path: "tlog.dir", kind: kindPath, def: "/var/lib/agent-canary/tlog", check: checkStatePath},
	{path: "tlog.origin", kind: kindString, req: true, check: checkOrigin},
	{path: "tlog.checkpoint_interval", kind: kindDuration, def: "1h", check: durRange(time.Minute, 24*time.Hour)},
	{path: "alerts.min_band", kind: kindString, def: "agent-likely", check: checkMinBand},
	{path: "privacy.store_body_prefix", kind: kindBool, def: "true"},
	{path: "privacy.include_ip", kind: kindBool, def: "false"},
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

// Dialer opens connections. No key uses a Dialer yet.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// Resolver looks up host names. No key uses a Resolver yet.
type Resolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// Net is the network access of the load path.
type Net struct {
	Dialer   Dialer
	Resolver Resolver
}

// SystemNet returns the Net with the system dialer and resolver.
func SystemNet() Net {
	return Net{Dialer: &net.Dialer{}, Resolver: net.DefaultResolver}
}

// Load is LoadWith with the system dialer and resolver.
func Load(path string, env []string) (*Config, error) {
	return LoadWith(path, env, SystemNet())
}

// LoadWith reads the config file at path one time. It applies the CANARY_*
// overrides in env (use os.Environ()). Precedence: default < file < env.
// LoadWith returns all errors together and never returns a partial config.
// LoadWith returns an error if n.Dialer or n.Resolver is nil.
// LoadWith passes n to load. No code in load uses n yet. A later network use must go
// through n. TestTS10_NoSystemNetwork fails on the source forms listed in its doc
// comment. It does not detect every way to use the network.
func LoadWith(path string, env []string, n Net) (*Config, error) {
	if n.Dialer == nil {
		return nil, errors.New("config: Net.Dialer is nil")
	}
	if n.Resolver == nil {
		return nil, errors.New("config: Net.Resolver is nil")
	}
	return load(path, env, keys, n)
}

func load(path string, env []string, table []key, n Net) (*Config, error) {
	return newLoader().load(path, env, table, n)
}

func envName(path string) string {
	return "CANARY_" + strings.ToUpper(strings.ReplaceAll(path, ".", "_"))
}

func (l *loader) load(path string, env []string, table []key, n Net) (*Config, error) {
	doc, err := ReadFile(path)
	if err != nil {
		return nil, errors.Join(readError(path, err, table))
	}
	l.env = env
	byPath := make(map[string]key, len(table))
	byEnv := make(map[string]key, len(table))
	for _, k := range table {
		byPath[k.path] = k
		byEnv[envName(k.path)] = k
	}
	vals := make(map[string]Value)
	raws := make(map[string]string) // raws holds the text of each value in vals.
	var errs []error
	keyError := func(k key, raw, src string, line int, detail string) error {
		if k.secret || k.kind == kindURL {
			raw = "" // An Error never holds a secret value or a URL: a URL can hold user information.
		}
		return &Error{Key: k.path, Source: src, Line: line, Detail: detail, Value: raw}
	}
	// set parses one value. A later source replaces an earlier one. A value that fails to parse is removed.
	set := func(k key, raw, tag, src string, line int) {
		v, detail := parse(k, raw, tag)
		if detail == "" {
			v.Source, v.Line = src, line
			vals[k.path], raws[k.path] = v, raw
			return
		}
		delete(vals, k.path)
		errs = append(errs, keyError(k, raw, src, line, detail))
	}
	for _, k := range table {
		if !k.req {
			set(k, k.def, "", "default", 0)
		}
	}

	// Lists: the list keys have no CANARY_ override, so byEnv does not hold the item keys.
	// The loader handles an item key like a scalar key from here: set, required, and check.
	itemKeys, listErrs := expandLists(doc, path, lists) // The loader reports listErrs after the required scalar keys.
	table = append(slices.Clone(table), itemKeys...)
	for _, k := range itemKeys {
		if leaf, ok := doc.Leaves[k.path]; ok {
			set(k, leaf.Value, leaf.Tag, path, leaf.Line)
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
		case isListPath(p): // expandLists reads the list and its items.
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
	errs = append(errs, listErrs...)
	// Each check runs one time, on the effective value. A key that fails is removed from vals.
	for _, k := range table {
		v, ok := vals[k.path]
		if !ok || k.check == nil {
			continue
		}
		if detail := k.check(l, raws[k.path]); detail != "" {
			delete(vals, k.path)
			errs = append(errs, keyError(k, raws[k.path], v.Source, v.Line, detail))
		}
	}
	errs = append(errs, crossCheck(vals)...)
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
			if p := secretItemPath(s); p != "" {
				return p
			}
			return s
		})
	}
	return &Error{Source: path, Detail: detail}
}

// secretItemPath returns the path of the secret item key that the path s is below, or "".
// The secret item keys come from the list schemas. For example, "tlog.publish[0].token_env.x"
// gives "tlog.publish[0].token_env".
func secretItemPath(s string) string {
	for _, l := range lists {
		rest, ok := strings.CutPrefix(s, l.path+"[")
		if !ok {
			continue
		}
		n, rest, ok := strings.Cut(rest, "].")
		if !ok || !decimal.MatchString(n) {
			continue
		}
		for _, schema := range l.schemas {
			for _, f := range schema {
				if f.secret && (strings.HasPrefix(rest, f.path+".") || strings.HasPrefix(rest, f.path+"[")) {
					return l.path + "[" + n + "]." + f.path
				}
			}
		}
	}
	return ""
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
