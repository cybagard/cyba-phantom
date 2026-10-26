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
	"unicode"

	"github.com/cybagard/cyba-phantom/internal/egress"
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
	// kindURL is a key whose value is never printed in an error. It can
	// hold user information.
	kindURL
)

var kindNames = [...]string{"string", "bool", "int", "uint", "byte size", "duration", "path", "URL"}
var kindTags = [...]string{"!!str", "!!bool", "!!int", "!!int", "!!int", "!!str", "!!str", "!!str"}

// key is one row of the key table.
type key struct {
	path string
	kind kind
	// def is the default value, parsed like an override.
	def string
	// req marks a required key: the file or the environment must set it.
	req bool
	// secret marks a key whose value is never printed.
	secret bool
	// maxItems > 0 marks a key in a list item that holds 1 to maxItems
	// scalars in a list.
	maxItems int
	// check returns a fixed detail if a parsed value breaks a rule, or "".
	check func(l *loader, raw string) string
	// endpoint, if set, parses the value as an outbound endpoint for AllowList.
	endpoint endpointParser
}

// endpointParser makes an Endpoint from a value.
// It returns a fixed detail on an error.
type endpointParser func(raw string) (Endpoint, string)

// keys is the production key table (04 section 3). It holds the scalar
// keys. The list keys are in the table lists. The loader adds the item
// keys to its table when it reads the lists (expandLists).
var keys = []key{
	{path: "listen.http", kind: kindString, def: ":80", check: checkListen},
	{path: "listen.https", kind: kindString, def: ":443", check: checkListen},
	{path: "ops.listen", kind: kindString, def: "127.0.0.1:9443", check: checkOpsListen},
	{path: "ops.basic_auth_htpasswd", kind: kindPath, def: "/etc/phantom/htpasswd", check: checkHtpasswd},
	{path: "acme.email", kind: kindString, req: true, check: checkEmail},
	{path: "acme.ca", kind: kindURL, def: "letsencrypt", check: checkCA},
	{path: "acme.cache_dir", kind: kindPath, def: "/var/lib/phantom/certs", check: checkCacheDir},
	{path: "bundle.path", kind: kindPath, def: "/var/lib/phantom/bundle/current.cbnd", check: checkBundlePath},
	{path: "bundle.fetch_url", kind: kindURL, check: checkFetchURL},
	// The bounds apply also if fetch_url is empty.
	{path: "bundle.fetch_interval", kind: kindDuration, def: "6h", check: durRange(15*time.Minute, 7*24*time.Hour)},
	{path: "limits.max_conns", kind: kindInt, def: "2000", check: intRange(1, 2000)},
	{path: "limits.body_bytes", kind: kindBytes, def: "65536", check: intRange(1, 65536)},
	{path: "limits.header_bytes", kind: kindBytes, def: "16384", check: intRange(8192, 16384)},
	{path: "limits.per_ip_rps", kind: kindInt, def: "50", check: intRange(1, 1000)},
	// The lower bound is per_ip_rps: a cross-check.
	{path: "limits.per_ip_burst", kind: kindInt, def: "200", check: intRange(1, 5000)},
	{path: "limits.queue_depth", kind: kindInt, def: "4096", check: intRange(1, 8192)},
	{path: "store.path", kind: kindPath, def: "/var/lib/phantom/events.db", check: checkStorePath},
	{path: "store.max_bytes", kind: kindBytes, def: "10737418240", check: intRange(268435456, math.MaxInt64)},
	{path: "store.retention_days.ip", kind: kindInt, def: "7", check: intRange(1, 7)},
	{path: "store.retention_days.raw", kind: kindInt, def: "30", check: intRange(1, 30)},
	// The lower bound is retention_days.raw: a cross-check.
	{path: "store.retention_days.events", kind: kindInt, def: "90", check: intRange(1, 90)},
	{path: "tlog.dir", kind: kindPath, def: "/var/lib/phantom/tlog", check: checkStatePath},
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

// SystemNet returns the Net with the egress dialer and the system resolver.
// The dialer has no timeout.
func SystemNet() Net {
	return Net{Dialer: egress.Dialer(0), Resolver: net.DefaultResolver}
}

// Load is LoadWith with the system dialer and resolver.
func Load(path string, env []string) (*Config, error) {
	return LoadWith(path, env, SystemNet())
}

// LoadWith reads the config file at path one time. It applies the PHANTOM_*
// overrides in env (use os.Environ()). Precedence: default < file < env.
// LoadWith returns all errors together and never returns a partial config.
// LoadWith returns an error if n.Dialer or n.Resolver is nil.
// LoadWith passes n to load, which keeps it in the loader. No key check
// uses n yet. A later network use must go through n.
// TestTS10_NoSystemNetwork fails on the source forms listed in its doc
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
	return "PHANTOM_" + strings.ToUpper(strings.ReplaceAll(path, ".", "_"))
}

func (l *loader) load(path string, env []string, table []key, n Net) (*Config, error) {
	l.env, l.net = env, n
	byPath := make(map[string]key, len(table))
	byEnv := make(map[string]key, len(table))
	for _, k := range table {
		byPath[k.path] = k
		byEnv[envName(k.path)] = k
	}
	doc, err := ReadFile(path)
	if err != nil {
		// A reader error does not hide the errors in variable names.
		return nil, errors.Join(append([]error{readError(path, err, table, lists)}, envEach(env, byEnv, nil)...)...)
	}
	vals := make(map[string]Value)
	raws := make(map[string]string) // raws holds the text of each value in vals.
	// failed marks a key whose last value fails to parse. The parse error
	// replaces the required-key error.
	failed := make(map[string]bool)
	var errs []error
	keyError := func(k key, raw, src string, line int, detail string) error {
		if k.secret || k.kind == kindURL {
			raw = "" // An Error never holds a secret value or a URL: a URL can hold user information.
		}
		return &Error{Key: k.path, Source: src, Line: line, Detail: detail, Value: raw}
	}
	// set parses one value. A later source replaces an earlier one.
	// If the value fails to parse, set removes the key from vals.
	set := func(k key, raw, tag, src string, line int) {
		v, detail := parse(k, raw, tag)
		failed[k.path] = detail != ""
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

	// Lists: the list keys have no PHANTOM_ override, so byEnv does not hold the item keys.
	// The loader handles an item key like a scalar key from here: set, required, and check.
	// The loader reports listErrs after the required scalar keys.
	itemKeys, listErrs := expandLists(doc, path, lists)
	table = append(slices.Clone(table), itemKeys...)
	for _, k := range itemKeys {
		if leaf, ok := doc.Leaves[k.path]; ok {
			set(k, leaf.Value, leaf.Tag, path, leaf.Line)
		}
	}

	// File: each node must be a known key or section. The errors come
	// sorted by line, then by path.
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

	errs = append(errs, envEach(env, byEnv, func(k key, name, raw string) { set(k, raw, "", name, 0) })...)

	for _, k := range table {
		if _, ok := vals[k.path]; k.req && !ok && !failed[k.path] {
			errs = append(errs, &Error{Key: k.path, Source: path, Detail: "the key is required"})
		}
	}
	errs = append(errs, listErrs...)
	// Each check runs one time, on the effective value. The loader removes
	// a key that fails from vals.
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
	errs = append(errs, crossCheck(l, vals)...)
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return &Config{values: vals}, nil
}

// foldDrop holds the characters that envFold removes.
var foldDrop = []*unicode.RangeTable{
	unicode.Cf,
	unicode.Mn,
	unicode.Me,
	unicode.Cc,
	unicode.Other_Default_Ignorable_Code_Point,
	unicode.Variation_Selector,
}

// envFold returns name in upper case. It changes a full-width form (U+FF01 to
// U+FF5E) to ASCII. It removes the characters in foldDrop, for example U+200B
// and the Hangul fillers. It also removes the white space at the start.
func envFold(name string) string {
	f := strings.Map(func(r rune) rune {
		if r >= 0xFF01 && r <= 0xFF5E {
			r -= 0xFEE0
		}
		if unicode.IsOneOf(foldDrop, r) {
			return -1
		}
		return unicode.ToUpper(r)
	}, name)
	return strings.TrimLeftFunc(f, unicode.IsSpace)
}

// envEach checks the names in env. If envFold of a name starts with PHANTOM,
// the key table must contain it. So a name such as PHANTOMX has an error.
// An unknown name gets the unknown-name error one time. A known name that
// occurs again gets the repeat error. Its first use calls use, if use is set.
func envEach(env []string, byEnv map[string]key, use func(k key, name, raw string)) []error {
	var errs []error
	seen := make(map[string]bool)
	for _, kv := range env {
		name, raw, _ := strings.Cut(kv, "=")
		if !strings.HasPrefix(envFold(name), "PHANTOM") {
			continue
		}
		k, ok := byEnv[name]
		switch {
		case !ok && seen[name]:
		case !ok:
			errs = append(errs, &Error{Source: name, Detail: "unknown PHANTOM_ variable"})
		case seen[name]:
			errs = append(errs, &Error{Source: name, Detail: "the variable occurs more than one time"})
		case use != nil:
			use(k, name, raw)
		}
		seen[name] = true
	}
	return errs
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

// readError changes a reader error into an Error. A wrapped system error
// becomes a fixed message. A ReadError gives its line and its detail.
// For a node, it also gives the key path and the column.
// A key below a secret key can be the secret value. So readError changes
// its path to the path of the secret key.
// The tables are parameters: readError does not read the global tables.
func readError(path string, err error, table []key, listTable []listKey) error {
	e := &Error{Source: path, Detail: "the loader cannot read the file"}
	var re *ReadError
	switch {
	case errors.Is(err, fs.ErrNotExist):
		e.Detail = "the file does not exist"
	case errors.Is(err, fs.ErrPermission):
		e.Detail = "permission denied"
	case errors.As(err, &re) && re.Err == nil:
		e.Detail, e.Line = re.Detail, re.Line
		if re.Column > 0 {
			e.Detail = cut(secretPath(re.Path, table, listTable)) + ": column " + strconv.Itoa(re.Column) + ": " + re.Detail
		}
	}
	return e
}

// secretPath returns the key path p. If p is below a secret key or has a
// secret item name, it returns the path of that secret.
// For the root, it returns "(root)".
func secretPath(p string, table []key, listTable []listKey) string {
	if i := slices.IndexFunc(table, func(k key) bool { return k.secret && isBelow(p, k.path) }); i >= 0 {
		return table[i].path
	}
	if s := secretItemPath(p, listTable); s != "" {
		return s
	}
	if p == "" {
		return "(root)"
	}
	return p
}

// isBelow reports whether the path s is below the key p: s has the prefix p+"." or p+"[".
func isBelow(s, p string) bool {
	return strings.HasPrefix(s, p+".") || strings.HasPrefix(s, p+"[")
}

// pathPart matches one part of a path: the text between the characters ".", "[", and "]".
var pathPart = regexp.MustCompile(`[^.\[\]]+`)

// secretItemPath cuts the path s after its first secret item name. A secret
// item name is the name of a secret key in a list schema. The cut does not
// depend on the shape of the list or on the item type.
// For example, "tlog.publish[0].token_env.x" and "token_env.x" give
// "tlog.publish[0].token_env" and "token_env".
// If s has no secret item name, it returns "".
func secretItemPath(s string, table []listKey) string {
	for _, m := range pathPart.FindAllStringIndex(s, -1) {
		if isSecretItemName(s[m[0]:m[1]], table) {
			return s[:m[1]]
		}
	}
	return ""
}

// isSecretItemName reports whether name is the name of a secret key in a schema of any list.
func isSecretItemName(name string, table []listKey) bool {
	for _, l := range table {
		for _, schema := range l.schemas {
			for _, f := range schema {
				if f.secret && f.path == name {
					return true
				}
			}
		}
	}
	return false
}

// userinfo matches user information and all text to the last "@" in the value.
// The start of a match is the first of two forms in the value.
// Form 1 is a ":" with all slashes, backslashes, and white space after it.
// Form 2 is two characters that are each a slash or a backslash.
// A more precise rule can miss a password form, so the loader removes too much.
var userinfo = regexp.MustCompile(`(?s)(:[/\\\s]*|[/\\]{2}).*@`)

// cutMarker starts a text that esc cuts on the left.
const cutMarker = "..."

// scheme matches a URL scheme: a letter, then letters, digits, "+", "-" or ".".
var scheme = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*$`)

// redact replaces the user information in s with "REDACTED@".
// It keeps the text before "REDACTED@" in two cases only.
// Case 1 needs two conditions. The text before the ":" is a URL scheme.
// Also, 2 or more slashes or backslashes follow the ":".
// In case 2, the match is two slashes or backslashes at the start of s.
// In each other case, redact keeps no text before "REDACTED@".
func redact(s string) string {
	m := userinfo.FindStringSubmatchIndex(s)
	if m == nil {
		return s
	}
	keep, g := "", s[m[2]:m[3]]
	if g[0] == ':' {
		if scheme.MatchString(s[:m[2]]) && strings.Count(g, "/")+strings.Count(g, `\`) >= 2 {
			keep = s[:m[3]]
		}
	} else if m[2] == 0 {
		keep = g
	}
	return keep + "REDACTED@" + s[m[1]:]
}

// esc is the one escaper for printed text (SEC-07).
// It redacts the user information. Then it escapes control characters (also
// the ESC of ANSI sequences), double quotes, backslashes, non-ASCII runes and
// invalid bytes. Then it cuts the result. It never cuts an escape sequence.
// If max < 0 and the cut removes text, the result starts with cutMarker.
// If max >= 0 or max <= -3, the result has at most |max| bytes.
func esc(s string, max int) string {
	q := strconv.QuoteToASCII(redact(s))
	q = q[1 : len(q)-1]
	i := 0
	if max >= 0 {
		for i < len(q) && i+escWidth(q[i:]) <= max {
			i += escWidth(q[i:])
		}
		return q[:i]
	}
	if len(q) <= -max {
		return q
	}
	for from := len(q) + max + len(cutMarker); i < from && i < len(q); {
		i += escWidth(q[i:])
	}
	return cutMarker + q[i:]
}

// escWidth returns the byte width of the character or escape at the start of q.
func escWidth(q string) int {
	if q[0] != '\\' || len(q) < 2 {
		return 1
	}
	if i := strings.IndexByte("xuU", q[1]); i >= 0 {
		return [...]int{4, 6, 10}[i]
	}
	return 2
}
