// Package config loads and validates the sensor configuration.
//
// The sensor reads one YAML file, applies environment overrides, and
// validates every key against its bounds. The loader fails closed: any error
// stops the start. The sensor reads the config one time at start. A config
// change needs a restart; SIGHUP reloads only the bundle, not the config.
//
// Precedence is default < file < environment. Each scalar key has one
// environment variable name: CANARY_ plus the key path in upper case, with
// each . changed to _ . A CANARY_ variable that is not in the key table is an
// error.
package config

import (
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Config holds the validated sensor configuration.
type Config struct {
	Listen Listen
	Ops    Ops
	Acme   Acme
}

// Listen holds the decoy listener addresses.
type Listen struct {
	HTTP  string
	HTTPS string
}

// Ops holds the ops listener settings.
type Ops struct {
	Listen            string
	BasicAuthHtpasswd string
}

// Acme holds the ACME certificate settings.
type Acme struct {
	Email    string
	CA       string
	CacheDir string
}

// kind is the scalar type a key holds.
type kind int

const (
	kindString kind = iota
	kindBool
	kindInt
	kindDuration
)

// key is one row of the key table. A new key needs a row here in the same
// change, with a bounds row in 04 section 3.
type key struct {
	path     string
	kind     kind
	def      string
	required bool
	secret   bool
}

// keys is the key table for this slice. The keys added with later slices join
// this table in their own changes.
var keys = []key{
	{path: "listen.http", kind: kindString, def: ":80"},
	{path: "listen.https", kind: kindString, def: ":443"},
	{path: "ops.listen", kind: kindString, def: "127.0.0.1:9443"},
	{path: "ops.basic_auth_htpasswd", kind: kindString, def: "/var/lib/agent-canary/htpasswd"},
	{path: "acme.email", kind: kindString, required: true},
	{path: "acme.ca", kind: kindString, def: "letsencrypt"},
	{path: "acme.cache_dir", kind: kindString, def: "/var/lib/agent-canary/certs"},
}

// keyEnvName builds the environment variable name for a key path.
func keyEnvName(path string) string {
	return "CANARY_" + strings.ToUpper(strings.ReplaceAll(path, ".", "_"))
}

// Options controls Load.
type Options struct {
	// StateRoot is the directory state paths must sit under after symlink
	// resolution. The default is /var/lib/agent-canary.
	StateRoot string

	// Check is true when Load runs behind --check. It marks the run for
	// reporting but does not change validation.
	Check bool

	// Env returns the environment pairs to read. The default is os.Environ.
	// Tests set it to a fixed list so the run does not read the host
	// environment.
	Env func() []string

	// Dialer and Resolver are seams for the no-network check. Load must not
	// call them for the current keys. Tests set them to fail on use and
	// assert the call never happens.
	Dialer   Dialer
	Resolver Resolver
}

// Dialer opens a network connection.
type Dialer interface {
	Dial(network, address string) (net.Conn, error)
}

// Resolver resolves a host name.
type Resolver interface {
	LookupHost(host string) ([]string, error)
}

func (o *Options) defaults() {
	if o.StateRoot == "" {
		o.StateRoot = "/var/lib/agent-canary"
	}
	if o.Env == nil {
		o.Env = os.Environ
	}
}

// Load reads, overrides, and validates the config at path. Any error stops
// the start.
func Load(path string, opts Options) (*Config, error) {
	opts.defaults()

	data, err := readFileCapped(path, &opts)
	if err != nil {
		return nil, err
	}

	leaves, nonLeaves, allPaths, err := parseCapped(data)
	if err != nil {
		return nil, err
	}

	cfg := new(Config)
	if err := cfg.fill(leaves, nonLeaves, allPaths, &opts); err != nil {
		return nil, err
	}
	return cfg, nil
}

// fill resolves each key (env, then file, then default) and validates it.
func (c *Config) fill(leaves map[string]leaf, nonLeaves, allPaths map[string]bool, opts *Options) error {
	for _, k := range keys {
		raw, source, l, err := resolve(k, leaves, nonLeaves, opts)
		if err != nil {
			return err
		}
		val, err := c.apply(k, raw, source, l, opts)
		if err != nil {
			return err
		}
		setValue(c, k.path, val)
	}
	for p := range allPaths {
		if !isKnownPath(p) {
			return newCfgError(p, "file", "unknown key", "")
		}
	}
	return checkEnvOverrides(opts)
}

// resolve returns the raw value for a key and its source.
func resolve(k key, leaves map[string]leaf, nonLeaves map[string]bool, opts *Options) (string, string, leaf, error) {
	if v, ok := osLookup(opts.Env, keyEnvName(k.path)); ok {
		return v, "env " + keyEnvName(k.path), leaf{}, nil
	}
	if nonLeaves[k.path] {
		return "", "", leaf{}, newCfgError(k.path, "file", "expected a scalar", "")
	}
	if l, ok := leaves[k.path]; ok {
		return l.value, "file line " + strconv.Itoa(l.line), l, nil
	}
	if k.def != "" {
		return k.def, "default", leaf{}, nil
	}
	if k.required {
		return "", "", leaf{}, newCfgError(k.path, "none", "required key is missing", "")
	}
	return "", "", leaf{}, nil
}

// checkScalar validates that a raw value matches the expected scalar type.
func checkScalar(k key, raw string, l leaf) error {
	switch k.kind {
	case kindString:
		return nil
	case kindBool:
		if raw != "true" && raw != "false" {
			return fmt.Errorf("must be true or false")
		}
	case kindInt:
		if l.style == yaml.SingleQuotedStyle || l.style == yaml.DoubleQuotedStyle {
			return fmt.Errorf("quoted numbers not allowed")
		}
		if _, err := strconv.ParseInt(raw, 10, 64); err != nil {
			return fmt.Errorf("must be a decimal integer")
		}
		if len(raw) > 0 && raw[0] == '0' && len(raw) > 1 {
			return fmt.Errorf("leading zeros not allowed")
		}
		if strings.ContainsAny(raw, "_") {
			return fmt.Errorf("underscores not allowed")
		}
	case kindDuration:
		if _, err := strconv.ParseInt(raw, 10, 64); err == nil {
			return fmt.Errorf("duration must be a string (e.g., 15m)")
		}
	}
	return nil
}

// apply validates a raw value against the key and returns the stored value.
// A validator failure becomes a cfgError that names the key, its source, the
// problem, and the value (for non-secret keys).
func (c *Config) apply(k key, raw, source string, l leaf, opts *Options) (string, error) {
	if err := checkScalar(k, raw, l); err != nil {
		return "", newCfgError(k.path, source, err.Error(), raw)
	}
	v, err := validateValue(k, raw, opts)
	if err != nil {
		return "", newCfgError(k.path, source, err.Error(), raw)
	}
	return v, nil
}

// validateValue runs the semantic check for one key.
func validateValue(k key, raw string, opts *Options) (string, error) {
	switch k.path {
	case "listen.http":
		return checkAddr(raw)
	case "listen.https":
		return checkAddr(raw)
	case "ops.listen":
		return checkOpsAddr(raw)
	case "ops.basic_auth_htpasswd":
		return checkHtpasswd(raw)
	case "acme.email":
		return checkEmail(raw)
	case "acme.ca":
		return checkCA(raw)
	case "acme.cache_dir":
		return checkStateDir(raw, opts.StateRoot)
	}
	return raw, nil
}

// isKnownPath reports whether p is a key or a prefix of one.
func isKnownPath(p string) bool {
	if p == "" {
		return false
	}
	for _, k := range keys {
		if k.path == p || strings.HasPrefix(k.path, p+".") {
			return true
		}
	}
	return false
}

// checkEnvOverrides rejects a CANARY_ variable that is not in the key table.
func checkEnvOverrides(opts *Options) error {
	known := make(map[string]bool, len(keys))
	for _, k := range keys {
		known[keyEnvName(k.path)] = true
	}
	for _, kv := range opts.Env() {
		name, _, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(name, "CANARY_") && !known[name] {
			return newCfgError("", "env "+name, "unknown CANARY_ variable", "")
		}
	}
	return nil
}

// setValue writes a validated value into the struct.
func setValue(c *Config, path, val string) {
	switch path {
	case "listen.http":
		c.Listen.HTTP = val
	case "listen.https":
		c.Listen.HTTPS = val
	case "ops.listen":
		c.Ops.Listen = val
	case "ops.basic_auth_htpasswd":
		c.Ops.BasicAuthHtpasswd = val
	case "acme.email":
		c.Acme.Email = val
	case "acme.ca":
		c.Acme.CA = val
	case "acme.cache_dir":
		c.Acme.CacheDir = val
	}
}

// AllowList returns the configured outbound endpoints. This set is the C4
// outbound allow-list. The egress test uses it.
func (c *Config) AllowList() []string {
	var out []string
	if isHTTPSURL(c.Acme.CA) {
		out = append(out, c.Acme.CA)
	}
	sort.Strings(out)
	return out
}

// osLookup reads one variable from the Options environment.
func osLookup(env func() []string, name string) (string, bool) {
	for _, kv := range env() {
		k, v, ok := strings.Cut(kv, "=")
		if ok && k == name {
			return v, true
		}
	}
	return "", false
}

// cfgError is a config failure that names the key and its source.
type cfgError struct {
	key    string
	source string
	detail string
	value  string
}

func (e cfgError) Error() string {
	var b strings.Builder
	if e.key != "" {
		b.WriteString("config: ")
		b.WriteString(e.key)
	} else {
		b.WriteString("config: file")
	}
	b.WriteString(": ")
	b.WriteString(e.detail)
	if e.source != "" && e.source != "none" {
		b.WriteString(" (")
		b.WriteString(e.source)
		b.WriteString(")")
	}
	if e.value != "" {
		b.WriteString(" value=")
		b.WriteString(e.value)
	}
	return b.String()
}

// newCfgError builds a cfgError, escaping and cutting the value. A secret key
// never shows its value.
func newCfgError(keyPath, source, detail, raw string) error {
	e := cfgError{key: keyPath, source: source, detail: detail}
	if secretByPath[keyPath] {
		return e
	}
	e.value = redact(raw)
	return e
}

// secretByPath marks a key whose value must not appear in output. This slice
// has no secret keys. The table grows with later slices.
var secretByPath = map[string]bool{}
