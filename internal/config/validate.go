package config

import (
	"errors"
	"fmt"
	"io/fs"
	"math"
	"net"
	"net/mail"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cybagard/cyba-phantom/internal/egress"
)

// defaultStateRoot is the directory that state paths must stay under.
const defaultStateRoot = "/var/lib/phantom"

// DefaultStateRoot is defaultStateRoot for the code outside this package.
const DefaultStateRoot = defaultStateRoot

// loader holds the settings that the validators use. A test sets them to use a temporary directory.
type loader struct {
	stateRoot string   // stateRoot is the directory that state paths must stay under after symlink resolution.
	euid      int      // euid is the user that runs the sensor.
	env       []string // env is the environment that the *_env keys name. The loader does not read the process environment.
	// net is the network access that LoadWith gets.
	net Net
}

func newLoader() *loader { return &loader{stateRoot: defaultStateRoot, euid: os.Geteuid()} }

// hostname matches host name labels that a dot separates. A label is not empty.
var hostname = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*$`)

// lastLabel returns the text after the last dot of host.
func lastLabel(host string) string {
	return host[strings.LastIndexByte(host, '.')+1:]
}

// numericLabel reports whether the last label of host is a number. A number is only
// decimal digits, or 0x or 0X with hex digits only (the hex part can be empty).
// Such a host is a number, not a name. Some resolvers read it as an IPv4 address.
func numericLabel(host string) bool {
	l := lastLabel(host)
	if l == "" {
		return false
	}
	if len(l) >= 2 && l[0] == '0' && (l[1] == 'x' || l[1] == 'X') {
		return strings.IndexFunc(l[2:], func(r rune) bool { return !isHex(r) }) < 0
	}
	return strings.IndexFunc(l, func(r rune) bool { return r < '0' || r > '9' }) < 0
}

func isHex(r rune) bool {
	return r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F'
}

// hostPort is a parsed host:port value.
type hostPort struct {
	host string
	addr netip.Addr // addr is valid if host is an IP literal.
	port int
}

// parseHostPort parses a host:port value. It returns a fixed detail on an error.
func parseHostPort(s string) (hostPort, string) {
	var hp hostPort
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return hp, "the value is not host:port"
	}
	if !decimal.MatchString(port) {
		return hp, "the port is not a decimal literal"
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return hp, "the port is not in the range 1 to 65535"
	}
	hp.host, hp.port = host, n
	a, err := netip.ParseAddr(host)
	if strings.HasPrefix(s, "[") && (err != nil || !a.Is6()) {
		return hp, "a host in brackets must be an IPv6 address"
	}
	if host == "" {
		return hp, ""
	}
	if err == nil {
		hp.addr = a
		return hp, ""
	}
	if !hostname.MatchString(host) || numericLabel(host) {
		return hp, "the host is not an IP literal or a host name"
	}
	return hp, ""
}

// wildcard reports whether the address binds all interfaces. A zone does not change this.
func (h hostPort) wildcard() bool {
	return h.host == "" || h.addr.WithZone("").Unmap().IsUnspecified()
}

// named reports whether the host is a name. The loader does not resolve names.
func (h hostPort) named() bool { return h.host != "" && !h.addr.IsValid() }

// overlaps reports whether h and o can bind the same address and port.
func (h hostPort) overlaps(o hostPort) bool {
	if h.port != o.port {
		return false
	}
	if h.wildcard() || o.wildcard() {
		return true
	}
	if h.addr.IsValid() && o.addr.IsValid() {
		return h.addr.WithZone("").Unmap() == o.addr.WithZone("").Unmap()
	}
	// A host name is on at least one side. The loader does not resolve names.
	return true
}

func checkListen(_ *loader, raw string) string {
	_, d := parseHostPort(raw)
	return d
}

func checkOpsListen(_ *loader, raw string) string {
	hp, d := parseHostPort(raw)
	switch {
	case d != "":
		return d
	case !hp.addr.IsValid():
		return "the host must be an IP literal"
	case hp.addr.Zone() != "":
		return "the IP literal must not have a zone"
	}
	a := hp.addr.Unmap()
	switch {
	case a.IsUnspecified():
		return "the IP literal must not be unspecified"
	case !a.IsLoopback() && !a.IsPrivate():
		return "the IP literal must be loopback or private (RFC 1918, RFC 4193)"
	}
	return ""
}

// opsConflict returns a detail if the ops address can clash with the listen address l.
// A listen host name with the same port is a clash: the loader does not resolve names.
func opsConflict(ops, l hostPort, name string) string {
	switch {
	case l.named() && l.port == ops.port:
		return "the port is the same as the port of " + name + ", and that host is a name"
	case ops.overlaps(l):
		return "the address overlaps the " + name + " address"
	}
	return ""
}

// crossCheck checks the rules that compare two keys. It skips a key that is not in vals.
// The loader removes a key from vals if its value failed to parse or failed its check.
func crossCheck(l *loader, vals map[string]Value) []error {
	get := func(p string) (hostPort, Value, bool) {
		v, ok := vals[p]
		if !ok {
			return hostPort{}, v, false
		}
		hp, d := parseHostPort(v.Str)
		return hp, v, d == ""
	}
	var errs []error
	fail := func(p string, v Value, detail string) {
		errs = append(errs, &Error{Key: p, Source: v.Source, Line: v.Line, Detail: detail})
	}
	httpA, _, okHTTP := get("listen.http")
	httpsA, httpsV, okHTTPS := get("listen.https")
	if okHTTP && okHTTPS && httpA.overlaps(httpsA) {
		fail("listen.https", httpsV, "the address must differ from listen.http")
	}
	if ops, v, ok := get("ops.listen"); ok {
		if okHTTP {
			if d := opsConflict(ops, httpA, "listen.http"); d != "" {
				fail("ops.listen", v, d)
			}
		}
		if okHTTPS {
			if d := opsConflict(ops, httpsA, "listen.https"); d != "" {
				fail("ops.listen", v, d)
			}
		}
	}
	// These checks compare a bound with the value of a second key. A key that failed is not in vals, so the loader skips it.
	for _, pair := range [][2]string{
		{"limits.per_ip_burst", "limits.per_ip_rps"},
		{"store.retention_days.events", "store.retention_days.raw"},
	} {
		if p, v, d := belowFloor(vals, pair[0], pair[1]); d != "" {
			fail(p, v, d)
		}
	}
	if s, ok := vals["store.path"]; ok {
		if d := storeConflict(l, vals, s.Str); d != "" {
			fail("store.path", s, d)
		}
	}
	if c, ok := vals["acme.cache_dir"]; ok {
		if d := cacheConflict(l, vals, c.Str); d != "" {
			fail("acme.cache_dir", c, d)
		}
	}
	if b, ok := vals["bundle.path"]; ok {
		if d := bundleConflict(vals, b.Str); d != "" {
			fail("bundle.path", b, d)
		}
	}
	return errs
}

// belowFloor checks that the value of key is not less than the value of floor.
// It skips the check if key or floor is not in vals. If key is at default, the
// operator set floor: the error names floor.
func belowFloor(vals map[string]Value, key, floor string) (string, Value, string) {
	k, ok := vals[key]
	f, okFloor := vals[floor]
	switch {
	case !ok || !okFloor || k.Int >= f.Int:
		return "", Value{}, ""
	case k.Source == "default":
		return floor, f, "the value must not be more than " + key
	}
	return key, k, "the value must not be less than " + floor
}

// intRange returns a check that the integer value is in the range lo to hi.
func intRange(lo, hi int64) func(*loader, string) string {
	return func(_ *loader, raw string) string {
		if n, _ := strconv.ParseInt(raw, 10, 64); n < lo || n > hi {
			if hi == math.MaxInt64 {
				return "the value must be at least " + strconv.FormatInt(lo, 10)
			}
			return "the value must be in the range " + strconv.FormatInt(lo, 10) + " to " + strconv.FormatInt(hi, 10)
		}
		return ""
	}
}

// durRange returns a check that the duration value is in the range lo to hi.
func durRange(lo, hi time.Duration) func(*loader, string) string {
	return func(_ *loader, raw string) string {
		if d, _ := time.ParseDuration(raw); d < lo || d > hi {
			return "the duration must be in the range " + lo.String() + " to " + hi.String()
		}
		return ""
	}
}

// originChars matches 1 to 128 bytes. Each byte is a letter, a digit, or one of these marks: dot, underscore, slash, hyphen.
var originChars = regexp.MustCompile(`^[A-Za-z0-9._/-]{1,128}$`)

func checkOrigin(_ *loader, raw string) string {
	if !originChars.MatchString(raw) {
		return "the origin must be 1 to 128 bytes of A-Z a-z 0-9 . _ / -"
	}
	return ""
}

func checkMinBand(_ *loader, raw string) string {
	if raw != "agent-likely" && raw != "agent-confirmed" {
		return "the band must be agent-likely or agent-confirmed"
	}
	return ""
}

// checkFetchURL accepts an empty value (the fetch is off) or an https URL.
func checkFetchURL(_ *loader, raw string) string {
	if raw == "" {
		return ""
	}
	_, d := parseURL(raw, "https")
	return d
}

// emailRule is the fixed text for a character outside 0x21-0x7E.
const emailRule = "the address must have only printable ASCII characters 0x21-0x7E"

// checkEmail accepts one address of printable ASCII characters 0x21-0x7E.
func checkEmail(_ *loader, raw string) string {
	if strings.ContainsFunc(raw, func(r rune) bool { return r < 0x21 || r > 0x7e }) {
		return emailRule
	}
	a, err := mail.ParseAddress(raw)
	if err != nil || a.Address != raw {
		return "the value must be exactly one address"
	}
	return ""
}

// parseURL checks raw as a URL with one of the schemes. It returns a fixed detail on an error.
// The detail never holds a part of the value.
func parseURL(raw string, schemes ...string) (*url.URL, string) {
	u, err := url.Parse(raw)
	switch {
	case err != nil:
		return nil, "the value is not a valid URL"
	case !slices.Contains(schemes, u.Scheme):
		return nil, "the URL scheme is not allowed"
	case u.Opaque != "":
		return nil, "the URL must not be opaque"
	case u.User != nil:
		return nil, "the URL must not have user information"
	case u.Fragment != "" || strings.Contains(raw, "#"):
		return nil, "the URL must not have a fragment"
	case strings.Contains(raw, "?"):
		return nil, "the URL must not have a query"
	case u.Hostname() == "":
		return nil, "the URL must have a host"
	}
	p := u.Port()
	switch {
	case p == "" && strings.HasSuffix(u.Host, ":"):
		return nil, "the URL port is empty"
	case p != "" && !decimal.MatchString(p):
		return nil, "the URL port is not a decimal literal"
	case p != "":
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return nil, "the URL port is not in the range 1 to 65535"
		}
	}
	host := u.Hostname()
	// The HTTP client can map a non-ASCII host to an IP address before it connects.
	for i := 0; i < len(host); i++ {
		if host[i] >= 0x80 {
			return nil, "the URL host must be ASCII"
		}
	}
	if a, err := netip.ParseAddr(host); err == nil {
		switch {
		case a.Zone() != "":
			return nil, "the URL host must not have a zone"
		case !egress.Permitted(a):
			return nil, "the URL host is an IP address that the egress rule refuses"
		}
	} else if !hostname.MatchString(host) {
		return nil, "the URL host is not an IP address or a host name"
	} else if numericLabel(host) {
		return nil, "the last label of the URL host is a number, and the host is not an IP address"
	}
	return u, ""
}

// Names of the ACME directories that the loader knows.
var caDirectories = map[string]string{
	"letsencrypt":         "https://acme-v02.api.letsencrypt.org/directory",
	"letsencrypt-staging": "https://acme-staging-v02.api.letsencrypt.org/directory",
}

// CADirectory returns the directory URL of an acme.ca value: the URL of a known shorthand, else raw as it is.
func CADirectory(raw string) string {
	if dir, ok := caDirectories[raw]; ok {
		return dir
	}
	return raw
}

func checkCA(_ *loader, raw string) string {
	if _, ok := caDirectories[raw]; ok {
		return ""
	}
	_, d := parseURL(raw, "https")
	return d
}

// Endpoint is one allowed outbound endpoint (C4).
type Endpoint struct{ Scheme, Host, Port string }

// checkHTTPS accepts an https URL.
func checkHTTPS(_ *loader, raw string) string {
	_, d := parseURL(raw, "https")
	return d
}

// endpoint makes an Endpoint. It writes the host in lower case and an IP literal in canonical form,
// so that two spellings of one endpoint are equal.
func endpoint(scheme, host, port string) Endpoint {
	host = strings.ToLower(host)
	if a, err := netip.ParseAddr(host); err == nil {
		host = a.Unmap().String()
	}
	return Endpoint{Scheme: scheme, Host: host, Port: port}
}

// parseEndpoint parses a scheme, "://", and host:port. The scheme must be one of schemes,
// in the exact case. The host is not empty. An IP literal has no zone and
// passes the egress rule, except for udp and tcp. It returns a fixed detail
// on an error.
func parseEndpoint(raw string, schemes []string) (Endpoint, string) {
	scheme, raw, ok := strings.Cut(raw, "://")
	if !ok || !slices.Contains(schemes, scheme) {
		return Endpoint{}, "the address scheme must be " + strings.Join(schemes, ", ") + " and be followed by ://"
	}
	hp, d := parseHostPort(raw)
	switch {
	case d != "":
		return Endpoint{}, d
	case hp.host == "":
		return Endpoint{}, "the host must not be empty"
	case hp.addr.Zone() != "":
		return Endpoint{}, "the host must not have a zone"
	case !hp.addr.IsValid() || scheme == "udp" || scheme == "tcp":
		// A name passes here. checkSyslogAddr checks udp and tcp.
	case !egress.Permitted(hp.addr):
		return Endpoint{}, "the host is an IP address that the egress rule refuses"
	}
	return endpoint(scheme, hp.host, strconv.Itoa(hp.port)), ""
}

var syslogSchemes = []string{"udp", "tcp", "tls"}

var smtpSchemes = []string{"smtp", "smtps"}

// loopbackLiteral reports whether a is an IP literal in 127.0.0.0/8 or is ::1. An IPv4-mapped
// IPv6 address is not loopback here: the rule names only these two forms (04 section 3).
func loopbackLiteral(a netip.Addr) bool {
	return a.Is4() && a.IsLoopback() || a == netip.IPv6Loopback()
}

// checkSyslogAddr accepts tls:// to any allowed host. It accepts udp:// and tcp:// only to a
// loopback IP literal: a host name is not loopback, because the loader does not resolve names.
func checkSyslogAddr(_ *loader, raw string) string {
	e, d := parseEndpoint(raw, syslogSchemes)
	if d != "" || e.Scheme == "tls" {
		return d
	}
	// Parse the host again: endpoint() unmaps an IPv4-mapped address, so e.Host cannot reject ::ffff:127.0.0.1.
	_, rest, _ := strings.Cut(raw, "://")
	if hp, _ := parseHostPort(rest); !loopbackLiteral(hp.addr) {
		return "the host of a udp or tcp address must be a loopback IP literal (127.0.0.0/8 or ::1)"
	}
	return ""
}

func checkSMTPHost(_ *loader, raw string) string {
	_, d := parseEndpoint(raw, smtpSchemes)
	return d
}

// AllowList returns the outbound endpoints that the config allows (C4): the endpoints of
// acme.ca, bundle.fetch_url (if set), tlog.publish[].url, and the alert sinks. An endpoint
// that two keys share is in the list one time. The order is acme.ca, bundle.fetch_url,
// tlog.publish, then alerts.sinks. A webhook has the scheme https, a syslog sink has udp, tcp, or tls,
// and an smtp sink has the scheme of its value: smtp or smtps. A loopback sink is in the list: it is
// not egress (04 section 3).
func (c *Config) AllowList() []Endpoint {
	var list []Endpoint
	add := func(e Endpoint) {
		if !slices.Contains(list, e) {
			list = append(list, e)
		}
	}
	fromURL := func(raw string) {
		if e, d := urlEndpoint(raw); d == "" {
			add(e)
		}
	}
	for _, p := range []string{"acme.ca", "bundle.fetch_url"} {
		raw := c.values[p].Str
		if p == "acme.ca" {
			raw = CADirectory(raw)
		}
		fromURL(raw)
	}
	for i := 0; c.values[fmt.Sprintf("tlog.publish[%d].type", i)].Str != ""; i++ {
		fromURL(c.values[fmt.Sprintf("tlog.publish[%d].url", i)].Str)
	}
	for i := 0; ; i++ {
		p := fmt.Sprintf("alerts.sinks[%d].", i)
		typ := c.values[p+"type"].Str
		if typ == "" {
			return list
		}
		// An unknown type has no schema: it adds nothing.
		for _, f := range sinkSchemas[typ] {
			if f.endpoint == nil {
				continue
			}
			if e, d := f.endpoint(c.values[p+f.path].Str); d == "" {
				add(e)
			}
		}
	}
}

// sinkSchemas holds the schemas of the alerts.sinks list.
// The lookup runs one time at start.
var sinkSchemas = schemasOf("alerts.sinks")

// schemasOf returns the item schemas of the list at path.
// It panics if the table has no such list.
func schemasOf(path string) map[string][]key {
	i := slices.IndexFunc(lists, func(l listKey) bool { return l.path == path })
	if i < 0 {
		panic("config: the list table has no list " + path)
	}
	return lists[i].schemas
}

// urlEndpoint makes the Endpoint of an https URL.
// The port is 443 if the URL has none.
func urlEndpoint(raw string) (Endpoint, string) {
	u, d := parseURL(raw, "https")
	if d != "" {
		return Endpoint{}, d
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	return endpoint(u.Scheme, u.Hostname(), port), ""
}

func syslogEndpoint(raw string) (Endpoint, string) { return parseEndpoint(raw, syslogSchemes) }

func smtpEndpoint(raw string) (Endpoint, string) { return parseEndpoint(raw, smtpSchemes) }

// checkPathForm checks that p is absolute, clean, and free of NUL.
func checkPathForm(p string) string {
	switch {
	case strings.ContainsRune(p, 0):
		return "the path must not contain NUL"
	case !filepath.IsAbs(p):
		return "the path must be absolute"
	case filepath.Clean(p) != p:
		return "the path must be clean"
	}
	return ""
}

// resolve resolves symlinks in p, or in its nearest existing ancestor, and adds the
// rest of the path. It never creates a file. A link that it cannot resolve is an error.
func resolve(p string) (string, error) {
	rest := ""
	for cur := p; ; cur = filepath.Dir(cur) {
		_, err := os.Lstat(cur)
		if err == nil {
			r, err := filepath.EvalSymlinks(cur)
			if err != nil {
				return "", err
			}
			return filepath.Join(r, rest), nil
		}
		if !errors.Is(err, fs.ErrNotExist) || filepath.Dir(cur) == cur {
			return "", err
		}
		rest = filepath.Join(filepath.Base(cur), rest)
	}
}

// under reports whether the resolved p is the resolved root or below it.
func under(root, p string) (bool, error) {
	r, err := resolve(root)
	if err != nil {
		return false, err
	}
	q, err := resolve(p)
	if err != nil {
		return false, err
	}
	rel, err := filepath.Rel(r, q)
	if err != nil {
		return false, nil
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)), nil
}

func checkStatePath(l *loader, raw string) string {
	if d := checkPathForm(raw); d != "" {
		return d
	}
	ok, err := under(l.stateRoot, raw)
	if err != nil {
		return "the loader cannot resolve the path"
	}
	if !ok {
		return "the path is not under the state directory after symlink resolution"
	}
	return ""
}

// storePart matches one path part of store.path below the state directory (SEC-20).
var storePart = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// checkStorePath applies the rules of checkStatePath. Then it checks the path
// text. A path that is equal to the state directory fails. A path that is not
// below it in the path text fails. Each part below it has only A-Z a-z 0-9 . _ -
// and is not "." or "..".
func checkStorePath(l *loader, raw string) string {
	if d := checkStatePath(l, raw); d != "" {
		return d
	}
	rel, err := filepath.Rel(l.stateRoot, raw)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "the path must be below the state directory"
	}
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		if part == "." || part == ".." || !storePart.MatchString(part) {
			return "each path part below the state directory must have only A-Z a-z 0-9 . _ - and must not be . or .."
		}
	}
	return ""
}

// checkCacheDir applies the rules of checkStorePath: the cache directory is below the state
// directory, and each path part has only A-Z a-z 0-9 . _ - (SEC-21). The cross-check
// cacheConflict compares it with the other state directories.
func checkCacheDir(l *loader, raw string) string { return checkStorePath(l, raw) }

// cacheConflict checks the acme.cache_dir value p (SEC-21). It returns a
// detail if p is in or above a directory that the sensor uses for other
// files. It compares the path text only. It folds A-Z with foldASCII. A key
// that is not in vals failed its own check, so it is skipped.
func cacheConflict(l *loader, vals map[string]Value, p string) string {
	p = foldASCII(p)
	if n := keyClash(p, vals, true, "tlog.dir", "bundle.path"); n != "" {
		return "the path must not be in or above " + n
	}
	if n := dirClash(p, l.stateRoot, true); n != "" {
		return "the path must not be in or above " + n
	}
	return ""
}

// stateDirs and stateFiles are the names in the state directory that
// other keys must not use.
var (
	stateDirs  = []string{"keys", "checkpoints"}
	stateFiles = []string{"checkpoint.state", "checkpoint.state.tmp", "writer.stop"}
)

// keyClash returns the name of the first key in names with a value in vals
// that p is in. If above is set, it also checks if p is above the value.
// The value of bundle.path is its directory. The caller folds p. A key that
// is not in vals is skipped.
func keyClash(p string, vals map[string]Value, above bool, names ...string) string {
	for _, k := range names {
		v, ok := vals[k]
		if !ok {
			continue
		}
		name := k
		if k == "bundle.path" {
			v.Str, name = filepath.Dir(v.Str), "the directory of bundle.path"
		}
		if s := foldASCII(v.Str); inDirText(p, s) || above && inDirText(s, p) {
			return name
		}
	}
	return ""
}

// dirClash is like keyClash for the directories in stateDirs. It returns
// the name, for example "the keys directory".
func dirClash(p, root string, above bool) string {
	for _, d := range stateDirs {
		if s := foldASCII(filepath.Join(root, d)); inDirText(p, s) || above && inDirText(s, p) {
			return "the " + d + " directory"
		}
	}
	return ""
}

// fileClash returns the first name in stateFiles that p is. If below is set,
// it also checks if p is below the file. The caller folds p.
func fileClash(p, root string, below bool) string {
	for _, f := range stateFiles {
		if s := foldASCII(filepath.Join(root, f)); p == s || below && inDirText(p, s) {
			return f
		}
	}
	return ""
}

// foldASCII changes the letters A-Z in s to a-z. No other byte changes, so a
// non-ASCII letter never matches an ASCII letter. This is not strings.ToLower.
func foldASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

// checkBundlePath applies the rules of checkStorePath. Then it checks that the file name ends in .cbnd (SEC-23).
// The keys, checkpoints and state-file compares fold A-Z with foldASCII.
// It also checks that the directory is not the state directory and is not in the keys or checkpoints directory.
// These new rules compare the path text only. checkStorePath resolves symlinks to check the state directory.
// checkStorePath requires a path below the state directory, so the state directory is the only path above those two directories.
// The cross-check bundleConflict compares the path with the other keys.
func checkBundlePath(l *loader, raw string) string {
	if d := checkStorePath(l, raw); d != "" {
		return d
	}
	if !strings.HasSuffix(raw, ".cbnd") {
		return "the file name must end in .cbnd"
	}
	if filepath.Base(raw) == ".cbnd" {
		return "the file name must have a character before .cbnd"
	}
	dir := filepath.Dir(raw)
	if dir == l.stateRoot {
		return "the directory must not be the state directory"
	}
	dir = foldASCII(dir)
	if n := dirClash(dir, l.stateRoot, false); n != "" {
		return "the directory must not be in " + n
	}
	if f := fileClash(dir, l.stateRoot, true); f != "" {
		return "the directory must not be or be in " + f
	}
	return ""
}

// bundleConflict checks p, a bundle.path value. It returns a detail if the
// directory of p is in or above tlog.dir or acme.cache_dir. It also returns
// a detail if the directory is store.path, a SQLite side file of it, or in one.
// It returns a detail if p is store.path (SEC-23). It compares the path text
// only. It folds the letters A-Z to a-z with foldASCII and no other letter.
// A key that is not in vals failed its own check, so it is skipped.
func bundleConflict(vals map[string]Value, p string) string {
	p = foldASCII(p)
	dir := filepath.Dir(p)
	if n := keyClash(dir, vals, true, "tlog.dir", "acme.cache_dir"); n != "" {
		return "the directory must not be in or above " + n
	}
	if v, ok := vals["store.path"]; ok {
		s := foldASCII(v.Str)
		if s == p {
			return "the path must not be store.path"
		}
		for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
			if inDirText(dir, s+suffix) {
				return "the directory must not be or be in store.path or a file of it"
			}
		}
	}
	return ""
}

// checkACMEName checks one entry of acme.names (SEC-21): a DNS name in lower case with
// at least two labels, and not an IP literal or an internal name.
func checkACMEName(_ *loader, raw string) string {
	if len(raw) > 253 {
		return "the name must have at most 253 bytes"
	}
	if _, err := netip.ParseAddr(raw); err == nil {
		return "the name must not be an IP literal"
	}
	labels := strings.Split(raw, ".")
	if len(labels) < 2 {
		return "the name must have at least two labels"
	}
	for _, label := range labels {
		switch {
		case label == "":
			return "the name must not have an empty label or a dot at the end"
		case len(label) > 63:
			return "each label must have at most 63 bytes"
		case !acmeLabel.MatchString(label):
			return "each label must have only a-z 0-9 - and must not start or end with -"
		}
	}
	for _, internal := range []string{"localhost", "local", "internal", "home.arpa"} {
		if strings.HasSuffix(raw, "."+internal) {
			return "the name must not be below localhost, local, internal or home.arpa"
		}
	}
	return ""
}

// acmeLabel matches one label of an acme.names entry.
var acmeLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

// inDirText reports whether the clean path p is the clean path d or is below it.
// It compares text only. The function under compares resolved paths.
func inDirText(p, d string) bool {
	return p == d || strings.HasPrefix(p, strings.TrimSuffix(d, string(filepath.Separator))+string(filepath.Separator))
}

// storeConflict returns a detail if the store.path value p is in a directory that the sensor
// uses for other files, or is one of its state files (SEC-20). It compares the path text only.
// It folds the letters A-Z to a-z with foldASCII.
// A key that is not in vals failed its own check, so it is skipped.
func storeConflict(l *loader, vals map[string]Value, p string) string {
	p = foldASCII(p)
	if n := keyClash(p, vals, false, "tlog.dir", "acme.cache_dir", "bundle.path"); n != "" {
		return "the path must not be in " + n
	}
	if n := dirClash(p, l.stateRoot, false); n != "" {
		return "the path must not be in " + n
	}
	if f := fileClash(p, l.stateRoot, false); f != "" {
		return "the path must not be " + f
	}
	return ""
}

// checkHtpasswd applies the file rules (04 section 3). The detail is fixed text. The
// loader shows the path in the Value field. The check opens the resolved file one time,
// then reads the type, owner, and mode from the open file, as ReadFile does.
func checkHtpasswd(l *loader, raw string) string {
	if d := checkPathForm(raw); d != "" {
		return d
	}
	r, err := filepath.EvalSymlinks(raw)
	if err != nil {
		return "the htpasswd file cannot be resolved"
	}
	f, err := os.OpenFile(r, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return "the htpasswd file cannot be opened"
	}
	defer f.Close()
	fi, err := f.Stat()
	switch {
	case err != nil:
		return "the htpasswd file cannot be read"
	case !fi.Mode().IsRegular():
		return "the htpasswd file is not a regular file"
	}
	if uid, ok := fileOwner(fi); !ok || (uid != 0 && int(uid) != l.euid) {
		return "the owner of the htpasswd file is not root or the sensor user"
	}
	switch perm := fi.Mode().Perm(); {
	case perm&0o020 != 0:
		return "the htpasswd file is writable by group"
	case perm&0o002 != 0:
		return "the htpasswd file is writable by other"
	case perm&0o004 != 0:
		return "the htpasswd file is readable by other"
	}
	return ""
}
