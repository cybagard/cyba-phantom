package config

import (
	"errors"
	"io/fs"
	"math"
	"net"
	"net/mail"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// defaultStateRoot is the directory that state paths must stay under.
const defaultStateRoot = "/var/lib/agent-canary"

// loader holds the settings that the validators use. A test sets them to use a temporary directory.
type loader struct {
	stateRoot string // stateRoot is the directory that state paths must stay under after symlink resolution.
	euid      int    // euid is the user that runs the sensor.
}

func newLoader() *loader { return &loader{stateRoot: defaultStateRoot, euid: os.Geteuid()} }

// hostname matches host name labels that a dot separates. A label is not empty.
var hostname = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*$`)

// lastLabel returns the text after the last dot of host. It ignores one dot at the end.
func lastLabel(host string) string {
	host = strings.TrimSuffix(host, ".")
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
	if host == "" {
		return hp, ""
	}
	if a, err := netip.ParseAddr(host); err == nil {
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
	return strings.EqualFold(h.host, o.host)
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
	case ops.overlaps(l):
		return "the address overlaps the " + name + " address"
	case l.named() && l.port == ops.port:
		return "the port is the same as the port of " + name + ", and that host is a name"
	}
	return ""
}

// crossCheck checks the rules that compare two keys. It skips a key that is not in vals.
// The loader removes a key from vals if its value failed to parse or failed its check.
func crossCheck(vals map[string]Value) []error {
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
	// A bound that depends on a second key. A key that failed is not in vals, so the loader skips it.
	if b, ok := vals["limits.per_ip_burst"]; ok {
		if r, ok := vals["limits.per_ip_rps"]; ok && b.Int < r.Int {
			fail("limits.per_ip_burst", b, "the value must not be less than limits.per_ip_rps")
		}
	}
	if e, ok := vals["store.retention_days.events"]; ok {
		if r, ok := vals["store.retention_days.raw"]; ok && e.Int < r.Int {
			fail("store.retention_days.events", e, "the value must not be less than store.retention_days.raw")
		}
	}
	if u, ok := vals["bundle.fetch_url"]; ok && u.Str != "" {
		if i, ok := vals["bundle.fetch_interval"]; ok && (i.Dur < 15*time.Minute || i.Dur > 7*24*time.Hour) {
			fail("bundle.fetch_interval", i, "the duration must be in the range 15m to 168h if bundle.fetch_url is set")
		}
	}
	return errs
}

// intRange returns a check that the integer value is in the range min to max.
func intRange(min, max int64) func(*loader, string) string {
	return func(_ *loader, raw string) string {
		if n, _ := strconv.ParseInt(raw, 10, 64); n < min || n > max {
			if max == math.MaxInt64 {
				return "the value must be at least " + strconv.FormatInt(min, 10)
			}
			return "the value must be in the range " + strconv.FormatInt(min, 10) + " to " + strconv.FormatInt(max, 10)
		}
		return ""
	}
}

// durRange returns a check that the duration value is in the range min to max.
func durRange(min, max time.Duration) func(*loader, string) string {
	return func(_ *loader, raw string) string {
		if d, _ := time.ParseDuration(raw); d < min || d > max {
			return "the duration must be in the range " + min.String() + " to " + max.String()
		}
		return ""
	}
}

// originChars matches 1 to 128 bytes of letters, digits, and . _ / -
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

func checkEmail(_ *loader, raw string) string {
	if strings.ContainsAny(raw, "\r\n") {
		return "the address must not contain CR or LF"
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
	case !contains(schemes, u.Scheme):
		return nil, "the URL scheme is not allowed"
	case u.Opaque != "":
		return nil, "the URL must not be opaque"
	case u.User != nil:
		return nil, "the URL must not have user information"
	case u.Fragment != "" || strings.Contains(raw, "#"):
		return nil, "the URL must not have a fragment"
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
		a0 := a.Unmap()
		switch {
		case a.Zone() != "":
			return nil, "the URL host must not have a zone"
		case a0.IsLinkLocalUnicast():
			return nil, "the URL host must not be link-local"
		case a0.IsUnspecified():
			return nil, "the URL host must not be unspecified"
		}
	} else if numericLabel(host) {
		return nil, "the URL host is a number but not an IP address in dotted form"
	}
	return u, ""
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// Names of the ACME directories that the loader knows.
var caDirectories = map[string]string{
	"letsencrypt":         "https://acme-v02.api.letsencrypt.org/directory",
	"letsencrypt-staging": "https://acme-staging-v02.api.letsencrypt.org/directory",
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

// AllowList returns the outbound endpoints that the config allows. In this version
// the list holds the acme.ca endpoint, and the bundle.fetch_url endpoint if it is set.
func (c *Config) AllowList() []Endpoint {
	var list []Endpoint
	for _, p := range []string{"acme.ca", "bundle.fetch_url"} {
		raw := c.values[p].Str
		if dir, ok := caDirectories[raw]; ok && p == "acme.ca" {
			raw = dir
		}
		u, d := parseURL(raw, "https")
		if d != "" {
			continue
		}
		port := u.Port()
		if port == "" {
			port = "443"
		}
		list = append(list, Endpoint{Scheme: u.Scheme, Host: strings.ToLower(u.Hostname()), Port: port})
	}
	return list
}

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
