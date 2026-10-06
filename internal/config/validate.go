package config

import (
	"errors"
	"io/fs"
	"net"
	"net/mail"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// defaultStateRoot is the directory that state paths must stay under.
const defaultStateRoot = "/var/lib/agent-canary"

// loader holds the settings that the validators use. A test sets them to use a temporary directory.
type loader struct {
	stateRoot string // stateRoot is the directory that state paths must stay under after symlink resolution.
	euid      int    // euid is the user that runs the sensor.
}

func newLoader() *loader { return &loader{stateRoot: defaultStateRoot, euid: os.Geteuid()} }

// hostname matches a DNS name for a listen address.
var hostname = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$`)

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
	if !hostname.MatchString(host) {
		return hp, "the host is not an IP literal or a host name"
	}
	return hp, ""
}

// wildcard reports whether the address binds all interfaces.
func (h hostPort) wildcard() bool { return h.host == "" || h.addr.IsUnspecified() }

// overlaps reports whether a and b can bind the same address and port.
func (h hostPort) overlaps(o hostPort) bool {
	if h.port != o.port {
		return false
	}
	if h.wildcard() || o.wildcard() {
		return true
	}
	if h.addr.IsValid() && o.addr.IsValid() {
		return h.addr.Unmap() == o.addr.Unmap()
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

// crossCheck checks the rules that compare two keys. It skips a key that has no valid value.
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
		if okHTTP && ops.overlaps(httpA) {
			fail("ops.listen", v, "the address must not be or be inside the listen.http address")
		}
		if okHTTPS && ops.overlaps(httpsA) {
			fail("ops.listen", v, "the address must not be or be inside the listen.https address")
		}
	}
	return errs
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
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return nil, "the URL port is not in the range 1 to 65535"
		}
	}
	if a, err := netip.ParseAddr(u.Hostname()); err == nil {
		a0 := a.Unmap()
		switch {
		case a.Zone() != "":
			return nil, "the URL host must not have a zone"
		case a0.IsLinkLocalUnicast():
			return nil, "the URL host must not be link-local"
		case a0.IsUnspecified():
			return nil, "the URL host must not be unspecified"
		}
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
// the list holds the acme.ca endpoint.
func (c *Config) AllowList() []Endpoint {
	v, ok := c.values["acme.ca"]
	if !ok {
		return nil
	}
	raw := v.Str
	if dir, ok := caDirectories[raw]; ok {
		raw = dir
	}
	u, d := parseURL(raw, "https")
	if d != "" {
		return nil
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	return []Endpoint{{Scheme: u.Scheme, Host: u.Hostname(), Port: port}}
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

// checkHtpasswd applies the file rules (04 section 3). The detail names the file and the failed rule.
func checkHtpasswd(l *loader, raw string) string {
	if d := checkPathForm(raw); d != "" {
		return d
	}
	r, err := filepath.EvalSymlinks(raw)
	if err != nil {
		return "the htpasswd file cannot be resolved: " + raw
	}
	fi, err := os.Stat(r)
	switch {
	case err != nil:
		return "the htpasswd file cannot be read: " + raw
	case !fi.Mode().IsRegular():
		return "the htpasswd file is not a regular file: " + raw
	}
	if uid, ok := fileOwner(fi); !ok || (uid != 0 && int(uid) != l.euid) {
		return "the owner of the htpasswd file is not root or the sensor user: " + raw
	}
	switch perm := fi.Mode().Perm(); {
	case perm&0o020 != 0:
		return "the htpasswd file is writable by group: " + raw
	case perm&0o002 != 0:
		return "the htpasswd file is writable by other: " + raw
	case perm&0o004 != 0:
		return "the htpasswd file is readable by other: " + raw
	}
	return ""
}
