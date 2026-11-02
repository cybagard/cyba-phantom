package bundle

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"html/template"
	"slices"
	"strings"
)

// The caps and names of a route map (SEC-32).
const (
	routeMapName   = "routes.json"
	maxRouteMapLen = 64 << 10
	maxRoutes      = 256
	maxPathBytes   = 256
	maxHeaderSlots = 4
	maxHostBytes   = 253
	maxLabelBytes  = 63
)

// routeTypes are the content types that a route can have. The match is exact.
var routeTypes = []string{
	"text/html; charset=utf-8", "text/plain; charset=utf-8",
	"text/css; charset=utf-8", "application/json", "image/png",
	"image/svg+xml", "image/x-icon",
}

// Route is one route of a vhost. One of Template and Asset is empty. Both are
// full archive names.
type Route struct {
	Path, Template, Asset, Type string
	Headers                     []HeaderSlot
}

// HeaderSlot is a header slot of a route.
type HeaderSlot struct{ Name, Trap string }

// RouteMap is the route map of one vhost. NotFound is empty when absent.
type RouteMap struct {
	Routes   []Route
	NotFound string
}

// maybe is a JSON member that is missing, or set to a value that is not null.
type maybe[T any] struct {
	v   T
	set bool
}

func (m *maybe[T]) UnmarshalJSONFrom(d *jsontext.Decoder) error {
	if d.PeekKind() == 'n' {
		return errors.New("null")
	}
	m.set = true
	return json.UnmarshalDecode(d, &m.v)
}

type rawRouteMap struct {
	Routes   maybe[[]rawRoute] `json:"routes"`
	NotFound maybe[string]     `json:"not_found"`
}

type rawRoute struct {
	Path     maybe[string]    `json:"path"`
	Template maybe[string]    `json:"template"`
	Asset    maybe[string]    `json:"asset"`
	Type     maybe[string]    `json:"type"`
	Headers  maybe[[]rawSlot] `json:"headers"`
}

type rawSlot struct {
	Name maybe[string] `json:"name"`
	Trap maybe[string] `json:"trap"`
}

// parseRoutes parses the route map of each vhost of the archive. A file must
// not be directly below vhosts/. Each vhost needs a valid name and a route map.
// The error holds no byte of the archive.
func parseRoutes(a *Archive, set map[string]*template.Template) (map[string]RouteMap, error) {
	out := map[string]RouteMap{}
	for _, name := range a.Names() {
		if rest, ok := strings.CutPrefix(name, templateDir); ok {
			host, _, below := strings.Cut(rest, "/")
			if !below || !validHost(host) {
				return nil, ErrContentInvalid
			}
			out[host] = RouteMap{}
		}
	}
	for host := range out {
		b, _ := a.File(templateDir + host + "/" + routeMapName)
		rm, ok := parseRouteMap(a, set, host, b)
		if !ok {
			return nil, ErrContentInvalid
		}
		out[host] = rm
	}
	return out, nil
}

// parseRouteMap checks the route map b of the vhost host. A missing file is an
// empty b, which is not an object.
func parseRouteMap(a *Archive, set map[string]*template.Template, host string, b []byte) (RouteMap, bool) {
	var raw rawRouteMap
	if len(b) > maxRouteMapLen || json.Unmarshal(b, &raw, parseOpts...) != nil {
		return RouteMap{}, false
	}
	prefix := templateDir + host + "/"
	// isTemplate and isAsset check the name of the same vhost.
	isTemplate := func(n string) bool {
		_, ok := set[n]
		return ok && strings.HasPrefix(n, prefix) && strings.HasSuffix(n, templateSuffix)
	}
	isAsset := func(n string) bool {
		_, ok := a.File(n)
		return ok && strings.HasPrefix(n, prefix) && !strings.HasSuffix(n, templateSuffix)
	}
	rs := raw.Routes.v
	if !raw.Routes.set || len(rs) < 1 || len(rs) > maxRoutes || raw.NotFound.set && !isTemplate(raw.NotFound.v) {
		return RouteMap{}, false
	}
	rm := RouteMap{NotFound: raw.NotFound.v}
	seen := map[string]bool{}
	for _, r := range rs {
		if !r.Path.set || seen[r.Path.v] || !validPath(r.Path.v) ||
			r.Template.set == r.Asset.set || !r.Type.set || !slices.Contains(routeTypes, r.Type.v) ||
			r.Template.set && !isTemplate(r.Template.v) || r.Asset.set && !isAsset(r.Asset.v) ||
			r.Headers.set && (len(r.Headers.v) < 1 || len(r.Headers.v) > maxHeaderSlots) {
			return RouteMap{}, false
		}
		seen[r.Path.v] = true
		route := Route{Path: r.Path.v, Template: r.Template.v, Asset: r.Asset.v, Type: r.Type.v}
		for _, s := range r.Headers.v {
			if !s.Name.set || !s.Trap.set {
				return RouteMap{}, false
			}
			route.Headers = append(route.Headers, HeaderSlot{s.Name.v, s.Trap.v})
		}
		rm.Routes = append(rm.Routes, route)
	}
	return rm, true
}

// validPath reports whether p is a route path: 1 to 256 bytes of / A-Z a-z 0-9
// . _ -, with a first byte "/". The path "/" is the root. In another path, no
// segment is empty, "." or "..".
func validPath(p string) bool {
	if len(p) < 1 || len(p) > maxPathBytes || p[0] != '/' ||
		strings.ContainsFunc(p, func(c rune) bool { return !strings.ContainsRune("/._-", c) && !alnum(c) }) {
		return false
	}
	if p == "/" {
		return true
	}
	return !slices.ContainsFunc(strings.Split(p[1:], "/"), func(s string) bool { return s == "" || s == "." || s == ".." })
}

func alnum(c rune) bool { return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' }

// validHost reports whether h has the form of a decoy name in lower case. It
// has at most 253 bytes and at least two labels. A label has 1 to 63 bytes of
// a-z 0-9 -, and does not start or end with "-". The last label is not all
// digits.
func validHost(h string) bool {
	labels := strings.Split(h, ".")
	if len(h) > maxHostBytes || len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if l == "" || len(l) > maxLabelBytes || l[0] == '-' || l[len(l)-1] == '-' ||
			strings.ContainsFunc(l, func(c rune) bool { return c != '-' && (c < '0' || c > '9') && (c < 'a' || c > 'z') }) {
			return false
		}
	}
	return strings.Trim(labels[len(labels)-1], "0123456789") != ""
}
