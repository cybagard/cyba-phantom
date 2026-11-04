package bundle

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"html/template"
	"slices"
	"strings"
)

// The name and the caps of a route map, and the caps of a vhost name (SEC-32).
const (
	routeMapName     = "routes.json"
	maxRouteMapBytes = 64 << 10
	maxRoutes        = 256
	maxPathBytes     = 256
	maxHeaderSlots   = 4
	maxHostBytes     = 253
	maxLabelBytes    = 63
)

// routeTypes are the content types that a route can have. The match is exact.
var routeTypes = []string{
	"text/html; charset=utf-8", "text/plain; charset=utf-8",
	"text/css; charset=utf-8", "application/json", "image/png",
	"image/svg+xml", "image/x-icon",
}

// Route is one route of a vhost. A route with no Callback has one of Template
// and Asset, and the other is empty. The one that is set is a full archive
// name. A route with a Callback has no Template and no Headers. It has an Asset
// and a Type, or no Asset and no Type (a route that answers with no body).
type Route struct {
	Path, Template, Asset, Type string
	Headers                     []HeaderSlot
	Callback                    *Callback
}

// Callback holds the positions of a callback route where a visitor can send
// a callback. A position that is not used is false or empty. At least one is
// used. Query and Body are parameter names. Header is a header name.
type Callback struct {
	Segment             bool
	Query, Header, Body string
}

// HeaderSlot is a header slot of a route.
type HeaderSlot struct{ Name, Trap string }

// RouteMap is the route map of one vhost. NotFound is empty when absent. Beacon
// is nil when absent.
type RouteMap struct {
	Routes   []Route
	NotFound string
	Beacon   *Beacon
}

// Beacon holds the two paths of the script beacon of a vhost. The paths differ.
// No path is the path of a route. No path is below the path of a route that has
// a Callback with Segment.
type Beacon struct{ Script, Post string }

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
	Beacon   maybe[rawBeacon]  `json:"beacon"`
}

type rawBeacon struct {
	Script maybe[string] `json:"script"`
	Post   maybe[string] `json:"post"`
}

type rawRoute struct {
	Path     maybe[string]      `json:"path"`
	Template maybe[string]      `json:"template"`
	Asset    maybe[string]      `json:"asset"`
	Type     maybe[string]      `json:"type"`
	Headers  maybe[[]rawSlot]   `json:"headers"`
	Callback maybe[rawCallback] `json:"callback"`
}

type rawCallback struct {
	Segment maybe[bool]   `json:"segment"`
	Query   maybe[string] `json:"query"`
	Header  maybe[string] `json:"header"`
	Body    maybe[string] `json:"body"`
}

type rawSlot struct {
	Name maybe[string] `json:"name"`
	Trap maybe[string] `json:"trap"`
}

// parseRoutes parses the route map of each vhost of the archive. A host name
// that is the second name part of a file below vhosts/ is a vhost. A file must
// not be directly below vhosts/. Each vhost needs a valid name and a
// routes.json file. A header slot needs a valid name and the id of a trap. Two
// slots of one route do not have the same name, with ASCII case ignored. The
// error holds no byte of the archive.
func parseRoutes(a *Archive, set map[string]*template.Template, traps []Trap) (map[string]RouteMap, error) {
	ids := map[string]bool{}
	for _, t := range traps {
		ids[t.ID] = true
	}
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
		rm, ok := parseRouteMap(a, set, ids, host, b)
		if !ok {
			return nil, ErrContentInvalid
		}
		out[host] = rm
	}
	return out, nil
}

// parseRouteMap checks the route map b of the vhost host. A missing file is an
// empty b, which is not an object.
func parseRouteMap(a *Archive, set map[string]*template.Template, ids map[string]bool, host string, b []byte) (RouteMap, bool) {
	var raw rawRouteMap
	if len(b) > maxRouteMapBytes || json.Unmarshal(b, &raw, parseOpts...) != nil {
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
	var segments []string // paths of the routes with a segment position
	for _, r := range rs {
		var ok bool
		if r.Callback.set {
			ok = !r.Template.set && !r.Headers.set && r.Asset.set == r.Type.set &&
				(!r.Asset.set || isAsset(r.Asset.v) && slices.Contains(routeTypes, r.Type.v))
		} else {
			ok = r.Template.set != r.Asset.set && r.Type.set && slices.Contains(routeTypes, r.Type.v) &&
				(!r.Template.set || isTemplate(r.Template.v)) && (!r.Asset.set || isAsset(r.Asset.v))
		}
		if !r.Path.set || seen[r.Path.v] || !validPath(r.Path.v) || !ok ||
			r.Headers.set && (len(r.Headers.v) < 1 || len(r.Headers.v) > maxHeaderSlots) {
			return RouteMap{}, false
		}
		seen[r.Path.v] = true
		route := Route{Path: r.Path.v, Template: r.Template.v, Asset: r.Asset.v, Type: r.Type.v}
		if r.Callback.set {
			cb, ok := callbackOf(r.Callback.v)
			if !ok {
				return RouteMap{}, false
			}
			route.Callback = &cb
			if cb.Segment {
				segments = append(segments, route.Path)
			}
		}
		for _, s := range r.Headers.v {
			if !s.Name.set || !s.Trap.set || !validHeaderName(s.Name.v) || !ids[s.Trap.v] {
				return RouteMap{}, false
			}
			// Slot names of one route must differ by more than ASCII case.
			if slices.ContainsFunc(route.Headers, func(h HeaderSlot) bool { return strings.EqualFold(h.Name, s.Name.v) }) {
				return RouteMap{}, false
			}
			route.Headers = append(route.Headers, HeaderSlot{s.Name.v, s.Trap.v})
		}
		rm.Routes = append(rm.Routes, route)
	}
	// This check needs all routes, so the member order does not matter.
	if raw.Beacon.set {
		b := raw.Beacon.v
		if !b.Script.set || !b.Post.set || b.Script.v == b.Post.v {
			return RouteMap{}, false
		}
		for _, p := range []string{b.Script.v, b.Post.v} {
			if !validPath(p) || seen[p] || slices.ContainsFunc(segments, func(s string) bool { return isBelow(p, s) }) {
				return RouteMap{}, false
			}
		}
		rm.Beacon = &Beacon{Script: b.Script.v, Post: b.Post.v}
	}
	return rm, true
}

// callbackOf checks the positions of a callback. It needs 1 to 4 positions.
// When Segment is set, it is true. Query and Body are 1 to 32 bytes of
// A-Z a-z 0-9 _ -. Header is a valid header slot name.
func callbackOf(r rawCallback) (Callback, bool) {
	cb := Callback{Segment: r.Segment.v, Query: r.Query.v, Header: r.Header.v, Body: r.Body.v}
	n := 0
	for _, set := range []bool{r.Segment.set, r.Query.set, r.Header.set, r.Body.set} {
		if set {
			n++
		}
	}
	ok := n >= 1 && (!r.Segment.set || r.Segment.v) &&
		(!r.Query.set || validParam(r.Query.v)) && (!r.Body.set || validParam(r.Body.v)) &&
		(!r.Header.set || validHeaderName(r.Header.v))
	return cb, ok
}

// validParam reports whether s is 1 to 32 bytes of A-Z a-z 0-9 _ -.
func validParam(s string) bool {
	return len(s) >= 1 && len(s) <= maxHeaderNameLen &&
		!strings.ContainsFunc(s, func(c rune) bool { return c != '_' && c != '-' && !alnum(c) })
}

// isBelow reports whether the path p is below the path root, that is, whether
// p starts with root and "/". Below "/" is each path other than "/".
func isBelow(p, root string) bool {
	if root == "/" {
		return p != "/"
	}
	return strings.HasPrefix(p, root+"/")
}

// validPath reports whether p is a route path. It has 1 to 256 bytes. The
// first byte is "/". Each other byte is a letter A-Z or a-z, a digit, or one
// of `/ . _ -`. The path "/" alone is the root. In another path, no segment is
// empty, "." or "..".
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
