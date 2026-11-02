package bundle

import (
	"fmt"
	"html/template"
	"maps"
	"reflect"
	"slices"
	"strings"
	"testing"
)

const (
	hostDir  = "vhosts/h.example/"
	otherDir = "vhosts/h.examplex/"
	pa       = `"path":"/a"`
	ty       = `"type":"text/html; charset=utf-8"`
	ti       = `"template":"` + hostDir + `index.tmpl"`
	png      = `"asset":"` + hostDir + `a.png"`
	slotJSON = `{"name":"X-A","trap":"t"}`
)

// rt gives a route map with these routes, in JSON.
func rt(routes ...string) string { return `{"routes":[` + strings.Join(routes, ",") + `]}` }

// doc gives a route map with one route that has exactly these members.
func doc(members ...string) string { return rt("{" + strings.Join(members, ",") + "}") }

// routeJSON gives a valid route map with one route to the file name.
func routeJSON(name string) string {
	kind := "asset"
	if strings.HasSuffix(name, templateSuffix) {
		kind = "template"
	}
	return doc(`"path":"/"`, fmt.Sprintf("%q:%q", kind, name), ty)
}

// withRoutes adds a valid route map for each vhost of the files. The route
// goes to the first file of the vhost.
func withRoutes(ents []ent) []ent {
	first := map[string]string{}
	for _, e := range ents {
		if rest, ok := strings.CutPrefix(e.name, templateDir); ok {
			if h, _, below := strings.Cut(rest, "/"); below && first[h] == "" {
				first[h] = e.name
			}
		}
	}
	out := slices.Clone(ents)
	for _, h := range slices.Sorted(maps.Keys(first)) {
		out = append(out, tf(templateDir+h+"/"+routeMapName, routeJSON(first[h])))
	}
	return out
}

// site is the files of the tests. It has two vhosts, and the name of one is a
// prefix of the name of the other. It has a template outside vhosts/.
func site(routes string) []ent {
	return []ent{
		tf(hostDir+"index.tmpl", "i"), tf(hostDir+"a.png", "p"), tf(hostDir+"sub/b.png", "q"),
		tf(hostDir+"UP.TMPL", "u"), tf(hostDir+routeMapName, routes),
		tf(otherDir+"o.tmpl", "o"), tf(otherDir+"o.png", "o"), tf(otherDir+routeMapName, routeJSON(otherDir+"o.tmpl")),
		tf("traps/t.tmpl", "t"),
	}
}

// refuse loads each route map of hosts h.example and expects content_invalid.
func refuse(t *testing.T, texts ...string) {
	t.Helper()
	for i, text := range texts {
		t.Run(fmt.Sprintf("%d %.40s", i, text), func(t *testing.T) { loadRaw(t, ErrContentInvalid, nil, site(text)...) })
	}
}

func spaced(s string, n int) string { return s + strings.Repeat(" ", n-len(s)) }

// manyRoutes gives n routes with different paths.
func manyRoutes(n int) string {
	var rs []string
	for i := range n {
		rs = append(rs, fmt.Sprintf(`{"path":"/p%d",%s,%s}`, i, ti, ty))
	}
	return rt(rs...)
}

// T-U-08: each refused form of a route map gives content_invalid. The running
// bundle and the files do not change.
func TestTU08RouteMapRefused(t *testing.T) {
	route := "{" + pa + "," + ti + "," + ty + "}"
	ok := rt(route)
	more := func(m string) string { return `{"routes":[` + route + `]` + m + `}` }
	refuse(t, "", "[]", `"x"`, "null", `{"routes":`, doc(`"path":"/`+"\xff"+`"`, ti, ty), spaced(ok, 65537),
		more(`,"routes":[`+route+`]`), more(`,"x":1`), `{"Routes":[`+route+`]}`, doc(`"Path":"/a"`, ti, ty),
		ok+"x", ok+ok, `{}`, `{"routes":[]}`, manyRoutes(257), more(`,"not_found":null`))
	refuse(t, `{"routes":null}`, doc(pa, ti, ty, `"headers":null`), doc(pa, `"template":null`, png, ty),
		doc(pa, ti, ty, `"headers":[{"name":null,"trap":"t"}]`))
	for _, p := range []string{"", "a", "/a b", "/a%41", "/a?x", "//x", "/a/", "/a//b", "/./a", "/a/..", "/" + strings.Repeat("a", 256)} {
		refuse(t, doc(`"path":"`+p+`"`, ti, ty))
	}
	refuse(t, rt(route, route))
	for _, target := range []string{
		ti + "," + png, `"template":"` + hostDir + `a.png"`, `"template":"` + otherDir + `o.tmpl"`,
		`"template":"` + hostDir + `none.tmpl"`, `"template":"traps/t.tmpl"`, `"asset":"` + hostDir + `index.tmpl"`,
		`"asset":"` + otherDir + `o.png"`, `"asset":"` + hostDir + `none.png"`,
	} {
		refuse(t, doc(pa, target, ty))
	}
	refuse(t, doc(pa, ty), doc(pa, ti), doc(pa, ti, `"type":"text/xml"`), doc(pa, ti, `"type":"Application/JSON"`), doc(ti, ty))
	for _, slots := range []string{"", strings.Repeat(slotJSON+",", 4) + slotJSON, `{"name":"X-A","trap":"t","x":1}`,
		`{"trap":"t"}`, `{"name":"X-A"}`, `{"name":1,"trap":"t"}`} {
		refuse(t, doc(pa, ti, ty, `"headers":[`+slots+`]`))
	}
	for _, nf := range []string{hostDir + "a.png", otherDir + "o.tmpl", hostDir + "none.tmpl"} {
		refuse(t, more(`,"not_found":"`+nf+`"`))
	}
}

// T-U-08: the structure of the archive gives content_invalid.
func TestTU08RouteVhostRefused(t *testing.T) {
	good := func(host string) []ent {
		return withRoutes([]ent{tf(templateDir+host+"/index.tmpl", "i")})
	}
	for name, ents := range map[string][]ent{
		"no route map":     {tf(hostDir+"index.tmpl", "i")},
		"one of two":       append(good("g.example"), tf(hostDir+"a.png", "p")),
		"file in vhosts":   append(good("h.example"), tf(templateDir+"x.png", "p")),
		"routes in subdir": {tf(hostDir+"index.tmpl", "i"), tf(hostDir+"sub/"+routeMapName, routeJSON(hostDir+"index.tmpl"))},
		"upper case":       good("H.example"), "one label": good("localhost"), "empty label": good("h..example"),
		"trailing dot": good("h.example."), "label starts -": good("-h.example"), "label ends -": good("h-.example"),
		"all digit last": good("h.123"), "underscore": good("h_x.example"),
	} {
		t.Run(name, func(t *testing.T) { loadRaw(t, ErrContentInvalid, nil, ents...) })
	}
}

// T-U-08: the limits of the host name, the label and the path.
func TestTU08RouteForms(t *testing.T) {
	l61, l63, l64 := strings.Repeat("a", 61), strings.Repeat("a", 63), strings.Repeat("a", 64)
	for host, want := range map[string]bool{
		"h.example": true, "a.b": true, "h-1.example": true, "h.x1": true, "h.1x": true, "1.x": true, "h.12a": true,
		l63 + "." + l63 + "." + l63 + "." + l61: true, l63 + "." + l63 + "." + l63 + "." + l61 + "a": false,
		l63 + ".x": true, l64 + ".x": false, "h.example.": false, "h": false, "": false, "h.1": false,
	} {
		if got := validHost(host); got != want {
			t.Errorf("validHost(%.20q) = %v", host, got)
		}
	}
	for path, want := range map[string]bool{
		"/": true, "/a": true, "/.well-known/x": true, "/a.b_c-D/9": true, "/..a": true, "/a..": true,
		"/" + strings.Repeat("a", 255): true, "/" + strings.Repeat("a", 256): false,
		"": false, "a": false, "//": false, "/a/": false, "/.": false, "/..": false, "/a b": false,
		"/%": false, "/\x00": false, "/é": false,
	} {
		if got := validPath(path); got != want {
			t.Errorf("validPath(%.20q) = %v", path, got)
		}
	}
}

// T-U-08: the size and count limits hold exactly.
func TestTU08RouteLimits(t *testing.T) {
	slots := func(n int) string {
		return doc(pa, ti, ty, `"headers":[`+strings.TrimSuffix(strings.Repeat(slotJSON+",", n), ",")+`]`)
	}
	for _, text := range []string{spaced(doc(pa, ti, ty), 65536), manyRoutes(256), slots(1), slots(4),
		doc(`"path":"/`+strings.Repeat("a", 255)+`"`, ti, ty), doc(`"path":"/"`, ti, ty)} {
		loadRaw(t, nil, nil, site(text)...)
	}
}

// T-U-08: a route goes to a template of the parsed set only. With no template
// step, the set is empty.
func TestTU08RouteParsedSet(t *testing.T) {
	none := func(e *env) { e.l.template = nil }
	empty := func(e *env) {
		e.l.template = func(*Archive) (map[string]*template.Template, error) { return nil, nil }
	}
	nf := `{"routes":[{` + pa + `,` + png + `,` + ty + `}],"not_found":"` + hostDir + `index.tmpl"}`
	for _, setup := range []func(*env){none, empty} {
		// The first five files are those of the vhost h.example.
		loadRaw(t, ErrContentInvalid, setup, site(doc(pa, ti, ty))[:5]...)
		loadRaw(t, ErrContentInvalid, setup, site(nf)[:5]...)
		loadRaw(t, nil, setup, site(doc(pa, png, ty))[:5]...)
	}
}

// T-U-08: a valid map gives the typed result. A caller cannot change the kept
// map through the result.
func TestTU08RouteMapAccepted(t *testing.T) {
	var rs []string
	want := RouteMap{NotFound: hostDir + "index.tmpl"}
	for i, typ := range []string{"text/html; charset=utf-8", "text/plain; charset=utf-8", "text/css; charset=utf-8",
		"application/json", "image/png", "image/svg+xml", "image/x-icon"} {
		r := Route{Path: fmt.Sprintf("/t%d", i), Type: typ, Asset: hostDir + "sub/b.png"}
		kind, name := "asset", r.Asset
		if i == 0 {
			kind, name, r.Asset, r.Template = "template", hostDir+"index.tmpl", "", hostDir+"index.tmpl"
		}
		rs = append(rs, fmt.Sprintf(`{"path":%q,"type":%q,%q:%q}`, r.Path, typ, kind, name))
		want.Routes = append(want.Routes, r)
	}
	four := []HeaderSlot{{"X-A", "t1"}, {"X-B", "t2"}, {"X-C", "t3"}, {"X-D", "t4"}}
	rs = append(rs, `{"path":"/","asset":"`+hostDir+`UP.TMPL","type":"image/png","headers":[{"name":"X-A","trap":"t1"}]}`,
		`{"path":"/.well-known/x","asset":"`+hostDir+`a.png","type":"image/png","headers":[`+
			`{"name":"X-A","trap":"t1"},{"name":"X-B","trap":"t2"},{"name":"X-C","trap":"t3"},{"name":"X-D","trap":"t4"}]}`)
	want.Routes = append(want.Routes,
		Route{Path: "/", Asset: hostDir + "UP.TMPL", Type: "image/png", Headers: four[:1]},
		Route{Path: "/.well-known/x", Asset: hostDir + "a.png", Type: "image/png", Headers: four})
	text := `{"routes":[` + strings.Join(rs, ",") + `],"not_found":"` + hostDir + "index.tmpl\"}\n \t"
	b := loadRaw(t, nil, nil, site(text)...)
	if got := b.Vhosts(); !slices.Equal(got, []string{"h.example", "h.examplex"}) {
		t.Errorf("vhosts %v", got)
	}
	if got, ok := b.Routes("h.example"); !ok || !reflect.DeepEqual(got, want) {
		t.Errorf("routes %+v, %v; want %+v", got, ok, want)
	}
	if o, ok := b.Routes("h.examplex"); !ok || len(o.Routes) != 1 || o.NotFound != "" || o.Routes[0].Headers != nil {
		t.Errorf("other vhost %+v, %v", o, ok)
	}
	if _, ok := b.Routes("none.example"); ok {
		t.Error("routes of a vhost that does not exist")
	}
	got, _ := b.Routes("h.example")
	got.Routes[0].Path, got.Routes[len(got.Routes)-1].Headers[0].Name = "/changed", "changed"
	got.Routes, got.NotFound = nil, "changed"
	b.Vhosts()[0] = "changed"
	if again, _ := b.Routes("h.example"); !reflect.DeepEqual(again, want) || b.Vhosts()[0] != "h.example" {
		t.Errorf("the kept map changed: %+v", again)
	}
	if nb := loadWith(t, nil, tf("traps/x.json", "{}")); len(nb.Vhosts()) != 0 {
		t.Errorf("a bundle with no vhost has vhosts %v", nb.Vhosts())
	}
}

// T-U-08: the new code and its error.
func TestTU08ContentInvalidCode(t *testing.T) {
	if c, ok := CodeOf(ErrContentInvalid); !ok || c != CodeContentInvalid || c.String() != "content_invalid" || ErrContentInvalid.Error() != "bundle: content_invalid" {
		t.Errorf("code %v, %v, text %q", c, ok, ErrContentInvalid)
	}
	for _, other := range []error{ErrArchiveInvalid, ErrBadSig, ErrManifestInvalid, ErrMinEngine, ErrExpired,
		ErrRollback, ErrTemplateParse, ErrSeedInvalid} {
		if c, _ := CodeOf(other); c == CodeContentInvalid {
			t.Errorf("%v has the code of ErrContentInvalid", other)
		}
	}
}
