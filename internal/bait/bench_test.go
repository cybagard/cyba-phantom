package bait

import (
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"testing"
	"unsafe"

	"github.com/cybagard/cyba-phantom/internal/bundle"
)

const (
	// pageBytes and pageActions are the size and the trap actions of the
	// template route page. It has 16 KiB and 64 trap ids, one action for each.
	pageBytes   = 16 << 10
	pageActions = 64
	// actionAllocs is the most allocations for each action of a template page.
	// A page with 1 to 64 actions allocates 18 for each action and 20 more.
	// With the race detector, the pools lose items. A page then allocates up
	// to 19 for each action.
	actionAllocs = 19
)

// pageOf makes a page of pageBytes bytes with the trap actions t0 to t(n-1).
func pageOf(n int) string {
	var sb strings.Builder
	for i := range n {
		seg := fmt.Sprintf(`<p>{{index .Trap "t%d"}}</p>`, i)
		sb.WriteString(seg + strings.Repeat(" ", pageBytes/n-len(seg)))
	}
	return sb.String()
}

// trapSet gives the traps t0 to t63 of traps/traps.json, one for each action.
func trapSet() string {
	specs := make([]trapSpec, pageActions)
	for i := range specs {
		specs[i] = trapSpec{fmt.Sprint("t", i), "hidden-p", "x {{.Token}}"}
	}
	return trapsJSON(specs)
}

// serveHandler returns a handler for the hardening bundle with 64 traps. The
// route /t is the page of pageOf with the given actions. The 404 template of
// example.com shows a trap.
func serveHandler(tb testing.TB, actions int) *Handler {
	b := hardBundle(tb, `<h1>{{index .Trap "t0"}}</h1>`, map[string]string{
		"traps/traps.json":          trapSet(),
		"vhosts/example.com/t.tmpl": pageOf(actions),
	})
	return New(fixedSource{b}, &fallbackFn{}, testQueue(tb))
}

// serveKinds are the kinds of response of the handler, one for each way that
// serve ends. limit is the most allocations of serve with the race detector.
// Measured without it: 15 for an asset and 0 for the fixed pages. It is 38 for
// the 404 template and for a page of 1 action.
var serveKinds = []struct {
	name, method, target, host string
	limit                      float64
}{
	{"asset GET", http.MethodGet, "/style.css", "example.com", 16},
	{"asset HEAD", http.MethodHead, "/style.css", "example.com", 16},
	{"template page", http.MethodGet, "/t", "example.com", 41},
	{"vhost 404 template", http.MethodGet, "/nope", "example.com", 41},
	{"fixed 404", http.MethodGet, "/nope", "kilo.example", 0},
	{"unknown host", http.MethodGet, "/", "other.example", 0},
	{"405", http.MethodPost, "/", "example.com", 0},
}

func kindRequest(method, target, host string) *http.Request {
	r := get(target, host)
	r.Method = method
	return r
}

// BenchmarkBaitServe measures a request of each kind through ServeHTTP. This
// includes the request event.
func BenchmarkBaitServe(b *testing.B) {
	h := serveHandler(b, pageActions)
	for _, k := range serveKinds {
		b.Run(k.name, func(b *testing.B) {
			r, w := kindRequest(k.method, k.target, k.host), &discard{h: http.Header{}}
			b.ReportAllocs()
			for b.Loop() {
				clear(w.h)
				h.ServeHTTP(w, r)
				h.q.TryTake()
			}
		})
	}
}

// allocsOf is the allocations of serve for one request on h.
func allocsOf(h *Handler, method, target, host string) float64 {
	b := h.src.Current()
	r, w := kindRequest(method, target, host), &discard{h: http.Header{}}
	s := h.sessionOf(r)
	return testing.AllocsPerRun(100, func() {
		clear(w.h)
		h.serve(w, r, b, &s)
	})
}

// TestTS28ServeAllocs checks the allocations of each kind against its limit.
// The limit of the template page is for a page of 1 action. A page of
// pageActions actions allocates at most actionAllocs more for each action. It
// calls serve and not ServeHTTP, for the reason of TestTU20RenderAllocs.
func TestTS28ServeAllocs(t *testing.T) {
	h, one := serveHandler(t, pageActions), serveHandler(t, 1)
	for _, k := range serveKinds {
		hk := h
		if k.name == "template page" {
			hk = one
		}
		got := allocsOf(hk, k.method, k.target, k.host)
		t.Logf("%s: %v allocations, limit %v", k.name, got, k.limit)
		if got > k.limit {
			t.Errorf("%s: %v allocations, limit %v", k.name, got, k.limit)
		}
		if k.name != "template page" {
			continue
		}
		many, limit := allocsOf(h, k.method, k.target, k.host), got+actionAllocs*(pageActions-1)
		t.Logf("template page of %d actions: %v allocations, limit %v", pageActions, many, limit)
		if many > limit {
			t.Errorf("template page of %d actions: %v allocations, limit %v", pageActions, many, limit)
		}
	}
}

const (
	// routeCap is the most routes in all route maps of a bundle.
	routeCap = 12288
	// baseRoutes is the number of routes of the test archive.
	baseRoutes = 10
	// siteHeapLimit is the most heap, in bytes, that one site keeps (T-S-28).
	// The bundle is at the route cap. It has the largest legal route shapes.
	siteHeapLimit = 10 << 20
	// maxRouteMap is the most routes in one route map.
	maxRouteMap = 256
	// slotMapRoutes is the routes of one vhost with four header slots. A route
	// map holds 64 KiB. 192 such routes fill about 61 KiB of it.
	slotMapRoutes = 192
	// mostVhosts is the most vhosts that load when each has a template of 64
	// trap actions. A bundle holds 16384 actions at most in its templates and
	// trap texts. The 64 trap texts use 64. So (16384 - 64) / 64 vhosts is the
	// most. 256 vhosts do not load. The archive entries are 20 + 2 * 255. This
	// is below the 1024 of MaxEntries.
	mostVhosts = 255
)

// shapeSpec describes the vhosts of one bundle shape. The routes of the test
// archive and the routes of the spec hold routeCap routes in all.
type shapeSpec struct {
	// vhosts is the number of vhosts. They share the routes equally.
	vhosts int
	// file and body are a file that every route of a vhost can name. An empty
	// file adds no file.
	file, body string
	// route gives the JSON of route j of a vhost.
	route func(host string, j int) string
	// members gives the text that follows the routes in a route map, or nil.
	// It always has a not_found member.
	members func(host string) string
	// traps adds traps/traps.json with 64 traps.
	traps bool
}

// files makes the files of the vhosts of the shape.
func (sp shapeSpec) files() map[string]string {
	files := map[string]string{}
	if sp.traps {
		files["traps/traps.json"] = trapSet()
	}
	total := routeCap - baseRoutes
	for i := range sp.vhosts {
		host := fmt.Sprintf("v%d.example", i)
		n := total / sp.vhosts
		if i < total%sp.vhosts {
			n++
		}
		parts := make([]string, n)
		for j := range parts {
			parts[j] = sp.route(host, j)
		}
		tail := ""
		if sp.members != nil {
			tail = sp.members(host)
		}
		files["vhosts/"+host+"/routes.json"] = `{"routes":[` + strings.Join(parts, ",") + `]` + tail + `}`
		if sp.file != "" {
			files["vhosts/"+host+"/"+sp.file] = sp.body
		}
	}
	return files
}

// vhostsFor is the number of vhosts with at most per routes each.
func vhostsFor(per int) int { return (routeCap - baseRoutes + per - 1) / per }

// longName gives a name of n bytes that starts with prefix.
func longName(prefix string, n int) string {
	return prefix + strings.Repeat("a", n-len(prefix))
}

// actionsPage makes a short page with n trap actions, one for each trap t0 to
// t(n-1). A page with no action has a fixed text.
func actionsPage(n int) string {
	if n == 0 {
		return "<p>p</p>"
	}
	var sb strings.Builder
	for i := range n {
		fmt.Fprintf(&sb, `<p>{{index .Trap "t%d"}}</p>`, i)
	}
	return sb.String()
}

// templateSpec is a shape of template routes in vhosts. A route has actions
// trap actions and slots header slots with 34-byte names.
func templateSpec(actions, slots, vhosts int) shapeSpec {
	return shapeSpec{vhosts, "p.tmpl", actionsPage(actions), func(host string, j int) string {
		headers := ""
		if slots > 0 {
			var hs []string
			for k := range slots {
				hs = append(hs, fmt.Sprintf(`{"name":%q,"trap":"t%d"}`, longName(fmt.Sprintf("X-Probe-%d-", k), 34), k))
			}
			headers = `,"headers":[` + strings.Join(hs, ",") + `]`
		}
		return fmt.Sprintf(`{"path":"/%d","template":"vhosts/%s/p.tmpl","type":"text/html; charset=utf-8"%s}`, j, host, headers)
	}, nil, true}
}

// vhostsSpec is the shape of the most vhosts. Each route has 64 actions and
// four slots. Each vhost also has a not_found of the same template and a
// beacon.
func vhostsSpec() shapeSpec {
	sp := templateSpec(64, 4, mostVhosts)
	sp.members = func(host string) string {
		return `,"not_found":"vhosts/` + host + `/p.tmpl","beacon":{"script":"/b.js","post":"/b/p"}`
	}
	return sp
}

// callbackSpec is a shape of callback routes with all four positions and an
// asset. The query and body names have 32 bytes, the header name 34.
func callbackSpec() shapeSpec {
	cb := fmt.Sprintf(`{"segment":true,"query":%q,"header":%q,"body":%q}`,
		longName("q", 32), longName("X-Cb-", 34), longName("b", 32))
	return shapeSpec{vhostsFor(slotMapRoutes), "f", "f", func(host string, j int) string {
		return fmt.Sprintf(`{"path":"/%d","asset":"vhosts/%s/f","type":"image/png","callback":%s}`, j, host, cb)
	}, nil, false}
}

// retainedOf builds the site of bd and gives the bytes of heap that it keeps
// after a GC. The bundle stays alive to the end. It holds the archive bytes,
// and a freed bundle would hide the cost of the site.
func retainedOf(bd *bundle.Bundle) (uint64, *site) {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	s := buildSite(bd)
	runtime.GC()
	runtime.ReadMemStats(&after)
	runtime.KeepAlive(bd)
	runtime.KeepAlive(s)
	return after.HeapAlloc - before.HeapAlloc, s
}

// shape is a named route shape of a bundle at the route cap.
type shape struct {
	name string
	spec shapeSpec
}

// boundShapes are the largest legal route shapes at the route cap. T-S-28
// bounds the site table of each one.
func boundShapes() []shape {
	return []shape{
		{"64 actions", templateSpec(64, 0, vhostsFor(maxRouteMap))},
		{"4 slots", templateSpec(0, 4, vhostsFor(slotMapRoutes))},
		{"64 actions and 4 slots", templateSpec(64, 4, vhostsFor(slotMapRoutes))},
		{"most vhosts", vhostsSpec()},
		{"callbacks with 4 positions", callbackSpec()},
	}
}

// benchShapes are the shapes of the benchmark: the two old shapes and the
// shapes of boundShapes.
func benchShapes() []shape {
	return append([]shape{
		{"assets", shapeSpec{vhostsFor(maxRouteMap), "f", "f", func(host string, j int) string {
			return fmt.Sprintf(`{"path":"/%d","asset":"vhosts/%s/f","type":"image/png"}`, j, host)
		}, nil, false}},
		{"callbacks", shapeSpec{vhostsFor(maxRouteMap), "", "", func(_ string, j int) string {
			return fmt.Sprintf(`{"path":"/%d","callback":{"query":"t"}}`, j)
		}, nil, false}},
	}, boundShapes()...)
}

// BenchmarkSiteBuild measures the build of the site table of a bundle at the
// route cap. It does this for each shape of benchShapes. It also reports the
// bytes that one built site keeps in memory.
func BenchmarkSiteBuild(b *testing.B) {
	for _, sh := range benchShapes() {
		b.Run(sh.name, func(b *testing.B) {
			bd := bundleFiles(b, "", sh.spec.files())
			if n := routesOf(bd); n != routeCap {
				b.Fatalf("bundle has %d routes, want %d", n, routeCap)
			}
			retained, _ := retainedOf(bd)
			b.ReportAllocs()
			for b.Loop() {
				buildSite(bd)
			}
			// The first b.Loop call clears the metrics: report after the loop.
			b.ReportMetric(float64(retained), "retained-B")
		})
	}
}

// routesOf is the number of routes in all route maps of bd.
func routesOf(bd *bundle.Bundle) (n int) {
	for _, host := range bd.Vhosts() {
		rm, _ := bd.Routes(host)
		n += len(rm.Routes)
	}
	return n
}

// TestTS28SiteTableBound checks the site table of a bundle at the route cap
// for each shape of boundShapes. One site keeps at most siteHeapLimit bytes of
// heap. It has one entry for each route and one for each not_found member. It
// also keeps at least a byte floor, so a measure that loses the bundle fails.
// The trap texts are not in this bound.
func TestTS28SiteTableBound(t *testing.T) {
	floor := uint64(routeCap) * uint64(unsafe.Sizeof(entry{}))
	for _, sh := range boundShapes() {
		t.Run(sh.name, func(t *testing.T) {
			bd := bundleFiles(t, "", sh.spec.files())
			if n := routesOf(bd); n != routeCap {
				t.Fatalf("bundle has %d routes, want %d", n, routeCap)
			}
			hosts := len(bd.Vhosts())
			got, s := retainedOf(bd)
			t.Logf("site keeps %d bytes, %.1f bytes for each route; floor %d, limit %d", got, float64(got)/routeCap, floor, siteHeapLimit)
			if n := len(s.hosts); n != hosts {
				t.Errorf("site has %d hosts, bundle has %d", n, hosts)
			}
			routes, notFound := 0, 0
			for _, paths := range s.hosts {
				for _, e := range paths {
					if e != nil {
						routes++
					}
				}
			}
			for _, e := range s.notFound {
				if e != nil {
					notFound++
				}
			}
			wantNF := 0
			if sh.spec.members != nil {
				wantNF = sh.spec.vhosts
			}
			if routes != routeCap || notFound != wantNF {
				t.Errorf("site has %d route entries and %d not_found entries, want %d and %d", routes, notFound, routeCap, wantNF)
			}
			if got < floor {
				t.Errorf("site keeps %d bytes, below the byte floor of %d", got, floor)
			}
			if got > siteHeapLimit {
				t.Errorf("site keeps %d bytes, above the limit of %d", got, siteHeapLimit)
			}
		})
	}
}
