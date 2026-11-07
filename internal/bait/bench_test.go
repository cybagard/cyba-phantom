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

// serveHandler returns a handler for the hardening bundle with 64 traps. The
// route /t is the page of pageOf with the given actions. The 404 template of
// example.com shows a trap.
func serveHandler(tb testing.TB, actions int) *Handler {
	specs := make([]trapSpec, pageActions)
	for i := range specs {
		specs[i] = trapSpec{fmt.Sprint("t", i), "hidden-p", "x {{.Token}}"}
	}
	b := hardBundle(tb, `<h1>{{index .Trap "t0"}}</h1>`, map[string]string{
		"traps/traps.json":          trapsJSON(specs),
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
	// The bundle is at the route cap. Its routes are template routes with four
	// header slots.
	siteHeapLimit = 10 << 20
	// templateVhostRoutes is the routes of one vhost in the template shape.
	// A route map holds 64 KiB. 192 such routes fill about 62 KB of it.
	templateVhostRoutes = 192
)

// shapeFiles makes the files of vhosts with total routes in all. A vhost has
// at most per routes. route gives the JSON of route j of a vhost. A vhost also
// has the file name with the text body, which its routes can name.
func shapeFiles(total, per int, name, body string, route func(host string, j int) string) map[string]string {
	extra := map[string]string{}
	for i := 0; total > 0; i++ {
		host := fmt.Sprintf("v%d.example", i)
		parts := make([]string, min(total, per))
		total -= len(parts)
		for j := range parts {
			parts[j] = route(host, j)
		}
		extra["vhosts/"+host+"/routes.json"] = `{"routes":[` + strings.Join(parts, ",") + `]}`
		extra["vhosts/"+host+"/"+name] = body
	}
	return extra
}

// capFiles makes the files of asset routes. All routes of a vhost name one
// file. The test archive and these files hold routeCap routes.
func capFiles() map[string]string {
	return shapeFiles(routeCap-baseRoutes, 256, "f", "f", func(host string, j int) string {
		return fmt.Sprintf(`{"path":"/%d","asset":"vhosts/%s/f","type":"image/png"}`, j, host)
	})
}

// callbackFiles makes the files of callback routes. A route has no asset and
// no type. The test archive and these files hold routeCap routes.
func callbackFiles() map[string]string {
	return shapeFiles(routeCap-baseRoutes, 256, "f", "f", func(_ string, j int) string {
		return fmt.Sprintf(`{"path":"/%d","callback":{"query":"t"}}`, j)
	})
}

// templateFiles makes the files of template routes. A route has four header
// slots, and each slot name has 34 bytes. All routes of a vhost name one
// template. The test archive and these files hold routeCap routes.
func templateFiles() map[string]string {
	return shapeFiles(routeCap-baseRoutes, templateVhostRoutes, "p.tmpl", "<p>p</p>", func(host string, j int) string {
		var slots []string
		for k := range 4 {
			name := fmt.Sprintf("X-Probe-%d-", k)
			slots = append(slots, fmt.Sprintf(`{"name":"%s","trap":"a"}`, name+strings.Repeat("a", 34-len(name))))
		}
		return fmt.Sprintf(`{"path":"/%d","template":"vhosts/%s/p.tmpl","type":"text/html; charset=utf-8","headers":[%s]}`,
			j, host, strings.Join(slots, ","))
	})
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

// siteShapes are the route shapes of a bundle at the route cap.
var siteShapes = []struct {
	name  string
	files func() map[string]string
}{
	{"assets", capFiles},
	{"callbacks", callbackFiles},
	{"templates", templateFiles},
}

// BenchmarkSiteBuild measures the build of the site table of a bundle at the
// route cap. It does this for three shapes of route. It also reports the bytes
// that one built site keeps in memory.
func BenchmarkSiteBuild(b *testing.B) {
	for _, sh := range siteShapes {
		b.Run(sh.name, func(b *testing.B) {
			bd := bundleFiles(b, "", sh.files())
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

// TestTS28SiteTableBound checks the site table of a bundle at the route cap.
// The routes are template routes with four header slots with 34-byte names.
// One site keeps at most siteHeapLimit bytes of heap. It keeps at least one
// entry for each route, so a measure that loses the bundle fails.
func TestTS28SiteTableBound(t *testing.T) {
	bd := bundleFiles(t, "", templateFiles())
	if n := routesOf(bd); n != routeCap {
		t.Fatalf("bundle has %d routes, want %d", n, routeCap)
	}
	hosts := len(bd.Vhosts())
	got, s := retainedOf(bd)
	floor := uint64(routeCap) * uint64(unsafe.Sizeof(entry{}))
	t.Logf("site keeps %d bytes, %.1f bytes for each route; limits %d and %d", got, float64(got)/routeCap, floor, siteHeapLimit)
	if n := len(s.hosts); n != hosts {
		t.Errorf("site has %d hosts, bundle has %d", n, hosts)
	}
	if got < floor {
		t.Errorf("site keeps %d bytes, below the floor of %d", got, floor)
	}
	if got > siteHeapLimit {
		t.Errorf("site keeps %d bytes, above the limit of %d", got, siteHeapLimit)
	}
}
