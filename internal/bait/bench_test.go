package bait

import (
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"testing"
)

const (
	// pageBytes and pageActions are the size and the trap actions of the
	// template route page. It has 16 KiB and 64 trap ids, one action for each.
	pageBytes   = 16 << 10
	pageActions = 64
	// actionAllocs is the most allocations for each action of a template page.
	// A page with 1 to 64 actions allocates 16 for each action and 18 more.
	// With the race detector, the pools lose items. A page then allocates up
	// to 17 for each action.
	actionAllocs = 17
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
// Measured without it: 15 for an asset and 0 for the fixed pages. It is 34 for
// the 404 template and for a page of 1 action.
var serveKinds = []struct {
	name, method, target, host string
	limit                      float64
}{
	{"asset GET", http.MethodGet, "/style.css", "example.com", 16},
	{"asset HEAD", http.MethodHead, "/style.css", "example.com", 16},
	{"template page", http.MethodGet, "/t", "example.com", 35},
	{"vhost 404 template", http.MethodGet, "/nope", "example.com", 35},
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
	// assetVhosts is the number of vhosts, besides the three of the test
	// archive, with 256 asset routes each. It is the largest number that
	// loads: 445 gives archive_invalid.
	assetVhosts = 444
	// callbackVhosts is the same for 256 callback routes with no asset. A
	// route is short, so the size of the archive limits the number. 743 gives
	// archive_invalid.
	callbackVhosts = 742
)

// capFiles makes the files of n more vhosts of 256 routes each. A vhost has one
// file, which all its routes name.
func capFiles(n int) map[string]string {
	extra := map[string]string{}
	for i := range n {
		host := fmt.Sprintf("v%d.example", i)
		var parts []string
		for j := range 256 {
			parts = append(parts, fmt.Sprintf(`{"path":"/%d","asset":"vhosts/%s/f","type":"image/png"}`, j, host))
		}
		extra["vhosts/"+host+"/routes.json"] = `{"routes":[` + strings.Join(parts, ",") + `]}`
		extra["vhosts/"+host+"/f"] = "f"
	}
	return extra
}

// callbackFiles makes the files of n more vhosts of 256 callback routes each.
// A route has no asset and no type.
func callbackFiles(n int) map[string]string {
	extra := map[string]string{}
	for i := range n {
		var parts []string
		for j := range 256 {
			parts = append(parts, fmt.Sprintf(`{"path":"/%d","callback":{"query":"t"}}`, j))
		}
		extra[fmt.Sprintf("vhosts/a%d.x/routes.json", i)] = `{"routes":[` + strings.Join(parts, ",") + `]}`
	}
	return extra
}

// BenchmarkSiteBuild measures the build of the site table of the largest bundle
// that loads. It does this for two shapes of route. It also reports the bytes
// that one built site keeps in memory.
func BenchmarkSiteBuild(b *testing.B) {
	shapes := []struct {
		name  string
		files func() map[string]string
	}{
		{"assets", func() map[string]string { return capFiles(assetVhosts) }},
		{"callbacks", func() map[string]string { return callbackFiles(callbackVhosts) }},
	}
	for _, sh := range shapes {
		b.Run(sh.name, func(b *testing.B) {
			bd := bundleFiles(b, "", sh.files())
			var before, after runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&before)
			s := buildSite(bd, placeholder)
			runtime.GC()
			runtime.ReadMemStats(&after)
			runtime.KeepAlive(s)
			b.ReportAllocs()
			for b.Loop() {
				buildSite(bd, placeholder)
			}
			// The first b.Loop call clears the metrics: report after the loop.
			b.ReportMetric(float64(after.HeapAlloc-before.HeapAlloc), "retained-B")
		})
	}
}
