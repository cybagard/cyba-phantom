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
	// fixedAllocs is the most allocations of a request apart from the actions.
	// Measured: 15 for an asset, 34 for the 404 template and 0 for the other
	// kinds. With the race detector, they are 16, 35 and 0.
	fixedAllocs = 35
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
// route /t is the page of pageOf. The 404 template of example.com shows a trap.
func serveHandler(tb testing.TB) *Handler {
	specs := make([]trapSpec, pageActions)
	for i := range specs {
		specs[i] = trapSpec{fmt.Sprint("t", i), "hidden-p", "x {{.Token}}"}
	}
	b := hardBundle(tb, `<h1>{{index .Trap "t0"}}</h1>`, map[string]string{
		"traps/traps.json":          trapsJSON(specs),
		"vhosts/example.com/t.tmpl": pageOf(pageActions),
	})
	return New(fixedSource{b}, &fallbackFn{}, testQueue(tb))
}

// serveKinds are the kinds of response of the handler, one for each way that
// serve ends.
var serveKinds = []struct{ name, method, target, host string }{
	{"asset GET", http.MethodGet, "/style.css", "example.com"},
	{"asset HEAD", http.MethodHead, "/style.css", "example.com"},
	{"template page", http.MethodGet, "/t", "example.com"},
	{"vhost 404 template", http.MethodGet, "/nope", "example.com"},
	{"fixed 404", http.MethodGet, "/nope", "kilo.example"},
	{"unknown host", http.MethodGet, "/", "other.example"},
	{"405", http.MethodPost, "/", "example.com"},
}

func kindRequest(method, target, host string) *http.Request {
	r := get(target, host)
	r.Method = method
	return r
}

// BenchmarkBaitServe measures a request of each kind through ServeHTTP. This
// includes the request event.
func BenchmarkBaitServe(b *testing.B) {
	h := serveHandler(b)
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

// TestTS28ServeAllocs checks the allocations of each kind. A template page
// allocates at most actionAllocs for each action, and each other kind at most
// fixedAllocs. It calls serve and not ServeHTTP, for the reason of
// TestTU20RenderAllocs.
func TestTS28ServeAllocs(t *testing.T) {
	h := serveHandler(t)
	b := h.src.Current()
	for _, k := range serveKinds {
		r, w := kindRequest(k.method, k.target, k.host), &discard{h: http.Header{}}
		s := h.sessionOf(r)
		got := testing.AllocsPerRun(100, func() {
			clear(w.h)
			h.serve(w, r, b, &s)
		})
		limit := float64(fixedAllocs)
		if k.name == "template page" {
			limit += actionAllocs * pageActions
		}
		t.Logf("%s: %v allocations, limit %v", k.name, got, limit)
		if got > limit {
			t.Errorf("%s: %v allocations, limit %v", k.name, got, limit)
		}
	}
}

// siteVhosts is the number of vhosts, besides the three of the test archive,
// with 256 routes each. It is the largest number that loads: 445 gives
// archive_invalid.
const siteVhosts = 444

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

// BenchmarkSiteBuild measures the build of the site table of a bundle at the
// archive cap. It also reports the bytes that one built site keeps in memory.
func BenchmarkSiteBuild(b *testing.B) {
	bd := bundleFiles(b, "", capFiles(siteVhosts))
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
	// The first call of b.Loop clears the metrics, so report after the loop.
	b.ReportMetric(float64(after.HeapAlloc-before.HeapAlloc), "retained-B")
}
