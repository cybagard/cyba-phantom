package bait

import (
	"net/http"
	"sync/atomic"
	"weak"

	"github.com/cybagard/cyba-phantom/internal/bundle"
)

// The fixed response bodies. No body holds a value from a request.
var (
	notFoundBody = []byte("not found\n")
	methodBody   = []byte("method not allowed\n")
)

// Header values of the responses. The fixed pages use textType. Only the 405
// page uses allow. The fixed pages and the asset responses use nosniff. Do not
// change an element of these slices. Each response shares them.
var (
	textType = []string{"text/plain; charset=utf-8"}
	nosniff  = []string{"nosniff"}
	allow    = []string{"GET, HEAD"}
)

// Source gives the running bundle. *bundle.Loader is a Source.
type Source interface {
	Current() *bundle.Bundle
}

// retiredKept is the number of replaced bundles that the handler remembers.
const retiredKept = 4

// state is the cache of the handler. cur holds the last installed bundle and
// its site. retired holds weak pointers to the last replaced bundles, newest
// first. A weak pointer does not keep a bundle in memory.
type state struct {
	cur     *slot
	retired [retiredKept]weak.Pointer[bundle.Bundle]
}

// Handler serves the routes of the running bundle.
type Handler struct {
	src      Source
	fallback http.Handler
	// sites holds the state. The handler keeps no other bundle or site.
	sites atomic.Pointer[state]
	// builds counts the builds of a site table. A test reads it.
	builds atomic.Int64
	// hook runs between the Load and the CompareAndSwap of siteOf. It is nil
	// in production. A test sets it.
	hook func()
}

// New returns a handler for the bundle of src. With no running bundle, fallback
// serves the request. It panics when src or fallback is nil.
func New(src Source, fallback http.Handler) *Handler {
	if src == nil || fallback == nil {
		panic("bait: New needs a source and a fallback handler")
	}
	return &Handler{src: src, fallback: fallback}
}

// siteOf returns the site of b. The handler keeps a strong pointer to cur only.
// A bundle in retired gets a site for its own request. The handler does not
// keep that site. Each other bundle becomes cur, also an older bundle that is
// not in retired. A request in flight keeps its bundle and site in local
// variables.
func (h *Handler) siteOf(b *bundle.Bundle) *site {
	for {
		st := h.sites.Load()
		if st != nil {
			if st.cur.b == b {
				return st.cur.site()
			}
			w := weak.Make(b)
			for _, r := range st.retired {
				if r == w {
					h.builds.Add(1)
					return buildSite(b)
				}
			}
		}
		n := &state{cur: &slot{b: b, count: &h.builds}}
		if st != nil {
			n.retired[0] = weak.Make(st.cur.b)
			copy(n.retired[1:], st.retired[:retiredKept-1])
		}
		if h.hook != nil {
			h.hook()
		}
		if h.sites.CompareAndSwap(st, n) {
			return n.cur.site()
		}
	}
}

// reply writes a fixed page. A HEAD request gets no body from net/http.
func reply(w http.ResponseWriter, code int, body []byte) {
	h := w.Header()
	h["Content-Type"] = textType
	h["X-Content-Type-Options"] = nosniff
	if code == http.StatusMethodNotAllowed {
		h["Allow"] = allow
	}
	w.WriteHeader(code)
	_, _ = w.Write(body)
}

// ServeHTTP reads the running bundle one time. A request then uses only that
// bundle. The order of the steps is host, method and path. A host with no
// vhost, a path with no route and a template route get the fixed 404 page.
// A method other than GET and HEAD gets the fixed 405 page. The handler never
// reads the body.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b := h.src.Current()
	if b == nil {
		h.fallback.ServeHTTP(w, r)
		return
	}
	var buf [maxHost]byte
	name, ok := foldHost(r.Host, &buf)
	routes, found := h.siteOf(b).hosts[string(name)]
	if !ok || !found {
		reply(w, http.StatusNotFound, notFoundBody)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		reply(w, http.StatusMethodNotAllowed, methodBody)
		return
	}
	e := routes[r.URL.EscapedPath()]
	if e == nil || !e.isAsset {
		reply(w, http.StatusNotFound, notFoundBody)
		return
	}
	hd := w.Header()
	hd["Content-Type"] = e.ctype
	hd["X-Content-Type-Options"] = nosniff
	hd["Content-Length"] = e.clen
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = e.asset.WriteTo(w)
	}
}
