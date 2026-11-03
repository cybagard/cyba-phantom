package bait

import (
	"net/http"
	"sync/atomic"

	"github.com/cybagard/cyba-phantom/internal/bundle"
)

// The fixed response bodies. No body holds a value from a request.
var (
	notFoundBody = []byte("not found\n")
	methodBody   = []byte("method not allowed\n")
)

// Header values of the fixed pages and of each asset response. A response
// uses these slices as they are.
var (
	textType = []string{"text/plain; charset=utf-8"}
	nosniff  = []string{"nosniff"}
	allow    = []string{"GET, HEAD"}
)

// Source gives the running bundle. *bundle.Loader is a Source.
type Source interface {
	Current() *bundle.Bundle
}

// Handler serves the routes of the running bundle.
type Handler struct {
	src      Source
	fallback http.Handler
	// last is the slot of the last bundle that a request saw. It is the only
	// site that the handler keeps.
	last atomic.Pointer[slot]
	// builds counts the builds of a site table. A test reads it.
	builds atomic.Int64
}

// New returns a handler for the bundle of src. With no running bundle, fallback
// serves the request.
func New(src Source, fallback http.Handler) *Handler {
	return &Handler{src: src, fallback: fallback}
}

// siteOf returns the site of b. The build runs one time for each bundle.
func (h *Handler) siteOf(b *bundle.Bundle) *site {
	for {
		p := h.last.Load()
		if p == nil || p.b != b {
			n := &slot{b: b, count: &h.builds}
			if !h.last.CompareAndSwap(p, n) {
				continue
			}
			p = n
		}
		return p.site()
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
// vhost or a path with no route gets the fixed 404 page. A method other than
// GET and HEAD gets the fixed 405 page. The handler never reads the body.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b := h.src.Current()
	if b == nil {
		h.fallback.ServeHTTP(w, r)
		return
	}
	var buf [253]byte
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
