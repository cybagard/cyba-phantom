package bait

import (
	"net/http"
	"net/netip"
	"sync/atomic"
	"weak"

	"github.com/cybagard/cyba-phantom/internal/bundle"
	"github.com/cybagard/cyba-phantom/internal/event"
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
	htmlType = []string{"text/html; charset=utf-8"}
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
	// token gives the token text of a site. A site build calls it one time.
	// It takes no request value. A test sets it before the first request.
	token func() string
	// execErrs counts the template execution errors.
	execErrs atomic.Int64
	// slotDrops counts the header slots left out of a response because the
	// value is not valid. It adds one for each slot at each such response.
	slotDrops atomic.Int64
	// q takes the request events.
	q *event.Queue
	// eventErrs counts the requests for which NewEvent returned an error.
	eventErrs atomic.Uint64
}

// New returns a handler for the bundle of src. With no running bundle, fallback
// serves the request and writes its own event. Else the handler puts one
// request event on q. It panics when src, fallback or q is nil.
func New(src Source, fallback http.Handler, q *event.Queue) *Handler {
	if src == nil || fallback == nil || q == nil {
		panic("bait: New needs a source, a fallback handler and a queue")
	}
	return &Handler{src: src, fallback: fallback, q: q, token: placeholderToken}
}

// clientIP gives the address part of addr. For a value that is not an address
// with a port, it gives addr, which NewEvent then accepts or refuses.
func clientIP(addr string) string {
	if ap, err := netip.ParseAddrPort(addr); err == nil {
		return ap.Addr().String()
	}
	return addr
}

// record puts one request event on the queue. code is the status that the
// engine wrote, or 0 when it wrote none. The event has the typed fields only
// and no detail. A NewEvent error adds one to eventErrs. A full queue counts
// its own drop. The call never waits.
func (h *Handler) record(r *http.Request, code int) {
	in := event.Input{
		Kind:     event.KindRequest,
		Vhost:    r.Host,
		Method:   r.Method,
		Path:     event.RequestPath(r.URL.RawPath, r.URL.Path),
		ClientIP: clientIP(r.RemoteAddr),
	}
	if code != 0 {
		st := int64(code)
		in.Status = &st
	}
	e, err := event.NewEvent(nil, in)
	if err != nil {
		h.eventErrs.Add(1)
		return
	}
	h.q.Enqueue(e)
}

// siteOf returns the site of b. The handler keeps a strong pointer to cur only.
// A bundle in retired gets a site for its own request. The handler does not
// keep that site. Any other bundle becomes cur. This includes a bundle that
// was never cur and a bundle that has left retired. A request in flight keeps
// its bundle and site in local variables.
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
					return buildSite(b, h.token())
				}
			}
		}
		n := &state{cur: &slot{b: b, count: &h.builds, token: h.token}}
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
// bundle. With no bundle, the fallback serves and writes its own event. Else
// the handler writes one event for the request.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b := h.src.Current()
	if b == nil {
		h.fallback.ServeHTTP(w, r)
		return
	}
	h.record(r, h.serve(w, r, b))
}

// serve answers the request from b and returns the status that it wrote. The
// order of the steps is host, method and path. A host with no vhost gets the
// fixed 404 page. A path with no route gets the 404 template of the vhost, or
// the fixed 404 page. A template route renders its template. A method other
// than GET and HEAD gets the fixed 405 page. The handler never reads the body.
// A render that ends the connection writes the event itself and does not
// return.
func (h *Handler) serve(w http.ResponseWriter, r *http.Request, b *bundle.Bundle) int {
	var buf [maxHost]byte
	name, ok := foldHost(r.Host, &buf)
	s := h.siteOf(b)
	routes, found := s.hosts[string(name)]
	if !ok || !found {
		reply(w, http.StatusNotFound, notFoundBody)
		return http.StatusNotFound
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		reply(w, http.StatusMethodNotAllowed, methodBody)
		return http.StatusMethodNotAllowed
	}
	e := routes[r.URL.EscapedPath()]
	if e == nil {
		if nf := s.notFound[string(name)]; nf != nil {
			return h.render(w, r, b, s, nf, http.StatusNotFound)
		}
		reply(w, http.StatusNotFound, notFoundBody)
		return http.StatusNotFound
	}
	if !e.isAsset {
		return h.render(w, r, b, s, e, http.StatusOK)
	}
	hd := w.Header()
	hd["Content-Type"] = e.ctype
	hd["X-Content-Type-Options"] = nosniff
	hd["Content-Length"] = e.clen
	h.addSlots(hd, e)
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = e.asset.WriteTo(w)
	}
	return http.StatusOK
}
