package bait

import (
	"crypto/rand"
	"net/http"
	"net/netip"
	"sync/atomic"
	"time"
	"weak"

	"github.com/cybagard/cyba-phantom/internal/bundle"
	"github.com/cybagard/cyba-phantom/internal/event"
	"github.com/cybagard/cyba-phantom/internal/session"
)

// cookieName is the name of the session cookie (SEC-35). internal/session reads
// the same name.
const cookieName = "sid"

// cookieAttrs are the attributes of the session cookie (SEC-35). There is no
// Domain attribute, so the cookie is host-only.
const cookieAttrs = "; Path=/; Max-Age=86400; HttpOnly; Secure; SameSite=Lax"

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
	// dk is the day key holder. The writer can share it. It is never nil.
	dk *session.DayKey
	// now gives the time of a request. The handler reads it one time for each
	// request and calls dk.At with that time at once. A test sets it.
	now func() time.Time
}

// New returns a handler for the bundle of src. With no running bundle, fallback
// serves the request and writes its own event. Else the handler puts one
// request event on q. It panics when src, fallback or q is nil. The handler
// makes its own day key holder. To share the holder with the writer, use
// NewWithDayKey.
func New(src Source, fallback http.Handler, q *event.Queue) *Handler {
	return NewWithDayKey(src, fallback, q, session.NewDayKey())
}

// NewWithDayKey is New with the day key holder as the last argument. The
// handler takes its key from dk. The writer can share dk, so both compute the
// same session id for one UTC date. A nil dk makes the handler use a new holder
// of its own, as store.NewWriterWithDayKey does.
func NewWithDayKey(src Source, fallback http.Handler, q *event.Queue, dk *session.DayKey) *Handler {
	if src == nil || fallback == nil || q == nil {
		panic("bait: New needs a source, a fallback handler and a queue")
	}
	if dk == nil {
		dk = session.NewDayKey()
	}
	return &Handler{src: src, fallback: fallback, q: q, token: placeholderToken, dk: dk, now: time.Now}
}

// reqSession is the session of one request. The handler resolves it one time,
// so each path of the request, the abort path too, uses the same value.
type reqSession struct {
	ip string // the client address text
	id string // the session id, or "" when the address is not valid
	// fresh is true when the request has no valid cookie. The response then
	// sets a new cookie. key is the day key that the request used.
	fresh bool
	key   session.Key
}

// sessionOf resolves the session of r. A request with one valid cookie has the
// id of the cookie. Else it has the keyed id of the client address, and the
// response sets a cookie. The handler keeps no session state in memory.
func (h *Handler) sessionOf(r *http.Request) reqSession {
	k := h.dk.At(h.now())
	s := reqSession{ip: clientIP(r.RemoteAddr), key: k}
	if v, ok := session.CookieFromHeader(r.Header); ok {
		if id, ok := k.CheckCookie(v); ok {
			s.id = id
			return s
		}
	}
	s.fresh = true
	if id := k.SessionID(s.ip, ""); id != nil {
		s.id = *id
	}
	return s
}

// setCookie sets the Set-Cookie header of a new session on hd. The value has a
// new random session id, not the id of the request. Call it only where a bait
// response starts, so a fixed page never carries it.
func (s *reqSession) setCookie(hd http.Header) {
	if !s.fresh {
		return
	}
	var id [16]byte
	_, _ = rand.Read(id[:]) // since Go 1.24 Read does not return an error
	hd["Set-Cookie"] = []string{cookieName + "=" + s.key.CookieValue(id) + cookieAttrs}
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
// engine wrote, or 0 when it wrote none. The event has the typed fields and
// the session id, and no detail. A NewEvent error adds one to eventErrs. A full
// queue counts its own drop. The call never waits.
func (h *Handler) record(r *http.Request, s *reqSession, code int) {
	in := event.Input{
		Kind:     event.KindRequest,
		Session:  s.id,
		Vhost:    r.Host,
		Method:   r.Method,
		Path:     event.RequestPath(r.URL.RawPath, r.URL.Path),
		ClientIP: s.ip,
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
// keep that site. A bundle outside retired becomes cur when its manifest
// version is not older than the version of cur. This includes a bundle that was
// never cur and a bundle that has left retired. An older bundle gets a site for
// its own request, like a bundle in retired. The state does not change. A
// request in flight keeps its bundle and site in local variables.
//
// Known limit: the loader can accept a bundle older than cur, but only after
// its version state is removed. Then each request for that bundle builds a
// site. This lasts until a bundle that is not older than cur loads, or the
// process starts again.
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
			if bundle.CompareVersion(b.Manifest().Version, st.cur.b.Manifest().Version) < 0 {
				h.builds.Add(1)
				return buildSite(b, h.token())
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
// bundle. With no bundle, the fallback serves and writes its own event, and
// sets no cookie. Else the handler resolves the session one time and writes one
// event for the request, with that session.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b := h.src.Current()
	if b == nil {
		h.fallback.ServeHTTP(w, r)
		return
	}
	s := h.sessionOf(r)
	code := h.serve(w, r, b, &s)
	h.record(r, &s, code)
}

// serve answers the request from b and returns the status that it wrote. The
// order of the steps is host, method and path. A host with no vhost gets the
// fixed 404 page. A path with no route gets the 404 template of the vhost, or
// the fixed 404 page. A template route renders its template. A method other
// than GET and HEAD gets the fixed 405 page. The handler never reads the body.
// A render that ends the connection writes the event itself and does not
// return. A template page and an asset response set the cookie of a new
// session. A fixed page does not.
func (h *Handler) serve(w http.ResponseWriter, r *http.Request, b *bundle.Bundle, sess *reqSession) int {
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
			return h.render(w, r, b, s, sess, nf, http.StatusNotFound)
		}
		reply(w, http.StatusNotFound, notFoundBody)
		return http.StatusNotFound
	}
	if !e.isAsset {
		return h.render(w, r, b, s, sess, e, http.StatusOK)
	}
	hd := w.Header()
	hd["Content-Type"] = e.ctype
	hd["X-Content-Type-Options"] = nosniff
	hd["Content-Length"] = e.clen
	h.addSlots(hd, e)
	sess.setCookie(hd)
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = e.asset.WriteTo(w)
	}
	return http.StatusOK
}
