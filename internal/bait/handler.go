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
	"github.com/cybagard/cyba-phantom/internal/token"
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
// page uses allow. The fixed pages, the asset responses and the beacon
// responses use nosniff. allowPost is in beacon.go. Do not change an element of
// these slices. Each response shares them.
var (
	textType = []string{"text/plain; charset=utf-8"}
	htmlType = []string{"text/html; charset=utf-8"}
	nosniff  = []string{"nosniff"}
	allow    = []string{"GET, HEAD"}
	// connClose is the Connection header value of a callback route and of the
	// beacon post path.
	connClose = []string{"close"}
)

// closeConn takes the connection from net/http and closes it. A writer that
// cannot hijack, for example an HTTP/2 stream or a test recorder, is left as it
// is. Call it after the flush. A later request on the connection gets no
// response. The connection caps do not count the handler after the close. So
// the work after the close must stay short. It takes only two short locks: the
// admission cap and, when the queue drops an event, the drop counters. It has
// no blocking send and no I/O.
func closeConn(w http.ResponseWriter) {
	if c, _, err := http.NewResponseController(w).Hijack(); err == nil {
		_ = c.Close()
	}
}

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

// Handler serves the routes and the beacon paths of the running bundle.
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
	// mintHook runs in a template render, after the route lookup and before the
	// mint. It is nil in production. A test sets it.
	mintHook func()
	// flushHook runs in a callback request and in a beacon post. It runs after
	// the flush and the close of the connection. It runs before the check of
	// the tokens or the ticket. A writer that cannot hijack runs it after the
	// flush. It is nil in production. A test sets it.
	flushHook func()
	// execErrs counts the template execution errors.
	execErrs atomic.Int64
	// noPlan counts the template pages that render with Execute because the
	// template has no plan (SEC-32). It adds one for each such page.
	noPlan atomic.Int64
	// slotDrops counts the header slots left out of a response because the
	// value is not valid. It adds one for each slot at each such response.
	slotDrops atomic.Int64
	// text gives the text of a token. The constructor sets it to token.Text.
	// Only a test changes it, while no request runs.
	text func([token.Size]byte) string
	// keys gives the key set of a bundle. The constructor sets it to
	// (*bundle.Bundle).Tokens. Only a test changes it, while no request
	// runs.
	keys func(*bundle.Bundle) *token.KeySet
	// noKeys counts the renders whose mint failed. The bundle has no key set,
	// for example. It adds one for each such render.
	noKeys atomic.Int64
	// q takes the request events.
	q *event.Queue
	// eventErrs counts the requests for which NewEvent returned an error.
	eventErrs atomic.Uint64
	// dk is the day key holder. The writer can share it. It is never nil.
	dk *session.DayKey
	// now gives the time of a request. The handler reads it one time for each
	// request and calls dk.At with that time at once. A test sets it.
	now func() time.Time
	// cookieOff is true when the session cookie is off (SEC-35). The handler
	// then sets no cookie and ignores each cookie. A request reads it one time.
	cookieOff atomic.Bool
	// ring verifies the tokens of the callback routes. SetRing sets it before
	// the first request. With nil, a callback route makes no callback event.
	ring *token.Ring
	// admit is the admission cap of the callback events. mono gives its clock:
	// the time since the start, on the monotonic clock. A test replaces mono
	// while no request runs.
	admit *callbackCap
	mono  func() time.Duration
	// capped counts the verified tokens that the cap refused. It adds one for
	// each such token. It is for phantom_callback_capped_total.
	capped atomic.Uint64
	// beaconOff is true when the JS beacon is off (SEC-38). The beacon paths
	// are then paths with no route. A request reads it one time.
	beaconOff atomic.Bool
}

// DisableBeacon turns the JS beacon off (SEC-38). The handler then serves a
// beacon path as a path with no route. A GET or HEAD gets the 404 decoy.
// Another method gets the fixed 405 page. The handler makes no beacon event.
// It is safe to call while requests run. A request that has started keeps the
// value that it read, so one request uses one value.
func (h *Handler) DisableBeacon() { h.beaconOff.Store(true) }

// DisableSessionCookie turns the session cookie off (SEC-35). No response then
// has a Set-Cookie header, and each request gets the keyed id of its client
// address. It is safe to call while requests run. A request that has started
// keeps the value that it read, so one request uses one value.
func (h *Handler) DisableSessionCookie() { h.cookieOff.Store(true) }

// capStart gives the start of the clock of the callback cap. A test replaces
// it.
var capStart = time.Now

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
	return &Handler{src: src, fallback: fallback, q: q, text: token.Text, keys: (*bundle.Bundle).Tokens, dk: dk, now: time.Now,
		admit: newCallbackCap(), mono: monotonicSince(capStart())}
}

// reqSession is the session of one request. The handler resolves it one time,
// so each path of the request, the abort path too, uses the same value.
type reqSession struct {
	ip string // the client address text
	id string // the session id, or "" when the address is not valid
	// fresh is true when the response may set a new cookie. This is when the
	// request has no valid cookie and the cookie is on. key is the day key
	// that the request used.
	fresh bool
	key   session.Key
	// at is the time of the request: the one clock read. The mint uses it
	// too. mint is the counter range of the response, or the zero value for
	// a response with no mint.
	at   time.Time
	mint event.MintRange
	// host holds the folded Host, and hostLen is the size of the vhost name that
	// it matched. hostLen is 0 when no vhost matched. serve sets both.
	host    [maxHost]byte
	hostLen int
	// firstCapped holds the trap id, token id and surface of the first token
	// that the callback cap refused. This is in position order. The request
	// event holds them. firstCapped.token is "" when the cap refused no token.
	firstCapped struct {
		trap, token string
		surface     event.Surface
	}
}

// sessionOf resolves the session of r. A request with one valid cookie has the
// id of the cookie. Else it has the keyed id of the client address, and the
// response sets a cookie. With the cookie off, each request has the keyed id
// and no response sets a cookie. The handler keeps no session state in memory.
func (h *Handler) sessionOf(r *http.Request) reqSession {
	at := h.now()
	k := h.dk.At(at)
	s := reqSession{ip: clientIP(r.RemoteAddr), key: k, at: at}
	off := h.cookieOff.Load()
	if !off {
		if v, ok := session.CookieFromHeader(r.Header); ok {
			if id, ok := k.CheckCookie(v); ok {
				s.id = id
				return s
			}
		}
	}
	s.fresh = !off
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

// clientIP gives the address part of addr, without an IPv6 zone. NewEvent
// refuses a zone, and the callback cap key already has none. For a value that
// is not an address, it gives addr, which NewEvent then accepts or refuses.
func clientIP(addr string) string {
	if ap, err := netip.ParseAddrPort(addr); err == nil {
		return ap.Addr().WithZone("").String()
	}
	if a, err := netip.ParseAddr(addr); err == nil && a.Zone() != "" {
		return a.WithZone("").String()
	}
	return addr
}

// record puts one request event on the queue. code is the status that the
// engine wrote, or 0 when it wrote none. The event has the typed fields, the
// session id and the mint range of the response. It has no detail. It has a
// trap id, a token id and a surface only when the callback cap refused a
// token. The vhost is the name of the bundle vhost that the Host matched, in
// lower case. With no match it has no vhost. It never holds the Host (SEC-41).
// A NewEvent error adds one to eventErrs. A full queue counts its own drop.
// The call never waits.
func (h *Handler) record(r *http.Request, s *reqSession, code int) {
	in := event.Input{
		Kind:     event.KindRequest,
		Session:  s.id,
		Vhost:    string(s.host[:s.hostLen]),
		Method:   r.Method,
		Path:     event.RequestPath(r.URL.RawPath, r.URL.Path),
		ClientIP: s.ip,
	}
	if s.mint.Count != 0 {
		in.Mint = &s.mint
	}
	if code != 0 {
		st := int64(code)
		in.Status = &st
	}
	if s.firstCapped.token != "" {
		in.TrapID, in.TokenID, in.Surface = s.firstCapped.trap, s.firstCapped.token, s.firstCapped.surface
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
// keep that site. A bundle outside retired becomes cur when its load sequence
// is higher than the sequence of cur. This includes a bundle that was never
// cur and a bundle that has left retired. The loader swapped in a bundle with a
// lower sequence before cur. That bundle gets a site for its own request, like
// a bundle in retired. The state does not change. Such a site has no render
// plan, so its pages render with Execute (SEC-32). The sequence does not depend
// on the manifest version, so a reload of the same archive counts as later. A
// request in flight keeps its bundle and site in local variables.
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
			if b.Sequence() <= st.cur.b.Sequence() {
				h.builds.Add(1)
				return buildSite(b)
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

// reply writes a fixed page. A 405 page has the Allow header of allow. A HEAD
// request gets no body from net/http.
func reply(w http.ResponseWriter, code int, body []byte) {
	replyAllow(w, code, body, allow)
}

// replyAllow is reply with the Allow value allowVal for a 405 page.
func replyAllow(w http.ResponseWriter, code int, body []byte, allowVal []string) {
	h := w.Header()
	h["Content-Type"] = textType
	h["X-Content-Type-Options"] = nosniff
	if code == http.StatusMethodNotAllowed {
		h["Allow"] = allowVal
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
// order of the steps is host, beacon path, method and path. A host with no
// vhost gets the fixed 404 page. The two beacon paths of the vhost come next.
// They are not routes (see serveBeacon). With the beacon off, they are paths
// with no route. A path with no route gets the 404 template of the vhost, or
// the fixed 404 page. A template route renders its template. A method other
// than GET and HEAD gets the fixed 405 page. A POST to a callback route with a
// body position is the exception. With the beacon on, a POST to the beacon post
// path is the other. Only these two read a body.
// A render that ends the connection writes the event itself and does not
// return. A template page and an asset response set the cookie of a new
// session. A fixed page does not.
func (h *Handler) serve(w http.ResponseWriter, r *http.Request, b *bundle.Bundle, sess *reqSession) int {
	name, ok := foldHost(r.Host, &sess.host)
	s := h.siteOf(b)
	routes, found := s.hosts[string(name)]
	if !ok || !found {
		reply(w, http.StatusNotFound, notFoundBody)
		return http.StatusNotFound
	}
	sess.hostLen = len(name)
	if bp := s.beacons[string(name)]; bp != nil && !h.beaconOff.Load() {
		if code, ok := h.serveBeacon(w, r, sess, bp); ok {
			return code
		}
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		// Only a callback route with a body position accepts POST (ADR-039).
		if r.Method == http.MethodPost {
			if e := routeEntry(routes, r.URL.EscapedPath()); e.acceptsPost() {
				return h.callback(w, r, sess, e)
			}
		}
		reply(w, http.StatusMethodNotAllowed, methodBody)
		return http.StatusMethodNotAllowed
	}
	e := routeEntry(routes, r.URL.EscapedPath())
	if e == nil {
		if nf := s.notFound[string(name)]; nf != nil {
			return h.render(w, r, b, s, sess, nf, http.StatusNotFound)
		}
		reply(w, http.StatusNotFound, notFoundBody)
		return http.StatusNotFound
	}
	if e.cb != nil {
		return h.callback(w, r, sess, e)
	}
	if !e.isAsset {
		return h.render(w, r, b, s, sess, e, http.StatusOK)
	}
	hd := w.Header()
	hd["Content-Type"] = e.ctype
	hd["X-Content-Type-Options"] = nosniff
	hd["Content-Length"] = e.clen
	m := h.mint(b, s, e, sess)
	h.addSlots(hd, &m)
	sess.setCookie(hd)
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = e.asset.WriteTo(w)
	}
	return http.StatusOK
}
