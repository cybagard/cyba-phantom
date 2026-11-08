package bait

import (
	"net/http"
	"net/netip"
	"slices"
	"strings"

	"github.com/cybagard/cyba-phantom/internal/bundle"
	"github.com/cybagard/cyba-phantom/internal/event"
	"github.com/cybagard/cyba-phantom/internal/token"
)

// callbackPos holds the positions of a callback route, ready to serve. header
// is the canonical header name. vhost is the vhost name of the bundle, for the
// callback record. The site build makes callbackPos, never a request.
type callbackPos struct {
	segment             bool
	query, header, body string
	vhost               string
}

func newCallbackPos(c *bundle.Callback, vhost string) *callbackPos {
	p := &callbackPos{segment: c.Segment, query: c.Query, body: c.Body, vhost: vhost}
	if c.Header != "" {
		p.header = HeaderName(c.Header)
	}
	return p
}

// These constants name the positions of a callback route. Their order is the
// order of the texts for Check and of the event rule.
const (
	posPath = iota
	posQuery
	posHeader
	posBody
)

// surfaces are the surfaces of the positions, in the order of the positions.
var surfaces = [token.Positions]event.Surface{
	event.SurfacePath, event.SurfaceQuery, event.SurfaceHeader, event.SurfaceBody,
}

// SetRing sets the ring that verifies the tokens of the callback routes. With
// no ring, a callback route gives its fixed response and no callback event.
// Call it before the first request. It is not safe to call it later.
func (h *Handler) SetRing(r *token.Ring) { h.ring = r }

// routeEntry gives the route for the escaped path p. The exact route of any
// kind comes first. Else a callback route with a segment position matches its
// path, "/" and one segment. At the root, only "/" and one segment match, so
// "//" and "//x" match no route. A path that no route matches gives nil.
func routeEntry(routes map[string]*entry, p string) *entry {
	if e := routes[p]; e != nil {
		return e
	}
	base := "/"
	switch i := strings.LastIndexByte(p, '/'); {
	case i < 0, i == 1:
		return nil
	case i > 1:
		base = p[:i]
	}
	if e := routes[base]; e != nil && e.cb != nil && e.cb.segment {
		return e
	}
	return nil
}

// acceptsPost tells if e is a callback route with a body position.
func (e *entry) acceptsPost() bool { return e != nil && e.cb != nil && e.cb.body != "" }

// callback answers a request for the callback route e. It reads the candidates
// and the body, writes the fixed response and flushes it. Only then it checks
// the tokens and builds the events. The response code reads no token result,
// so each result gives the same bytes. The route sets no cookie.
func (h *Handler) callback(w http.ResponseWriter, r *http.Request, sess *reqSession, e *entry) int {
	var texts [token.Positions]string
	cb := e.cb
	if cb.segment {
		texts[posPath] = PathCandidate(r.URL.EscapedPath(), e.route.Path)
	}
	if cb.query != "" {
		texts[posQuery] = QueryCandidate(r.URL.RawQuery, cb.query)
	}
	if cb.header != "" {
		texts[posHeader] = HeaderCandidate(r.Header, cb.header)
	}
	if cb.body != "" {
		if c, ok := BodyCandidate(r, cb.body); ok {
			texts[posBody] = string(c[:])
		}
	}
	code := http.StatusNoContent
	hd := w.Header()
	hd["X-Content-Type-Options"] = nosniff
	if e.isAsset {
		code = http.StatusOK
		hd["Content-Type"] = e.ctype
		hd["Content-Length"] = e.clen
	}
	w.WriteHeader(code)
	if e.isAsset && r.Method != http.MethodHead {
		_, _ = e.asset.WriteTo(w)
	}
	_ = http.NewResponseController(w).Flush()
	h.callbackEvents(r, sess, e, code, texts)
	return code
}

// callbackEvents checks the texts. It puts one callback event on the queue for
// each distinct verified token that passes the admission cap (SEC-37). A token
// at two positions gives one event, with the surface of its first position.
// A token with no valid client key gets no event. A token that the cap
// refuses gets no event. It adds one to the counter of capped tokens. The
// first such token goes to sess for the request event. No event, error or
// count holds a text.
func (h *Handler) callbackEvents(r *http.Request, sess *reqSession, e *entry, code int, texts [token.Positions]string) {
	if h.ring == nil {
		return
	}
	res := h.ring.Check(texts)
	var seen [token.Positions]string
	st := int64(code)
	var key netip.Addr
	var haveKey bool
	for i, rs := range res {
		if !rs.OK {
			continue
		}
		tok, _ := token.Parse(texts[i])
		id := token.ID(tok)
		if slices.Contains(seen[:i], id) {
			continue
		}
		seen[i] = id
		if !haveKey {
			if a, err := netip.ParseAddr(sess.ip); err == nil {
				key, haveKey = event.CounterKey(a)
			}
			if !haveKey {
				return
			}
		}
		if !h.admit.allow(id, key, h.mono()) {
			h.capped.Add(1)
			if sess.capped.token == "" {
				sess.capped.trap, sess.capped.token, sess.capped.surface = rs.Trap, id, surfaces[i]
			}
			continue
		}
		var d event.Detail
		if rs.Stale || rs.Future || rs.Reference {
			d = event.Detail{}
			if rs.Stale {
				d["stale"] = event.Bool(true)
			}
			if rs.Future {
				d["future"] = event.Bool(true)
			}
			if rs.Reference {
				d["reference_seed"] = event.Bool(true)
			}
		}
		ev, err := event.NewEvent(nil, event.Input{
			Kind: event.KindCallback, Session: sess.id, Vhost: e.cb.vhost, Method: r.Method,
			Path: e.route.Path, Status: &st, TrapID: rs.Trap, TokenID: id,
			Surface: surfaces[i], Detail: d, ClientIP: sess.ip,
			Link: &event.CallbackLink{SetID: rs.SetID, Unit: rs.Unit, Counter: rs.Counter},
		})
		if err != nil {
			h.eventErrs.Add(1)
			continue
		}
		h.q.Enqueue(ev)
	}
}
