package bait

import (
	"net/http"
	"slices"
	"strings"

	"github.com/cybagard/cyba-phantom/internal/bundle"
	"github.com/cybagard/cyba-phantom/internal/event"
	"github.com/cybagard/cyba-phantom/internal/token"
)

// callbackPos holds the positions of a callback route, ready to serve. header
// is the canonical header name. The site build makes it, never a request.
type callbackPos struct {
	segment             bool
	query, header, body string
}

func newCallbackPos(c *bundle.Callback) *callbackPos {
	p := &callbackPos{segment: c.Segment, query: c.Query, body: c.Body}
	if c.Header != "" {
		p.header = HeaderName(c.Header)
	}
	return p
}

// surfaces are the surfaces of the positions. The order is the order of the
// texts for Check and of the event rule: path, query, header, body.
var surfaces = [token.Positions]event.Surface{
	event.SurfacePath, event.SurfaceQuery, event.SurfaceHeader, event.SurfaceBody,
}

// SetRing sets the ring that verifies the tokens of the callback routes. With
// no ring, a callback route gives its fixed response and no callback event.
// Call it before the first request. It is not safe to call it later.
func (h *Handler) SetRing(r *token.Ring) { h.ring = r }

// callbackEntry gives the callback route for the escaped path p. The exact
// path comes first. Else a route with a segment position matches its path, "/"
// and one segment. A path that no callback route matches gives nil.
func callbackEntry(routes map[string]*entry, p string) *entry {
	if e := routes[p]; e != nil {
		return e
	}
	i := strings.LastIndexByte(p, '/')
	if i < 0 {
		return nil
	}
	if e := routes[max(p[:i], "/")]; e != nil && e.cb != nil && e.cb.segment {
		return e
	}
	return nil
}

// callback answers a request for the callback route e. It reads the candidates
// and the body, writes the fixed response and flushes it. Only then it checks
// the tokens and builds the events. The response code reads no token result,
// so each result gives the same bytes. The route sets no cookie.
func (h *Handler) callback(w http.ResponseWriter, r *http.Request, sess *reqSession, e *entry) int {
	var texts [token.Positions]string
	cb := e.cb
	if cb.segment {
		texts[0] = PathCandidate(r.URL.EscapedPath(), e.route.Path)
	}
	if cb.query != "" {
		texts[1] = QueryCandidate(r.URL.RawQuery, cb.query)
	}
	if cb.header != "" {
		texts[2] = HeaderCandidate(r.Header, cb.header)
	}
	if cb.body != "" {
		if c, ok := BodyCandidate(r, cb.body); ok {
			texts[3] = string(c[:])
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

// callbackEvents checks the texts and puts one callback event on the queue for
// each distinct verified token. A token at two positions gives one event, with
// the surface of its first position. No event, error or count holds a text.
func (h *Handler) callbackEvents(r *http.Request, sess *reqSession, e *entry, code int, texts [token.Positions]string) {
	if h.ring == nil {
		return
	}
	res := h.ring.Check(texts)
	var seen [token.Positions]string
	st := int64(code)
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
			Kind: event.KindCallback, Session: sess.id, Vhost: r.Host, Method: r.Method,
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
