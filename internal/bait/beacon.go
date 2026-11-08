package bait

import (
	"io"
	"net/http"
	"strconv"

	"github.com/cybagard/cyba-phantom/internal/event"
)

// The script has 27 fixed bytes, the post path and the ticket.
const (
	scriptHead = `navigator.sendBeacon("`
	scriptMid  = `","`
	scriptTail = `")`
	// ticketLen is the size of a ticket. A route path has at most 256 bytes.
	ticketLen     = 26
	beaconBodyMax = 64 // the most body bytes that the post path reads
	scriptMax     = len(scriptHead) + 256 + len(scriptMid) + ticketLen + len(scriptTail)
)

// Header values of the beacon responses. Do not change an element.
var (
	jsType    = []string{"text/javascript; charset=utf-8"}
	noStore   = []string{"no-store"}
	allowPost = []string{"POST"}
)

// beacon holds the two paths of a vhost, ready to serve. The paths are not
// routes. vhost is the vhost name of the bundle.
type beacon struct{ script, post, vhost string }

// serveBeacon answers a request for a beacon path of bp. It returns false for
// each other path. The script path accepts GET and HEAD. The post path accepts
// POST. Each other method gets the fixed 405 page and no body byte is read.
func (h *Handler) serveBeacon(w http.ResponseWriter, r *http.Request, sess *reqSession, bp *beacon) (int, bool) {
	switch r.URL.EscapedPath() {
	case bp.script:
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			replyAllow(w, http.StatusMethodNotAllowed, methodBody, allow)
			return http.StatusMethodNotAllowed, true
		}
		return beaconScript(w, r, sess, bp), true
	case bp.post:
		if r.Method != http.MethodPost {
			replyAllow(w, http.StatusMethodNotAllowed, methodBody, allowPost)
			return http.StatusMethodNotAllowed, true
		}
		return h.beaconPost(w, r, sess, bp), true
	}
	return 0, false
}

// beaconScript writes the script. It holds the post path, the ticket of the
// session and fixed bytes, and no request byte. A request with no session id
// gets an empty ticket, so its POST gives no event. The script sets no cookie.
// The ticket uses the one clock read of the request.
func beaconScript(w http.ResponseWriter, r *http.Request, sess *reqSession, bp *beacon) int {
	var buf [scriptMax]byte
	b := append(buf[:0], scriptHead...)
	b = append(b, bp.post...)
	b = append(b, scriptMid...)
	b = append(b, sess.key.BeaconTicket(sess.id, sess.at)...)
	b = append(b, scriptTail...)
	hd := w.Header()
	hd["Content-Type"] = jsType
	hd["Cache-Control"] = noStore
	hd["X-Content-Type-Options"] = nosniff
	hd["Content-Length"] = []string{strconv.Itoa(len(b))}
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = w.Write(b)
	}
	return http.StatusOK
}

// beaconPost reads at most beaconBodyMax body bytes. Then it writes the fixed
// 204 and flushes it. Only then it checks the ticket and makes the event. The
// check result changes no response byte. The route sets no cookie.
func (h *Handler) beaconPost(w http.ResponseWriter, r *http.Request, sess *reqSession, bp *beacon) int {
	// A body is a ticket only when the read ends at EOF with exactly ticketLen
	// bytes. No trim and no decode.
	var buf [beaconBodyMax]byte
	n := 0
	var err error
	if r.Body != nil && r.ContentLength <= beaconBodyMax {
		for n < len(buf) && err == nil {
			var m int
			m, err = r.Body.Read(buf[n:])
			n += m
		}
	}
	isTicket := n == ticketLen && err == io.EOF
	w.Header()["X-Content-Type-Options"] = nosniff
	w.WriteHeader(http.StatusNoContent)
	_ = http.NewResponseController(w).Flush()
	if isTicket && sess.key.CheckBeaconTicket(string(buf[:n]), sess.id, sess.at) {
		st := int64(http.StatusNoContent)
		e, err := event.NewEvent(nil, event.Input{
			Kind: event.KindBeacon, Session: sess.id, Vhost: bp.vhost, Method: r.Method,
			Path: bp.post, Status: &st, ClientIP: sess.ip,
		})
		if err != nil {
			h.eventErrs.Add(1)
		} else {
			h.q.Enqueue(e)
		}
	}
	return http.StatusNoContent
}
