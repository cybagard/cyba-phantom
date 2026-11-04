package bait

import (
	"errors"
	"net/http"

	"github.com/cybagard/cyba-phantom/internal/bundle"
)

// maxResponse is the most body bytes of one response (SEC-32).
const maxResponse = 1 << 20

// placeholder is the token text until the engine mints real tokens. It holds
// only printable ASCII, with no "--" and no "<", so `comment` keeps it.
const placeholder = "placeholder-token"

// placeholderToken is the token seam. It takes no request value.
func placeholderToken() string { return placeholder }

// errOverCap is the error of a write that would pass maxResponse.
var errOverCap = errors.New("bait: response over the cap")

// capWriter streams a page to the response. It starts the response at the
// first byte. So an error before that byte can still give the fixed 404 page.
// It refuses a write that would take the page over maxResponse.
type capWriter struct {
	w       http.ResponseWriter
	h       *Handler
	e       *entry
	sess    *reqSession
	code    int // the status of the page
	n       int
	started bool
	over    bool
}

func (c *capWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(p) > maxResponse-c.n {
		c.over = true
		return 0, errOverCap
	}
	c.start()
	n, err := c.w.Write(p)
	c.n += n
	return n, err
}

// start writes the slot headers, the cookie of a new session and the status of
// the page one time. An error page never gets here, so it has neither.
func (c *capWriter) start() {
	if !c.started {
		c.started = true
		hd := c.w.Header()
		c.h.addSlots(hd, c.e)
		c.sess.setCookie(hd)
		c.w.WriteHeader(c.code)
	}
}

// render runs the template of e and streams the page with the status code. It
// returns the status that it wrote. The data is the trap text map of the site.
// The site makes it one time, so it holds no request value and a request
// allocates no map for it. An error counts one time. Before the first byte,
// and not over the cap, the response is the fixed 404 page. Else the
// connection closes: render then writes the event, with the status of the
// first byte or none, and panics. The panic with ErrAbortHandler also keeps the
// stack out of the server log. No error text goes anywhere.
func (h *Handler) render(w http.ResponseWriter, r *http.Request, b *bundle.Bundle, s *site, sess *reqSession, e *entry, code int) int {
	hd := w.Header()
	hd["Content-Type"] = e.ctype
	hd["X-Content-Type-Options"] = nosniff
	cw := capWriter{w: w, h: h, e: e, sess: sess, code: code}
	err := b.Execute(&cw, e.route.Template, bundle.Page{Trap: s.texts})
	if err == nil {
		cw.start()
		return code
	}
	h.execErrs.Add(1)
	if cw.started || cw.over {
		written := 0
		if cw.started {
			written = code
		}
		h.record(r, sess, written)
		panic(http.ErrAbortHandler)
	}
	reply(w, http.StatusNotFound, notFoundBody)
	return http.StatusNotFound
}
