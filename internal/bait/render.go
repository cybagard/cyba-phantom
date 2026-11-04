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

// start writes the 200 status one time.
func (c *capWriter) start() {
	if !c.started {
		c.started = true
		c.w.WriteHeader(http.StatusOK)
	}
}

// trapTexts gives the text of each trap for one page. Each text is the
// instruction of the trap with token, and the page escapes it later.
func trapTexts(traps []bundle.Trap, token string) map[string]string {
	m := make(map[string]string, len(traps))
	for _, t := range traps {
		m[t.ID] = t.Render(token)
	}
	return m
}

// render runs the template of e and streams the page. The data holds no
// request value. An error counts one time. Before the first byte, and not over
// the cap, the response is the fixed 404 page. Else the connection closes. The
// panic with ErrAbortHandler also keeps the stack out of the server log. No
// error text goes anywhere.
func (h *Handler) render(w http.ResponseWriter, b *bundle.Bundle, s *site, e *entry) {
	hd := w.Header()
	hd["Content-Type"] = e.ctype
	hd["X-Content-Type-Options"] = nosniff
	cw := capWriter{w: w}
	err := b.Execute(&cw, e.route.Template, bundle.Page{Trap: trapTexts(s.traps, h.token())})
	if err == nil {
		cw.start()
		return
	}
	h.execErrs.Add(1)
	if cw.started || cw.over {
		panic(http.ErrAbortHandler)
	}
	reply(w, http.StatusNotFound, notFoundBody)
}
