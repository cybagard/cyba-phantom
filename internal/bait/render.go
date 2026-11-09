package bait

import (
	"errors"
	"net/http"

	"github.com/cybagard/cyba-phantom/internal/bundle"
	"github.com/cybagard/cyba-phantom/internal/event"
	"github.com/cybagard/cyba-phantom/internal/token"
)

// maxResponse is the most body bytes of one response (SEC-32).
const maxResponse = 1 << 20

// minted is what one response gets from its mint. It has the trap texts for
// the template and the header slots with a valid value. It also has the number
// of slots left out.
type minted struct {
	page  bundle.Page
	slots []slotHeader
	left  int
	// planned is true when the page renders from its plan. Then toks has the
	// token text of each action and page has no trap texts.
	planned bool
	toks    [maxActs]string
}

// mint gives the trap texts and the header slots of one response of e. It
// reserves the tokens of all trap actions and header slots with one MintRange
// call. The call uses the key set of b and the time of the request. The range
// goes on sess for the request event. A mint that fails counts one in noKeys.
// So does a bundle with no key set. Then each trap text is "" and no header
// slot is set. The response is still served (C3). No token text goes anywhere
// but into the response.
func (h *Handler) mint(b *bundle.Bundle, s *site, e *entry, sess *reqSession) (m minted) {
	m.left = e.left
	acts := len(e.acts)
	n := acts + len(e.slots)
	m.planned = e.plan != nil
	if n == 0 {
		return m
	}
	if acts > 0 && !m.planned {
		m.page.Trap = make(map[string]string, acts)
	}
	var out [token.MaxRange][token.Size]byte
	// idx joins the action indexes and the slot indexes in one array on the
	// stack. e.acts is shared, so the mint reads it and never changes it.
	var idx [token.MaxRange]int
	ks := h.keys(b)
	// A loaded bundle has at most 64 trap actions and 4 header slots, so n
	// is never over token.MaxRange here.
	failed := n > token.MaxRange
	var first uint64
	if !failed {
		var err error
		copy(idx[:], e.acts)
		copy(idx[acts:], e.slots)
		first, err = ks.MintRange(idx[:n], sess.at, out[:n])
		failed = err != nil
	}
	if failed {
		h.noKeys.Add(1)
		// A page with empty trap texts has no token for its plan. It renders
		// with Execute.
		if m.planned {
			m.unplan(s, e.acts, 0)
		}
		for _, i := range e.acts {
			m.page.Trap[s.traps[i].ID] = ""
		}
		return m
	}
	// Verify of the first token gives the time unit of the mint. The unit
	// formula stays in internal/token.
	unit := token.Verify([]*token.KeySet{ks}, out[0]).Unit
	sum := b.SHA256()
	sess.mint = event.MintRange{Unit: unit, Count: uint8(n), First: first, IssuedAt: sess.at.UnixMilli()}
	copy(sess.mint.SetID[:], sum[:])
	for i, ix := range idx[:n] {
		t := h.text(out[i])
		if i < acts {
			if m.planned && len(t) > maxTokText {
				// This is no token, as a token text has 26 bytes. The page
				// renders with Execute, so its writes stay those of Execute.
				m.unplan(s, e.acts, i)
			}
			if m.planned {
				m.toks[i] = t
			} else {
				m.page.Trap[s.traps[ix].ID] = s.traps[ix].Render(t)
			}
			continue
		}
		v := s.traps[ix].Render(t)
		if validSlotValue(v) {
			m.slots = append(m.slots, slotHeader{e.names[i-acts], []string{v}})
		} else {
			m.left++
		}
	}
	return m
}

// unplan turns a plan page into a page for Execute. It makes the trap text map.
// The first done actions get the text of their tokens in toks.
func (m *minted) unplan(s *site, acts []int, done int) {
	m.planned = false
	m.page.Trap = make(map[string]string, len(acts))
	for j := range done {
		t := s.traps[acts[j]]
		m.page.Trap[t.ID] = t.Render(m.toks[j])
	}
}

// errOverCap is the error of a write that would pass maxResponse.
var errOverCap = errors.New("bait: response over the cap")

// capWriter streams a page to the response. It starts the response at the
// first byte. So an error before that byte can still give the fixed 404 page.
// It refuses a write that would take the page over maxResponse.
type capWriter struct {
	w       http.ResponseWriter
	h       *Handler
	m       minted
	sess    *reqSession
	code    int // the status of the page
	n       int
	started bool
	over    bool
	// scratch holds a short token text for writeString, so a plan page copies
	// a token with no allocation.
	scratch [maxTokText]byte
}

// writeString is Write for a string. It copies a short text into scratch. It
// converts a longer text.
func (c *capWriter) writeString(s string) error {
	if len(s) > len(c.scratch) {
		_, err := c.Write([]byte(s))
		return err
	}
	_, err := c.Write(c.scratch[:copy(c.scratch[:], s)])
	return err
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
		c.h.addSlots(hd, &c.m)
		c.sess.setCookie(hd)
		c.w.WriteHeader(c.code)
	}
}

// render streams the page of e with the status code. A template with a plan
// writes the fixed bytes and the token texts. Else it runs the template, and a
// template with no plan counts one in noPlan. It returns the status that it
// wrote. For a page with no plan, the data is the trap text map of the mint of
// this response. It holds no request value. An error counts one time.
// Before the first byte, and not over the cap, the response is the fixed 404
// page. Then the event keeps the mint range. Else the connection closes. Render
// then writes the event, with the status of the first byte or none and the
// mint range, and panics. The panic with ErrAbortHandler also keeps the stack
// out of the server log. No error text goes anywhere.
func (h *Handler) render(w http.ResponseWriter, r *http.Request, b *bundle.Bundle, s *site, sess *reqSession, e *entry, code int) int {
	hd := w.Header()
	hd["Content-Type"] = e.ctype
	hd["X-Content-Type-Options"] = nosniff
	if h.mintHook != nil {
		h.mintHook()
	}
	cw := capWriter{w: w, h: h, m: h.mint(b, s, e, sess), sess: sess, code: code}
	var err error
	if cw.m.planned {
		err = e.plan.write(&cw, &cw.m.toks)
	} else {
		if e.plan == nil {
			h.noPlan.Add(1)
		}
		err = b.Execute(&cw, e.route.Template, cw.m.page)
	}
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
