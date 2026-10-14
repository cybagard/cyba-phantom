package listener

import (
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/cybagard/cyba-phantom/internal/event"
)

// The fixed response bodies. No body holds a value from a request.
const (
	helloBody    = "hello\n"
	notFoundBody = "not found\n"
	methodBody   = "method not allowed\n"
)

// maxLocation is the largest size in bytes of a Location value.
const maxLocation = 2048

// names maps the lower-case form of each configured name to the name as the
// config holds it.
type names map[string]string

func newNames(list []string) names {
	n := make(names, len(list))
	for _, s := range list {
		n[strings.ToLower(s)] = s
	}
	return n
}

// match removes a port from host, changes it to lower case and looks it up. It
// returns the configured name. An unknown form gives false.
func (n names) match(host string) (string, bool) {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	s, ok := n[strings.ToLower(host)]
	return s, ok
}

// reply writes a fixed response and returns its status code. It sets no Server
// header. A HEAD request gets the same headers and no body.
func reply(w http.ResponseWriter, code int, body string) int {
	h := w.Header()
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("X-Content-Type-Options", "nosniff")
	if code == http.StatusMethodNotAllowed {
		h.Set("Allow", "GET, HEAD")
	}
	w.WriteHeader(code)
	_, _ = w.Write([]byte(body))
	return code
}

func readMethod(m string) bool { return m == http.MethodGet || m == http.MethodHead }

// HelloHandler is the handler of the TLS socket. Each request gives one request
// event.
type HelloHandler struct {
	names names
	rec   recorder
}

// NewHelloHandler returns the handler for the configured names (acme.names) and
// the queue that takes the request events.
func NewHelloHandler(list []string, q *event.Queue) *HelloHandler {
	return &HelloHandler{names: newNames(list), rec: recorder{q: q}}
}

// EventErrors is the number of requests for which NewEvent returned an error.
func (h *HelloHandler) EventErrors() uint64 { return h.rec.errs.Load() }

func (h *HelloHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	code, body := http.StatusOK, helloBody
	if _, ok := h.names.match(r.Host); !ok {
		code, body = http.StatusNotFound, notFoundBody
	} else if !readMethod(r.Method) {
		code, body = http.StatusMethodNotAllowed, methodBody
	}
	h.rec.record(r, code)
	reply(w, code, body)
}

// Redirect is the handler of the plain HTTP socket. It writes no event.
type Redirect struct{ names names }

// NewRedirect returns the handler for the configured names (acme.names).
func NewRedirect(list []string) *Redirect { return &Redirect{names: newNames(list)} }

func (h *Redirect) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	name, ok := h.names.match(r.Host)
	switch {
	case !ok:
		reply(w, http.StatusNotFound, notFoundBody)
	case !readMethod(r.Method):
		reply(w, http.StatusMethodNotAllowed, methodBody)
	default:
		w.Header().Set("Location", location(name, r.URL.Path))
		w.WriteHeader(http.StatusPermanentRedirect)
	}
}

// location makes the target of a redirect: the configured name and the path
// with each segment escaped. It has no query. It is at most maxLocation bytes,
// and a cut never splits a %XX escape.
func location(name, path string) string {
	segs := strings.Split(path, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	p := strings.Join(segs, "/")
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	loc := "https://" + name + p
	if len(loc) > maxLocation {
		loc = loc[:maxLocation]
		if loc[maxLocation-1] == '%' {
			loc = loc[:maxLocation-1]
		} else if loc[maxLocation-2] == '%' {
			loc = loc[:maxLocation-2]
		}
	}
	return loc
}
