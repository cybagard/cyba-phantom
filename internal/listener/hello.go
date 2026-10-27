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

func getOrHead(m string) bool { return m == http.MethodGet || m == http.MethodHead }

// decide makes the choice of both handlers for the Host and method of r. It
// returns the configured name, the status code and the body. A Host that is not
// configured gets 404. Else a method other than GET and HEAD gets 405. Else the
// code is 200.
func (n names) decide(r *http.Request) (name string, code int, body string) {
	name, ok := n.match(r.Host)
	switch {
	case !ok:
		return "", http.StatusNotFound, notFoundBody
	case !getOrHead(r.Method):
		return name, http.StatusMethodNotAllowed, methodBody
	}
	return name, http.StatusOK, helloBody
}

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

// ServeHTTP writes the fixed page for the Host and method of r: 200 for a
// configured name with GET or HEAD, 405 for another method, else 404. It
// records one request event with the status code that it writes.
func (h *HelloHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	_, code, body := h.names.decide(r)
	h.rec.record(r, code)
	reply(w, code, body)
}

// Redirect is the handler of the plain HTTP socket. It writes no event.
type Redirect struct{ names names }

// NewRedirect returns the handler for the configured names (acme.names).
func NewRedirect(list []string) *Redirect { return &Redirect{names: newNames(list)} }

// ServeHTTP writes a 308 to the https form of the path for a configured name
// with GET or HEAD, 405 for another method, else 404. It writes no event.
func (h *Redirect) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	name, code, body := h.names.decide(r)
	if code != http.StatusOK {
		reply(w, code, body)
		return
	}
	w.Header().Set("Location", location(name, r.URL))
	w.WriteHeader(http.StatusPermanentRedirect)
}

// location makes the target of a redirect: the configured name and the path of
// u with its escapes kept. It has no query. It never decodes an escape, so a
// %2F stays %2F. It is at most maxLocation bytes, and a cut never splits a
// token.
//
// The source is RawPath when it is set, else Path. In RawPath, a '%' with two
// hex digits is one token, and the code writes its digits in upper case. The
// code copies '/'. It writes each other byte as url.PathEscape writes that
// byte alone. So a '%' that starts no valid escape, and each '%' of Path, gives
// "%25".
func location(name string, u *url.URL) string {
	src, raw := u.RawPath, u.RawPath != ""
	if !raw {
		src = u.Path
	}
	// A token is as long as the source bytes that it takes or longer. So the
	// first maxLocation bytes of the source are enough.
	if len(src) > maxLocation {
		src = src[:maxLocation]
	}
	var b strings.Builder
	// A source byte makes at most 3 bytes. The code adds at most one '/'.
	b.Grow(min(maxLocation, len("https://")+len(name)+1+3*len(src)))
	b.WriteString("https://")
	b.WriteString(name)
	if !strings.HasPrefix(src, "/") {
		b.WriteByte('/')
	}
	var tok [3]byte
	for i := 0; i < len(src); {
		step, t := 1, tok[:1]
		switch c := src[i]; {
		case c == '/':
			tok[0] = c
		case c == '%' && raw && i+2 < len(src) && isHex(src[i+1]) && isHex(src[i+2]):
			step, t = 3, tok[:3]
			tok = [3]byte{'%', upperHex(src[i+1]), upperHex(src[i+2])}
		default:
			if keptByte(c) {
				tok[0] = c
			} else {
				t = tok[:3]
				tok = [3]byte{'%', hexDigits[c>>4], hexDigits[c&15]}
			}
		}
		if b.Len()+len(t) > maxLocation {
			break
		}
		b.Write(t)
		i += step
	}
	return b.String()
}

const hexDigits = "0123456789ABCDEF"

// keptByte reports whether url.PathEscape writes c as it is: a letter, a digit
// or one of "-._~$&+:=@".
func keptByte(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' ||
		strings.IndexByte("-._~$&+:=@", c) >= 0
}

func isHex(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

func upperHex(c byte) byte {
	if c >= 'a' {
		return c - ('a' - 'A')
	}
	return c
}
