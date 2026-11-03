package bait

import (
	"bufio"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"weak"

	"github.com/cybagard/cyba-phantom/internal/bundle"
	"github.com/cybagard/cyba-phantom/internal/event"
	"github.com/cybagard/cyba-phantom/internal/listener"
)

// swap is a source that counts the calls of Current. Call n gives list[n], and
// the last bundle after the end of the list.
type swap struct {
	list  []*bundle.Bundle
	calls int
}

func (s *swap) Current() *bundle.Bundle {
	i := min(s.calls, len(s.list)-1)
	s.calls++
	if i < 0 {
		return nil
	}
	return s.list[i]
}

// raw parses the text of a request with the net/http parser.
func raw(tb testing.TB, req string) *http.Request {
	tb.Helper()
	r, err := http.ReadRequest(bufio.NewReader(strings.NewReader(req)))
	mustOK(tb, err)
	return r
}

func get(target, host string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.URL.Path, r.URL.RawPath, r.Host = target, "", host
	return r
}

func serve(tb testing.TB, h http.Handler, r *http.Request) *httptest.ResponseRecorder {
	tb.Helper()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func newHandler(tb testing.TB) *Handler {
	return New(&swap{list: []*bundle.Bundle{newBundle(tb)}}, &fallbackFn{})
}

// helloHandler returns the listener handler for example.com.
func helloHandler(tb testing.TB) *listener.HelloHandler {
	q, err := event.NewQueue(event.MinQueueDepth, event.NewCounters())
	mustOK(tb, err)
	return listener.NewHelloHandler([]string{"example.com"}, q)
}

const notFoundPage = "not found\n"

// wantFixed checks the fixed 404 page: bytes and the exact header map.
func wantFixed(t *testing.T, name string, w *httptest.ResponseRecorder) {
	t.Helper()
	want := http.Header{"Content-Type": {text}, "X-Content-Type-Options": {"nosniff"}}
	if w.Code != 404 || w.Body.String() != notFoundPage || !reflect.DeepEqual(w.Header(), want) {
		t.Errorf("%s: code %d body %q header %v, want the fixed 404 page", name, w.Code, w.Body.String(), w.Header())
	}
}

// TestTU20FixedPages compares the fixed 404 and 405 pages with the listener
// pages. It checks the status, the body and the exact header map.
func TestTU20FixedPages(t *testing.T) {
	h, hello := newHandler(t), helloHandler(t)
	for _, c := range []struct {
		code         int
		method, host string
	}{
		{404, http.MethodGet, "other.example"},
		{405, http.MethodPost, "example.com"},
	} {
		req := func() *http.Request {
			r := get("/", c.host)
			r.Method = c.method
			return r
		}
		got, want := serve(t, h, req()), serve(t, hello, req())
		if want.Code != c.code {
			t.Fatalf("listener code %d, want %d", want.Code, c.code)
		}
		if got.Code != want.Code || got.Body.String() != want.Body.String() ||
			!reflect.DeepEqual(got.Header(), want.Header()) {
			t.Errorf("%d page: code %d body %q header %v, want body %q header %v",
				c.code, got.Code, got.Body.String(), got.Header(), want.Body.String(), want.Header())
		}
	}
}

// TestTU20NewNil checks that New refuses a nil source and a nil fallback.
func TestTU20NewNil(t *testing.T) {
	fb := &fallbackFn{}
	for name, f := range map[string]func(){
		"nil fallback": func() { New(&swap{}, nil) },
		"nil source":   func() { New(nil, fb) },
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: New did not panic", name)
				}
			}()
			f()
		}()
	}
}

// TestTU20Host checks the host rule: a port and A-Z are cut or folded. A
// trailing dot, a byte of 0x80 or more and an unknown host get the fixed 404
// page. The Kelvin sign (U+212A, bytes E2 84 AA) lower-cases to k, so a
// Unicode fold would match kilo.example.
func TestTU20Host(t *testing.T) {
	h := newHandler(t)
	for _, c := range []struct{ host, want string }{
		{"example.com", "<p>index</p>\n"},
		{"EXAMPLE.com:443", "<p>index</p>\n"},
		{"Example.Com", "<p>index</p>\n"},
		{"kilo.example:8080", "kilo\n"},
		{"Kilo.example", "kilo\n"},
		{"example.com:", "<p>index</p>\n"},
		{"example.com:9", "<p>index</p>\n"},
		{"example.com:8089", "<p>index</p>\n"},
		{"ZULU.example", "zulu\n"},
		{"zuLu.Example:9", "zulu\n"},
		{"example.com.", ""},
		{"example.com.:443", ""},
		{"other.example", ""},
		{"", ""},
		{"\xe2\x84\xaailo.example", ""},
		{"kilo.example\xc3\xa9", ""},
	} {
		w := serve(t, h, raw(t, "GET / HTTP/1.1\r\nHost: "+c.host+"\r\n\r\n"))
		if c.want == "" {
			wantFixed(t, c.host, w)
		} else if w.Code != 200 || w.Body.String() != c.want {
			t.Errorf("host %q: code %d body %q, want %q", c.host, w.Code, w.Body.String(), c.want)
		}
	}
	// The absolute form gives the host of the request line.
	for _, c := range []struct{ line, host, want string }{
		{"http://example.com/", "other.example", "<p>index</p>\n"},
		{"http://other.example/", "example.com", ""},
		{"http://EXAMPLE.com:80/b", "x.example", "route b\n"},
		{"http://\xe2\x84\xaailo.example/", "kilo.example", ""},
	} {
		w := serve(t, h, raw(t, "GET "+c.line+" HTTP/1.1\r\nHost: "+c.host+"\r\n\r\n"))
		if c.want == "" {
			wantFixed(t, c.line, w)
		} else if w.Body.String() != c.want {
			t.Errorf("%s: body %q, want %q", c.line, w.Body.String(), c.want)
		}
	}
}

// TestTU20HostLength checks the fold of a host of 253 bytes and of 254 bytes.
// A host of 253 bytes is the longest vhost name. A bundle archive cannot hold
// that name, as the tar name field is too short. So the test calls foldHost.
func TestTU20HostLength(t *testing.T) {
	rep := strings.Repeat
	long := "Z" + rep("a", 62) + "." + rep("B", 63) + "." + rep("c", 63) + "." + rep("D", 61)
	if len(long) != maxHost {
		t.Fatalf("test host has %d bytes", len(long))
	}
	var buf [maxHost]byte
	got, ok := foldHost(long+":8089", &buf)
	if want := strings.ToLower(long); !ok || string(got) != want {
		t.Errorf("253 bytes with a port: ok %v, got %q", ok, got)
	}
	if got, ok := foldHost(long+"d", &buf); ok {
		t.Errorf("254 bytes: ok, got %q", got)
	}
}

// TestTU20Path checks the path rule. An escape form never reaches a route that
// a decode or a clean would reach.
func TestTU20Path(t *testing.T) {
	h := newHandler(t)
	for _, c := range []struct{ target, want string }{
		{"/", "<p>index</p>\n"},
		{"/a/b", "route a/b\n"},
		{"/b", "route b\n"},
		{"/x", "route x\n"},
		{"/secrets/token.seed", "route note\n"},
		{"/x?y=1", "route x\n"},
		{"/a/../b", ""},
		{"/a/./b", ""},
		{"/%2e%2e/secrets/token.seed", ""},
		{"/%2E%2E/b", ""},
		{"/a%00b", ""},
		{"/a%2Fb", ""},
		{"/a%2fb", ""},
		{"/%62", ""},
		{"//x", ""},
		{"/x/", ""},
		{"/X", ""},
		{"*", ""},
		{"/{{.T}}", ""},
	} {
		w := serve(t, h, raw(t, "GET "+c.target+" HTTP/1.1\r\nHost: example.com\r\n\r\n"))
		if c.want == "" {
			wantFixed(t, c.target, w)
		} else if w.Code != 200 || w.Body.String() != c.want {
			t.Errorf("path %q: code %d body %q, want %q", c.target, w.Code, w.Body.String(), c.want)
		}
	}
}

// TestTU20Assets checks the bytes, type and headers of each asset route.
// HEAD gives the same headers and no body.
func TestTU20Assets(t *testing.T) {
	h := newHandler(t)
	for _, rt := range exampleRoutes {
		if rt.file == "t.tmpl" {
			continue
		}
		for _, m := range []string{http.MethodGet, http.MethodHead} {
			w := serve(t, h, raw(t, m+" "+rt.path+" HTTP/1.1\r\nHost: example.com\r\n\r\n"))
			body := rt.body
			if m == http.MethodHead {
				body = ""
			}
			want := http.Header{
				"Content-Type":           {rt.typ},
				"X-Content-Type-Options": {"nosniff"},
				"Content-Length":         {strconv.Itoa(len(rt.body))},
			}
			if w.Code != 200 || w.Body.String() != body || !reflect.DeepEqual(w.Header(), want) {
				t.Errorf("%s %s: code %d body %q header %v, want header %v", m, rt.path, w.Code, w.Body.String(), w.Header(), want)
			}
		}
	}
}

// TestTS02NeverServed checks an archive file that no route names. It gets the
// fixed 404 page, also when the path names the file.
func TestTS02NeverServed(t *testing.T) {
	h := newHandler(t)
	for _, c := range []struct{ host, target string }{
		{"example.com", "/routes.json"},
		{"example.com", "/unrouted.txt"},
		{"example.com", "/only.txt"},
		{"example.com", "/kilo.txt"},
		{"example.com", "/vhosts/example.com/routes.json"},
		{"example.com", "/vhosts/example.com/unrouted.txt"},
		{"example.com", "/vhosts/kilo.example/only.txt"},
		{"example.com", "/vhosts/kilo.example/routes.json"},
		{"example.com", "/manifest.json"},
		{"example.com", "/traps/traps.json"},
		{"kilo.example", "/vhosts/example.com/index.html"},
		{"kilo.example", "/secrets/token.seed"},
		{"kilo.example", "/manifest.json"},
		{"kilo.example", "/traps/traps.json"},
		{"kilo.example", "/routes.json"},
		{"kilo.example", "/only.txt"},
		{"example.com", "/score/a"},
		{"example.com", "/fp/a"},
		{"kilo.example", "/score/a"},
		{"kilo.example", "/fp/a"},
	} {
		wantFixed(t, c.host+c.target, serve(t, h, get(c.target, c.host)))
	}
}

// TestTU20OneBundle checks that a request calls Current one time, and that the
// response comes from that bundle. The source gives another bundle after the
// first call.
func TestTU20OneBundle(t *testing.T) {
	first, second := bundleWith(t, ""), bundleWith(t, "-second")
	src := &swap{list: []*bundle.Bundle{first, second}}
	h := New(src, &fallbackFn{})
	for i, want := range []string{"<p>index</p>\n", "<p>index-second</p>\n"} {
		w := serve(t, h, get("/", "example.com"))
		if src.calls != i+1 || w.Body.String() != want {
			t.Fatalf("request %d: %d calls, body %q, want %q", i+1, src.calls, w.Body.String(), want)
		}
	}
	if st := h.sites.Load(); st.cur.b != second || st.retired[0] != weak.Make(first) {
		t.Error("the handler keeps a bundle that is not the last, or does not retire the first")
	}
}

// fallbackFn marks the calls of the fallback handler.
type fallbackFn struct{ calls int }

func (f *fallbackFn) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	f.calls++
	w.WriteHeader(http.StatusTeapot)
}

// TestTU20NoBundle checks that the fallback handler serves with no bundle. The
// first case uses a fake fallback. The second uses the hello handler.
func TestTU20NoBundle(t *testing.T) {
	fb := &fallbackFn{}
	h := New(&swap{}, fb)
	if w := serve(t, h, get("/", "example.com")); w.Code != http.StatusTeapot || fb.calls != 1 {
		t.Errorf("code %d, fallback calls %d", w.Code, fb.calls)
	}

	h = New(&swap{}, helloHandler(t))
	w := serve(t, h, get("/", "example.com"))
	if w.Code != 200 || w.Body.String() != "hello\n" || w.Header().Get("Content-Type") != text ||
		w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("hello GET: code %d body %q header %v", w.Code, w.Body.String(), w.Header())
	}
	r := get("/", "example.com")
	r.Method = http.MethodPost
	if w := serve(t, h, r); w.Code != 405 || w.Header().Get("Allow") != "GET, HEAD" {
		t.Errorf("hello POST: code %d header %v", w.Code, w.Header())
	}
}

// TestTU20TemplateRoute checks that a template route gets the fixed 404 page
// until the render step exists.
func TestTU20TemplateRoute(t *testing.T) {
	wantFixed(t, "/t", serve(t, newHandler(t), get("/t", "example.com")))
}

// countBody counts the reads of a request body.
type countBody struct{ calls int }

func (c *countBody) Read([]byte) (int, error) {
	c.calls++
	return 0, io.EOF
}

func (c *countBody) Close() error { return nil }

// TestTS02Method checks the methods other than GET and HEAD. They get the
// fixed 405 page with Allow, and the handler reads no body byte. The host
// check comes first, so an unknown host gets the 404 page. GET and HEAD read no
// body byte either.
func TestTS02Method(t *testing.T) {
	h := newHandler(t)
	for _, m := range []string{http.MethodGet, http.MethodHead} {
		for _, target := range []string{"/style.css", "/nope", "/t"} {
			body := &countBody{}
			r := get(target, "example.com")
			r.Method, r.Body = m, body
			serve(t, h, r)
			if body.calls != 0 {
				t.Errorf("%s %s: %d body reads", m, target, body.calls)
			}
		}
	}
	for _, m := range []string{"POST", "PUT", "DELETE", "OPTIONS", "PATCH", "TRACE", "get"} {
		for _, target := range []string{"/", "/t", "/nope", "/a%2Fb"} {
			body := &countBody{}
			r := get(target, "example.com")
			r.Method, r.Body = m, body
			w := serve(t, h, r)
			hd := w.Header()
			if w.Code != 405 || w.Body.String() != "method not allowed\n" || hd.Get("Allow") != "GET, HEAD" ||
				hd.Get("Content-Type") != text || hd.Get("X-Content-Type-Options") != "nosniff" {
				t.Errorf("%s %s: code %d body %q header %v", m, target, w.Code, w.Body.String(), hd)
			}
			if body.calls != 0 {
				t.Errorf("%s %s: %d body reads", m, target, body.calls)
			}
		}
	}
	r := get("/", "other.example")
	r.Method = http.MethodPost
	wantFixed(t, "unknown host", serve(t, h, r))
	w := serve(t, h, raw(t, "OPTIONS * HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	want := http.Header{"Content-Type": {text}, "X-Content-Type-Options": {"nosniff"}, "Allow": {"GET, HEAD"}}
	if w.Code != 405 || w.Body.String() != "method not allowed\n" || !reflect.DeepEqual(w.Header(), want) {
		t.Errorf("OPTIONS *: code %d body %q header %v, want the fixed 405 page", w.Code, w.Body.String(), w.Header())
	}
}

// discard is a response writer that keeps nothing.
type discard struct{ h http.Header }

func (d *discard) Header() http.Header         { return d.h }
func (d *discard) WriteHeader(int)             {}
func (d *discard) Write(p []byte) (int, error) { return len(p), nil }

func bench(b *testing.B, target, host string) {
	h := newHandler(b)
	r := get(target, host)
	w := &discard{h: http.Header{}}
	b.ReportAllocs()
	for b.Loop() {
		clear(w.h)
		h.ServeHTTP(w, r)
	}
}

func BenchmarkAsset(b *testing.B) { bench(b, "/style.css", "example.com") }

func BenchmarkDecoy404(b *testing.B) { bench(b, "/nope", "Example.COM:443") }
