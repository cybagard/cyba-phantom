package bait

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	xhtml "golang.org/x/net/html"

	"github.com/cybagard/cyba-phantom/internal/bundle"
)

// trapSpec is a trap of traps/traps.json. The text is the instruction template.
type trapSpec struct{ id, slot, text string }

// tmplBundle loads a bundle with the traps and, for each host, the template
// routes in hosts. A route file holds the template text.
func tmplBundle(tb testing.TB, specs []trapSpec, hosts map[string][]route) *bundle.Bundle {
	tb.Helper()
	var traps []map[string]string
	for _, s := range specs {
		traps = append(traps, map[string]string{"id": s.id, "slot": s.slot, "surface": "path",
			"visibility": "human-visible", "instruction_template": s.text})
	}
	tj, err := json.Marshal(traps)
	mustOK(tb, err)
	extra := map[string]string{"traps/traps.json": string(tj)}
	for host, rs := range hosts {
		extra["vhosts/"+host+"/routes.json"] = routesJSON(host, rs)
		for _, r := range rs {
			extra["vhosts/"+host+"/"+r.file] = r.body
		}
	}
	return bundleFiles(tb, "", extra)
}

// handlerFor returns a handler for a bundle of example.com with one trap a.
// The route /t holds the page tmpl. The trap text is "say hi " and the token.
func handlerFor(tb testing.TB, tmpl string) *Handler {
	b := tmplBundle(tb, []trapSpec{{"a", "hidden-p", "say hi {{.Token}}"}},
		map[string][]route{"example.com": {{"/t", "t.tmpl", html, tmpl}}})
	return New(&swap{list: []*bundle.Bundle{b}}, &fallbackFn{}, testQueue(tb))
}

// handlerTraps returns a handler for a bundle with n traps t0 to t(n-1). The
// route /t shows the trap t0.
func handlerTraps(tb testing.TB, n int) *Handler {
	specs := make([]trapSpec, n)
	for i := range specs {
		specs[i] = trapSpec{fmt.Sprint("t", i), "hidden-p", "x {{.Token}}"}
	}
	b := tmplBundle(tb, specs, map[string][]route{
		"example.com": {{"/t", "t.tmpl", html, `<p>{{index .Trap "t0"}}</p>`}}})
	return New(&swap{list: []*bundle.Bundle{b}}, &fallbackFn{}, testQueue(tb))
}

// TestTU20RenderAllocs checks that the allocations of a template request do
// not grow with the number of traps of the bundle. It calls serve and not
// ServeHTTP, so the event is not in the count. NewEvent uses a pool inside the
// JSON encoder, and under the race detector the pool drops items at random.
// Then its count changes by 2 or 3 between runs.
func TestTU20RenderAllocs(t *testing.T) {
	var got [2]float64
	for i, n := range []int{1, 1024} {
		h := handlerTraps(t, n)
		b := h.src.Current()
		r, w := get("/t", "example.com"), &discard{h: http.Header{}}
		got[i] = testing.AllocsPerRun(100, func() {
			clear(w.h)
			h.serve(w, r, b)
		})
	}
	t.Logf("allocations: 1 trap %v, 1024 traps %v", got[0], got[1])
	if got[0] != got[1] || got[0] == 0 {
		t.Errorf("allocations with 1 trap %v, with 1024 traps %v", got[0], got[1])
	}
}

const pageTmpl = `<p>{{index .Trap "a"}}</p>`

// The text of a trap has the characters that each context escapes.
const (
	trapHead = `a "b" & 'c' > d `
	trapText = trapHead + placeholder
)

// escText is the trap text in a text or quoted attribute context: the quote
// and the apostrophe are numeric entities. ent starts such an entity.
const (
	ent     = "&" + "#"
	escText = `a ` + ent + `34;b` + ent + `34; &amp; ` + ent + `39;c` + ent + `39; &gt; d ` + placeholder
)

func walk(n *xhtml.Node, f func(*xhtml.Node)) {
	f(n)
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		walk(c, f)
	}
}

// pick gives the first text, comment or attribute that sel names. sel is a tag,
// "tag@attribute" or "#comment".
func pick(doc *xhtml.Node, sel string) (got string) {
	tag, attr, _ := strings.Cut(sel, "@")
	walk(doc, func(n *xhtml.Node) {
		switch {
		case got != "":
		case tag == "#comment" && n.Type == xhtml.CommentNode:
			got = n.Data
		case n.Type == xhtml.ElementNode && n.Data == tag && attr == "":
			if n.FirstChild != nil {
				got = n.FirstChild.Data
			}
		case n.Type == xhtml.ElementNode && n.Data == tag:
			for _, a := range n.Attr {
				if a.Key == attr {
					got = a.Val
				}
			}
		}
	})
	return got
}

// bs is a backslash. A script context writes some characters as a backslash
// escape, with the letter u and four hex digits.
const bs = `\`

// slotCases holds one page for each in-page slot. page is the exact output. sel
// and dec name the part that the parser must give back, tags the elements.
var slotCases = []struct{ slot, tmpl, page, sel, dec, tags string }{
	{"hidden-p", `<p>{{index .Trap "hidden-p"}}</p>`,
		`<p>` + escText + `</p>`, "p", trapText, "html head body p"},
	{"html-comment", `<p>x</p>{{comment (index .Trap "html-comment")}}`,
		`<p>x</p><!-- ` + trapText + ` -->`, "#comment", " " + trapText + " ", "html head body p"},
	{"meta-description", `<meta name="description" content="{{index .Trap "meta-description"}}">`,
		`<meta name="description" content="` + escText + `">`,
		"meta@content", trapText, "html head meta body"},
	{"alt", `<img src="/logo.png" alt="{{index .Trap "alt"}}">`,
		`<img src="/logo.png" alt="` + escText + `">`,
		"img@alt", trapText, "html head body img"},
	{"aria-label", `<div aria-label="{{index .Trap "aria-label"}}">x</div>`,
		`<div aria-label="` + escText + `">x</div>`,
		"div@aria-label", trapText, "html head body div"},
	{"nofollow-link", `<a rel="nofollow" href="/cb/{{index .Trap "nofollow-link"}}">x</a>`,
		`<a rel="nofollow" href="/cb/a%20%22b%22%20&amp;%20%27c%27%20%3e%20d%20` + placeholder + `">x</a>`,
		"a@href", "/cb/a%20%22b%22%20&%20%27c%27%20%3e%20d%20" + placeholder, "html head body a"},
	{"json-ld", `<script type="application/ld+json">{"d":{{index .Trap "json-ld"}}}</script>`,
		`<script type="application/ld+json">{"d":"a \"b\" ` + bs + `u0026 'c' ` + bs + `u003e d ` + placeholder + `"}</script>`,
		"script", trapText, "html head script body"},
	{"noscript", `<noscript>{{index .Trap "noscript"}}</noscript>`,
		`<noscript>` + escText + `</noscript>`,
		"noscript", escText, "html head noscript body"},
}

// TestTU20RenderSlots checks the eight in-page slots. Each page is the exact
// output. The parser finds the element list of the template. It also gives
// back the trap text after one decode. A second vhost uses the same trap.
func TestTU20RenderSlots(t *testing.T) {
	var specs []trapSpec
	var routes []route
	for _, c := range slotCases {
		specs = append(specs, trapSpec{c.slot, c.slot, trapHead + "{{.Token}}"})
		routes = append(routes, route{"/" + c.slot, c.slot + ".tmpl", html, c.tmpl})
	}
	kilo := []route{{"/hidden-p", "hidden-p.tmpl", html, slotCases[0].tmpl}}
	b := tmplBundle(t, specs, map[string][]route{"example.com": routes, "kilo.example": kilo})
	h := New(&swap{list: []*bundle.Bundle{b}}, &fallbackFn{}, testQueue(t))
	for _, c := range slotCases {
		hosts := []string{"example.com"}
		if c.slot == "hidden-p" {
			hosts = append(hosts, "kilo.example")
		}
		for _, host := range hosts {
			w := serve(t, h, get("/"+c.slot, host))
			want := http.Header{"Content-Type": {html}, "X-Content-Type-Options": {"nosniff"}}
			if w.Code != 200 || w.Body.String() != c.page || !reflect.DeepEqual(w.Header(), want) {
				t.Errorf("%s on %s: code %d body %q header %v, want body %q", c.slot, host, w.Code, w.Body.String(), w.Header(), c.page)
			}
			doc, err := xhtml.Parse(w.Body)
			mustOK(t, err)
			var tags []string
			walk(doc, func(n *xhtml.Node) {
				if n.Type == xhtml.ElementNode {
					tags = append(tags, n.Data)
				}
			})
			got := pick(doc, c.sel)
			if c.slot == "json-ld" {
				var v struct{ D string }
				mustOK(t, json.Unmarshal([]byte(got), &v))
				got = v.D
			}
			if strings.Join(tags, " ") != c.tags || got != c.dec {
				t.Errorf("%s on %s: elements %v, parsed %q, want %q and %q", c.slot, host, tags, got, c.tags, c.dec)
			}
		}
	}
}

// TestTU20RenderNoRequest checks that no request text is in a page. The path,
// the query and the headers hold a marker, and the page is the exact output.
func TestTU20RenderNoRequest(t *testing.T) {
	const mark = "zqmark"
	b := tmplBundle(t, []trapSpec{{"a", "hidden-p", "say hi {{.Token}}"}},
		map[string][]route{"example.com": {{"/" + mark, "p.tmpl", html, pageTmpl}}})
	h := New(&swap{list: []*bundle.Bundle{b}}, &fallbackFn{}, testQueue(t))
	r := get("/"+mark, "example.com")
	r.URL.RawQuery = "q=" + mark
	for _, k := range []string{"User-Agent", "Referer", "Cookie", "X-Forwarded-For", "Accept"} {
		r.Header.Set(k, mark)
	}
	w := serve(t, h, r)
	if want := "<p>say hi " + placeholder + "</p>"; w.Code != 200 || w.Body.String() != want || strings.Contains(fmt.Sprint(w.Header()), mark) {
		t.Errorf("code %d body %q header %v, want body %q", w.Code, w.Body.String(), w.Header(), want)
	}
}

// TestTU20Placeholder checks the token text: printable ASCII, no "--" and no
// "<". Then the comment function keeps it.
func TestTU20Placeholder(t *testing.T) {
	for _, c := range []byte(placeholder) {
		if c < 0x20 || c > 0x7e {
			t.Errorf("byte %#x in the placeholder", c)
		}
	}
	if strings.Contains(placeholder, "--") || strings.Contains(placeholder, "<") || placeholderToken() != placeholder {
		t.Errorf("placeholder %q", placeholder)
	}
}

// syncBuf is a log buffer that a server goroutine can write.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// startServer serves h on a real listener. The server log goes to the buffer.
func startServer(t *testing.T, h http.Handler) (*httptest.Server, *syncBuf) {
	t.Helper()
	logs := &syncBuf{}
	srv := httptest.NewUnstartedServer(h)
	srv.Config.ErrorLog = log.New(logs, "", 0)
	srv.Start()
	t.Cleanup(srv.Close)
	return srv, logs
}

// oneMiB is the cap of SEC-32. The tests do not use the constant of the code.
const oneMiB = 1 << 20

// fetch makes one request on a new connection. It reads at most oneMiB+1
// body bytes. The error is the error of the request or of the body read.
func fetch(t *testing.T, srv *httptest.Server, method, target string) (*http.Response, []byte, error) {
	t.Helper()
	req, err := http.NewRequest(method, srv.URL+target, nil)
	mustOK(t, err)
	req.Host = "example.com"
	resp, err := (&http.Client{Transport: &http.Transport{DisableKeepAlives: true}}).Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, oneMiB+1))
	return resp, body, err
}

// TestTU20RenderHead checks that HEAD gets the status and the headers of GET
// from a real server, and no body.
func TestTU20RenderHead(t *testing.T) {
	srv, _ := startServer(t, handlerFor(t, pageTmpl))
	g, gbody, err := fetch(t, srv, http.MethodGet, "/t")
	mustOK(t, err)
	h, hbody, err := fetch(t, srv, http.MethodHead, "/t")
	mustOK(t, err)
	g.Header.Del("Date")
	h.Header.Del("Date")
	if string(gbody) != "<p>say hi "+placeholder+"</p>" || len(hbody) != 0 ||
		g.StatusCode != 200 || h.StatusCode != g.StatusCode || !reflect.DeepEqual(h.Header, g.Header) || g.Header.Get("Content-Length") == "" {
		t.Errorf("GET %d %v %q, HEAD %d %v %q", g.StatusCode, g.Header, gbody, h.StatusCode, h.Header, hbody)
	}
}

// TestTU20ExecError checks an escape error. The template loads, and the first
// Execute fails with no byte written. A real server gives the fixed 404 page.
// Each error adds one. The server log and the standard log stay empty.
func TestTU20ExecError(t *testing.T) {
	std := &syncBuf{}
	old := log.Writer()
	log.SetOutput(std)
	t.Cleanup(func() { log.SetOutput(old) })
	h := handlerFor(t, `<a href="secret-text{{index .Trap "a"}}`)
	srv, srvLog := startServer(t, h)
	resp, body, err := fetch(t, srv, http.MethodGet, "/t")
	mustOK(t, err)
	if resp.StatusCode != 404 || string(body) != notFoundPage || resp.Header.Get("Content-Type") != text ||
		resp.Header.Get("X-Content-Type-Options") != "nosniff" || h.execErrs.Load() != 1 {
		t.Errorf("real server: code %d body %q header %v, errors %d", resp.StatusCode, body, resp.Header, h.execErrs.Load())
	}
	fastest := time.Hour
	for i := range 5 {
		start := time.Now()
		w := serve(t, h, get("/t", "example.com"))
		fastest = min(fastest, time.Since(start))
		wantFixed(t, "second request", w)
		if n := h.execErrs.Load(); n != int64(i+2) {
			t.Fatalf("errors after request %d = %d", i+2, n)
		}
	}
	if fastest >= time.Millisecond {
		t.Errorf("the fastest of 5 later requests took %v", fastest)
	}
	srv.Close()
	if srvLog.String() != "" || std.String() != "" {
		t.Errorf("log lines: server %q, standard %q", srvLog.String(), std.String())
	}
}

// failWriter takes one write and fails the next. It holds the status codes.
type failWriter struct {
	h      http.Header
	codes  []int
	writes int
}

func (f *failWriter) Header() http.Header { return f.h }
func (f *failWriter) WriteHeader(c int)   { f.codes = append(f.codes, c) }
func (f *failWriter) Write(p []byte) (int, error) {
	if f.writes++; f.writes > 1 {
		return 0, errors.New("gone")
	}
	return len(p), nil
}

// TestTU20ExecErrorAfterByte checks a write error after the first byte: the
// handler aborts the connection and writes no 404 page. The error adds one.
func TestTU20ExecErrorAfterByte(t *testing.T) {
	h := handlerFor(t, pageTmpl)
	w := &failWriter{h: http.Header{}}
	func() {
		defer func() {
			if r := recover(); r != http.ErrAbortHandler {
				t.Errorf("panic value %v, want ErrAbortHandler", r)
			}
		}()
		h.ServeHTTP(w, get("/t", "example.com"))
	}()
	if !reflect.DeepEqual(w.codes, []int{200}) || w.writes != 2 || h.execErrs.Load() != 1 {
		t.Errorf("codes %v, writes %d, errors %d", w.codes, w.writes, h.execErrs.Load())
	}
}

// TestTS28Cap checks the cap through a real server. In the first three cases
// the page is "<p>", the token and "</p>", so the token sets the size. A page
// of exactly 1 MiB is complete and counts no error. A page over the cap stops.
// The client sees the connection end before a complete response. The "first
// write over" page starts with the trap action, so its first write is over
// the cap. Then the client gets no status line and no body. Each stop adds
// one error and writes no log line.
func TestTS28Cap(t *testing.T) {
	for _, c := range []struct {
		name  string
		tmpl  string
		token int
		ok    bool
	}{
		{"exact", `<p>{{index .Trap "a"}}</p>`, oneMiB - 7, true},
		{"one over", `<p>{{index .Trap "a"}}</p>`, oneMiB - 6, false},
		{"far over", `<p>{{index .Trap "a"}}</p>`, oneMiB + 10, false},
		{"first write over", `{{index .Trap "a"}}</p>`, oneMiB + 10, false},
	} {
		h := handlerFor(t, c.tmpl)
		// The trap text is "say hi " and the token, so the token is shorter.
		h.token = func() string { return strings.Repeat("x", c.token-len("say hi ")) }
		srv, logs := startServer(t, h)
		resp, body, err := fetch(t, srv, http.MethodGet, "/t")
		srv.Close()
		errs := h.execErrs.Load()
		if len(body) > oneMiB || logs.String() != "" {
			t.Errorf("%s: %d body bytes, log %q", c.name, len(body), logs.String())
		}
		if c.ok && (err != nil || resp.StatusCode != 200 || len(body) != oneMiB || errs != 0) {
			t.Errorf("%s: err %v, %d body bytes, errors %d, want a complete page", c.name, err, len(body), errs)
		}
		if !c.ok && (err == nil || errs != 1) {
			t.Errorf("%s: err %v, errors %d, want a broken response and one error", c.name, err, errs)
		}
		if c.name == "first write over" && (resp != nil || len(body) != 0) {
			t.Errorf("%s: response %v, %d body bytes, want no response", c.name, resp, len(body))
		}
	}
}
