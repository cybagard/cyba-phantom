package bait

import (
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"

	xhtml "golang.org/x/net/html"

	"github.com/cybagard/cyba-phantom/internal/bundle"
	"github.com/cybagard/cyba-phantom/internal/event"
)

// outTrap is a trap text with the characters that the page escaper changes.
const outTrap = `q " & < > ' `

// escOut is the same text after one escape in a text context. The token is
// the placeholder.
const escOut = `q ` + ent + `34; &amp; &lt; &gt; ` + ent + `39; ` + placeholder

// The route map of example.com for the out-of-page tests. The route /t has a
// header slot and a page. The route /e has a page with an escape error. The
// route /o has a page whose first write can pass the cap.
const outRoutes = `{"routes":[
{"path":"/t","template":"vhosts/example.com/t.tmpl","type":"text/html; charset=utf-8","headers":[{"name":"X-Note","trap":"n"}]},
{"path":"/e","template":"vhosts/example.com/e.tmpl","type":"text/html; charset=utf-8","headers":[{"name":"X-Note","trap":"n"}]},
{"path":"/u","template":"vhosts/example.com/t.tmpl","type":"text/html; charset=utf-8","headers":[{"name":"X-NOTE","trap":"n"}]},
{"path":"/o","template":"vhosts/example.com/o.tmpl","type":"text/html; charset=utf-8"},
{"path":"/a","asset":"vhosts/example.com/a.txt","type":"text/plain; charset=utf-8","headers":[{"name":"X-Note","trap":"n"}]},
{"path":"/robots.txt","template":"vhosts/example.com/robots.tmpl","type":"text/plain; charset=utf-8"},
{"path":"/.well-known/ai-plugin.json","template":"vhosts/example.com/ai.tmpl","type":"application/json"}],
"not_found":"vhosts/example.com/nf.tmpl"}`

// outHandler returns a handler for a bundle of example.com with the routes of
// outRoutes. Each trap has the text outTrap and the token. kilo.example has
// no 404 template.
func outHandler(tb testing.TB) *Handler { return outHandlerQ(tb, testQueue(tb)) }

// outHandlerQ is outHandler with the queue q.
func outHandlerQ(tb testing.TB, q *event.Queue) *Handler {
	tb.Helper()
	var specs []trapSpec
	for _, id := range []string{"n", "r", "j", "f"} {
		specs = append(specs, trapSpec{id, "hidden-p", outTrap + "{{.Token}}"})
	}
	tj, err := json.Marshal(func() (out []map[string]string) {
		for _, s := range specs {
			out = append(out, map[string]string{"id": s.id, "slot": s.slot, "surface": "path",
				"visibility": "human-visible", "instruction_template": s.text})
		}
		return
	}())
	mustOK(tb, err)
	const dir = "vhosts/example.com/"
	b := bundleFiles(tb, "", map[string]string{
		"traps/traps.json":      string(tj),
		dir + "routes.json":     outRoutes,
		dir + "t.tmpl":          `<p>{{index .Trap "f"}}</p>`,
		dir + "e.tmpl":          `<a href="x{{index .Trap "f"}}`,
		dir + "o.tmpl":          `{{index .Trap "f"}}</p>`,
		dir + "a.txt":           "asset\n",
		dir + "robots.tmpl":     "User-agent: *\nDisallow: {{index .Trap \"r\"}}\n",
		dir + "ai.tmpl":         `{"description":"{{index .Trap "j"}}"}`,
		dir + "nf.tmpl":         `<h1>{{index .Trap "f"}}</h1>`,
		"vhosts/kilo.example/x": "x",
	})
	return New(&swap{list: []*bundle.Bundle{b}}, &fallbackFn{}, q)
}

// TestTI02OutOfPage checks the four out-of-page slots of one bundle through a
// real server. They are the header slot, robots.txt, the well-known file and
// the 404 page. Each body is the exact output of one escape in a text context.
func TestTI02OutOfPage(t *testing.T) {
	srv, _ := startServer(t, outHandler(t))
	for _, c := range []struct {
		name, method, target, ctype, body string
		code                              int
		note                              bool
	}{
		{"header slot", "GET", "/t", html, "<p>" + escOut + "</p>", 200, true},
		{"header slot on head", "HEAD", "/t", html, "", 200, true},
		{"header slot on asset", "GET", "/a", text, "asset\n", 200, true},
		{"robots.txt", "GET", "/robots.txt", text, "User-agent: *\nDisallow: " + escOut + "\n", 200, false},
		{"well-known", "GET", "/.well-known/ai-plugin.json", "application/json", `{"description":"` + escOut + `"}`, 200, false},
		{"404 body", "GET", "/nope", html, "<h1>" + escOut + "</h1>", 404, false},
		{"404 body on head", "HEAD", "/nope", html, "", 404, false},
	} {
		resp, body, err := fetch(t, srv, c.method, c.target)
		mustOK(t, err)
		note := resp.Header.Values("X-Note")
		if resp.StatusCode != c.code || string(body) != c.body || resp.Header.Get("Content-Type") != c.ctype ||
			resp.Header.Get("X-Content-Type-Options") != "nosniff" || (len(note) == 1) != c.note || len(note) > 1 {
			t.Errorf("%s: code %d body %q header %v", c.name, resp.StatusCode, body, resp.Header)
		}
		if c.note && (len(note) != 1 || note[0] != outTrap+placeholder) {
			t.Errorf("%s: X-Note %q, want %q", c.name, note, outTrap+placeholder)
		}
	}
	// The JSON body parses. The text keeps the entities of the page escaper.
	_, body, err := fetch(t, srv, "GET", "/.well-known/ai-plugin.json")
	mustOK(t, err)
	var v struct{ Description string }
	if err := json.Unmarshal(body, &v); err != nil || v.Description != escOut {
		t.Errorf("JSON body %q: err %v, description %q", body, err, v.Description)
	}
	// The 404 page parses to its heading, with the trap text back.
	_, body, err = fetch(t, srv, "GET", "/nope")
	mustOK(t, err)
	doc, err := xhtml.Parse(strings.NewReader(string(body)))
	mustOK(t, err)
	if got := pick(doc, "h1"); got != outTrap+placeholder {
		t.Errorf("404 heading %q", got)
	}
}

// TestTU20SlotValue checks the rule for a header value through a real server,
// on GET and on HEAD. The token is the value. A left-out header adds one to
// the counter at each request. A valid value is one header line.
func TestTU20SlotValue(t *testing.T) {
	// The trap text is outTrap and the token, so the token is shorter.
	long := strings.Repeat("v", 1024-len(outTrap))
	for _, c := range []struct {
		name, val string
		ok        bool
	}{
		{"valid", "a b ~", true},
		{"1024 bytes", long, true},
		{"1025 bytes", long + "v", false},
		{"CR", "a\rb", false},
		{"LF", "a\nb", false},
		{"NUL", "a\x00b", false},
		{"tab", "a\tb", false},
		{"0x1F", "a\x1fb", false},
		{"0x7F", "a\x7fb", false},
		{"0xFF", "a\xffb", false},
		{"0x20 and 0x7E", "a ~b", true},
	} {
		h := outHandler(t)
		h.token = func() string { return c.val }
		srv, _ := startServer(t, h)
		for _, method := range []string{"GET", "HEAD"} {
			resp, _, err := fetch(t, srv, method, "/t")
			mustOK(t, err)
			got := resp.Header.Values("X-Note")
			want := []string(nil)
			if c.ok {
				want = []string{outTrap + c.val}
			}
			if resp.StatusCode != 200 || !reflect.DeepEqual(got, want) {
				t.Errorf("%s %s: code %d, %d X-Note values, want %d", c.name, method, resp.StatusCode, len(got), len(want))
			}
		}
		if n, want := h.slotDrops.Load(), map[bool]int64{true: 0, false: 2}[c.ok]; n != want {
			t.Errorf("%s: slotDrops %d, want %d", c.name, n, want)
		}
	}
}

// TestTU20SlotName checks the name of a header slot. The load rule permits the
// name X-NOTE, and the response has the canonical key X-Note.
func TestTU20SlotName(t *testing.T) {
	w := serve(t, outHandler(t), get("/u", "example.com"))
	if _, ok := w.Header()["X-NOTE"]; ok || len(w.Header()["X-Note"]) != 1 {
		t.Errorf("header %v, want the one key X-Note", w.Header())
	}
}

// TestTU20SlotNeverReplaces checks the write function. The map holds the fixed
// headers of the engine. A slot with the name of one of them, in any case,
// changes nothing. A slot with a new name is added once.
func TestTU20SlotNeverReplaces(t *testing.T) {
	fixed := http.Header{"Content-Type": {"text/plain"}, "X-Content-Type-Options": {"nosniff"},
		"Content-Length": {"5"}, "Allow": {"GET, HEAD"}}
	for name := range fixed {
		for _, v := range []string{name, strings.ToLower(name), strings.ToUpper(name),
			strings.ToLower(name[:1]) + strings.ToUpper(name[1:])} {
			hd := fixed.Clone()
			putSlots(hd, []slotHeader{{v, []string{"evil"}}})
			if !reflect.DeepEqual(hd, fixed) {
				t.Errorf("slot %q changed the headers: %v", v, hd)
			}
		}
	}
	hd := fixed.Clone()
	putSlots(hd, []slotHeader{{"X-Note", []string{"1"}}, {"x-note", []string{"2"}}, {"X-Other", []string{"3"}}})
	want := fixed.Clone()
	want["X-Note"], want["X-Other"] = []string{"1"}, []string{"3"}
	if !reflect.DeepEqual(hd, want) {
		t.Errorf("headers %v, want %v", hd, want)
	}
}

// TestTU20SlotErrorPage checks the fixed 404 page of an execution error. It has
// no slot header. The error adds to the error counter only.
func TestTU20SlotErrorPage(t *testing.T) {
	h := outHandler(t)
	wantFixed(t, "error page", serve(t, h, get("/e", "example.com")))
	if h.execErrs.Load() != 1 || h.slotDrops.Load() != 0 {
		t.Errorf("errors %d, slotDrops %d", h.execErrs.Load(), h.slotDrops.Load())
	}
}

// TestTU20NotFound checks the 404 template. A known vhost with the template
// renders it with status 404, on GET and on HEAD. An unknown host and a vhost
// with no template get the fixed page. A POST gets the fixed 405 page first.
func TestTU20NotFound(t *testing.T) {
	h := outHandler(t)
	page := "<h1>" + escOut + "</h1>"
	for _, m := range []string{"GET", "HEAD"} {
		r := get("/nope", "EXAMPLE.com")
		r.Method = m
		w := serve(t, h, r)
		want := http.Header{"Content-Type": {html}, "X-Content-Type-Options": {"nosniff"}}
		dropCookie(t, m, w.Header())
		// The recorder keeps the body of HEAD. A real server drops it.
		if w.Code != 404 || w.Body.String() != page || !reflect.DeepEqual(w.Header(), want) {
			t.Errorf("%s: code %d body %q header %v", m, w.Code, w.Body.String(), w.Header())
		}
	}
	wantFixed(t, "unknown host", serve(t, h, get("/nope", "other.example")))
	wantFixed(t, "no template", serve(t, h, get("/nope", "kilo.example")))
	r := get("/nope", "example.com")
	r.Method = http.MethodPost
	if w := serve(t, h, r); w.Code != 405 || w.Body.String() != "method not allowed\n" || w.Header().Get("Allow") != "GET, HEAD" {
		t.Errorf("POST: code %d body %q header %v", w.Code, w.Body.String(), w.Header())
	}
}

// TestTU20NotFoundErrors checks the error rule of the 404 template. The cap,
// the error counter and the close are those of a template route.
func TestTU20NotFoundErrors(t *testing.T) {
	// An error before the first byte gives the fixed page.
	const dir = "vhosts/example.com/"
	b := bundleFiles(t, "", map[string]string{
		dir + "routes.json": `{"routes":[{"path":"/t","template":"` + dir + `t.tmpl","type":"text/html; charset=utf-8"}],"not_found":"` + dir + `nf.tmpl"}`,
		dir + "t.tmpl":      "t",
		dir + "nf.tmpl":     `<a href="x{{index .Trap "a"}}`,
	})
	h := New(&swap{list: []*bundle.Bundle{b}}, &fallbackFn{}, testQueue(t))
	wantFixed(t, "error", serve(t, h, get("/nope", "example.com")))
	if h.execErrs.Load() != 1 {
		t.Errorf("errors %d", h.execErrs.Load())
	}
	// A write error after the first byte closes the connection with status 404.
	h = outHandler(t)
	w := &failWriter{h: http.Header{}}
	func() {
		defer func() {
			if r := recover(); r != http.ErrAbortHandler {
				t.Errorf("panic value %v", r)
			}
		}()
		h.ServeHTTP(w, get("/nope", "example.com"))
	}()
	if !reflect.DeepEqual(w.codes, []int{404}) || h.execErrs.Load() != 1 {
		t.Errorf("codes %v, errors %d", w.codes, h.execErrs.Load())
	}
}
