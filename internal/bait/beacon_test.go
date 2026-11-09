package bait

import (
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cybagard/cyba-phantom/internal/event"
)

const (
	bcScript = "/bc.js"
	bcPost   = "/bc/p"
	bcAddr   = "192.0.2.1:4000"
	// bcNF is the 404 template of zulu.example, a vhost with no beacon member.
	bcNF = "<h1>zulu missing</h1>"
)

// bcEnv is a handler for a bundle whose example.com has a beacon member. Its
// clock is now.
type bcEnv struct {
	h   *Handler
	q   *event.Queue
	now time.Time
}

// newBC returns a bcEnv. The post path of the beacon is post. zulu.example has
// a 404 template and no beacon member.
func newBC(t testing.TB, post string) *bcEnv {
	t.Helper()
	rm := strings.TrimSuffix(routesJSON("example.com", exampleRoutes), "}") +
		`,"beacon":{"script":"` + bcScript + `","post":"` + post + `"}}`
	zm := strings.TrimSuffix(routesJSON("zulu.example", zuluRoutes), "}") +
		`,"not_found":"vhosts/zulu.example/nf.tmpl"}`
	b := bundleFiles(t, "", map[string]string{
		"vhosts/example.com/routes.json":  rm,
		"vhosts/zulu.example/routes.json": zm,
		"vhosts/zulu.example/nf.tmpl":     bcNF,
	})
	e := &bcEnv{q: queueOf(t, 64), now: testDay}
	e.h = New(fixedSource{b}, &fallbackFn{}, e.q)
	e.h.now = func() time.Time { return e.now }
	return e
}

// do serves a request. A non-empty cookie is the sid cookie. The body counter
// tells how many bytes the handler read. A length of -2 keeps the length of the
// body, and -1 is a body of unknown length.
func (e *bcEnv) do(method, target, host, addr, cookie string, body string, length int64) (*httptest.ResponseRecorder, int) {
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	r.Host, r.RemoteAddr = host, addr
	if length != -2 {
		r.ContentLength = length
	}
	if cookie != "" {
		r.Header.Set("Cookie", "sid="+cookie)
	}
	tb := &tallyBody{ReadCloser: r.Body}
	r.Body = tb
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	return w, tb.got
}

// ticket asks for the script as the client and gives its ticket.
func (e *bcEnv) ticket(t testing.TB, addr, cookie string) string {
	t.Helper()
	w, _ := e.do("GET", bcScript, "example.com", addr, cookie, "", -2)
	e.q.Drain()
	parts := strings.Split(w.Body.String(), `"`)
	if len(parts) != 5 || len(parts[3]) != 26 {
		t.Fatalf("script %q has no ticket", w.Body.String())
	}
	return parts[3]
}

// TestTU25BeaconScript checks the script of the beacon (SEC-38). The body is
// the fixed text with the post path and the ticket of the session. Each request
// has marker bytes in the query, a header and the cookie. None is in the body.
// The cookie is not set. HEAD gets the headers and no body. A request with no
// session id gets an empty ticket. The longest post path gives 309 bytes. A
// host in capitals with a port gets the same script.
func TestTU25BeaconScript(t *testing.T) {
	long := "/" + strings.Repeat("p", 255)
	for _, c := range []struct {
		name, host, post, method, addr string
		ticketOf                       string // session address, "" for none
		longest                        bool
	}{
		{"plain", "example.com", bcPost, "GET", bcAddr, "192.0.2.1", false},
		{"head", "example.com", bcPost, "HEAD", bcAddr, "192.0.2.1", false},
		{"no session id", "example.com", bcPost, "GET", "not-an-address", "", false},
		{"longest post path", "example.com", long, "GET", bcAddr, "192.0.2.1", true},
		{"host in capitals with a port", "EXAMPLE.COM:443", bcPost, "GET", bcAddr, "192.0.2.1", false},
	} {
		e := newBC(t, c.post)
		r := httptest.NewRequest(c.method, bcScript+"?q=MARKER", nil)
		r.Host, r.RemoteAddr = c.host, c.addr
		r.Header.Set("X-Marker", "MARKER")
		r.Header.Set("Cookie", "sid=MARKER")
		w := serve(t, e.h, r)
		want := `navigator.sendBeacon("` + c.post + `","`
		if c.ticketOf != "" {
			want += e.h.dk.At(e.now).BeaconTicket(keyedID(t, e.h, c.ticketOf), e.now)
		}
		want += `")`
		wantBody := want
		if c.method == "HEAD" {
			wantBody = ""
		}
		hd := http.Header{"Content-Type": {"text/javascript; charset=utf-8"}, "Cache-Control": {"no-store"},
			"X-Content-Type-Options": {"nosniff"}, "Content-Length": {strconv.Itoa(len(want))}}
		if w.Code != 200 || w.Body.String() != wantBody || !reflect.DeepEqual(w.Header(), hd) {
			t.Errorf("%s: code %d body %q header %v, want body %q header %v", c.name, w.Code, w.Body.String(), w.Header(), wantBody, hd)
		}
		if c.longest && (len(want) != 309 || len(want) > scriptMax) {
			t.Errorf("%s: script has %d bytes, want 309 and at most %d", c.name, len(want), scriptMax)
		}
		// An address that is not valid gives no event: NewEvent refuses it.
		n := btoi(c.ticketOf != "")
		if evs := e.q.Drain(); len(evs) != n || n == 1 && evs[0].Kind() != event.KindRequest {
			t.Errorf("%s: %d events, want %d request events", c.name, len(evs), n)
		}
	}
}

// TestTU25BeaconMethods checks the methods of the two beacon paths. Another
// method gets the fixed 405 page with its Allow value and reads no body byte.
// A GET of both paths on a vhost with no beacon member gives the fixed 404
// page. If the vhost has a 404 template, the GET gives that page.
func TestTU25BeaconMethods(t *testing.T) {
	e := newBC(t, bcPost)
	all := []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
	for _, c := range []struct {
		path, allow string
		ok          []string
	}{
		{bcScript, "GET, HEAD", []string{"GET", "HEAD"}},
		{bcPost, "POST", []string{"POST"}},
	} {
		for _, m := range all {
			w, got := e.do(m, c.path, "example.com", bcAddr, "", "body", -2)
			e.q.Drain()
			if !slices.Contains(c.ok, m) {
				if got != 0 {
					t.Errorf("%s %s: the handler read %d body bytes", m, c.path, got)
				}
				want := http.Header{"Content-Type": {text}, "X-Content-Type-Options": {"nosniff"}, "Allow": {c.allow}}
				if w.Code != 405 || w.Body.String() != string(methodBody) || !reflect.DeepEqual(w.Header(), want) {
					t.Errorf("%s %s: code %d body %q header %v, want the fixed 405 page", m, c.path, w.Code, w.Body.String(), w.Header())
				}
			} else if w.Code != 200 && w.Code != 204 {
				t.Errorf("%s %s: code %d", m, c.path, w.Code)
			}
		}
		// The beacon paths are on the vhost of their route map only.
		w, _ := e.do("GET", c.path, "kilo.example", bcAddr, "", "", -2)
		wantFixed(t, "kilo.example "+c.path, w)
		// A vhost with a 404 template and no beacon member gives its template.
		w, _ = e.do("GET", c.path, "zulu.example", bcAddr, "", "", -2)
		if w.Code != 404 || w.Body.String() != bcNF {
			t.Errorf("zulu.example %s: code %d body %q, want 404 and %q", c.path, w.Code, w.Body.String(), bcNF)
		}
	}
}

// TestTS32BeaconPost checks the POST of a ticket (SEC-38, SEC-32). Only the
// exact ticket of the session, at an age of 0 to 5 000 ms, gives one beacon
// event. Each case gives one request event. Each case gives the same 204, the
// same headers (with "Connection: close") and no body. A host in capitals with
// a port gives the same.
func TestTS32BeaconPost(t *testing.T) {
	e := newBC(t, bcPost)
	tk := e.ticket(t, bcAddr, "")
	w, _ := e.do("GET", "/t", "example.com", "192.0.2.9:1", "", "", -2)
	other := newCookie(t, "other session", w.Header())
	e.q.Drain()
	bit := []byte(tk)
	bit[12] ^= 1
	pad := func(n int) string { return tk + strings.Repeat("a", n-len(tk)) }
	const ms = time.Millisecond
	for _, c := range []struct {
		name, body, cookie, host string
		at                       time.Duration
		length                   int64
		want                     bool
	}{
		{"valid", tk, "", "example.com", 0, -2, true},
		{"age 5 000 ms", tk, "", "example.com", 5000 * ms, -2, true},
		{"unknown length", tk, "", "example.com", 0, -1, true},
		{"host in capitals with a port", tk, "", "EXAMPLE.COM:443", 0, -2, true},
		{"other session", tk, other, "example.com", 0, -2, false},
		{"age 5 001 ms", tk, "", "example.com", 5001 * ms, -2, false},
		{"future", tk, "", "example.com", -ms, -2, false},
		{"one bit changed", string(bit), "", "example.com", 0, -2, false},
		{"empty", "", "", "example.com", 0, -2, false},
		{"25 bytes", tk[:25], "", "example.com", 0, -2, false},
		{"27 bytes", tk + "a", "", "example.com", 0, -2, false},
		{"newline", tk + "\n", "", "example.com", 0, -2, false},
		{"64 bytes", pad(64), "", "example.com", 0, -2, false},
		{"65 bytes, unknown length", pad(65), "", "example.com", 0, -1, false},
		{"length over 64", pad(65), "", "example.com", 0, 65, false},
		{"300 KiB, unknown length", pad(300 << 10), "", "example.com", 0, -1, false},
	} {
		e.now = testDay.Add(c.at)
		w, got := e.do("POST", bcPost, c.host, bcAddr, c.cookie, c.body, c.length)
		hd := http.Header{"X-Content-Type-Options": {"nosniff"}, "Connection": {"close"}}
		if w.Code != 204 || w.Body.Len() != 0 || !reflect.DeepEqual(w.Header(), hd) {
			t.Errorf("%s: code %d body %q header %v, want 204, no body, %v", c.name, w.Code, w.Body.String(), w.Header(), hd)
		}
		if got > 64 || c.length > 64 && got != 0 {
			t.Errorf("%s: the handler read %d bytes", c.name, got)
		}
		reqs, beacons := 0, 0
		for _, ev := range e.q.Drain() {
			b := ev.Record()
			if b.Kind == event.KindRequest {
				reqs++
			} else if beacons++; b.Kind != event.KindBeacon || b.Session == nil || *b.Session != keyedID(t, e.h, "192.0.2.1") ||
				*b.Vhost != "example.com" || *b.Method != "POST" || *b.Path != bcPost || *b.Status != 204 || ev.IP() != "192.0.2.1" {
				t.Errorf("%s: beacon record %+v, address %q", c.name, b, ev.IP())
			}
		}
		if reqs != 1 || beacons != btoi(c.want) {
			t.Errorf("%s: %d request and %d beacon events, want 1 and %d", c.name, reqs, beacons, btoi(c.want))
		}
	}
}

// newBCOff returns a bcEnv like newBC, with the beacon off. If nf is set,
// example.com also has a 404 template. The ticket is one that the script gave
// while the beacon was on.
func newBCOff(t testing.TB, nf bool) (e *bcEnv, tk string) {
	t.Helper()
	rm := strings.TrimSuffix(routesJSON("example.com", exampleRoutes), "}") +
		`,"beacon":{"script":"` + bcScript + `","post":"` + bcPost + `"}`
	files := map[string]string{}
	if nf {
		rm += `,"not_found":"vhosts/example.com/nf.tmpl"`
		files["vhosts/example.com/nf.tmpl"] = bcNF
	}
	files["vhosts/example.com/routes.json"] = rm + "}"
	e = &bcEnv{q: queueOf(t, 64), now: testDay}
	e.h = New(fixedSource{bundleFiles(t, "", files)}, &fallbackFn{}, e.q)
	e.h.now = func() time.Time { return e.now }
	tk = e.ticket(t, bcAddr, "")
	e.h.DisableBeacon()
	return e, tk
}

// TestTU25BeaconOff checks the off switch (SEC-38). A request to a beacon path
// gets what the same method gets on a path with no route. The status, body and
// headers are the same. GET and HEAD get the 404 template or the fixed 404
// page. POST gets the fixed 405 page. Set-Cookie is there only where the
// no-route page has it. The body has no ticket. No request makes a beacon
// event. Each makes one request event.
func TestTU25BeaconOff(t *testing.T) {
	for _, nf := range []bool{false, true} {
		e, tk := newBCOff(t, nf)
		cookieOf := func(w *httptest.ResponseRecorder) bool {
			_, ok := w.Header()["Set-Cookie"]
			return ok
		}
		for _, m := range []string{"GET", "HEAD", "POST"} {
			body := ""
			if m == "POST" {
				body = tk
			}
			ref, _ := e.do(m, "/no-route", "example.com", bcAddr, "", body, -2)
			e.q.Drain()
			if m == "GET" && (ref.Code != 404 || (ref.Body.String() == bcNF) != nf) {
				t.Fatalf("nf %t: no-route page has code %d, body %q", nf, ref.Code, ref.Body.String())
			}
			if m == "POST" && ref.Code != 405 {
				t.Fatalf("nf %t: POST to a path with no route has code %d, want 405", nf, ref.Code)
			}
			if m == "GET" && cookieOf(ref) != nf {
				t.Fatalf("nf %t: no-route page has Set-Cookie %t", nf, cookieOf(ref))
			}
			for _, p := range []string{bcScript, bcPost} {
				w, _ := e.do(m, p, "example.com", bcAddr, "", body, -2)
				evs := e.q.Drain()
				h, rh := w.Header().Clone(), ref.Header().Clone()
				h.Del("Set-Cookie")
				rh.Del("Set-Cookie")
				if w.Code != ref.Code || w.Body.String() != ref.Body.String() || !reflect.DeepEqual(h, rh) || cookieOf(w) != cookieOf(ref) {
					t.Errorf("nf %t: %s %s: code %d body %q header %v, want code %d body %q header %v",
						nf, m, p, w.Code, w.Body.String(), w.Header(), ref.Code, ref.Body.String(), ref.Header())
				}
				if strings.Contains(w.Body.String(), tk) || strings.Contains(w.Body.String(), "sendBeacon") {
					t.Errorf("nf %t: %s %s: body %q has script text", nf, m, p, w.Body.String())
				}
				if len(evs) != 1 || evs[0].Kind() != event.KindRequest {
					t.Errorf("nf %t: %s %s: %d events, want 1 request event", nf, m, p, len(evs))
				}
			}
		}
	}
}

// bcReader is a request body for the post path. It gives data, then end. At
// most step bytes come in a call. If late is set, end comes in a later call.
// An endless body gives one byte for each call, and 0 bytes for an empty
// buffer. After 200 calls it fails, so a loop that stops only on an error ends.
type bcReader struct {
	data           string
	step           int
	end            error
	late, endless  bool
	calls, gotByte int
}

func (b *bcReader) Read(p []byte) (int, error) {
	if b.calls++; b.calls > 200 {
		return 0, io.ErrClosedPipe
	}
	if b.endless {
		n := min(len(p), 1)
		b.gotByte += n
		return n, nil
	}
	lim := len(b.data)
	if b.step > 0 {
		lim = min(lim, b.step)
	}
	n := copy(p, b.data[:lim])
	b.data = b.data[n:]
	b.gotByte += n
	if b.data != "" || b.late && n > 0 {
		return n, nil
	}
	return n, b.end
}

// TestTS32BeaconBodyEnd checks how the body of a POST ends (SEC-32). The ticket
// counts only when the read ends with io.EOF at 26 bytes. Another error after
// the 26 bytes gives no beacon event. A body that never ends is read for 64
// bytes only. Each POST returns in 5 s and gives 204 and one request event.
func TestTS32BeaconBodyEnd(t *testing.T) {
	e := newBC(t, bcPost)
	tk := e.ticket(t, bcAddr, "")
	for _, c := range []struct {
		name  string
		body  bcReader
		calls int
		want  bool
	}{
		{"ticket and EOF", bcReader{data: tk, end: io.EOF}, 1, true},
		{"ticket, EOF in a later call", bcReader{data: tk, end: io.EOF, late: true}, 2, true},
		{"ticket and another error", bcReader{data: tk, end: io.ErrUnexpectedEOF}, 1, false},
		{"ticket, another error in a later call", bcReader{data: tk, end: io.ErrUnexpectedEOF, late: true}, 2, false},
		{"never ends", bcReader{endless: true}, 64, false},
	} {
		r := httptest.NewRequest("POST", bcPost, nil)
		r.Host, r.RemoteAddr, r.ContentLength = "example.com", bcAddr, -1
		r.Body = io.NopCloser(&c.body)
		w := httptest.NewRecorder()
		done := make(chan struct{})
		go func() { e.h.ServeHTTP(w, r); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: the handler did not return in 5 s", c.name)
		}
		reqs, beacons := 0, 0
		for _, ev := range e.q.Drain() {
			if ev.Record().Kind == event.KindBeacon {
				beacons++
			} else {
				reqs++
			}
		}
		if w.Code != 204 || w.Body.Len() != 0 || c.body.calls != c.calls || c.body.gotByte > 64 || reqs != 1 || beacons != btoi(c.want) {
			t.Errorf("%s: code %d, %d reads, %d bytes, %d request and %d beacon events, want 204, %d reads, at most 64 bytes, 1 and %d",
				c.name, w.Code, c.body.calls, c.body.gotByte, reqs, beacons, c.calls, btoi(c.want))
		}
	}
}

// TestTS32BeaconFlush checks that the post path flushes the 204 before it makes
// the beacon event.
func TestTS32BeaconFlush(t *testing.T) {
	e := newBC(t, bcPost)
	tk := e.ticket(t, bcAddr, "")
	r := httptest.NewRequest("POST", bcPost, strings.NewReader(tk))
	r.Host, r.RemoteAddr = "example.com", bcAddr
	w := &flushProbe{ResponseRecorder: httptest.NewRecorder(), q: e.q}
	e.h.ServeHTTP(w, r)
	if !w.Flushed || w.atFlush != 0 || len(e.q.Drain()) != 2 {
		t.Errorf("flushed %v, %d events at the flush, want true and 0, and 2 events after", w.Flushed, w.atFlush)
	}
}

// BenchmarkBeaconScript measures one GET of the script path.
func BenchmarkBeaconScript(b *testing.B) { benchBC(b, "GET", bcScript, false) }

// BenchmarkBeaconPost measures one POST of a valid ticket. It makes the beacon
// event and the request event.
func BenchmarkBeaconPost(b *testing.B) { benchBC(b, "POST", bcPost, true) }

// benchBC measures one request. With withTicket, the body is a valid ticket.
func benchBC(b *testing.B, method, target string, withTicket bool) {
	e := newBC(b, bcPost)
	body := ""
	if withTicket {
		body = e.ticket(b, bcAddr, "")
	}
	r := httptest.NewRequest(method, target, nil)
	r.Host, r.RemoteAddr, r.ContentLength = "example.com", bcAddr, int64(len(body))
	rd, w := &rewind{data: []byte(body)}, &discard{h: http.Header{}}
	b.ReportAllocs()
	for b.Loop() {
		clear(w.h)
		rd.off, r.Body = 0, rd
		e.h.ServeHTTP(w, r)
		e.q.Drain()
	}
}
