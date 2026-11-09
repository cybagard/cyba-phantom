package bait

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"
	"weak"

	"github.com/cybagard/cyba-phantom/internal/bundle"
	"github.com/cybagard/cyba-phantom/internal/event"
	"github.com/cybagard/cyba-phantom/internal/session"
	"github.com/cybagard/cyba-phantom/internal/token"
)

// testDay is the time of the handler clock in the tests of the events and of
// the session cookie. The tests step it to change the UTC date.
var testDay = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

// eventHandler returns the handler of outHandler with a queue of depth. Its
// clock stands at testDay, so a test cannot see a change of the UTC date.
func eventHandler(t *testing.T, depth int) (*Handler, *event.Queue) {
	t.Helper()
	q := queueOf(t, depth)
	h := outHandlerQ(t, q)
	h.now = func() time.Time { return testDay }
	return h, q
}

// keyedID returns the keyed session id of ip under the day key of the clock of
// h. It is the id that a request with no valid cookie has.
func keyedID(t testing.TB, h *Handler, ip string) string {
	t.Helper()
	id := h.dk.At(h.now()).SessionID(ip, "")
	if id == nil {
		t.Fatalf("no keyed id for %q", ip)
	}
	return *id
}

// cookieAttrText are the attributes that SEC-35 names, in the order that the
// handler writes them.
const cookieAttrText = "; Path=/; Max-Age=86400; HttpOnly; Secure; SameSite=Lax"

// newCookie checks that hd has exactly one Set-Cookie header with the name sid
// and the attributes of SEC-35. It returns the cookie value, or "" after it
// reported an error.
func newCookie(t testing.TB, name string, hd http.Header) string {
	t.Helper()
	v := hd.Values("Set-Cookie")
	if len(v) != 1 {
		t.Errorf("%s: %d Set-Cookie headers, want 1", name, len(v))
		return ""
	}
	val, ok := strings.CutSuffix(v[0], cookieAttrText)
	if val, ok2 := strings.CutPrefix(val, "sid="); ok && ok2 {
		c, err := http.ParseSetCookie(v[0])
		if err != nil || c.Value != val || c.Path != "/" || c.MaxAge != 86400 || c.Domain != "" ||
			!c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode {
			t.Errorf("%s: cookie %+v, err %v", name, c, err)
		}
		return val
	}
	t.Errorf("%s: Set-Cookie %q, want sid=<value>%s", name, v[0], cookieAttrText)
	return ""
}

// dropCookie checks the cookie of a new session as newCookie does. Then it
// removes the cookie. An exact comparison of the other headers can follow.
func dropCookie(t testing.TB, name string, hd http.Header) string {
	t.Helper()
	val := newCookie(t, name, hd)
	hd.Del("Set-Cookie")
	return val
}

// oneEvent takes the only event of q. The IP is the client address text.
func oneEvent(t *testing.T, name string, q *event.Queue) (rec event.Record, ip string) {
	t.Helper()
	evs := q.Drain()
	if len(evs) != 1 || evs[0].Kind() != event.KindRequest {
		t.Fatalf("%s: %d events, want one request event", name, len(evs))
	}
	return evs[0].Record(), evs[0].IP()
}

// aborts runs the handler and tells if the request ended with ErrAbortHandler.
func aborts(h *Handler, w http.ResponseWriter, r *http.Request) (aborted bool) {
	defer func() { aborted = recover() == http.ErrAbortHandler }()
	h.ServeHTTP(w, r)
	return false
}

// TestTU20RequestEvents checks the event of each kind of response. It has the
// typed fields and the status that the engine wrote. It has no detail.
func TestTU20RequestEvents(t *testing.T) {
	for _, c := range []struct {
		name, method, host, path string
		status                   int
		target                   string // raw request target, if not empty
	}{
		{"200 template", "GET", "example.com", "/t", 200, ""},
		{"200 asset", "GET", "Example.COM:443", "/a", 200, ""},
		{"404 unknown host", "GET", "other.example", "/t", 404, ""},
		{"404 no route with 404 template", "GET", "example.com", "/nope", 404, ""},
		{"404 no route without 404 template", "GET", "kilo.example", "/nope", 404, ""},
		{"405", "POST", "example.com", "/t", 405, ""},
		{"HEAD", "HEAD", "example.com", "/t", 200, ""},
		{"error before the first byte", "GET", "example.com", "/e", 404, ""},
		// The parser sets RawPath. The event path keeps its escape, with
		// upper-case hex digits.
		{"escaped slash", "GET", "example.com", "/a%2Fb", 404, "/a%2fb"},
	} {
		h, q := eventHandler(t, 8)
		r := get(c.path, c.host)
		if c.target != "" {
			r = raw(t, c.method+" "+c.target+" HTTP/1.1\r\nHost: "+c.host+"\r\n\r\n")
			r.RemoteAddr = "192.0.2.1:1234"
		}
		r.Method = c.method
		w := serve(t, h, r)
		rec, ip := oneEvent(t, c.name, q)
		if w.Code != c.status || rec.Status == nil || *rec.Status != int64(c.status) ||
			*rec.Vhost != c.host || *rec.Method != c.method || *rec.Path != c.path || ip != "192.0.2.1" ||
			len(rec.Detail) != 0 || rec.Session == nil || *rec.Session != keyedID(t, h, "192.0.2.1") ||
			rec.TrapID != nil || rec.TokenID != nil {
			t.Errorf("%s: code %d, record %+v, ip %q", c.name, w.Code, rec, ip)
		}
	}
}

// TestTU20RequestEventAbort checks the event of a response that ends the
// connection. After a byte the status is the one written. Before any status,
// the event has none.
func TestTU20RequestEventAbort(t *testing.T) {
	big := func() string { return strings.Repeat("x", oneMiB+10) }
	for _, c := range []struct {
		name, path string
		token      func() string
		status     int64
	}{
		{"write error after a byte", "/t", nil, 200},
		{"404 page write error after a byte", "/nope", nil, 404},
		{"over the cap after a byte", "/t", big, 200},
		{"first write over the cap", "/o", big, 0},
	} {
		h, q := eventHandler(t, 8)
		var w http.ResponseWriter = &failWriter{h: http.Header{}}
		if c.token != nil {
			h.text = func([token.Size]byte) string { return c.token() }
			w = httptest.NewRecorder()
		}
		if !aborts(h, w, get(c.path, "example.com")) {
			t.Errorf("%s: no abort", c.name)
		}
		rec, _ := oneEvent(t, c.name, q)
		if len(rec.Detail) != 0 || (c.status == 0) != (rec.Status == nil) || rec.Status != nil && *rec.Status != c.status {
			t.Errorf("%s: record %+v", c.name, rec)
		}
	}
}

// TestTU20RequestEventText checks a path of 2 KiB of invalid UTF-8, and
// markers in the query and in the headers. The path gives one event with no
// error. A marker is in no field.
func TestTU20RequestEventText(t *testing.T) {
	h, q := eventHandler(t, 8)
	serve(t, h, get("/"+strings.Repeat("\xff", 2048), "example.com"))
	rec, _ := oneEvent(t, "invalid path", q)
	if h.eventErrs.Load() != 0 || rec.Path == nil || !utf8.ValidString(*rec.Path) || !strings.HasPrefix(*rec.Path, "/%FF%FF") ||
		rec.Status == nil || *rec.Status != 404 || len(rec.Detail) != 0 {
		t.Errorf("errors %d, record %+v", h.eventErrs.Load(), rec)
	}
	const mark = "zqmark"
	r := get("/t", "example.com")
	r.URL.RawQuery = "q=" + mark
	for _, k := range []string{"User-Agent", "Referer", "Cookie", "X-Forwarded-For", "Forwarded", "Accept"} {
		r.Header.Set(k, mark)
	}
	serve(t, h, r)
	rec, ip := oneEvent(t, "markers", q)
	out, err := json.Marshal(rec)
	mustOK(t, err)
	if strings.Contains(string(out), mark) || strings.Contains(ip, mark) || len(rec.Detail) != 0 ||
		rec.Status == nil || *rec.Status != 200 {
		t.Errorf("a marker is in the event, or the status is wrong: %s, ip %q", out, ip)
	}
}

// TestTU20RequestEventAddr checks the client address. The engine passes on
// each form that the listener passes on. NewEvent refuses a value that is not
// an address, and the refusal adds one to the counter.
func TestTU20RequestEventAddr(t *testing.T) {
	for _, c := range []struct {
		addr, ip string
		refused  bool
	}{
		{"192.0.2.7:80", "192.0.2.7", false},
		{"[2001:db8::1]:443", "2001:db8::1", false},
		{"192.0.2.7", "192.0.2.7", false},
		{"::1", "::1", false},
		{"[fe80::1%eth0]:80", "fe80::1", false},
		{"fe80::1%eth0", "fe80::1", false},
		{"[::ffff:192.0.2.1]:80", "::ffff:192.0.2.1", false},
		{"not-an-address", "", true},
		{"example.com:80", "", true},
	} {
		h, q := eventHandler(t, 8)
		r := get("/t", "example.com")
		r.RemoteAddr = c.addr
		if w := serve(t, h, r); w.Code != 200 {
			t.Errorf("%q: code %d", c.addr, w.Code)
		}
		if c.refused {
			if n := len(q.Drain()); n != 0 || h.eventErrs.Load() != 1 {
				t.Errorf("%q: %d events, errors %d", c.addr, n, h.eventErrs.Load())
			}
			continue
		}
		rec, ip := oneEvent(t, c.addr, q)
		if ip != c.ip || h.eventErrs.Load() != 0 || rec.Status == nil || *rec.Status != 200 || len(rec.Detail) != 0 {
			t.Errorf("%q: ip %q, errors %d, record %+v", c.addr, ip, h.eventErrs.Load(), rec)
		}
	}
}

// TestTU20RequestEventZoneSession checks the session id of a zoned address,
// with the cookie off. It is the keyed id of the address without its zone. It
// is the id of a request from the plain address.
func TestTU20RequestEventZoneSession(t *testing.T) {
	h, q := eventHandler(t, 8)
	h.cookieOff.Store(true)
	var ids [2]string
	for i, from := range []string{"[fe80::1%eth0]:80", "[fe80::1]:80"} {
		r := get("/t", "example.com")
		r.RemoteAddr = from
		serve(t, h, r)
		rec, ip := oneEvent(t, from, q)
		if rec.Session == nil || ip != "fe80::1" {
			t.Fatalf("%q: session %v, ip %q", from, rec.Session, ip)
		}
		ids[i] = *rec.Session
	}
	if want := keyedID(t, h, "fe80::1"); ids[0] != want || ids[1] != want {
		t.Errorf("session ids %q, want %q for both", ids, want)
	}
}

// TestTU20RequestEventQueue checks the no-bundle path and the full queue. With
// no bundle the engine writes no event. A full queue counts its drop and the
// request does not wait.
func TestTU20RequestEventQueue(t *testing.T) {
	q := queueOf(t, 1)
	fb := &fallbackFn{}
	none := New(&swap{}, fb, q)
	serve(t, none, get("/", "example.com"))
	if fb.calls != 1 || len(q.Drain()) != 0 {
		t.Errorf("no bundle: fallback calls %d", fb.calls)
	}
	h, q := eventHandler(t, 1)
	for range 6 {
		if w := serve(t, h, get("/t", "example.com")); w.Code != 200 {
			t.Fatalf("code %d", w.Code)
		}
	}
	d := q.Dropped()
	if n := len(q.Drain()); d.Bulk != 5 || d.Evidence != 0 || d.Invalid != 0 || n != 1 {
		t.Errorf("dropped %+v, %d events queued", d, n)
	}
}

// sessionEvent serves r and returns the response and the session of the one
// request event. The session is "" when the event has none.
func sessionEvent(t *testing.T, name string, h *Handler, r *http.Request) (*httptest.ResponseRecorder, string) {
	t.Helper()
	w := serve(t, h, r)
	rec, _ := oneEvent(t, name, h.q)
	if rec.Session == nil {
		return w, ""
	}
	return w, *rec.Session
}

// withCookie returns a request for target with the Cookie lines.
func withCookie(target string, lines ...string) *http.Request {
	r := get(target, "example.com")
	for _, l := range lines {
		r.Header.Add("Cookie", l)
	}
	return r
}

// TestTU24CookieRoundTrip checks the cookie of a new client (SEC-35). The
// response has one Set-Cookie header. Its value goes back through
// CookieFromHeader and CheckCookie under the shared key, and its id is not the
// keyed id. The request that got the cookie has the keyed id in its event. The
// next request with the cookie has the cookie id and gets no new cookie.
func TestTU24CookieRoundTrip(t *testing.T) {
	h, _ := eventHandler(t, 64)
	keyed := keyedID(t, h, "192.0.2.1")
	w, first := sessionEvent(t, "first", h, get("/t", "example.com"))
	val := newCookie(t, "first", w.Header())
	if first != keyed {
		t.Errorf("first request has id %q, want the keyed id %q", first, keyed)
	}
	r := withCookie("/t", "sid="+val)
	got, ok := session.CookieFromHeader(r.Header)
	if !ok || got != val {
		t.Fatalf("CookieFromHeader gave %q, %v for %q", got, ok, val)
	}
	id, ok := h.dk.At(h.now()).CheckCookie(val)
	if !ok || id == keyed {
		t.Fatalf("CheckCookie gave %q, %v; the keyed id is %q", id, ok, keyed)
	}
	for range 2 {
		w, second := sessionEvent(t, "second", h, withCookie("/t", "sid="+val))
		if second != id || len(w.Header().Values("Set-Cookie")) != 0 {
			t.Errorf("returning client: id %q, want %q; headers %v", second, id, w.Header())
		}
	}
	// A handler with the same holder reads the cookie. It has no state.
	h2 := NewWithDayKey(h.src, &fallbackFn{}, h.q, h.dk)
	h2.now = h.now
	if _, other := sessionEvent(t, "other handler", h2, withCookie("/t", "sid="+val)); other != id {
		t.Errorf("a second handler gave id %q, want %q", other, id)
	}
	// The event holds the id and no cookie text.
	rec := func() string {
		serve(t, h, withCookie("/t", "sid="+val))
		out, err := json.Marshal(h.q.Drain()[0].Record())
		mustOK(t, err)
		return string(out)
	}()
	if strings.Contains(rec, val) || !strings.Contains(rec, id) {
		t.Errorf("event %s: holds the cookie value, or lacks the id", rec)
	}
}

// TestTU24TwoClients checks that two new clients behind one client key get two
// different cookie ids and the same keyed id.
func TestTU24TwoClients(t *testing.T) {
	h, _ := eventHandler(t, 64)
	var vals, ids, keyed [2]string
	for i, addr := range []string{"192.0.2.1:1111", "192.0.2.1:2222"} {
		r := get("/t", "example.com")
		r.RemoteAddr = addr
		var w *httptest.ResponseRecorder
		w, keyed[i] = sessionEvent(t, addr, h, r)
		vals[i] = newCookie(t, addr, w.Header())
		ids[i], _ = h.dk.At(h.now()).CheckCookie(vals[i])
	}
	if vals[0] == vals[1] || ids[0] == "" || ids[0] == ids[1] || keyed[0] != keyed[1] {
		t.Errorf("cookies %v, ids %v, keyed ids %v", vals, ids, keyed)
	}
}

// TestTU24KeyedFallback checks the requests that have the keyed id. The cases
// are no cookie, a bad tag, two sid cookies, and a malformed value. They are
// also other names and another UTC date. Each gets a new cookie.
func TestTU24KeyedFallback(t *testing.T) {
	for _, c := range []struct {
		name  string
		step  time.Duration
		lines func(v string) []string
	}{
		{"no cookie", 0, func(string) []string { return nil }},
		{"bad tag", 0, func(v string) []string { return []string{"sid=" + flip(v)} }},
		{"two parts", 0, func(v string) []string { return []string{"sid=" + v + "; sid=" + v} }},
		{"two lines", 0, func(v string) []string { return []string{"sid=" + v, "sid=" + v} }},
		{"upper case", 0, func(v string) []string { return []string{"sid=" + strings.ToUpper(v)} }},
		{"41 bytes", 0, func(v string) []string { return []string{"sid=" + v[:41]} }},
		{"empty value", 0, func(string) []string { return []string{"sid="} }},
		{"other names", 0, func(v string) []string { return []string{"xsid=" + v + "; SID=" + v + "; sid2=" + v} }},
		{"another UTC date", 24 * time.Hour, func(v string) []string { return []string{"sid=" + v} }},
	} {
		h, _ := eventHandler(t, 64)
		w, _ := sessionEvent(t, c.name, h, get("/t", "example.com"))
		old := newCookie(t, c.name, w.Header())
		if old == "" {
			t.Fatalf("%s: no cookie to start from", c.name)
		}
		day := testDay.Add(c.step)
		h.now = func() time.Time { return day }
		w, id := sessionEvent(t, c.name, h, withCookie("/t", c.lines(old)...))
		fresh := newCookie(t, c.name, w.Header())
		cid, ok := h.dk.At(day).CheckCookie(fresh)
		if want := keyedID(t, h, "192.0.2.1"); id != want || !ok || cid == want || fresh == old {
			t.Errorf("%s: id %q, want the keyed id %q; new cookie id %q, valid %v", c.name, id, want, cid, ok)
		}
	}
}

// flip changes the first character of a cookie value, so the id differs from
// the id of the tag.
func flip(v string) string {
	if v[0] == 'a' {
		return "b" + v[1:]
	}
	return "a" + v[1:]
}

// TestTU24CookieResponses checks which responses carry the cookie. A template
// page, the 404 template and an asset do. A fixed page does not: unknown host,
// 405, the fixed 404 and the fixed 404 after an execution error. A valid
// cookie gets no header on any response.
func TestTU24CookieResponses(t *testing.T) {
	h, _ := eventHandler(t, 64)
	w, _ := sessionEvent(t, "issue", h, get("/t", "example.com"))
	valid := newCookie(t, "issue", w.Header())
	for _, c := range []struct {
		name, method, host, path string
		code                     int
		cookie                   bool
	}{
		{"template", "GET", "example.com", "/t", 200, true},
		{"template head", "HEAD", "example.com", "/t", 200, true},
		{"asset", "GET", "example.com", "/a", 200, true},
		{"asset head", "HEAD", "example.com", "/a", 200, true},
		{"404 template", "GET", "example.com", "/nope", 404, true},
		{"unknown host", "GET", "other.example", "/t", 404, false},
		{"405", "POST", "example.com", "/t", 405, false},
		{"fixed 404", "GET", "kilo.example", "/nope", 404, false},
		{"error before the first byte", "GET", "example.com", "/e", 404, false},
	} {
		for _, lines := range [][]string{nil, {"sid=" + valid}} {
			r := get(c.path, c.host)
			r.Method = c.method
			for _, l := range lines {
				r.Header.Add("Cookie", l)
			}
			w, _ := sessionEvent(t, c.name, h, r)
			if got := len(w.Header().Values("Set-Cookie")); w.Code != c.code || got != map[bool]int{true: 1}[c.cookie && lines == nil] {
				t.Errorf("%s with cookie %v: code %d, %d Set-Cookie headers", c.name, lines != nil, w.Code, got)
			}
			if c.cookie && lines == nil {
				newCookie(t, c.name, w.Header())
			}
		}
	}
	// With no bundle, the fallback serves and sets no cookie.
	fb := &fallbackFn{}
	none := New(&swap{}, fb, queueOf(t, 8))
	if w := serve(t, none, get("/t", "example.com")); fb.calls != 1 || len(w.Header().Values("Set-Cookie")) != 0 {
		t.Errorf("no bundle: %d fallback calls, headers %v", fb.calls, w.Header())
	}
}

// TestTU24AbortSession checks the event of a response that ends the connection.
// It has the session of the normal path. A new client has the keyed id. A
// returning client has the cookie id.
func TestTU24AbortSession(t *testing.T) {
	h, _ := eventHandler(t, 64)
	w, keyed := sessionEvent(t, "issue", h, get("/t", "example.com"))
	val := newCookie(t, "issue", w.Header())
	cookieID, _ := h.dk.At(h.now()).CheckCookie(val)
	for _, c := range []struct {
		name, want string
		lines      []string
	}{
		{"new client", keyed, nil},
		{"returning client", cookieID, []string{"sid=" + val}},
	} {
		fw := &failWriter{h: http.Header{}}
		if !aborts(h, fw, withCookie("/t", c.lines...)) {
			t.Errorf("%s: no abort", c.name)
		}
		rec, _ := oneEvent(t, c.name, h.q)
		if rec.Session == nil || *rec.Session != c.want {
			t.Errorf("%s: session %v, want %q", c.name, rec.Session, c.want)
		}
		if got := len(fw.h.Values("Set-Cookie")); got != map[bool]int{true: 1}[c.lines == nil] {
			t.Errorf("%s: %d Set-Cookie headers", c.name, got)
		}
	}
}

// TestTU24ClockRead checks that a request reads the clock one time. This holds
// on the normal path, on the abort path and on a fixed page. The date step of
// TestTU24KeyedFallback shows that the clock sets the date of the key.
func TestTU24ClockRead(t *testing.T) {
	h, _ := eventHandler(t, 64)
	reads := 0
	h.now = func() time.Time { reads++; return testDay }
	serve(t, h, get("/t", "example.com"))
	serve(t, h, get("/nope", "other.example"))
	aborts(h, &failWriter{h: http.Header{}}, get("/t", "example.com"))
	if reads != 3 {
		t.Errorf("%d clock reads for 3 requests", reads)
	}
}

// TestTU24SharedHolder checks NewWithDayKey. The handler uses the holder that
// it gets. So the key of the caller reads its cookies and gives its ids. A nil
// holder gives the handler a holder of its own. New does the same.
func TestTU24SharedHolder(t *testing.T) {
	b := newBundle(t)
	src := &swap{list: []*bundle.Bundle{b}}
	dk := session.NewDayKey()
	h := NewWithDayKey(src, &fallbackFn{}, queueOf(t, 8), dk)
	h.now = func() time.Time { return testDay }
	w, id := sessionEvent(t, "shared", h, get("/", "example.com"))
	val := newCookie(t, "shared", w.Header())
	key := dk.At(testDay)
	if _, ok := key.CheckCookie(val); !ok {
		t.Error("the key of the shared holder does not accept the cookie")
	}
	if want := key.SessionID("192.0.2.1", ""); want == nil || *want != id {
		t.Errorf("event id %q, keyed id of the shared holder %v", id, want)
	}
	for name, own := range map[string]*Handler{
		"nil holder": NewWithDayKey(src, &fallbackFn{}, queueOf(t, 8), nil),
		"New":        New(src, &fallbackFn{}, queueOf(t, 8)),
	} {
		if own.dk == nil || own.dk == dk {
			t.Errorf("%s: holder %p, shared %p", name, own.dk, dk)
			continue
		}
		own.now = func() time.Time { return testDay }
		w, _ := sessionEvent(t, name, own, get("/", "example.com"))
		if _, ok := key.CheckCookie(newCookie(t, name, w.Header())); ok {
			t.Errorf("%s: the shared key accepts the cookie of a handler with its own holder", name)
		}
	}
	for name, f := range map[string]func(){
		"nil source":   func() { NewWithDayKey(nil, &fallbackFn{}, queueOf(t, 8), dk) },
		"nil fallback": func() { NewWithDayKey(src, nil, queueOf(t, 8), dk) },
		"nil queue":    func() { NewWithDayKey(src, &fallbackFn{}, nil, dk) },
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: NewWithDayKey did not panic", name)
				}
			}()
			f()
		}()
	}
}

// TestTU24CookieSwitchRace calls DisableSessionCookie while 4 goroutines serve
// requests. Under -race, a plain bool fails here with a data race. After the
// call, a response sets no cookie.
func TestTU24CookieSwitchRace(t *testing.T) {
	h := New(fixedSource{mixedBundle(t, 0x09, "f", "n")}, &fallbackFn{}, queueOf(t, 64))
	started := make(chan struct{})
	var once sync.Once
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for range 200 {
				serve(t, h, get("/t", "example.com"))
				h.q.Drain()
				once.Do(func() { close(started) })
			}
		})
	}
	<-started
	h.DisableSessionCookie()
	wg.Wait()
	if c := serve(t, h, get("/t", "example.com")).Header().Values("Set-Cookie"); len(c) != 0 {
		t.Errorf("Set-Cookie %v after DisableSessionCookie", c)
	}
}

// TestTU20SiteSameSequence checks two different bundles with the same load
// sequence (zero, as a bundle that no loader swapped in). The second bundle
// does not become cur, because its sequence is not higher than that of cur. It
// gets a site for its own request.
func TestTU20SiteSameSequence(t *testing.T) {
	first, second := new(bundle.Bundle), new(bundle.Bundle)
	h := New(&swap{}, &fallbackFn{}, testQueue(t))
	h.siteOf(first)
	h.siteOf(second)
	if st := h.sites.Load(); st.cur.b != first || st.retired[0] != (weak.Pointer[bundle.Bundle]{}) {
		t.Error("a bundle with a sequence that is not higher became cur")
	}
	if n := h.builds.Load(); n != 2 {
		t.Errorf("builds = %d, want 2", n)
	}
}

// offHandler returns a handler with the session cookie off. It shares the day
// key holder and the clock of on. So a cookie of on has a valid tag.
func offHandler(t *testing.T, on *Handler) *Handler {
	t.Helper()
	off := NewWithDayKey(on.src, &fallbackFn{}, queueOf(t, 64), on.dk)
	off.now = on.now
	off.DisableSessionCookie()
	return off
}

// TestTU24CookieOff checks the off switch (SEC-35). No response has a
// Set-Cookie header, also with a valid cookie. The event has the keyed id, not
// the id of the cookie.
func TestTU24CookieOff(t *testing.T) {
	on, _ := eventHandler(t, 64)
	w, _ := sessionEvent(t, "issue", on, get("/t", "example.com"))
	valid := newCookie(t, "issue", w.Header())
	cookieID, ok := on.dk.At(on.now()).CheckCookie(valid)
	if !ok {
		t.Fatal("the cookie of the on handler is not valid")
	}
	off := offHandler(t, on)
	keyed := keyedID(t, off, "192.0.2.1")
	if cookieID == keyed {
		t.Fatal("the cookie id equals the keyed id")
	}
	for _, c := range []struct{ name, method, host, path string }{
		{"template", "GET", "example.com", "/t"},
		{"template head", "HEAD", "example.com", "/t"},
		{"asset", "GET", "example.com", "/a"},
		{"asset head", "HEAD", "example.com", "/a"},
		{"404 template", "GET", "example.com", "/nope"},
		{"unknown host", "GET", "other.example", "/t"},
		{"405", "POST", "example.com", "/t"},
		{"fixed 404", "GET", "kilo.example", "/nope"},
		{"error before the first byte", "GET", "example.com", "/e"},
	} {
		for _, lines := range [][]string{nil, {"sid=" + valid}} {
			r := get(c.path, c.host)
			r.Method = c.method
			for _, l := range lines {
				r.Header.Add("Cookie", l)
			}
			w, id := sessionEvent(t, c.name, off, r)
			if got := w.Header().Values("Set-Cookie"); len(got) != 0 || id != keyed {
				t.Errorf("%s with cookie %v: Set-Cookie %q, id %q, want the keyed id %q",
					c.name, lines != nil, got, id, keyed)
			}
		}
	}
}

// TestTU24CookieOffAbort checks the off switch on the path of a response that
// ends the connection. The event has the keyed id and no cookie is set.
func TestTU24CookieOffAbort(t *testing.T) {
	on, _ := eventHandler(t, 64)
	w, _ := sessionEvent(t, "issue", on, get("/t", "example.com"))
	valid := newCookie(t, "issue", w.Header())
	off := offHandler(t, on)
	keyed := keyedID(t, off, "192.0.2.1")
	for _, lines := range [][]string{nil, {"sid=" + valid}} {
		fw := &failWriter{h: http.Header{}}
		if !aborts(off, fw, withCookie("/t", lines...)) {
			t.Errorf("cookie %v: no abort", lines != nil)
		}
		rec, _ := oneEvent(t, "abort", off.q)
		if rec.Session == nil || *rec.Session != keyed {
			t.Errorf("cookie %v: session %v, want %q", lines != nil, rec.Session, keyed)
		}
		if got := fw.h.Values("Set-Cookie"); len(got) != 0 {
			t.Errorf("cookie %v: Set-Cookie %q", lines != nil, got)
		}
	}
}

// TestTU24CookieDefaultOn checks that a handler with no call of the switch
// sets one cookie for a new client.
func TestTU24CookieDefaultOn(t *testing.T) {
	h, _ := eventHandler(t, 64)
	w, _ := sessionEvent(t, "default", h, get("/t", "example.com"))
	newCookie(t, "default", w.Header())
}

// TestTU24CookieOffClockRead checks that a request reads the clock one time
// also with the cookie off.
func TestTU24CookieOffClockRead(t *testing.T) {
	on, _ := eventHandler(t, 64)
	off := offHandler(t, on)
	reads := 0
	off.now = func() time.Time { reads++; return testDay }
	serve(t, off, withCookie("/t", "sid=x"))
	aborts(off, &failWriter{h: http.Header{}}, get("/t", "example.com"))
	if reads != 2 {
		t.Errorf("%d clock reads for 2 requests", reads)
	}
}

// fixedSource is a source that gives one bundle. Many goroutines can call it.
type fixedSource struct{ b *bundle.Bundle }

func (s fixedSource) Current() *bundle.Bundle { return s.b }

// TestTU24CookieOffRace runs concurrent requests on a handler with the cookie
// off. The race detector can find a write of the switch on the request path.
// No response has a cookie.
func TestTU24CookieOffRace(t *testing.T) {
	on, _ := eventHandler(t, 64)
	w, _ := sessionEvent(t, "issue", on, get("/t", "example.com"))
	valid := newCookie(t, "issue", w.Header())
	off := offHandler(t, on)
	off.src = fixedSource{on.src.Current()}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 20 {
				r := get("/t", "example.com")
				if i%2 == 1 {
					r.Header.Add("Cookie", "sid="+valid)
				}
				w := httptest.NewRecorder()
				off.ServeHTTP(w, r)
				if got := w.Header().Values("Set-Cookie"); len(got) != 0 {
					t.Errorf("Set-Cookie %q", got)
				}
			}
		}()
	}
	wg.Wait()
}
