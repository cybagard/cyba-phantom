package bait

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/cybagard/cyba-phantom/internal/event"
)

// eventHandler returns the handler of outHandler with a queue of depth.
func eventHandler(t *testing.T, depth int) (*Handler, *event.Queue) {
	t.Helper()
	q := queueOf(t, depth)
	return outHandlerQ(t, q), q
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
	}{
		{"200 template", "GET", "example.com", "/t", 200},
		{"200 asset", "GET", "Example.COM:443", "/a", 200},
		{"404 unknown host", "GET", "other.example", "/t", 404},
		{"404 no route with 404 template", "GET", "example.com", "/nope", 404},
		{"404 no route without 404 template", "GET", "kilo.example", "/nope", 404},
		{"405", "POST", "example.com", "/t", 405},
		{"HEAD", "HEAD", "example.com", "/t", 200},
		{"error before the first byte", "GET", "example.com", "/e", 404},
	} {
		h, q := eventHandler(t, 8)
		r := get(c.path, c.host)
		r.Method = c.method
		w := serve(t, h, r)
		rec, ip := oneEvent(t, c.name, q)
		if w.Code != c.status || rec.Status == nil || *rec.Status != int64(c.status) ||
			*rec.Vhost != c.host || *rec.Method != c.method || *rec.Path != c.path || ip != "192.0.2.1" ||
			len(rec.Detail) != 0 || rec.Session != nil || rec.TrapID != nil || rec.TokenID != nil {
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
			h.token = c.token
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
	if h.eventErrs.Load() != 0 || rec.Path == nil || !utf8.ValidString(*rec.Path) || !strings.HasPrefix(*rec.Path, "/%FF%FF") {
		t.Errorf("errors %d, path %v", h.eventErrs.Load(), rec.Path)
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
	if strings.Contains(string(out), mark) || strings.Contains(ip, mark) || len(rec.Detail) != 0 {
		t.Errorf("a marker is in the event: %s, ip %q", out, ip)
	}
}

// TestTU20RequestEventAddr checks the client address. A form that the
// listener passes on is passed on here. NewEvent refuses a value that is not
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
		if _, ip := oneEvent(t, c.addr, q); ip != c.ip || h.eventErrs.Load() != 0 {
			t.Errorf("%q: ip %q, errors %d", c.addr, ip, h.eventErrs.Load())
		}
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
	if d.Bulk+d.Evidence+d.Invalid == 0 || len(q.Drain()) != 1 {
		t.Errorf("dropped %+v", d)
	}
}
