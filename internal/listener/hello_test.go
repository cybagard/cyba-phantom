package listener

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"

	"github.com/cybagard/cyba-phantom/internal/event"
)

var helloNames = []string{"decoy.test", "other.test"}

func newHelloQueue(t *testing.T, depth int) (*HelloHandler, *event.Queue, *event.Counters) {
	t.Helper()
	c := event.NewCounters()
	q, err := event.NewQueue(depth, c)
	if err != nil {
		t.Fatal(err)
	}
	return NewHelloHandler(helloNames, q), q, c
}

// serveRaw sends a request that is not checked by the client and returns the
// bytes of the whole response (status line, headers and body).
func serveRaw(t *testing.T, h http.Handler, r *http.Request) (*http.Response, string) {
	t.Helper()
	if r.URL == nil {
		r.URL = &url.URL{Path: "/"}
	}
	if r.Header == nil {
		r.Header = http.Header{}
	}
	if r.RemoteAddr == "" {
		r.RemoteAddr = "192.0.2.7:4000"
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var b bytes.Buffer
	if err := w.Result().Write(&b); err != nil {
		t.Fatal(err)
	}
	return w.Result(), b.String()
}

func TestHelloRequestsGiveEvents(t *testing.T) {
	h, q, _ := newHelloQueue(t, 16)
	rg := newRig(t, 8, testHeaderBytes, defaultTimeouts, h)
	rg.serve(t)
	const n = 5
	for i := 0; i < n; i++ {
		c := rg.dial(t)
		if got := roundTrip(c, "GET /p HTTP/1.1\r\nHost: Decoy.Test:443\r\n\r\n"); got != 200 {
			t.Fatalf("status %d", got)
		}
	}
	evs := q.Drain()
	if len(evs) != n {
		t.Fatalf("events: got %d, want %d", len(evs), n)
	}
	for _, e := range evs {
		if e.DB.IP != "127.0.0.1" || e.Record.Kind != event.KindRequest || *e.Record.Status != 200 || *e.Record.Path != "/p" {
			t.Fatalf("event: %+v ip %q", e.Record, e.DB.IP)
		}
	}
	if h.EventErrors() != 0 {
		t.Fatal("event errors")
	}
}

func TestHelloFullQueueSameResponse(t *testing.T) {
	h, q, c := newHelloQueue(t, event.MinQueueDepth)
	var first string
	for i := 0; i <= event.MinQueueDepth; i++ {
		_, raw := serveRaw(t, h, &http.Request{Method: "GET", Host: "decoy.test"})
		if i == 0 {
			first = raw
		} else if raw != first {
			t.Fatalf("response %d changed:\n%q\n%q", i, raw, first)
		}
	}
	if d := q.Dropped().Bulk; d != 1 {
		t.Fatalf("bulk drops %d, want 1", d)
	}
	counts, _ := c.Snapshot()
	if counts[netip.MustParseAddr("192.0.2.7")] != 1 {
		t.Fatalf("key counter: %v", counts)
	}
}

func TestHelloForwardedHeadersNotInEvent(t *testing.T) {
	h, q, _ := newHelloQueue(t, 4)
	r := &http.Request{Method: "GET", Host: "decoy.test", Header: http.Header{
		"X-Forwarded-For": {"203.0.113.9 fwdmark"}, "Forwarded": {"for=203.0.113.9;fwdmark"}}}
	serveRaw(t, h, r)
	e, ok := q.TryTake()
	if !ok {
		t.Fatal("no event")
	}
	rec, _ := json.Marshal(e.Record)
	all := string(rec) + e.DB.IP + string(e.DB.BodyPrefix)
	if strings.Contains(all, "fwdmark") || strings.Contains(all, "203.0.113.9") || e.DB.IP != "192.0.2.7" {
		t.Fatalf("forwarded value in event: %s", all)
	}
}

func TestHelloAndRedirectNeverReflect(t *testing.T) {
	long := strings.Repeat("a", 5000)
	cases := []struct{ name, m string }{
		{"script", "<script>"}, {"crlf", "x\r\nSet-Cookie: a=b"}, {"pct", "%0d%0a"},
		{"host", "evil.example"}, {"long", long},
	}
	for _, tc := range cases {
		for _, h := range []http.Handler{func() http.Handler { h, _, _ := newHelloQueue(t, 4); return h }(), NewRedirect(helloNames)} {
			// The marker in the query, a header and a foreign Host must never show.
			for _, host := range []string{"decoy.test", tc.m} {
				r := &http.Request{Method: "GET", Host: host, URL: &url.URL{Path: "/", RawQuery: tc.m},
					Header: http.Header{"X-Probe": {tc.m}, "User-Agent": {tc.m}, "Referer": {tc.m}}}
				resp, raw := serveRaw(t, h, r)
				if strings.Contains(raw, tc.m) || resp.Header.Get("Server") != "" {
					t.Fatalf("%s: reflected or Server header: %q", tc.name, raw)
				}
			}
			// The marker in the path: only the redirect copies it, escaped.
			resp, raw := serveRaw(t, h, &http.Request{Method: "GET", Host: "DECOY.test:80", URL: &url.URL{Path: "/" + tc.m}})
			if _, redirect := h.(*Redirect); !redirect {
				if strings.Contains(raw, tc.m) {
					t.Fatalf("%s: path reflected: %q", tc.name, raw)
				}
				continue
			}
			loc := resp.Header.Get("Location")
			u, err := url.Parse(loc)
			if err != nil || u.Scheme != "https" || u.Host != "decoy.test" || u.RawQuery != "" {
				t.Fatalf("%s: bad Location %q (%v)", tc.name, loc, err)
			}
			if len(loc) > 2048 || strings.ContainsAny(loc, "<\r\n") || strings.Contains(loc, "%0d%0a") || resp.StatusCode != 308 {
				t.Fatalf("%s: unsafe Location or status %d: %q", tc.name, resp.StatusCode, loc)
			}
			if strings.Contains(loc[len(loc)-2:], "%") {
				t.Fatalf("%s: cut inside an escape: %q", tc.name, loc[len(loc)-4:])
			}
		}
	}
}

func TestMethodAndHostRules(t *testing.T) {
	hello, q, _ := newHelloQueue(t, 8)
	for _, h := range []http.Handler{hello, NewRedirect(helloNames)} {
		for _, tc := range []struct {
			method, host string
			want         int
			body         string
		}{
			{"POST", "decoy.test", 405, methodBody},
			{"GET", "unknown.test", 404, notFoundBody},
			{"GET", "", 404, notFoundBody},
			{"GET", "[::1]:80:x", 404, notFoundBody},
			{"PRI", "unknown.test", 404, notFoundBody},
		} {
			resp, raw := serveRaw(t, h, &http.Request{Method: tc.method, Host: tc.host})
			if resp.StatusCode != tc.want || !strings.HasSuffix(raw, tc.body) || resp.Header.Get("Server") != "" {
				t.Fatalf("%s %q: %d %q", tc.method, tc.host, resp.StatusCode, raw)
			}
		}
	}
	// GET and HEAD on a configured name: one fixed body, and no body for HEAD.
	for _, m := range []string{"GET", "HEAD"} {
		resp, _ := serveRaw(t, hello, &http.Request{Method: m, Host: "other.test", URL: &url.URL{Path: "/any/path"}})
		if resp.StatusCode != 200 {
			t.Fatalf("%s: %d", m, resp.StatusCode)
		}
	}
	_, raw := serveRaw(t, hello, &http.Request{Method: "GET", Host: "other.test"})
	if !strings.HasSuffix(raw, helloBody) {
		t.Fatalf("body %q", raw)
	}
	if got := len(q.Drain()); got != 8 {
		t.Fatalf("events: %d", got)
	}
}

func TestRedirectWritesNoEvent(t *testing.T) {
	_, q, _ := newHelloQueue(t, 4)
	serveRaw(t, NewRedirect(helloNames), &http.Request{Method: "GET", Host: "decoy.test", URL: &url.URL{Path: "/a b"}})
	if n := len(q.Drain()); n != 0 {
		t.Fatalf("events: %d", n)
	}
	resp, _ := serveRaw(t, NewRedirect(helloNames), &http.Request{Method: "GET", Host: "decoy.test", URL: &url.URL{Path: "/a b/c"}})
	if got := resp.Header.Get("Location"); got != "https://decoy.test/a%20b/c" {
		t.Fatalf("Location %q", got)
	}
}

func TestNewEventErrorCountsAndServes(t *testing.T) {
	h, q, _ := newHelloQueue(t, 4)
	// A remote address that is not an IP makes NewEvent return an error.
	resp, raw := serveRaw(t, h, &http.Request{Method: "GET", Host: "decoy.test", RemoteAddr: "not-an-address"})
	if resp.StatusCode != 200 || !strings.HasSuffix(raw, helloBody) {
		t.Fatalf("response changed: %q", raw)
	}
	if h.EventErrors() != 1 || len(q.Drain()) != 0 {
		t.Fatalf("errors %d", h.EventErrors())
	}
}

func TestPriOverTLSGivesNotFoundAndOneEvent(t *testing.T) {
	h, q, _ := newHelloQueue(t, 4)
	rg := newRig(t, 8, testHeaderBytes, defaultTimeouts, h)
	rg.serve(t)
	c, err := tls.Dial("tcp", rg.addr, rg.clientConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := io.WriteString(c, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 404 || string(body) != notFoundBody {
		t.Fatalf("got %d %q", resp.StatusCode, body)
	}
	evs := q.Drain()
	if len(evs) != 1 {
		t.Fatalf("events: %d", len(evs))
	}
	r := evs[0].Record
	if *r.Method != "PRI" || *r.Status != 404 || r.FP != nil || evs[0].DB.IP != "127.0.0.1" {
		t.Fatalf("event: %+v", r)
	}
}

func BenchmarkHelloHandler(b *testing.B) {
	c := event.NewCounters()
	q, err := event.NewQueue(event.MaxQueueDepth, c)
	if err != nil {
		b.Fatal(err)
	}
	h := NewHelloHandler(helloNames, q)
	r := &http.Request{Method: "GET", Host: "decoy.test", URL: &url.URL{Path: "/"},
		Header: http.Header{}, RemoteAddr: "192.0.2.7:4000"}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		h.ServeHTTP(httptest.NewRecorder(), r)
		if i%1024 == 1023 {
			q.Drain()
		}
	}
}
