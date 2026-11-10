package listener

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

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

// T-U-19: each request over TLS gives one request event, with the client IP of
// the connection.
func TestTU19RequestsGiveEvents(t *testing.T) {
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
		rec := e.Record()
		if e.IP() != "127.0.0.1" || e.Kind() != event.KindRequest || *rec.Status != 200 || *rec.Path != "/p" {
			t.Fatalf("event: %+v ip %q", rec, e.IP())
		}
	}
	if h.EventErrors() != 0 {
		t.Fatal("event errors")
	}
}

var requestPathRows = []struct{ target, want string }{
	{"/a%2Fb<c", "/a%2Fb%3Cc"},
	{"/a%0ab", "/a%0Ab"},
	{"/a%7f", "/a%7F"},
	{"/%2541", "/%2541"},
	{"/é", "/%C3%A9"},
}

// T-U-21: the stored path of a request event keeps each escape of the request
// target with upper-case hex digits. It decodes none, and it holds no control
// byte or non-ASCII byte.
func TestTU21RequestEventPath(t *testing.T) {
	for _, tc := range requestPathRows {
		h, q, _ := newHelloQueue(t, 4)
		serveRaw(t, h, readRequest(t, tc.target, "decoy.test"))
		evs := q.Drain()
		if len(evs) != 1 {
			t.Fatalf("target %q: %d events, want 1", tc.target, len(evs))
		}
		if got := *evs[0].Record().Path; got != tc.want {
			t.Errorf("target %q: stored path %q, want %q", tc.target, got, tc.want)
		}
	}
}

// T-U-21: event.RequestPath and location make the same path for each byte
// after "/". They also do this for the five URLs in this test, for
// requestPathRows and for redirectEscapeRows.
func TestTU21RequestPathMatchesLocation(t *testing.T) {
	us := []*url.URL{{Path: "/%41"}, {Path: "/%zz", RawPath: "/%zz"}, {Path: "/a%", RawPath: "/a%"},
		{Path: "/%2z", RawPath: "/%2z"}, {Path: "/a%4", RawPath: "/a%4"}}
	for b := 0; b < 256; b++ {
		us = append(us, &url.URL{Path: "/" + string([]byte{byte(b)})})
	}
	for _, tc := range requestPathRows {
		us = append(us, readRequest(t, tc.target, "decoy.test").URL)
	}
	for _, tc := range redirectEscapeRows {
		us = append(us, readRequest(t, tc.target, "decoy.test").URL)
	}
	for _, u := range us {
		want := strings.TrimPrefix(location("decoy.test", u), "https://decoy.test")
		if got := event.RequestPath(u.RawPath, u.Path); got != want {
			t.Errorf("RawPath %q, Path %q: RequestPath %q, location %q", u.RawPath, u.Path, got, want)
		}
	}
}

// T-U-19: a full queue drops the event and counts the drop for its lane and
// key. The response bytes do not change.
func TestTU19FullQueueSameResponse(t *testing.T) {
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

// T-U-19: a forwarded-header marker is not in the event.
func TestTU19ForwardedHeadersNotInEvent(t *testing.T) {
	h, q, _ := newHelloQueue(t, 4)
	r := &http.Request{Method: "GET", Host: "decoy.test", Header: http.Header{
		"X-Forwarded-For": {"203.0.113.9 fwdmark"}, "Forwarded": {"for=203.0.113.9;fwdmark"}}}
	serveRaw(t, h, r)
	e, ok := q.TryTake()
	if !ok {
		t.Fatal("no event")
	}
	rec, _ := json.Marshal(e.Record())
	all := string(rec) + e.IP() + string(e.BodyPrefix())
	if strings.Contains(all, "fwdmark") || strings.Contains(all, "203.0.113.9") || e.IP() != "192.0.2.7" {
		t.Fatalf("forwarded value in event: %s", all)
	}
}

// T-S-17: markers in the query, Host and headers are not in any response. A
// marker in the path is only in the Location of the redirect, with each segment
// escaped. The redirect goes only to a configured name, and a foreign Host gets
// the 404 page with no Location.
func TestTS17HelloAndRedirectNeverReflect(t *testing.T) {
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
				if host != "decoy.test" && (resp.StatusCode != 404 || resp.Header.Get("Location") != "") {
					t.Fatalf("%s: foreign Host: status %d, Location %q", tc.name, resp.StatusCode, resp.Header.Get("Location"))
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
			if len(loc) > maxLocation || strings.ContainsAny(loc, "<\r\n") || strings.Contains(loc, "%0d%0a") || resp.StatusCode != 308 {
				t.Fatalf("%s: unsafe Location or status %d: %q", tc.name, resp.StatusCode, loc)
			}
			if strings.Contains(loc[len(loc)-2:], "%") {
				t.Fatalf("%s: cut inside an escape: %q", tc.name, loc[len(loc)-4:])
			}
		}
	}
}

// T-S-17: on both handlers, a method other than GET and HEAD gets 405, and an
// unknown or malformed Host gets 404. On the TLS handler, GET and HEAD on a
// configured name get 200.
func TestTS17MethodAndHostRules(t *testing.T) {
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
	// GET and HEAD on a configured name: status 200, and one fixed body for GET.
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

// T-S-17: the Location of the redirect has each path segment escaped. The path
// "*" gives "/%2A", and the empty path gives "/".
func TestTS17RedirectEscapesSegments(t *testing.T) {
	for _, tc := range []struct{ path, want string }{
		{"/a b/c", "https://decoy.test/a%20b/c"},
		{"*", "https://decoy.test/%2A"},
		{"", "https://decoy.test/"},
	} {
		resp, _ := serveRaw(t, NewRedirect(helloNames), &http.Request{Method: "GET", Host: "decoy.test", URL: &url.URL{Path: tc.path}})
		if got := resp.Header.Get("Location"); got != tc.want {
			t.Fatalf("path %q: Location %q, want %q", tc.path, got, tc.want)
		}
	}
}

// readRequest parses a request for target and host, as the server does.
func readRequest(t *testing.T, target, host string) *http.Request {
	t.Helper()
	raw := "GET " + target + " HTTP/1.1\r\nHost: " + host + "\r\n\r\n"
	r, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		t.Fatalf("target %q: ReadRequest: %v", target, err)
	}
	return r
}

// redirectEscapeRows are the targets of TestTS17RedirectKeepsEscapes, with the
// Location that the redirect gives. TestTU21RequestPathMatchesLocation also
// uses them.
var redirectEscapeRows = []struct{ target, want string }{
	{"/..%2F..%2Fevilmark", "https://decoy.test/..%2F..%2Fevilmark"},
	{"/%2f%2fevil.example", "https://decoy.test/%2F%2Fevil.example"},
	{"/%2e%2e/x", "https://decoy.test/%2E%2E/x"},
	{"/%5cevil", "https://decoy.test/%5Cevil"},
	{"/a%2Fb<c", "https://decoy.test/a%2Fb%3Cc"},
	{"/..%2F<mark>", "https://decoy.test/..%2F%3Cmark%3E"},
	{"/[x]", "https://decoy.test/%5Bx%5D"},
	{"/%41", "https://decoy.test/%41"},
	// These rows hold the hex digit edges 9, a, A and F.
	{"/%9a%2F", "https://decoy.test/%9A%2F"},
	{"/%2F%A0", "https://decoy.test/%2F%A0"},
	{"/a%252Fb", "https://decoy.test/a%252Fb"},
	{"/%0d%0aSet-Cookie:x", "https://decoy.test/%0D%0ASet-Cookie:x"},
	{"/é", "https://decoy.test/%C3%A9"},
	{"/%c3%a9", "https://decoy.test/%C3%A9"},
	{"http://decoy.test/x%2Fy", "https://decoy.test/x%2Fy"},
}

// T-S-17: the Location of the redirect keeps each escape of the request path.
// It decodes none, so "%2F" stays "%2F". A byte that needs an escape gets one.
func TestTS17RedirectKeepsEscapes(t *testing.T) {
	for _, tc := range redirectEscapeRows {
		resp, _ := serveRaw(t, NewRedirect(helloNames), readRequest(t, tc.target, "decoy.test"))
		if got := resp.Header.Get("Location"); resp.StatusCode != 308 || got != tc.want {
			t.Errorf("target %q: status %d, Location %q, want %q", tc.target, resp.StatusCode, got, tc.want)
		}
	}
}

// T-S-17: a byte other than "/" and "%" gets the escape of url.PathEscape.
// A "%" that starts no valid escape gets "%25", in RawPath and in Path.
func TestTS17LocationEscapesEachByte(t *testing.T) {
	for b := 0; b < 256; b++ {
		if b == '/' || b == '%' {
			continue
		}
		s := string([]byte{byte(b)})
		if got, want := location("decoy.test", &url.URL{Path: "/" + s}), "https://decoy.test/"+url.PathEscape(s); got != want {
			t.Errorf("byte %#x: %q, want %q", b, got, want)
		}
	}
	for _, tc := range []struct {
		u    url.URL
		want string
	}{
		{url.URL{Path: "/%zz", RawPath: "/%zz"}, "https://decoy.test/%25zz"},
		{url.URL{Path: "/a%", RawPath: "/a%"}, "https://decoy.test/a%25"},
		{url.URL{Path: "/%41"}, "https://decoy.test/%2541"},
		// A partial escape at the end is not a token. A bad second digit is
		// not a token.
		{url.URL{Path: "/%2z", RawPath: "/%2z"}, "https://decoy.test/%252z"},
		{url.URL{Path: "/a%4", RawPath: "/a%4"}, "https://decoy.test/a%254"},
	} {
		if got := location("decoy.test", &tc.u); got != tc.want {
			t.Errorf("RawPath %q, Path %q: %q, want %q", tc.u.RawPath, tc.u.Path, got, tc.want)
		}
	}
}

// T-S-17: the host of the redirect is always the configured name, never the
// request Host. The request Host is DECOY.test:80, and the Location host is
// decoy.test. A path with two slashes, a backslash, or their escaped forms does
// not change the host.
func TestTS17RedirectHostIsAlwaysConfigured(t *testing.T) {
	for _, target := range []string{
		"//evil.example", "/\\evil.example", "/%2F%2Fevil.example", "///evil.example", "/\\/evil.example",
		"/%5Cevil.example", "/%5cevil.example", "/%2f%2fevil.example",
	} {
		resp, _ := serveRaw(t, NewRedirect(helloNames), readRequest(t, target, "DECOY.test:80"))
		loc := resp.Header.Get("Location")
		t.Logf("target %q: status %d, Location %q", target, resp.StatusCode, loc)
		if resp.StatusCode != 308 || loc == "" {
			t.Fatalf("target %q: status %d, Location %q", target, resp.StatusCode, loc)
		}
		u, err := url.Parse(loc)
		if err != nil || u.Scheme != "https" || u.Host != "decoy.test" || u.User != nil {
			t.Fatalf("target %q: bad Location %q (%v)", target, loc, err)
		}
	}
}

// T-U-19: a NewEvent error adds one to the error counter. The response does not
// change and the queue gets no event.
func TestTU19NewEventErrorCountsAndServes(t *testing.T) {
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

// T-U-19: a peer address with an IPv6 zone gives one request event. The stored
// client address has no zone. The error counter does not change. An
// IPv4-mapped address keeps its form.
func TestTU19ZonedPeerGivesOneEventWithoutZone(t *testing.T) {
	for _, tc := range []struct{ remote, want string }{
		{"[fe80::1%eth0]:1234", "fe80::1"},
		{"[fe80::2%en7]:1234", "fe80::2"},
		{"[::ffff:192.0.2.1]:1234", "::ffff:192.0.2.1"},
		{"[::ffff:192.0.2.1%eth0]:1234", "::ffff:192.0.2.1"},
	} {
		t.Run(tc.remote, func(t *testing.T) {
			h, q, _ := newHelloQueue(t, 4)
			resp, _ := serveRaw(t, h, &http.Request{Method: "GET", Host: "decoy.test", RemoteAddr: tc.remote})
			evs := q.Drain()
			if resp.StatusCode != 200 || h.EventErrors() != 0 || len(evs) != 1 {
				t.Fatalf("status %d, errors %d, events %d", resp.StatusCode, h.EventErrors(), len(evs))
			}
			if got := evs[0].IP(); got != tc.want {
				t.Errorf("stored IP %q, want %q", got, tc.want)
			}
		})
	}
}

// T-S-17: a PRI * HTTP/2.0 request over TLS gets the fixed 404 page and one
// request event.
func TestTS17PriOverTLSGivesNotFoundAndOneEvent(t *testing.T) {
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
	r := evs[0].Record()
	if *r.Method != "PRI" || *r.Status != 404 || r.FP != nil || evs[0].IP() != "127.0.0.1" {
		t.Fatalf("event: %+v", r)
	}
}

// T-S-17: an "OPTIONS *" request goes to the handler on both sockets. A
// configured Host gets 405 with Allow. An unknown Host gets 404. Neither gets
// the 200 with no body of net/http. Over TLS each request gives one request
// event and no refused event, also with "Connection: close". The stored path
// is %2A: the code escapes '*' and adds no leading '/'. On the plain socket it
// gives no Location and no event.
func TestTS17OptionsStarGoesToHandler(t *testing.T) {
	for _, tc := range []struct {
		host string
		code int
		body string
	}{{"decoy.test", 405, methodBody}, {"unknown.test", 404, notFoundBody}} {
		h, q, _ := newHelloQueue(t, 4)
		rg, closed := newClosedRig(t, defaultTimeouts, h)
		rg.serve(t)
		ln := listenLoopback(t)
		go func() { _ = rg.s.ServePlain(ln, NewRedirect(helloNames)) }()
		tlsDial := func() (net.Conn, error) { return dialTLS(rg.addr, rg.clientConfig()) }
		for _, d := range []struct {
			dial   func() (net.Conn, error)
			header string
		}{
			{tlsDial, ""},
			{func() (net.Conn, error) { return dialTCP(ln.Addr().String()) }, ""},
			{tlsDial, "Connection: close\r\n"},
		} {
			c, err := d.dial()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := io.WriteString(c, "OPTIONS * HTTP/1.1\r\nHost: "+tc.host+"\r\n"+d.header+"\r\n"); err != nil {
				t.Fatal(err)
			}
			resp, err := http.ReadResponse(bufio.NewReader(c), nil)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			allow := resp.Header.Get("Allow")
			if resp.StatusCode != tc.code || string(body) != tc.body || resp.Header.Get("Location") != "" || (tc.code == 405) != (allow == "GET, HEAD") {
				t.Fatalf("host %q: %d %q Allow %q", tc.host, resp.StatusCode, body, allow)
			}
			_ = c.Close()
			// The hook of the closed TLS connection must run before Shutdown.
			if _, ok := c.(*tls.Conn); ok {
				waitClosed(t, closed)
			}
		}
		// Shutdown waits for the close of the plain client.
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err := rg.s.Shutdown(ctx)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		evs := q.Drain()
		if len(evs) != 2 {
			t.Fatalf("host %q: %d request events, want 2", tc.host, len(evs))
		}
		for _, e := range evs {
			if r := e.Record(); e.Kind() != event.KindRequest || *r.Method != "OPTIONS" || *r.Path != "%2A" || *r.Status != int64(tc.code) {
				t.Fatalf("host %q: event %+v", tc.host, r)
			}
		}
		wantRefused(t, rg, 0)
	}
}

// T-U-19: BenchmarkHelloHandler measures one request on the TLS handler: the
// reply and the request event. The figure includes the httptest recorder.
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
	n := 0
	for b.Loop() {
		h.ServeHTTP(httptest.NewRecorder(), r)
		if n++; n%1024 == 0 {
			q.Drain()
		}
	}
}

// T-S-17: a cut of the Location never ends inside a %XX escape. The path is
// "/", then pad "a" bytes, then 2100 copies of one unit. The unit is "%2F"
// (kept), "<" (escaped to "%3C") or "a". For the two 3-byte units, the pads 0,
// 1 and 2 give values of 2047, 2048 and 2046 bytes.
func TestTS17LocationCutKeepsEscapes(t *testing.T) {
	for _, unit := range []string{"%2F", "<", "a"} {
		for pad := 0; pad <= 3; pad++ {
			u := &url.URL{RawPath: "/" + strings.Repeat("a", pad) + strings.Repeat(unit, 2100)}
			loc := location("decoy.test", u)
			if len(loc) > maxLocation || len(loc) < maxLocation-2 {
				t.Fatalf("unit %q pad %d: length %d", unit, pad, len(loc))
			}
			if strings.Contains(loc[len(loc)-2:], "%") {
				t.Fatalf("unit %q pad %d: cut inside an escape: %q", unit, pad, loc[len(loc)-4:])
			}
			if p, err := url.Parse(loc); err != nil || p.Host != "decoy.test" {
				t.Fatalf("unit %q pad %d: Location %q (%v)", unit, pad, loc[len(loc)-8:], err)
			}
		}
	}
}

// T-S-17: a cut stops at the first token that does not fit. A later byte that
// fits is not written. The path has 2027 "a", then "<" (3 bytes, too long),
// then "bb". The Location is 2046 bytes.
func TestTS17LocationCutStopsAtFirstToken(t *testing.T) {
	p := "/" + strings.Repeat("a", 2027) + "<bb"
	for _, u := range []url.URL{{Path: p}, {Path: p, RawPath: p}} {
		if got := len(location("decoy.test", &u)); got != 2046 {
			t.Errorf("RawPath %t: length %d, want 2046", u.RawPath != "", got)
		}
	}
}

// T-S-17: location makes one allocation for each path, not one for each
// escaped byte. The path "<<" fills the Grow hint, which is 1 byte above a size
// class of the allocator. A hint 2 bytes short then needs a second allocation.
// The rows "" and "<" give one allocation also with a hint 2 bytes short.
// maxLocation sets the hint of the long path.
func TestTS17LocationAllocationsAreFixed(t *testing.T) {
	for _, p := range []string{"", "<", "<<", strings.Repeat("<", 16384)} {
		u := &url.URL{Path: p}
		if got := testing.AllocsPerRun(10, func() { location("decoy.test", u) }); got != 1 {
			t.Fatalf("path of %d bytes: %v allocations, want 1", len(p), got)
		}
	}
}

// T-S-17: the work of location is bounded by maxLocation, not by the path.
// Each case has its own bound on the heap of one run (max, in bytes). No bound
// is over 16 KiB, and the short path stays under 256 B.
func TestTS17LocationWorkIsBounded(t *testing.T) {
	for _, tc := range []struct {
		name, path string
		max        int64
	}{
		{"short", "/a/b", 256},
		{"slash", strings.Repeat("/", 16384), 4096},
		{"escape", strings.Repeat("<", 16384), 16384},
		{"mixed", "/" + strings.Repeat("<", 238) + "/" + strings.Repeat("<", 16384), 16384},
		{"kept escape", strings.Repeat("%2f", 6000), 4096},
	} {
		u := &url.URL{Path: tc.path, RawPath: tc.path}
		r := testing.Benchmark(func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				location("decoy.test", u)
			}
		})
		t.Logf("%s: %d B/op, %d allocs/op", tc.name, r.AllocedBytesPerOp(), r.AllocsPerOp())
		if got := r.AllocedBytesPerOp(); got >= tc.max {
			t.Fatalf("%s: %d bytes in each run, want less than %d", tc.name, got, tc.max)
		}
		if loc := location("decoy.test", u); len(loc) > maxLocation {
			t.Fatalf("%s: length %d", tc.name, len(loc))
		}
	}
}

// hostShapes are the Host values of T-S-35 for the names decoy.test and
// kilo.example. want is the stored vhost, or "" for no vhost.
var hostShapes = []struct{ name, host, want string }{
	{"exact", "decoy.test", "decoy.test"},
	{"upper case", "DECOY.TEST", "decoy.test"},
	{"port", "decoy.test:8443", "decoy.test"},
	{"upper case and port", "DECOY.test:443", "decoy.test"},
	{"colon with no digits", "decoy.test:", "decoy.test"},
	{"port that is not digits", "decoy.test:abc", ""},
	{"trailing dot", "decoy.test.", ""},
	{"punycode", "xn--bcher-kva.example", ""},
	{"raw UTF-8", "bücher.example", ""},
	{"Kelvin sign", "Kilo.example", ""},
	{"upper case with port", "KILO.example:443", "kilo.example"},
	{"IPv4", "192.0.2.1", ""},
	{"IPv4 with port", "192.0.2.1:443", ""},
	{"IPv6", "[2001:db8::1]", ""},
	{"IPv6 with port", "[2001:db8::1]:443", ""},
	{"IPv6 zone", "[fe80::1%25eth0]", ""},
	{"empty", "", ""},
	{"253 bytes", strings.Repeat("a", 253), ""},
	{"257 bytes", strings.Repeat("a", 257), ""},
	{"NUL escape", "x%00y.example", ""},
}

func vhostOf(rec event.Record) string {
	if rec.Vhost == nil {
		return ""
	}
	return *rec.Vhost
}

// T-S-35: each Host shape gives a configured name or no vhost in the event.
// The Kelvin sign is no match. The redirect handler uses the same match.
func TestTS35HelloStoresMatchedName(t *testing.T) {
	list := []string{"decoy.test", "kilo.example"}
	for _, tc := range hostShapes {
		q, err := event.NewQueue(4, event.NewCounters())
		if err != nil {
			t.Fatal(err)
		}
		resp, _ := serveRaw(t, NewHelloHandler(list, q), &http.Request{Method: "GET", Host: tc.host})
		evs := q.Drain()
		if len(evs) != 1 {
			t.Fatalf("%s: %d events", tc.name, len(evs))
		}
		if got := vhostOf(evs[0].Record()); got != tc.want {
			t.Errorf("%s: stored vhost %q, want %q", tc.name, got, tc.want)
		}
		code, rcode := 404, 404
		if tc.want != "" {
			code, rcode = 200, 308
		}
		rd, _ := serveRaw(t, NewRedirect(list), &http.Request{Method: "GET", Host: tc.host})
		if resp.StatusCode != code || rd.StatusCode != rcode {
			t.Errorf("%s: status %d and redirect %d, want %d and %d", tc.name, resp.StatusCode, rd.StatusCode, code, rcode)
		}
	}
}

// T-S-35: 10 000 distinct Hosts give at most one stored value for each name
// and one for no vhost.
func TestTS35HelloBoundsStoredValues(t *testing.T) {
	h, q, _ := newHelloQueue(t, 1000)
	seen := map[string]bool{}
	for i := 0; i < 10000; i++ {
		host := fmt.Sprintf("h%d.test", i)
		if i%2 == 0 {
			host = fmt.Sprintf("DeCoY.TeSt:%d", i)
		}
		serveRaw(t, h, &http.Request{Method: "GET", Host: host})
		if i%1000 == 999 {
			for _, e := range q.Drain() {
				seen[vhostOf(e.Record())] = true
			}
		}
	}
	if len(seen) > len(helloNames)+1 || !seen["decoy.test"] || !seen[""] {
		t.Errorf("%d distinct stored values, want at most %d, with decoy.test and none", len(seen), len(helloNames)+1)
	}
}

// T-S-35: one request over TLS stores the configured name, not the Host.
func TestTS35HelloTLSStoresName(t *testing.T) {
	h, q, _ := newHelloQueue(t, 4)
	rg := newRig(t, 8, testHeaderBytes, defaultTimeouts, h)
	rg.serve(t)
	c, err := tls.Dial("tcp", rg.addr, rg.clientConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if got := roundTrip(c, "GET / HTTP/1.1\r\nHost: DECOY.test:443\r\n\r\n"); got != 200 {
		t.Fatalf("status %d", got)
	}
	evs := q.Drain()
	if len(evs) != 1 || vhostOf(evs[0].Record()) != "decoy.test" {
		t.Fatalf("events %d, want one with vhost decoy.test", len(evs))
	}
}
