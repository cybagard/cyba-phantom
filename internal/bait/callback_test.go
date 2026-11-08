package bait

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cybagard/cyba-phantom/internal/event"
	"github.com/cybagard/cyba-phantom/internal/token"
)

const (
	cbRoutePath = "/api/v2/internal"
	cbHeaderKey = "X-Request-Token"
	cbAssetBody = "callback\n"
	cbPositions = `{"segment":true,"query":"ref","header":"` + cbHeaderKey + `","body":"tok"}`
	// cbRoutes are a callback route with an asset, one with no asset and one
	// with the query position only.
	cbRoutes = `,{"path":"` + cbRoutePath + `","asset":"vhosts/example.com/cb.txt","type":"text/plain; charset=utf-8","callback":` + cbPositions + `}` +
		`,{"path":"/nc","callback":` + cbPositions + `}` +
		`,{"path":"/nq","asset":"vhosts/example.com/cb.txt","type":"text/plain; charset=utf-8","callback":{"query":"ref"}}`
)

// cbEnv is a handler with a ring and a queue, and the key set that mints
// tokens for the ring.
type cbEnv struct {
	h  *Handler
	q  *event.Queue
	ks *token.KeySet
}

func newCBEnv(t testing.TB) *cbEnv { return newCBEnvFiles(t, nil) }

// newCBEnvFiles is newCBEnv with the files of extra added to the archive.
func newCBEnvFiles(t testing.TB, extra map[string]string) *cbEnv {
	t.Helper()
	rm := strings.TrimSuffix(routesJSON("example.com", exampleRoutes), "]}") + cbRoutes + "]}"
	files := map[string]string{
		"vhosts/example.com/routes.json": rm,
		"vhosts/example.com/cb.txt":      cbAssetBody,
	}
	maps.Copy(files, extra)
	l := archiveLoader(t, "", files)
	b, err := l.Load(true)
	mustOK(t, err)
	q := queueOf(t, 64)
	h := New(l, &fallbackFn{}, q)
	h.SetRing(l.Ring())
	return &cbEnv{h: h, q: q, ks: b.Tokens()}
}

// mint gives the text of a token of trap "a", minted at the given time.
func (e *cbEnv) mint(t testing.TB, at time.Time) string {
	t.Helper()
	tok, err := e.ks.Mint(0, at)
	mustOK(t, err)
	return token.Text(tok)
}

// cbReqN makes a request to route with toks at the positions path, query,
// header and body. An empty text leaves the position absent.
func cbReqN(method, route string, toks [4]string) *http.Request {
	target, body := route, ""
	if toks[0] != "" {
		target += "/" + toks[0]
	}
	if toks[1] != "" {
		target += "?ref=" + toks[1]
	}
	if toks[3] != "" {
		body = `{"tok":"` + toks[3] + `"}`
	}
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	r := httptest.NewRequest(method, target, rd)
	r.Host = "example.com"
	if toks[2] != "" {
		r.Header.Set(cbHeaderKey, toks[2])
	}
	return r
}

// cbReq is cbReqN with the one text tok at position pos.
func cbReq(method, route string, pos int, tok string) *http.Request {
	var toks [4]string
	toks[pos] = tok
	return cbReqN(method, route, toks)
}

// methodOf gives the method that can carry a token at pos.
func methodOf(pos int) string {
	if pos == 3 {
		return http.MethodPost
	}
	return http.MethodGet
}

// take drains q and splits the records by kind.
func take(q *event.Queue) (reqs, cbs []event.Record) {
	for _, ev := range q.Drain() {
		switch r := ev.Record(); r.Kind {
		case event.KindRequest:
			reqs = append(reqs, r)
		case event.KindCallback:
			cbs = append(cbs, r)
		}
	}
	return reqs, cbs
}

// flushProbe counts the events that are on the queue when the handler flushes.
type flushProbe struct {
	*httptest.ResponseRecorder
	q       *event.Queue
	atFlush int
}

func (f *flushProbe) Flush() {
	f.atFlush += len(f.q.Drain())
	f.ResponseRecorder.Flush()
}

// TestTI04CallbackSurfaces checks the handler part of T-I-04. A token at each
// position gives one callback event. The test checks the surface, the trap,
// the token id and the route path. It also checks the vhost, the method, the
// status, the client address and the link. The request gives one request
// event. The handler flushes the response before any event. A route with an
// asset gives 200. A route with none gives 204.
func TestTI04CallbackSurfaces(t *testing.T) {
	e := newCBEnv(t)
	for _, rt := range []struct {
		path string
		code int
	}{{cbRoutePath, 200}, {"/nc", 204}} {
		for pos, surface := range surfaces {
			tok := e.mint(t, time.Now())
			w := &flushProbe{ResponseRecorder: httptest.NewRecorder(), q: e.q}
			r := cbReq(methodOf(pos), rt.path, pos, tok)
			e.h.ServeHTTP(w, r)
			evs := e.q.Drain()
			var reqs, cbs []event.Record
			var cbEv *event.Event
			for _, ev := range evs {
				switch rec := ev.Record(); rec.Kind {
				case event.KindRequest:
					reqs = append(reqs, rec)
				case event.KindCallback:
					cbs, cbEv = append(cbs, rec), ev
				}
			}
			if w.atFlush != 0 || !w.Flushed || w.Code != rt.code {
				t.Errorf("%s %s: %d events at the flush, flushed %v, code %d", rt.path, surface, w.atFlush, w.Flushed, w.Code)
			}
			if len(reqs) != 1 || len(cbs) != 1 {
				t.Fatalf("%s %s: %d request and %d callback events, want 1 and 1", rt.path, surface, len(reqs), len(cbs))
			}
			parsed, _ := token.Parse(tok)
			c := cbs[0]
			if c.Surface == nil || *c.Surface != surface || c.TrapID == nil || *c.TrapID != "a" ||
				c.TokenID == nil || *c.TokenID != token.ID(parsed) || c.Path == nil || *c.Path != rt.path {
				t.Errorf("%s %s: callback record %+v", rt.path, surface, c)
			}
			if c.Vhost == nil || *c.Vhost != "example.com" || c.Method == nil || *c.Method != methodOf(pos) ||
				c.Status == nil || *c.Status != int64(rt.code) {
				t.Errorf("%s %s: callback vhost, method or status in %+v", rt.path, surface, c)
			}
			if ip := cbEv.IP(); ip != "192.0.2.1" {
				t.Errorf("%s %s: client address %q", rt.path, surface, ip)
			}
			// The link comes from an independent check of the token.
			res := token.Verify([]*token.KeySet{e.ks}, parsed)
			want := event.CallbackLink{SetID: res.SetID, Unit: res.Unit, Counter: res.Counter}
			if link, ok := cbEv.Link(); !ok || link != want {
				t.Errorf("%s %s: link %+v (%v), want %+v", rt.path, surface, link, ok, want)
			}
			if c.Session == nil || reqs[0].Session == nil || *c.Session != *reqs[0].Session {
				t.Errorf("%s %s: session of the callback differs from the request", rt.path, surface)
			}
			if want := (event.Detail{"reference_seed": event.Bool(true)}); !reflect.DeepEqual(c.Detail, want) {
				t.Errorf("%s %s: detail %v, want %v", rt.path, surface, c.Detail, want)
			}
		}
	}
}

// TestTI04CallbackDistinct checks that each distinct verified token gives one
// event, with the surface of its first position.
func TestTI04CallbackDistinct(t *testing.T) {
	e := newCBEnv(t)
	a, b, c, d := e.mint(t, time.Now()), e.mint(t, time.Now()), e.mint(t, time.Now()), e.mint(t, time.Now())
	// Each case reuses the tokens, so the clock steps past the token window.
	var clock time.Duration
	e.h.mono = func() time.Duration { return clock }
	for _, tc := range []struct {
		name string
		toks [4]string
		want []event.Surface
	}{
		{"four tokens", [4]string{a, b, c, d}, []event.Surface{"path", "query", "header", "body"}},
		{"query and body", [4]string{"", a, "", a}, []event.Surface{"query"}},
		{"path and header", [4]string{a, "", a, ""}, []event.Surface{"path"}},
		{"same token four times", [4]string{a, a, a, a}, []event.Surface{"path"}},
		{"one bad token", [4]string{a, strings.Repeat("a", 26), b, ""}, []event.Surface{"path", "header"}},
	} {
		clock += 2 * capTokenWindow
		w := httptest.NewRecorder()
		e.h.ServeHTTP(w, cbReqN(http.MethodPost, cbRoutePath, tc.toks))
		reqs, cbs := take(e.q)
		var got []event.Surface
		for _, r := range cbs {
			got = append(got, *r.Surface)
		}
		if len(reqs) != 1 || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: %d request events, callback surfaces %v, want %v", tc.name, len(reqs), got, tc.want)
		}
	}
}

// dump gives the status, the headers without Date and the body of a response.
func dump(w *httptest.ResponseRecorder) string {
	res := w.Result()
	hd := res.Header.Clone()
	hd.Del("Date")
	body, _ := io.ReadAll(res.Body)
	return fmt.Sprintf("%d %v %q flushed=%v", res.StatusCode, hd, body, w.Flushed)
}

// head gives the status of a response and its headers without Date.
func head(w *httptest.ResponseRecorder) string {
	hd := w.Result().Header.Clone()
	hd.Del("Date")
	return fmt.Sprintf("%d %v", w.Code, hd)
}

// otherKeySetToken gives the text of a token that a key set outside of the
// ring minted.
func otherKeySetToken(t testing.TB) string {
	t.Helper()
	ks, err := token.NewKeySet(bytes.Repeat([]byte{9}, 32), [32]byte{2}, []string{"a"}, false)
	mustOK(t, err)
	tok, err := ks.Mint(0, time.Now())
	mustOK(t, err)
	return token.Text(tok)
}

// TestTS32CallbackFixedResponse checks the response for good, stale, future,
// bad, absent, other-key-set and capped tokens. It must have equal bytes at
// each position, and no Set-Cookie. For a capped token, the test also checks
// the capped counter and the missing callback event. So the case is not a good
// token. The test does this for a route with an asset and a route with none,
// for GET, HEAD and POST. Both routes have a body
// position, so POST also goes to the path, query and header positions. The
// test checks the header values. A HEAD response has the status and headers
// of the GET response.
func TestTS32CallbackFixedResponse(t *testing.T) {
	e := newCBEnv(t)
	toks := map[string]string{
		"good":   e.mint(t, time.Now()),
		"stale":  e.mint(t, time.Now().Add(-26*time.Hour)),
		"future": e.mint(t, time.Now().Add(2*time.Hour)),
		"bad":    strings.Repeat("a", 26),
		"other":  otherKeySetToken(t),
		"none":   "",
		// The cap admits this token one time below. Each later use is capped.
		"capped": e.mint(t, time.Now()),
	}
	e.h.ServeHTTP(httptest.NewRecorder(), cbReq(http.MethodGet, cbRoutePath, posQuery, toks["capped"]))
	e.q.Drain()
	const ctype = "text/plain; charset=utf-8"
	for _, rt := range []struct {
		path  string
		code  int
		body  string
		ctype string
	}{{cbRoutePath, 200, cbAssetBody, ctype}, {"/nc", 204, "", ""}} {
		// Each method has one response for each position and token kind.
		dumps, heads := map[string]string{}, map[string]string{}
		for pos := range surfaces {
			for _, m := range []string{http.MethodGet, http.MethodHead, http.MethodPost} {
				for _, kind := range []string{"good", "stale", "future", "bad", "other", "none", "capped"} {
					w := httptest.NewRecorder()
					before := e.h.capped.Load()
					e.h.ServeHTTP(w, cbReq(m, rt.path, pos, toks[kind]))
					reqs, cbs := take(e.q)
					// A GET or HEAD reads no body: no token at the body.
					if read := pos != posBody || m == http.MethodPost; kind == "capped" && read &&
						(e.h.capped.Load() != before+1 || len(cbs) != 0 || len(reqs) != 1 || reqs[0].TokenID == nil) {
						t.Errorf("%s %s pos %d: the token was not capped (%d callback events, %d capped)", m, rt.path, pos, len(cbs), e.h.capped.Load()-before)
					}
					got := dump(w)
					want := rt.body
					if m == http.MethodHead {
						want = ""
					}
					res := w.Result()
					if w.Code != rt.code || w.Body.String() != want || len(res.Header.Values("Set-Cookie")) != 0 {
						t.Errorf("%s %s pos %d %s: %s", m, rt.path, pos, kind, got)
					}
					wantLen := []string(nil)
					if rt.code == 200 {
						wantLen = []string{strconv.Itoa(len(cbAssetBody))}
					}
					if !reflect.DeepEqual(res.Header["X-Content-Type-Options"], []string{"nosniff"}) ||
						res.Header.Get("Content-Type") != rt.ctype || !reflect.DeepEqual(res.Header["Content-Length"], wantLen) {
						t.Errorf("%s %s pos %d %s: headers %v", m, rt.path, pos, kind, res.Header)
					}
					if first, ok := dumps[m]; !ok {
						dumps[m], heads[m] = got, head(w)
					} else if got != first {
						t.Errorf("%s %s pos %d %s: response differs:\n%s\n%s", m, rt.path, pos, kind, got, first)
					}
				}
			}
		}
		if heads[http.MethodHead] != heads[http.MethodGet] || heads[http.MethodPost] != heads[http.MethodGet] {
			t.Errorf("%s: GET, HEAD and POST differ in status or headers:\n%v", rt.path, heads)
		}
	}
}

// TestTS32CallbackDetail checks the detail members: stale, future and
// reference_seed, true members only.
func TestTS32CallbackDetail(t *testing.T) {
	e := newCBEnv(t)
	for _, tc := range []struct {
		name string
		at   time.Time
		want event.Detail
	}{
		{"good", time.Now(), event.Detail{"reference_seed": event.Bool(true)}},
		{"stale", time.Now().Add(-26 * time.Hour), event.Detail{"reference_seed": event.Bool(true), "stale": event.Bool(true)}},
		{"future", time.Now().Add(2 * time.Hour), event.Detail{"reference_seed": event.Bool(true), "stale": event.Bool(true), "future": event.Bool(true)}},
	} {
		e.h.ServeHTTP(httptest.NewRecorder(), cbReq(http.MethodGet, cbRoutePath, 1, e.mint(t, tc.at)))
		_, cbs := take(e.q)
		if len(cbs) != 1 || !reflect.DeepEqual(cbs[0].Detail, tc.want) {
			t.Errorf("%s: records %+v, want detail %v", tc.name, cbs, tc.want)
		}
	}
	// A text that is no token of the ring gives no callback event. This holds
	// for a token that a key set outside of the ring minted.
	for name, text := range map[string]string{"bad": strings.Repeat("a", 26), "other key set": otherKeySetToken(t)} {
		e.h.ServeHTTP(httptest.NewRecorder(), cbReq(http.MethodGet, cbRoutePath, 1, text))
		if reqs, cbs := take(e.q); len(reqs) != 1 || len(cbs) != 0 {
			t.Errorf("%s token: %d request and %d callback events", name, len(reqs), len(cbs))
		}
	}
}

// TestTS32CallbackMarker checks that the token text is in no member of a
// callback event and in no detail. The handler counts no error. The request
// event keeps the escaped request path, because ADR-039 says so.
// So the test skips the request event of a path callback. The callback event
// also does not hold the case of the Host header.
func TestTS32CallbackMarker(t *testing.T) {
	e := newCBEnv(t)
	for pos, surface := range surfaces {
		marker := e.mint(t, time.Now())
		r := cbReq(methodOf(pos), cbRoutePath, pos, marker)
		r.Host = "eXaMpLe.CoM"
		e.h.ServeHTTP(httptest.NewRecorder(), r)
		for _, ev := range e.q.Drain() {
			if pos == posPath && ev.Kind() == event.KindRequest {
				continue
			}
			b, err := json.Marshal(ev.Record())
			mustOK(t, err)
			text := string(b) + fmt.Sprintf("%+v", ev.Record()) + ev.IP()
			if strings.Contains(text, marker) {
				t.Errorf("%s: the marker is in the %s event", surface, ev.Kind())
			}
			if ev.Kind() == event.KindCallback && strings.Contains(text, "eXaMpLe") {
				t.Errorf("%s: the Host case is in the callback event", surface)
			}
		}
	}
	if n := e.h.eventErrs.Load(); n != 0 {
		t.Errorf("%d event errors", n)
	}
}

// TestTS32CallbackVhost checks that the callback record has the vhost name of
// the bundle, not the Host header of the request. The request event keeps the
// Host header.
func TestTS32CallbackVhost(t *testing.T) {
	e := newCBEnv(t)
	host := "eXaMpLe.CoM:" + strings.Repeat("9", 300)
	r := cbReq(http.MethodGet, cbRoutePath, posQuery, e.mint(t, time.Now()))
	r.Host = host
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	reqs, cbs := take(e.q)
	if w.Code != 200 || len(reqs) != 1 || len(cbs) != 1 {
		t.Fatalf("code %d with %d request and %d callback events", w.Code, len(reqs), len(cbs))
	}
	if cbs[0].Vhost == nil || *cbs[0].Vhost != "example.com" {
		t.Errorf("callback vhost %v, want example.com", cbs[0].Vhost)
	}
	// NewEvent bounds the text of the Host header.
	if v := reqs[0].Vhost; v == nil || !strings.HasPrefix(*v, "eXaMpLe.CoM:") {
		t.Errorf("request vhost %v, want the Host header", v)
	}
}

// TestTS32CallbackHeaderName checks a route with a header name that is not
// canonical. A token in the canonical header gives one callback event.
func TestTS32CallbackHeaderName(t *testing.T) {
	e := newCBEnvFiles(t, map[string]string{
		"vhosts/lima.example/routes.json": `{"routes":[{"path":"/h","callback":{"header":"X-REQUEST-TOKEN"}}]}`,
	})
	r := httptest.NewRequest(http.MethodGet, "/h", nil)
	r.Host = "lima.example"
	r.Header.Set("X-Request-Token", e.mint(t, time.Now()))
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	reqs, cbs := take(e.q)
	if w.Code != 204 || len(reqs) != 1 || len(cbs) != 1 || *cbs[0].Surface != event.SurfaceHeader {
		t.Errorf("code %d with %d request and %d callback events %+v", w.Code, len(reqs), len(cbs), cbs)
	}
}

// TestTS32CallbackRoutes checks the route match and the methods. A callback
// route matches its path, and with a segment position its path and one segment.
// Only a callback route with a body position accepts POST.
func TestTS32CallbackRoutes(t *testing.T) {
	e := newCBEnv(t)
	for _, tc := range []struct {
		method, target string
		code           int
	}{
		{"GET", "/nq", 200},
		{"HEAD", "/nq", 200},
		{"POST", "/nq", 405},
		{"POST", "/nc", 204},
		{"PUT", "/nc", 405},
		{"POST", "/t", 405},
		{"GET", cbRoutePath + "/hello", 200},
		{"GET", cbRoutePath + "/", 200},
		{"GET", cbRoutePath + "/a/b", 404},
		{"POST", cbRoutePath + "/a/b", 405},
		{"GET", "/nq/hello", 404},
		{"GET", "/api/v2", 404},
	} {
		r := httptest.NewRequest(tc.method, tc.target, nil)
		r.Host = "example.com"
		w := httptest.NewRecorder()
		e.h.ServeHTTP(w, r)
		if _, cbs := take(e.q); w.Code != tc.code || len(cbs) != 0 {
			t.Errorf("%s %s: code %d with %d callback events, want %d with none", tc.method, tc.target, w.Code, len(cbs), tc.code)
		}
	}
}

// TestTS32CallbackNoRing checks that a handler with no ring gives the fixed
// response and the request event, and no callback event.
func TestTS32CallbackNoRing(t *testing.T) {
	e := newCBEnv(t)
	tok := e.mint(t, time.Now())
	with := httptest.NewRecorder()
	e.h.ServeHTTP(with, cbReq(http.MethodGet, cbRoutePath, 1, tok))
	e.q.Drain()
	e.h.ring = nil
	without := httptest.NewRecorder()
	e.h.ServeHTTP(without, cbReq(http.MethodGet, cbRoutePath, 1, tok))
	reqs, cbs := take(e.q)
	if dump(with) != dump(without) || len(reqs) != 1 || len(cbs) != 0 {
		t.Errorf("no ring: %d request and %d callback events\n%s\n%s", len(reqs), len(cbs), dump(with), dump(without))
	}
}

// rootRoutes make "/" of kilo.example a callback route with a segment
// position. The vhost has one more route: an exact route with the shape of a
// token.
const (
	exactShape = "aaaaaaaaaaaaaaaaaaaaaaaaaa"
	rootRoutes = `{"routes":[` +
		`{"path":"/","asset":"vhosts/kilo.example/kilo.txt","type":"text/plain; charset=utf-8","callback":{"segment":true}},` +
		`{"path":"/` + exactShape + `","asset":"vhosts/kilo.example/other.txt","type":"text/plain; charset=utf-8"}]}`
)

// TestTS32CallbackRootSegment checks a segment callback route at the root
// path. It matches "/" and "/" with one segment. An exact route of the vhost
// comes first. "//", "//x", "//" with a token, "" and "*" get the 404 decoy.
func TestTS32CallbackRootSegment(t *testing.T) {
	e := newCBEnvFiles(t, map[string]string{
		"vhosts/kilo.example/routes.json": rootRoutes,
		"vhosts/kilo.example/other.txt":   "other\n",
	})
	for _, tc := range []struct {
		target, body string
		code         int
		token        bool
	}{
		{"/" + e.mint(t, time.Now()), "kilo\n", 200, true},
		{"/", "kilo\n", 200, false},
		{"/" + exactShape, "other\n", 200, false},
		{"/a/b", "not found\n", 404, false},
		{"//", "not found\n", 404, false},
		{"//x", "not found\n", 404, false},
		{"//" + e.mint(t, time.Now()), "not found\n", 404, false},
		{"", "not found\n", 404, false},
		{"*", "not found\n", 404, false},
	} {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		// The request line "GET * HTTP/1.1" gives the path "*". An
		// absolute-form target with no path gives an empty path.
		r.URL.Path = tc.target
		r.Host = "kilo.example"
		w := httptest.NewRecorder()
		e.h.ServeHTTP(w, r)
		_, cbs := take(e.q)
		if w.Code != tc.code || w.Body.String() != tc.body || len(cbs) != btoi(tc.token) {
			t.Errorf("GET %s: code %d body %q with %d callback events", tc.target, w.Code, w.Body.String(), len(cbs))
		}
		if tc.token && (len(cbs) != 1 || *cbs[0].Surface != event.SurfacePath || *cbs[0].Path != "/") {
			t.Errorf("GET %s: callback records %+v", tc.target, cbs)
		}
	}
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

// TestTS32CallbackLiveDetail checks the detail with a key set that is not of a
// reference bundle. A good token has no detail member. A stale token has only
// stale. A future token has stale and future.
func TestTS32CallbackLiveDetail(t *testing.T) {
	e := newCBEnv(t)
	ks, err := token.NewKeySet(bytes.Repeat([]byte{7}, 32), [32]byte{1}, []string{"a"}, false)
	mustOK(t, err)
	ring := token.NewRing(time.Now)
	ring.Swap(ks)
	e.h.SetRing(ring)
	e.ks = ks
	for _, tc := range []struct {
		name string
		at   time.Time
		want event.Detail
	}{
		{"good", time.Now(), nil},
		{"stale", time.Now().Add(-26 * time.Hour), event.Detail{"stale": event.Bool(true)}},
		{"future", time.Now().Add(2 * time.Hour), event.Detail{"future": event.Bool(true), "stale": event.Bool(true)}},
	} {
		e.h.ServeHTTP(httptest.NewRecorder(), cbReq(http.MethodGet, cbRoutePath, 1, e.mint(t, tc.at)))
		_, cbs := take(e.q)
		if len(cbs) != 1 || len(cbs[0].Detail) != len(tc.want) || (len(tc.want) > 0 && !reflect.DeepEqual(cbs[0].Detail, tc.want)) {
			t.Errorf("%s: records %+v, want detail %v", tc.name, cbs, tc.want)
		}
	}
}

// BenchmarkCallbackFourPositions measures one callback request with a token at
// each of the 4 positions. It includes the 4 callback events and the request
// event.
func BenchmarkCallbackFourPositions(b *testing.B) {
	e := newCBEnv(b)
	var toks [4]string
	for i := range toks {
		toks[i] = e.mint(b, time.Now())
	}
	r := cbReqN(http.MethodPost, cbRoutePath, toks)
	body := &rewind{data: []byte(`{"tok":"` + toks[3] + `"}`)}
	w := &discard{h: http.Header{}}
	// The clock steps past the token window at each request, so each request
	// makes its 4 callback events.
	var clock time.Duration
	e.h.mono = func() time.Duration { return clock }
	b.ReportAllocs()
	for b.Loop() {
		clock += 2 * capTokenWindow
		clear(w.h)
		body.off, r.Body = 0, body
		e.h.ServeHTTP(w, r)
		for {
			if _, ok := e.q.TryTake(); !ok {
				break
			}
		}
	}
}
