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
// position gives one callback event. It has the surface, the trap, the token
// id and the route path. The request gives one request event. The handler
// flushes the response before any event.
func TestTI04CallbackSurfaces(t *testing.T) {
	e := newCBEnv(t)
	for pos, surface := range surfaces {
		tok := e.mint(t, time.Now())
		w := &flushProbe{ResponseRecorder: httptest.NewRecorder(), q: e.q}
		r := cbReq(methodOf(pos), cbRoutePath, pos, tok)
		e.h.ServeHTTP(w, r)
		reqs, cbs := take(e.q)
		if w.atFlush != 0 || !w.Flushed || w.Code != 200 {
			t.Errorf("%s: %d events at the flush, flushed %v, code %d", surface, w.atFlush, w.Flushed, w.Code)
		}
		if len(reqs) != 1 || len(cbs) != 1 {
			t.Fatalf("%s: %d request and %d callback events, want 1 and 1", surface, len(reqs), len(cbs))
		}
		parsed, _ := token.Parse(tok)
		c := cbs[0]
		if c.Surface == nil || *c.Surface != surface || c.TrapID == nil || *c.TrapID != "a" ||
			c.TokenID == nil || *c.TokenID != token.ID(parsed) || c.Path == nil || *c.Path != cbRoutePath {
			t.Errorf("%s: callback record %+v", surface, c)
		}
		if c.Session == nil || reqs[0].Session == nil || *c.Session != *reqs[0].Session {
			t.Errorf("%s: session of the callback differs from the request", surface)
		}
		if want := (event.Detail{"reference_seed": event.Bool(true)}); !reflect.DeepEqual(c.Detail, want) {
			t.Errorf("%s: detail %v, want %v", surface, c.Detail, want)
		}
	}
}

// TestTI04CallbackDistinct checks that each distinct verified token gives one
// event, with the surface of its first position.
func TestTI04CallbackDistinct(t *testing.T) {
	e := newCBEnv(t)
	a, b, c, d := e.mint(t, time.Now()), e.mint(t, time.Now()), e.mint(t, time.Now()), e.mint(t, time.Now())
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

// TestTS32CallbackFixedResponse checks that good, stale, future, bad and absent
// tokens give equal response bytes at each position, with no Set-Cookie. It
// does this for a route with an asset and a route with none, for GET, HEAD and
// POST.
func TestTS32CallbackFixedResponse(t *testing.T) {
	e := newCBEnv(t)
	toks := map[string]string{
		"good":   e.mint(t, time.Now()),
		"stale":  e.mint(t, time.Now().Add(-26*time.Hour)),
		"future": e.mint(t, time.Now().Add(2*time.Hour)),
		"bad":    strings.Repeat("a", 26),
		"none":   "",
	}
	for _, rt := range []struct {
		path string
		code int
		body string
	}{{cbRoutePath, 200, cbAssetBody}, {"/nc", 204, ""}} {
		for pos := range surfaces {
			methods := []string{http.MethodGet, http.MethodHead}
			if pos == 3 {
				methods = []string{http.MethodPost}
			}
			for _, m := range methods {
				var first string
				for _, kind := range []string{"good", "stale", "future", "bad", "none"} {
					w := httptest.NewRecorder()
					e.h.ServeHTTP(w, cbReq(m, rt.path, pos, toks[kind]))
					e.q.Drain()
					got := dump(w)
					want := rt.body
					if m == http.MethodHead {
						want = ""
					}
					if w.Code != rt.code || w.Body.String() != want || len(w.Result().Header.Values("Set-Cookie")) != 0 {
						t.Errorf("%s %s pos %d %s: %s", m, rt.path, pos, kind, got)
					}
					if first == "" {
						first = got
					} else if got != first {
						t.Errorf("%s %s pos %d %s: response differs:\n%s\n%s", m, rt.path, pos, kind, got, first)
					}
				}
			}
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
	// A text that is no token of the ring gives no callback event.
	e.h.ServeHTTP(httptest.NewRecorder(), cbReq(http.MethodGet, cbRoutePath, 1, strings.Repeat("a", 26)))
	if reqs, cbs := take(e.q); len(reqs) != 1 || len(cbs) != 0 {
		t.Errorf("bad token: %d request and %d callback events", len(reqs), len(cbs))
	}
}

// TestTS32CallbackMarker checks that the token text is in no member of a
// callback event and in no detail. The handler counts no error. The request
// event of a path callback keeps the escaped request path by design.
func TestTS32CallbackMarker(t *testing.T) {
	e := newCBEnv(t)
	for pos, surface := range surfaces {
		marker := e.mint(t, time.Now())
		e.h.ServeHTTP(httptest.NewRecorder(), cbReq(methodOf(pos), cbRoutePath, pos, marker))
		for _, ev := range e.q.Drain() {
			if pos == 0 && ev.Kind() == event.KindRequest {
				continue
			}
			b, err := json.Marshal(ev.Record())
			mustOK(t, err)
			if strings.Contains(string(b)+fmt.Sprintf("%+v", ev.Record())+ev.IP(), marker) {
				t.Errorf("%s: the marker is in the %s event", surface, ev.Kind())
			}
		}
	}
	if n := e.h.eventErrs.Load(); n != 0 {
		t.Errorf("%d event errors", n)
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
// position. The vhost has two more routes: an exact route with the shape of a
// token, and a plain route.
const (
	exactShape = "aaaaaaaaaaaaaaaaaaaaaaaaaa"
	rootRoutes = `{"routes":[` +
		`{"path":"/","asset":"vhosts/kilo.example/kilo.txt","type":"text/plain; charset=utf-8","callback":{"segment":true}},` +
		`{"path":"/` + exactShape + `","asset":"vhosts/kilo.example/other.txt","type":"text/plain; charset=utf-8"}]}`
)

// TestTS32CallbackRootSegment checks a segment callback route at the root
// path. It matches "/" and "/" with one segment. An exact route of the vhost
// comes first.
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
	} {
		r := httptest.NewRequest(http.MethodGet, tc.target, nil)
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
	b.ReportAllocs()
	for b.Loop() {
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
