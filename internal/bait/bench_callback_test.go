package bait

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/cybagard/cyba-phantom/internal/event"
	"github.com/cybagard/cyba-phantom/internal/token"
)

// callbackRig is a callback handler and a POST to the route. The POST has a
// token at each of the 4 positions and a body of exactly 4 KiB. With good
// false, the 4 texts have the shape of a token and verify to nothing.
type callbackRig struct {
	*cbEnv
	ent   *entry
	toks  [token.Positions]string
	r     *http.Request
	body  *rewind
	w     *discard
	clock time.Duration
}

func newCallbackRig(tb testing.TB, good bool) *callbackRig {
	e := newCBEnv(tb)
	var toks [4]string
	for i := range toks {
		toks[i] = strings.Repeat("a", candidateLen)
		if good {
			toks[i] = e.mint(tb, time.Now())
		}
	}
	r := cbReqN(http.MethodPost, cbRoutePath, toks)
	const head = `{"pad":"`
	tail := `","tok":"` + toks[3] + `"}`
	data := head + strings.Repeat("x", bodyMax-len(head)-len(tail)) + tail
	g := &callbackRig{cbEnv: e, toks: toks, r: r, body: &rewind{data: []byte(data)}, w: &discard{h: http.Header{}}}
	g.ent = e.h.siteOf(e.h.src.Current()).hosts["example.com"][cbRoutePath]
	r.ContentLength = int64(len(data))
	e.h.mono = func() time.Duration { return g.clock }
	return g
}

// check reads the 4 candidates of the request and checks them, as the callback
// code does. The texts stay in this call, as they stay in the callback code.
func (g *callbackRig) check() [token.Positions]token.Result {
	var texts [token.Positions]string
	g.body.reset()
	g.r.Body = g.body
	texts[posPath] = PathCandidate(g.r.URL.EscapedPath(), g.ent.route.Path)
	texts[posQuery] = QueryCandidate(g.r.URL.RawQuery, g.ent.cb.query)
	texts[posHeader] = HeaderCandidate(g.r.Header, g.ent.cb.header)
	if c, ok := BodyCandidate(g.r, g.ent.cb.body); ok {
		texts[posBody] = string(c[:])
	}
	return g.h.ring.Check(texts)
}

// serve serves the request two token windows after the last one, so the cap
// admits each token. It gives the number of events that the request made.
func (g *callbackRig) serve() (events int) {
	g.clock += 2 * capTokenWindow
	g.body.reset()
	g.r.Body = g.body
	clear(g.w.h)
	g.h.ServeHTTP(g.w, g.r)
	for {
		if _, ok := g.q.TryTake(); !ok {
			return events
		}
		events++
	}
}

// BenchmarkCallbackScansAndCheck measures the 4 candidate scans, with a body of
// 4 KiB, and the check of the 4 texts. It builds no event.
func BenchmarkCallbackScansAndCheck(b *testing.B) {
	g := newCallbackRig(b, true)
	b.ReportAllocs()
	for b.Loop() {
		g.check()
	}
}

// BenchmarkCallbackEventBuild measures the build of one callback event with
// the token id. The handler does the same for a good token.
func BenchmarkCallbackEventBuild(b *testing.B) {
	g := newCallbackRig(b, true)
	res := g.check()
	tok, _ := token.Parse(g.toks[posQuery])
	sess := g.h.sessionOf(g.r)
	st := int64(http.StatusOK)
	b.ReportAllocs()
	for b.Loop() {
		_, err := event.NewEvent(nil, event.Input{
			Kind: event.KindCallback, Session: sess.id, Vhost: "example.com", Method: http.MethodGet,
			Path: cbRoutePath, Status: &st, TrapID: res[posQuery].Trap, TokenID: token.ID(tok),
			Surface: event.SurfaceQuery, ClientIP: sess.ip,
			Link: &event.CallbackLink{SetID: res[posQuery].SetID, Unit: res[posQuery].Unit, Counter: res[posQuery].Counter},
		})
		if err != nil {
			b.Fatal(err)
		}
	}
}
