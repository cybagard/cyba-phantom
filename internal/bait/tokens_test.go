package bait

import (
	"bytes"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	xhtml "golang.org/x/net/html"

	"github.com/cybagard/cyba-phantom/internal/bundle"
	"github.com/cybagard/cyba-phantom/internal/event"
	"github.com/cybagard/cyba-phantom/internal/token"
)

// tokenRE matches a token text: 26 characters of the base32 alphabet.
var tokenRE = regexp.MustCompile(`[a-z2-7]{26}`)

// tokensOf returns the token texts of a response in the order of the mint.
// The body comes first, then the X-Note header. Each text must verify under the
// key set of b. The results are in the same order.
func tokensOf(t *testing.T, b *bundle.Bundle, w *httptest.ResponseRecorder) ([]string, []token.Result) {
	t.Helper()
	texts := tokenRE.FindAllString(w.Body.String(), -1)
	texts = append(texts, tokenRE.FindAllString(strings.Join(w.Header().Values("X-Note"), " "), -1)...)
	var res []token.Result
	for _, s := range texts {
		tok, ok := token.Parse(s)
		r := token.Verify([]*token.KeySet{b.Tokens()}, tok)
		if !ok || !r.OK {
			t.Fatalf("token text %q does not verify", s)
		}
		res = append(res, r)
	}
	return texts, res
}

// realHandler returns the handler of outHandler with the real token text and a
// clock that counts its reads.
func realHandler(t *testing.T, depth int) (h *Handler, q *event.Queue, reads *int) {
	h, q = eventHandler(t, depth)
	h.text = token.Text
	reads = new(int)
	h.now = func() time.Time { *reads++; return testDay }
	return h, q, reads
}

func ids(res []token.Result) (out []string) {
	for _, r := range res {
		out = append(out, r.Trap)
	}
	return out
}

// nextCounter mints one token under the key set of b and gives its counter.
func nextCounter(t *testing.T, b *bundle.Bundle) uint64 {
	t.Helper()
	var out [1][token.Size]byte
	first, err := b.Tokens().MintRange([]int{0}, testDay, out[:])
	mustOK(t, err)
	return first
}

// rcStatus gives the status of a request event, or 0 when it has none.
func rcStatus(ev *event.Event) int64 {
	if s := ev.Record().Status; s != nil {
		return *s
	}
	return 0
}

// TestTI02HandlerTokens fetches each page with token slots twice, from two
// clients with no cookie. Each slot is there. The tokens of the two sessions
// differ. Each token verifies to the trap of its slot. The body parses.
func TestTI02HandlerTokens(t *testing.T) {
	for _, c := range []struct {
		name, path string
		code       int
		traps      []string
	}{
		{"page and header slot", "/t", 200, []string{"f", "n"}},
		{"asset and header slot", "/a", 200, []string{"n"}},
		{"404 page", "/nope", 404, []string{"f"}},
		{"robots.txt", "/robots.txt", 200, []string{"r"}},
		{"well-known file", "/.well-known/ai-plugin.json", 200, []string{"j"}},
	} {
		h, _, _ := realHandler(t, 8)
		b := h.src.Current()
		var got [2][]string
		for i, addr := range []string{"192.0.2.1:1000", "192.0.2.2:1000"} {
			r := get(c.path, "example.com")
			r.RemoteAddr = addr
			w := serve(t, h, r)
			texts, res := tokensOf(t, b, w)
			got[i] = texts
			if w.Code != c.code || strings.Join(ids(res), " ") != strings.Join(c.traps, " ") {
				t.Errorf("%s: code %d, trap ids %v, want %d and %v", c.name, w.Code, ids(res), c.code, c.traps)
			}
			switch ct := w.Header().Get("Content-Type"); {
			case strings.HasPrefix(ct, "text/html"):
				if _, err := xhtml.Parse(bytes.NewReader(w.Body.Bytes())); err != nil {
					t.Errorf("%s: HTML does not parse: %v", c.name, err)
				}
			case ct == "application/json":
				if !json.Valid(w.Body.Bytes()) {
					t.Errorf("%s: JSON does not parse", c.name)
				}
			}
		}
		for i := range c.traps {
			if len(got[0]) != len(c.traps) || len(got[1]) != len(c.traps) || got[0][i] == got[1][i] {
				t.Errorf("%s: slot %d: tokens %q and %q, want two texts that differ", c.name, i, got[0], got[1])
			}
		}
	}
}

// abortAfterFirst takes one write and fails the next, and keeps what it took.
type abortAfterFirst struct {
	*httptest.ResponseRecorder
	writes int
}

func (a *abortAfterFirst) Write(p []byte) (int, error) {
	if a.writes++; a.writes > 1 {
		return 0, errors.New("gone")
	}
	return a.ResponseRecorder.Write(p)
}

// TestTS31MintOnEvent checks the request event of a render. It has one clock
// read, the session, and the counter range of the tokens of the response. The
// record has no trap id, no token id and no detail.
func TestTS31MintOnEvent(t *testing.T) {
	for _, c := range []struct {
		name, path string
		abort      bool
		count      int // tokens of the mint: trap actions and header slots
		seen       int // tokens that the client got
	}{
		{"template and header slot", "/t", false, 2, 2},
		{"404 template", "/nope", false, 1, 1},
		{"asset and header slot", "/a", false, 1, 1},
		{"abort after the first write", "/t", true, 2, 1},
	} {
		h, q, reads := realHandler(t, 8)
		b := h.src.Current()
		rec := httptest.NewRecorder()
		var w http.ResponseWriter = rec
		if c.abort {
			w = &abortAfterFirst{ResponseRecorder: rec}
		}
		before := nextCounter(t, b)
		if aborted := aborts(h, w, get(c.path, "example.com")); aborted != c.abort {
			t.Fatalf("%s: aborted %v", c.name, aborted)
		}
		// One range for the render: the counter moves by its count. The probe
		// mint before and after takes one more.
		if moved := (nextCounter(t, b) - before) & (event.MintCounterLimit - 1); moved != uint64(c.count)+1 {
			t.Errorf("%s: the counter moved by %d, want %d", c.name, moved, c.count+1)
		}
		evs := q.Drain()
		if len(evs) != 1 || *reads != 1 {
			t.Fatalf("%s: %d events, %d clock reads, want 1 and 1", c.name, len(evs), *reads)
		}
		m, ok := evs[0].Mint()
		rc := evs[0].Record()
		_, res := tokensOf(t, b, rec)
		sum := b.SHA256()
		if !ok || int(m.Count) != c.count || len(res) != c.seen || m.IssuedAt != testDay.UnixMilli() ||
			string(m.SetID[:]) != string(sum[:8]) {
			t.Fatalf("%s: mint %+v (%v), %d tokens seen", c.name, m, ok, len(res))
		}
		for i, r := range res {
			if want := (m.First + uint64(c.count-c.seen+i)) & (event.MintCounterLimit - 1); r.Counter != want || r.Unit != m.Unit {
				t.Errorf("%s: token %d has counter %d and unit %d, want %d and %d", c.name, i, r.Counter, r.Unit, want, m.Unit)
			}
		}
		if rc.Session == nil || *rc.Session == "" || rc.TrapID != nil || rc.TokenID != nil || len(rc.Detail) != 0 {
			t.Errorf("%s: record %+v", c.name, rc)
		}
	}
}

// TestTS31NoKeySet checks a render with no key set. Each trap text is empty
// and the header slot is left out. One counter counts the render. The page
// serves, and the event has no mint range.
func TestTS31NoKeySet(t *testing.T) {
	h, q, _ := realHandler(t, 8)
	h.keys = func(*bundle.Bundle) *token.KeySet { return nil }
	w := serve(t, h, get("/t", "example.com"))
	if w.Code != 200 || w.Body.String() != "<p></p>" || len(w.Header().Values("X-Note")) != 0 ||
		h.noKeys.Load() != 1 || h.slotDrops.Load() != 0 {
		t.Errorf("code %d, body %q, header %v, noKeys %d, slotDrops %d", w.Code, w.Body.String(), w.Header(), h.noKeys.Load(), h.slotDrops.Load())
	}
	evs := q.Drain()
	if _, ok := evs[0].Mint(); len(evs) != 1 || ok || evs[0].Record().Session == nil {
		t.Errorf("%d events, mint %v", len(evs), ok)
	}
	serve(t, h, get("/a", "example.com"))
	if h.noKeys.Load() != 2 {
		t.Errorf("noKeys after the asset %d, want 2", h.noKeys.Load())
	}
}

// slotValueHandler returns a handler for a bundle with a header slot on /t.
// The page /t has a trap action. The page /s has nothing to mint. The trap n
// has the text nText and the token.
func slotValueHandler(t *testing.T, nText string) (*Handler, *event.Queue) {
	t.Helper()
	const dir = "vhosts/example.com/"
	tj, err := json.Marshal([]map[string]string{
		{"id": "n", "slot": "hidden-p", "surface": "path", "visibility": "human-visible", "instruction_template": nText + "{{.Token}}"},
		{"id": "f", "slot": "hidden-p", "surface": "path", "visibility": "human-visible", "instruction_template": "x"}})
	mustOK(t, err)
	b := bundleFiles(t, "", map[string]string{
		"traps/traps.json":  string(tj),
		dir + "routes.json": `{"routes":[{"path":"/t","template":"` + dir + `t.tmpl","type":"text/html; charset=utf-8","headers":[{"name":"X-Note","trap":"n"}]},{"path":"/s","template":"` + dir + `s.tmpl","type":"text/html; charset=utf-8"}]}`,
		dir + "t.tmpl":      `<p>{{index .Trap "f"}}</p>`,
		dir + "s.tmpl":      "static",
	})
	q := testQueue(t)
	return New(&swap{list: []*bundle.Bundle{b}}, &fallbackFn{}, q), q
}

// TestTS31SlotValueWithToken checks the header value rule on the value with the
// token in it, at each response. A slot that fails it is left out and counted.
// A page with nothing to mint has no mint range.
func TestTS31SlotValueWithToken(t *testing.T) {
	for _, c := range []struct {
		name, text string
		ok         bool
	}{
		{"1024 bytes", strings.Repeat("v", 1024-26), true},
		{"1025 bytes", strings.Repeat("v", 1025-26), false},
		{"tab", "a\tb", false},
		{"DEL", "a\x7fb", false},
		{"printable", "a ~b", true},
	} {
		h, q := slotValueHandler(t, c.text)
		for range 2 {
			w := serve(t, h, get("/t", "example.com"))
			if got := w.Header().Values("X-Note"); w.Code != 200 || (len(got) == 1) != c.ok {
				t.Errorf("%s: code %d, X-Note %q, want present %v", c.name, w.Code, got, c.ok)
			}
		}
		if n, want := h.slotDrops.Load(), map[bool]int64{true: 0, false: 2}[c.ok]; n != want {
			t.Errorf("%s: slotDrops %d, want %d", c.name, n, want)
		}
		if evs := q.Drain(); len(evs) != 2 {
			t.Fatalf("%s: %d events", c.name, len(evs))
		} else if m, ok := evs[0].Mint(); !ok || m.Count != 2 {
			t.Errorf("%s: mint %+v (%v), want a range of 2", c.name, m, ok)
		}
	}
	h, q := slotValueHandler(t, "v")
	if w := serve(t, h, get("/s", "example.com")); w.Code != 200 || w.Body.String() != "static" || h.noKeys.Load() != 0 {
		t.Errorf("static page: code %d, body %q, noKeys %d", w.Code, w.Body.String(), h.noKeys.Load())
	}
	if evs := q.Drain(); len(evs) != 1 {
		t.Fatalf("%d events", len(evs))
	} else if _, ok := evs[0].Mint(); ok {
		t.Error("a page with nothing to mint has a mint range")
	}
}

// TestTS31NoTokenOrCookieText checks that no token text, cookie value or tag is
// in an event or the standard log. The requests are a new client and a client
// that returns its cookie. They are also an abort and a render with no key set.
// A response over the cap through a real server checks the error log of the
// server too.
func TestTS31NoTokenOrCookieText(t *testing.T) {
	logs := &syncBuf{}
	old := log.Writer()
	log.SetOutput(logs)
	t.Cleanup(func() { log.SetOutput(old) })
	h, q, _ := realHandler(t, 16)
	b := h.src.Current()
	w1 := serve(t, h, get("/t", "example.com"))
	cookie := newCookie(t, "first", w1.Header())
	marks, _ := tokensOf(t, b, w1)
	marks = append(marks, cookie, cookie[27:])
	r2 := get("/t", "example.com")
	r2.Header.Set("Cookie", "sid="+cookie)
	more, _ := tokensOf(t, b, serve(t, h, r2))
	marks = append(marks, more...)
	r3 := get("/t", "example.com")
	r3.Header.Set("Cookie", "sid="+cookie)
	rec := httptest.NewRecorder()
	aborts(h, &abortAfterFirst{ResponseRecorder: rec}, r3)
	marks = append(marks, tokenRE.FindAllString(strings.Join(rec.Header().Values("X-Note"), " "), -1)...)
	h.keys = func(*bundle.Bundle) *token.KeySet { return nil }
	serve(t, h, r2)
	var out strings.Builder
	for _, ev := range q.Drain() {
		j, err := json.Marshal(ev.Record())
		mustOK(t, err)
		out.WriteString(string(j) + ev.IP() + "\n")
	}
	out.WriteString(logs.String())
	if len(marks) != 7 || h.eventErrs.Load() != 0 {
		t.Fatalf("%d markers, %d event errors", len(marks), h.eventErrs.Load())
	}
	for _, m := range marks {
		if strings.Contains(out.String(), m) {
			t.Errorf("marker %q is in an event or a log line", m)
		}
	}

	// A response over the cap through a real server: the abort path. The error
	// log of the server holds no token text, cookie value or tag.
	errsBefore := h.execErrs.Load()
	var mu sync.Mutex
	var texts []string
	h.keys = (*bundle.Bundle).Tokens
	h.text = func(tok [token.Size]byte) string {
		s := token.Text(tok)
		mu.Lock()
		texts = append(texts, s)
		mu.Unlock()
		return s + strings.Repeat("x", oneMiB)
	}
	srv, srvLog := startServer(t, h)
	req, err := http.NewRequest(http.MethodGet, srv.URL+"/t", nil)
	mustOK(t, err)
	req.Host = "example.com"
	req.Header.Set("Cookie", "sid="+cookie)
	_, err = (&http.Client{Transport: &http.Transport{DisableKeepAlives: true}}).Do(req)
	srv.Close()
	mu.Lock()
	marks = append(texts, cookie, cookie[27:])
	mu.Unlock()
	if err == nil || h.execErrs.Load() != errsBefore+1 || len(marks) != 4 {
		t.Fatalf("over the cap: err %v, %d errors after %d, %d markers", err, h.execErrs.Load(), errsBefore, len(marks))
	}
	for _, m := range marks {
		if strings.Contains(srvLog.String(), m) || strings.Contains(logs.String(), m) {
			t.Errorf("marker %q is in the server log or the standard log", m)
		}
	}
}

// mixedBundle loads a bundle with the traps ids in this order and the seed
// byte seed. The route /t has the trap action f and a header slot X-Note for
// the trap n.
func mixedBundle(t *testing.T, seed byte, ids ...string) *bundle.Bundle {
	t.Helper()
	const dir = "vhosts/example.com/"
	var traps []map[string]string
	for _, id := range ids {
		traps = append(traps, map[string]string{"id": id, "slot": "hidden-p", "surface": "path",
			"visibility": "human-visible", "instruction_template": "x " + id + " {{.Token}}"})
	}
	tj, err := json.Marshal(traps)
	mustOK(t, err)
	return bundleFiles(t, "", map[string]string{
		"secrets/token.seed": strings.Repeat(string([]byte{seed}), 32),
		"traps/traps.json":   string(tj),
		dir + "routes.json":  `{"routes":[{"path":"/t","template":"` + dir + `t.tmpl","type":"text/html; charset=utf-8","headers":[{"name":"X-Note","trap":"n"}]}]}`,
		dir + "t.tmpl":       `<p>{{index .Trap "f"}}</p>`,
	})
}

// verifyUnder verifies the token text s under the key set of b.
func verifyUnder(b *bundle.Bundle, s string) token.Result {
	tok, ok := token.Parse(s)
	if !ok {
		return token.Result{}
	}
	return token.Verify([]*token.KeySet{b.Tokens()}, tok)
}

// TestTS31OneBundleForARequest serves a route with trap actions and a header
// slot. The source gives one bundle to the request and the other bundle to
// each later call. The two have another seed and another trap order. The
// tokens verify under the first bundle only, with the trap of their slot. The
// set id is that of the first bundle.
func TestTS31OneBundleForARequest(t *testing.T) {
	a := mixedBundle(t, 0x09, "f", "n")
	b := mixedBundle(t, 0x0b, "n", "f")
	for i, c := range []struct{ cur, other *bundle.Bundle }{{a, b}, {b, a}} {
		q := queueOf(t, 8)
		h := New(&swap{list: []*bundle.Bundle{c.cur, c.other}}, &fallbackFn{}, q)
		w := serve(t, h, get("/t", "example.com"))
		texts := tokenRE.FindAllString(w.Body.String()+" "+w.Header().Get("X-Note"), -1)
		if w.Code != 200 || len(texts) != 2 {
			t.Fatalf("request %d: code %d, tokens %v", i, w.Code, texts)
		}
		for j, want := range []string{"f", "n"} {
			if r := verifyUnder(c.cur, texts[j]); !r.OK || r.Trap != want {
				t.Errorf("request %d token %d: %+v, want trap %s under the first bundle", i, j, r, want)
			}
			if verifyUnder(c.other, texts[j]).OK {
				t.Errorf("request %d token %d verifies under the other bundle", i, j)
			}
		}
		m, ok := q.Drain()[0].Mint()
		sum := c.cur.SHA256()
		if !ok || string(m.SetID[:]) != string(sum[:8]) || m.Count != 2 {
			t.Errorf("request %d: mint %+v (%v), want the set id of the first bundle", i, m, ok)
		}
	}
}

// TestTS31MintIndexList gives mint two lists that a loaded bundle cannot make.
// One has 69 indexes. One has an index that is not a trap. The render counts
// one in noKeys, gives empty trap texts and keeps no range.
func TestTS31MintIndexList(t *testing.T) {
	h, _, _ := realHandler(t, 8)
	b := h.src.Current()
	s := buildSite(b)
	for _, c := range []struct {
		name string
		list []int
	}{
		{"69 indexes", append([]int{0, 1, 2}, make([]int, token.MaxRange+1-3)...)},
		{"index that is not a trap", []int{0, 1, len(s.traps)}},
	} {
		before := h.noKeys.Load()
		sess := &reqSession{at: testDay}
		m := h.mint(b, s, &entry{mint: c.list, acts: 2}, sess)
		if h.noKeys.Load() != before+1 || sess.mint.Count != 0 || len(m.slots) != 0 || len(m.page.Trap) != 2 ||
			m.page.Trap[s.traps[0].ID] != "" || m.page.Trap[s.traps[1].ID] != "" {
			t.Errorf("%s: noKeys %d after %d, mint %+v, trap texts %q", c.name, h.noKeys.Load(), before, sess.mint, m.page.Trap)
		}
	}
}
