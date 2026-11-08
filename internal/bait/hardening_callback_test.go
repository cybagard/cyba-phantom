package bait

import (
	"fmt"
	"go/ast"
	"go/build"
	"go/parser"
	gotoken "go/token"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cybagard/cyba-phantom/internal/bundle"
	"github.com/cybagard/cyba-phantom/internal/event"
	"github.com/cybagard/cyba-phantom/internal/token"
)

// cbSwapLoader is swapLoader with a callback route /cb that has a query
// position. put replaces the archive with one of another seed byte.
func cbSwapLoader(t *testing.T) (l *bundle.Loader, put func(seed byte, n int)) {
	t.Helper()
	dir := t.TempDir()
	var trust bundle.TrustSet
	put = func(seed byte, n int) {
		files := mixedFiles(t, seed, "f", "n")
		const rm = "vhosts/example.com/routes.json"
		files[rm] = strings.TrimSuffix(files[rm], "]}") + `,{"path":"/cb","callback":{"query":"ref"}}]}`
		files["manifest.json"] = manifestOf(fmt.Sprintf("2026.11.01-%d", n))
		trust = writeArchive(t, dir, "", files)
	}
	put(0x09, 1)
	root, err := os.OpenRoot(dir)
	mustOK(t, err)
	t.Cleanup(func() { root.Close() })
	l = bundle.NewLoader(root, "bundle/current.cbnd", trust, nil)
	_, err = l.Load(true)
	mustOK(t, err)
	return l, put
}

// TestTS32SwapDuringCallback swaps the bundle and the ring after the response
// is flushed and before the check of the token. The token comes from a render
// of the old bundle. The callback event must have the key set id of the old
// bundle. This is the second key set of the ring. The writer must store the
// token row of the old mint row.
func TestTS32SwapDuringCallback(t *testing.T) {
	l, put := cbSwapLoader(t)
	old := l.Current()
	rig := newStoreRig(t)
	h := NewWithDayKey(loaderSrc{l}, &fallbackFn{}, rig.q, rig.dk)
	h.SetRing(l.Ring())
	page := serve(t, h, get("/t", "example.com"))
	texts := tokenRE.FindAllString(page.Body.String()+" "+page.Header().Get("X-Note"), -1)
	if page.Code != 200 || len(texts) != 2 {
		t.Fatalf("render: code %d, tokens %v", page.Code, texts)
	}
	var cur *bundle.Bundle
	h.flushHook = func() {
		put(0x0b, 2)
		var err error
		cur, err = l.Load(true)
		mustOK(t, err)
	}
	r := get("/cb", "example.com")
	r.URL.RawQuery = "ref=" + texts[0]
	if w := serve(t, h, r); w.Code != http.StatusNoContent {
		t.Fatalf("callback: code %d", w.Code)
	}
	if cur == nil || l.Current() != cur || cur == old {
		t.Fatal("the hook did not swap the running bundle")
	}
	oldSum, newSum := old.SHA256(), cur.SHA256()
	if string(oldSum[:8]) == string(newSum[:8]) {
		t.Fatalf("the two bundles have the same set id %x", oldSum[:8])
	}
	evs := rig.q.Drain()
	var cb *event.Event
	for _, ev := range evs {
		if ev.Kind() == event.KindCallback {
			cb = ev
		}
		rig.q.Enqueue(ev)
	}
	if cb == nil {
		t.Fatal("no callback event")
	}
	tok, _ := token.Parse(texts[0])
	res := token.Verify([]*token.KeySet{cur.Tokens(), old.Tokens()}, tok)
	link, ok := cb.Link()
	if want := (event.CallbackLink{SetID: res.SetID, Unit: res.Unit, Counter: res.Counter}); !ok || link != want ||
		res.Set != token.Second || string(link.SetID[:]) != string(oldSum[:8]) {
		t.Errorf("link %+v (%v), want the old set id %x, set %v, counter %d", link, ok, oldSum[:8], res.Set, res.Counter)
	}
	rig.drain(t)
	const joined = `SELECT count(*) FROM token t JOIN mint m ON m.session_id = t.session_id AND m.issued_at = t.issued_at
WHERE m.set_id = ? AND t.token_id = ? AND t.trap_id = 'f' AND t.cb_count = 1`
	if n, all := countOf(t, rig.db, joined, oldSum[:8], token.ID(tok)), countOf(t, rig.db, "SELECT count(*) FROM token"); n != 1 || all != 1 {
		t.Errorf("%d token rows of the old mint row, %d token rows in all, want 1 and 1", n, all)
	}
	if n := countOf(t, rig.db, "SELECT count(*) FROM mint WHERE set_id <> ?", oldSum[:8]); n != 0 {
		t.Errorf("%d mint rows of another key set", n)
	}
}

// TestTS32SwapRaceCallback runs callbacks in parallel while the loader swaps
// the bundle and the ring 20 times. Under -race, the test fails on a data race.
// Each response is the fixed 204.
func TestTS32SwapRaceCallback(t *testing.T) {
	l, put := cbSwapLoader(t)
	h := New(loaderSrc{l}, &fallbackFn{}, queueOf(t, 64))
	h.SetRing(l.Ring())
	tok, err := l.Current().Tokens().Mint(0, time.Now())
	mustOK(t, err)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 200 {
				r := get("/cb", "example.com")
				r.URL.RawQuery = "ref=" + token.Text(tok)
				if w := serve(t, h, r); w.Code != http.StatusNoContent {
					t.Errorf("code %d", w.Code)
					return
				}
				for _, ok := h.q.TryTake(); ok; _, ok = h.q.TryTake() {
				}
			}
		})
	}
	for i := range 20 {
		put([]byte{0x0b, 0x09}[i%2], i+2)
		_, err := l.Load(true)
		mustOK(t, err)
	}
	wg.Wait()
}

// queryParsers are the names of the calls that parse a query or a form. A
// callback route reads its candidates with its own scans (SEC-37).
var queryParsers = []string{"ParseQuery", "ParseForm", "FormValue", "PostFormValue", "ParseMultipartForm", "MultipartReader"}

// queryRefs gives the position of each selector in src that names one of
// queryParsers, or URL.Query. The match is on the syntax tree, so a comment or
// a string does not match.
func queryRefs(path string, src any) ([]gotoken.Position, error) {
	fset := gotoken.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, 0)
	if err != nil {
		return nil, err
	}
	var out []gotoken.Position
	ast.Inspect(f, func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok {
			x, isSel := sel.X.(*ast.SelectorExpr)
			if slices.Contains(queryParsers, sel.Sel.Name) || isSel && x.Sel.Name == "URL" && sel.Sel.Name == "Query" {
				out = append(out, fset.Position(sel.Sel.Pos()))
			}
		}
		return true
	})
	return out, nil
}

// querySample has seven references that queryRefs must report. It also has a
// comment, a string, a field and a call of another Query. queryRefs must not
// report these.
const querySample = `package p
// r.ParseForm()
func f(r *http.Request) {
	_ = "r.FormValue(x)"
	r.URL.Query()
	url.ParseQuery("a=b")
	r.ParseForm()
	_ = r.FormValue
	r.PostFormValue("a")
	r.ParseMultipartForm(1)
	r.MultipartReader()
	_ = c.Query
	db.Query("x")
}
`

// TestTS32NoQueryParserCall scans the files of this package that are not
// tests. It fails when one refers to URL.Query, ParseQuery, ParseForm,
// FormValue, PostFormValue, ParseMultipartForm or MultipartReader. The check
// reads the files of each GOOS and GOARCH.
func TestTS32NoQueryParserCall(t *testing.T) {
	if got, err := queryRefs("p.go", querySample); err != nil || len(got) != 7 {
		t.Fatalf("the scan finds %v (%v), want 7 references", got, err)
	}
	ctx := build.Default
	ctx.UseAllFiles = true
	pkg, err := ctx.ImportDir(".", 0)
	mustOK(t, err)
	files := slices.Concat(pkg.GoFiles, pkg.CgoFiles)
	if len(files) == 0 {
		t.Fatal("the package has no file")
	}
	for _, name := range files {
		refs, err := queryRefs(filepath.Join(pkg.Dir, name), nil)
		mustOK(t, err)
		for _, p := range refs {
			t.Errorf("%s: call of a query or form parser", p)
		}
	}
}

// TestTS02CallbackSegmentForms sends the one-segment forms to a callback route
// with a segment position, on a real server. The forms are raw, because
// httptest.NewRequest changes them. Each form gets the response of the route
// path, byte for byte except Date. No byte of the segment is in the response.
// No callback event is on the queue. A token in the same place gives the same
// response and one callback event. So the missing event is not by chance.
func TestTS02CallbackSegmentForms(t *testing.T) {
	e := newCBEnv(t)
	srv := httptest.NewServer(e.h)
	defer srv.Close()
	date := regexp.MustCompile(`(?m)^Date: .*\r\n`)
	fetch := func(target string) string {
		c, err := net.Dial("tcp", srv.Listener.Addr().String())
		mustOK(t, err)
		defer c.Close()
		mustOK(t, c.SetDeadline(time.Now().Add(10*time.Second)))
		_, err = io.WriteString(c, "GET "+target+" HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
		mustOK(t, err)
		b, err := io.ReadAll(c)
		mustOK(t, err)
		return date.ReplaceAllString(string(b), "")
	}
	plain := fetch(cbRoutePath)
	if !strings.HasPrefix(plain, "HTTP/1.1 200 ") || !strings.HasSuffix(plain, "\r\n\r\n"+cbAssetBody) {
		t.Fatalf("the route gives %q", plain)
	}
	take(e.q)
	for _, seg := range []string{"/", "/..", "/%2e%2e", "/%2E%2E", "/{{.T}}"} {
		got := fetch(cbRoutePath + seg)
		if got != plain || len(seg) > 1 && strings.Contains(got, seg[1:]) {
			t.Errorf("%s: response %q, want %q", seg, got, plain)
		}
	}
	if _, cbs := take(e.q); len(cbs) != 0 {
		t.Errorf("%d callback events for the forms, want 0", len(cbs))
	}
	text := e.mint(t, time.Now())
	if got := fetch(cbRoutePath + "/" + text); got != plain {
		t.Errorf("token segment: response %q, want %q", got, plain)
	}
	if _, cbs := take(e.q); len(cbs) != 1 || *cbs[0].Surface != event.SurfacePath {
		t.Errorf("token segment: callback events %+v, want 1 at the path", cbs)
	}
}

// TestMain runs the bounded scan checks before every other test of the
// package. An older test that calls a scan which does not stop would else hang
// until the timeout of go test, and the bounded tests would not run. A failed
// check stops the test binary with status 1.
func TestMain(m *testing.M) {
	failed := false
	for _, check := range []func() error{checkBodyReadLoop, checkBodyScanEscapes, checkQueryAdvances} {
		if err := check(); err != nil {
			fmt.Fprintln(os.Stderr, "FAIL:", err)
			failed = true
		}
	}
	if failed {
		os.Exit(1)
	}
	os.Exit(m.Run())
}

// withinErr runs f and returns an error when f does not return in 5 s or when
// it panics. A loop that does not stop would else last to the timeout of go
// test. f must put its results in variables that the caller reads after withinErr.
func withinErr(f func()) error {
	done := make(chan any, 1)
	go func() {
		defer func() { done <- recover() }()
		f()
	}()
	select {
	case p := <-done:
		if p != nil {
			return fmt.Errorf("panic: %v", p)
		}
	case <-time.After(5 * time.Second):
		return fmt.Errorf("no return in 5 s")
	}
	return nil
}

// stream is a body that counts its Read calls. It gives its data and then
// io.EOF. After 8 calls it fails with a full buffer. So a read loop that does
// not stop ends by value and not by a hang.
type stream struct {
	data                   []byte
	calls, empty, afterEOF int
	eof                    bool
}

func (s *stream) Read(p []byte) (int, error) {
	s.calls++
	if len(p) == 0 {
		s.empty++
	} else if s.eof {
		s.afterEOF++
	}
	if s.calls > 8 {
		return len(p), io.ErrClosedPipe
	}
	if len(s.data) == 0 {
		s.eof = true
		return 0, io.EOF
	}
	n := copy(p, s.data)
	s.data = s.data[n:]
	return n, nil
}

// TestTS32BodyReadLoopStops checks the read loop of BodyCandidate. After a body
// that fills the buffer, it must not read again with an empty buffer. After
// io.EOF, it must not read again.
func TestTS32BodyReadLoopStops(t *testing.T) {
	if err := checkBodyReadLoop(); err != nil {
		t.Error(err)
	}
}

func checkBodyReadLoop() error {
	member := `{"tok":"` + strings.Repeat("a", candidateLen) + `"}`
	for _, tc := range []struct {
		name string
		body string
		ok   bool
	}{
		{"body over the buffer", member + strings.Repeat(" ", bodyMax), false},
		{"body that ends", member, true},
	} {
		s := &stream{data: []byte(tc.body)}
		r := &http.Request{Method: http.MethodPost, Body: io.NopCloser(s), ContentLength: -1}
		var ok bool
		if err := withinErr(func() { _, ok = BodyCandidate(r, "tok") }); err != nil {
			return fmt.Errorf("%s: %w", tc.name, err)
		}
		if ok != tc.ok || s.calls > 2 || s.empty != 0 || s.afterEOF != 0 {
			return fmt.Errorf("%s: ok %v, %d reads, %d empty, %d after EOF, want %v, 2 or fewer, 0, 0", tc.name, ok, s.calls, s.empty, s.afterEOF, tc.ok)
		}
	}
	return nil
}

// TestTS32BodyScanEscapes checks that the string scan moves past an escape
// and no further. A member before the token has an escape in its value. The
// scan must still find the token.
func TestTS32BodyScanEscapes(t *testing.T) {
	if err := checkBodyScanEscapes(); err != nil {
		t.Error(err)
	}
}

func checkBodyScanEscapes() error {
	tok := strings.Repeat("a", candidateLen)
	for _, v := range []string{`a\nb`, `n\n`, `\\n`, `\"`, `\` + "u0041x"} {
		var got []byte
		var found bool
		if err := withinErr(func() { got, found = bodyMember([]byte(`{"x":"`+v+`","tok":"`+tok+`"}`), "tok") }); err != nil {
			return fmt.Errorf("value %q: %w", v, err)
		}
		if !found || string(got) != tok {
			return fmt.Errorf("value %q: found %v, candidate %q", v, found, got)
		}
	}
	return nil
}

// TestTS32QueryCandidateAdvances checks that the query scan moves to the part
// after each "&". A scan that goes back reads the same part for ever.
func TestTS32QueryCandidateAdvances(t *testing.T) {
	if err := checkQueryAdvances(); err != nil {
		t.Error(err)
	}
}

func checkQueryAdvances() error {
	tok := strings.Repeat("a", candidateLen)
	for _, tc := range []struct{ query, want string }{
		{"x=1&ref=" + tok, tok},
		{"ref=" + tok + "&x=1", tok},
		{"a&b&ref=" + tok + "&c", tok},
		{"ref=" + tok + "&ref=" + tok, ""},
	} {
		var got string
		if err := withinErr(func() { got = QueryCandidate(tc.query, "ref") }); err != nil {
			return fmt.Errorf("query %q: %w", tc.query, err)
		}
		if got != tc.want {
			return fmt.Errorf("query %q: candidate %q, want %q", tc.query, got, tc.want)
		}
	}
	return nil
}

// The bounds of one callback request (T-S-32, T-P-12). They come from a
// measurement on linux/arm64 before the build. The scans and the check of 4
// candidates allocate nothing. This holds with a body of 4 KiB, past the
// pooled buffer.
// One callback event with its token id has 79 allocations. A bound is
// the measured value plus 10 %. The test checks no time, because a time
// depends on the host. The benchmarks report it. race_test.go sets eventAllocs
// for the race detector.
var eventAllocs = 79.0

const boundSlack = 1.1

// TestTS32ScansAndCheckAllocs checks the 4 scans and the check of 4 good
// candidates, with a body of 4 KiB. They must allocate nothing.
func TestTS32ScansAndCheckAllocs(t *testing.T) {
	g := newCallbackRig(t, true)
	good := 0
	allocs := testing.AllocsPerRun(100, func() {
		for _, res := range g.check() {
			if res.OK {
				good++
			}
		}
	})
	if want := 4 * 101; good != want {
		t.Fatalf("%d good results, want %d", good, want)
	}
	if allocs != 0 {
		t.Errorf("%v allocations, want 0", allocs)
	}
}

// TestTS32CallbackRequestAllocs checks the allocations of one callback request
// with 4 good distinct tokens. The bound has two parts. The first part is the
// allocations of the same request with 4 texts that verify to nothing. That
// request has the request event and no callback event. The second part is 4
// callback events with 10 % more.
func TestTS32CallbackRequestAllocs(t *testing.T) {
	none, good := newCallbackRig(t, false), newCallbackRig(t, true)
	if n, m := none.serve(), good.serve(); n != 1 || m != 5 {
		t.Fatalf("%d events for no good token and %d for 4, want 1 and 5", n, m)
	}
	base := testing.AllocsPerRun(50, func() { none.serve() })
	got := testing.AllocsPerRun(50, func() { good.serve() })
	bound := base + 4*eventAllocs*boundSlack
	t.Logf("%v allocations with 4 good tokens, %v with none, bound %v", got, base, bound)
	if got > bound {
		t.Errorf("%v allocations, want %v or fewer", got, bound)
	}
}
