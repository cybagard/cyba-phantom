package bait

import (
	"context"
	"database/sql"
	"fmt"
	"go/ast"
	"go/build"
	"go/parser"
	gotoken "go/token"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"

	"github.com/cybagard/cyba-phantom/internal/bundle"
	"github.com/cybagard/cyba-phantom/internal/event"
	"github.com/cybagard/cyba-phantom/internal/session"
	"github.com/cybagard/cyba-phantom/internal/store"
	"github.com/cybagard/cyba-phantom/internal/tlog"
	"github.com/cybagard/cyba-phantom/internal/token"
)

// swapLoader returns a real loader for the bundle of mixedFiles with the seed
// byte 0x09. put replaces the archive with one of another seed byte. The
// manifest version n must rise with each put, or the load is a rollback.
func swapLoader(t *testing.T) (l *bundle.Loader, put func(seed byte, n int)) {
	t.Helper()
	dir := t.TempDir()
	var trust bundle.TrustSet
	put = func(seed byte, n int) {
		files := mixedFiles(t, seed, "f", "n")
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

// TestTS31SwapDuringRender swaps the running bundle of a real loader. The new
// bundle has another seed. The swap comes after the route lookup and before
// the mint. The request keeps the bundle that it read. Each token verifies
// under the key set of the old bundle, which is second in the list. It gives
// the trap of its slot. The request event goes through a real store writer.
// The stored mint row is the only one, and its set id is that of the old
// bundle. The test also checks the order. The site of the route comes first,
// then the swap, then the key set of the mint. The key function is the one of
// the handler, wrapped. The test does not wait for the zero of the old seed.
func TestTS31SwapDuringRender(t *testing.T) {
	l, put := swapLoader(t)
	old := l.Current()
	put(0x0b, 2)
	rig := newStoreRig(t)
	h := NewWithDayKey(loaderSrc{l}, &fallbackFn{}, rig.q, rig.dk)
	var cur *bundle.Bundle
	var order []string
	h.mintHook = func() {
		var err error
		cur, err = l.Load(true)
		mustOK(t, err)
		order = append(order, "swap")
	}
	keys := h.keys
	h.keys = func(b *bundle.Bundle) *token.KeySet {
		order = append(order, "keys")
		return keys(b)
	}
	h.hook = func() { order = append(order, "site") }
	w := serve(t, h, get("/t", "example.com"))
	if cur == nil || l.Current() != cur || cur == old {
		t.Fatal("the hook did not swap the running bundle")
	}
	if !slices.Equal(order, []string{"site", "swap", "keys"}) {
		t.Fatalf("order %v, want the site, the swap, then the key set of the mint", order)
	}
	texts := tokenRE.FindAllString(w.Body.String()+" "+w.Header().Get("X-Note"), -1)
	if w.Code != 200 || len(texts) != 2 {
		t.Fatalf("code %d, tokens %v", w.Code, texts)
	}
	sets := []*token.KeySet{cur.Tokens(), old.Tokens()}
	for i, want := range []string{"f", "n"} {
		tok, ok := token.Parse(texts[i])
		if r := token.Verify(sets, tok); !ok || !r.OK || r.Set != token.Second || r.Trap != want {
			t.Errorf("token %d: %+v, want trap %s under the old bundle", i, r, want)
		}
		if verifyUnder(cur, texts[i]).OK {
			t.Errorf("token %d verifies under the new bundle", i)
		}
	}
	rig.drain(t)
	var setID []byte
	var count int
	sum := old.SHA256()
	if n := countOf(t, rig.db, "SELECT count(*) FROM mint"); n != 1 {
		t.Fatalf("%d mint rows, want 1", n)
	}
	mustOK(t, rig.db.QueryRow("SELECT set_id, count FROM mint").Scan(&setID, &count))
	if string(setID) != string(sum[:8]) || count != 2 {
		t.Errorf("mint row %x count %d, want the set id %x of the old bundle", setID, count, sum[:8])
	}
}

// TestTS31SwapRace runs requests in parallel while the loader swaps 20 times
// between two seeds. Under -race, the test fails on a data race. Each response
// has its two tokens.
func TestTS31SwapRace(t *testing.T) {
	l, put := swapLoader(t)
	h := New(loaderSrc{l}, &fallbackFn{}, queueOf(t, 64))
	done := make(chan struct{})
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for {
				select {
				case <-done:
					return
				default:
				}
				w := serve(t, h, get("/t", "example.com"))
				if n := len(tokenRE.FindAllString(w.Body.String()+" "+w.Header().Get("X-Note"), -1)); w.Code != 200 || n != 2 {
					t.Errorf("code %d, %d tokens", w.Code, n)
					return
				}
				h.q.TryTake()
			}
		})
	}
	for i := range 20 {
		put([]byte{0x0b, 0x09}[i%2], i+2)
		_, err := l.Load(true)
		mustOK(t, err)
	}
	close(done)
	wg.Wait()
}

// countOf gives the integer that a query with one row and one column returns.
func countOf(t *testing.T, db *sql.DB, query string, args ...any) (n int) {
	t.Helper()
	mustOK(t, db.QueryRow(query, args...).Scan(&n))
	return n
}

// storeRig is a queue with a real store writer behind it. The handler of a test
// shares the queue and the day key.
type storeRig struct {
	q  *event.Queue
	w  *store.Writer
	db *sql.DB
	dk *session.DayKey
}

// newStoreRig opens a database and a log in a new state directory.
func newStoreRig(t *testing.T) storeRig {
	t.Helper()
	top, err := filepath.EvalSymlinks(t.TempDir())
	mustOK(t, err)
	state := filepath.Join(top, "state")
	mustOK(t, os.Mkdir(state, 0o700))
	root, err := os.OpenRoot(state)
	mustOK(t, err)
	t.Cleanup(func() { root.Close() })
	db, err := store.Open(root, "events.db", store.Options{})
	mustOK(t, err)
	t.Cleanup(func() { db.Close() })
	mustOK(t, store.Migrate(db, "origin"))
	lg, err := tlog.OpenLog(root, "tlog")
	mustOK(t, err)
	t.Cleanup(func() { lg.Close() })
	q, dk := queueOf(t, 16), session.NewDayKey()
	w := store.NewWriterWithDayKey(db, q, false, nil, store.Recovery{State: root, Origin: "origin", Log: lg}, dk)
	return storeRig{q, w, db, dk}
}

// drain closes the queue and runs the writer until it has stored each event.
// It fails when the writer stops or sees a mint range twice.
func (r storeRig) drain(t *testing.T) {
	t.Helper()
	r.q.Close()
	mustOK(t, r.w.Run(context.Background()))
	if !r.w.Healthy() {
		t.Fatalf("the writer stopped: %v", r.w.Err())
	}
	if d := r.w.MintDuplicates(); d != 0 {
		t.Errorf("%d mint ranges that the table already had", d)
	}
}

// TestTS31RowsForEachRequest serves requests through the handler into a real
// writer. Each request gives one event row of kind request. A request with a
// mint gives one mint row, and a request with none gives no mint row. Three
// requests of one session give one session row with req_count 3. No mint range
// comes twice to the writer. The statement count of the writer is not checked:
// the store has no exported way to read it.
func TestTS31RowsForEachRequest(t *testing.T) {
	rig := newStoreRig(t)
	q, db := rig.q, rig.db
	h := NewWithDayKey(fixedSource{mixedBundle(t, 0x09, "f", "n")}, &fallbackFn{}, q, rig.dk)
	// Three requests of the first client mint. The second client gets the
	// fixed 404 page, so its request has no mint.
	for _, c := range []struct{ ip, target string }{
		{"192.0.2.1:1000", "/t"}, {"192.0.2.1:1001", "/t"}, {"192.0.2.1:1002", "/t"}, {"192.0.2.2:1000", "/nope"},
	} {
		r := get(c.target, "example.com")
		r.RemoteAddr = c.ip
		serve(t, h, r)
	}
	rig.drain(t)
	for _, c := range []struct {
		what, query string
		want        int
	}{
		{"request events", "SELECT count(*) FROM event WHERE kind = 'request'", 4},
		{"mint rows", "SELECT count(*) FROM mint", 3},
		{"mint rows of the client with the fixed page", "SELECT count(*) FROM mint WHERE session_id = (SELECT id FROM session WHERE ip = '192.0.2.2')", 0},
		{"session rows", "SELECT count(*) FROM session", 2},
		{"req_count of the first session", "SELECT req_count FROM session WHERE ip = '192.0.2.1'", 3},
		{"req_count of the second session", "SELECT req_count FROM session WHERE ip = '192.0.2.2'", 1},
	} {
		if got := countOf(t, db, c.query); got != c.want {
			t.Errorf("%s: %d, want %d", c.what, got, c.want)
		}
	}
}

// cookieRefs gives the position of each selector in src that refers to
// Cookie, Cookies, CookiesNamed or ParseCookie. A call, a method value, a
// method expression and a field of a literal all have a selector. The match is
// on the syntax tree, so a comment or a string does not match.
func cookieRefs(path string, src any) ([]gotoken.Position, error) {
	fset := gotoken.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, 0)
	if err != nil {
		return nil, err
	}
	var out []gotoken.Position
	ast.Inspect(f, func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok && slices.Contains([]string{"Cookie", "Cookies", "CookiesNamed", "ParseCookie"}, sel.Sel.Name) {
			out = append(out, fset.Position(sel.Sel.Pos()))
		}
		return true
	})
	return out, nil
}

// cookieSample has seven references that cookieRefs must report. It also has
// a comment and a string that it must not report.
const cookieSample = `package p
// r.Cookie("sid")
func f(r *http.Request) {
	_ = "r.Cookies()"
	r.Cookie("sid")
	fmt.Println(r.Cookie("sid"))
	g := r.Cookie
	h := (*http.Request).Cookie
	_ = T{F: r.CookiesNamed}
	http.ParseCookie("a=b")
	x.y.Cookies()
}
`

// TestTS31NoRequestCookieCall fails when a file of this package or of
// internal/session, that is not a test, refers to the Cookie, Cookies,
// CookiesNamed or ParseCookie method or function. The session cookie comes
// from session.CookieFromHeader. The check reads the files of each GOOS and
// GOARCH, as TestTS02DirectImports does.
func TestTS31NoRequestCookieCall(t *testing.T) {
	if got, err := cookieRefs("p.go", cookieSample); err != nil || len(got) != 7 {
		t.Fatalf("the scan finds %v (%v), want 7 references and none in the comment or the string", got, err)
	}
	ctx := build.Default
	ctx.UseAllFiles = true
	for _, dir := range []string{".", "../session"} {
		pkg, err := ctx.ImportDir(dir, 0)
		mustOK(t, err)
		files := slices.Concat(pkg.GoFiles, pkg.CgoFiles)
		if len(files) == 0 {
			t.Fatalf("%s has no file", dir)
		}
		for _, name := range files {
			refs, err := cookieRefs(filepath.Join(pkg.Dir, name), nil)
			mustOK(t, err)
			for _, p := range refs {
				t.Errorf("%s: reference to a cookie function of the request", p)
			}
		}
	}
}
