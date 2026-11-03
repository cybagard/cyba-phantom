package bait

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
	"weak"

	"github.com/cybagard/cyba-phantom/internal/bundle"
)

// route is a route of the test vhost. file is below vhosts/<host>/.
type route struct{ path, file, typ, body string }

const (
	html = "text/html; charset=utf-8"
	text = "text/plain; charset=utf-8"
)

// The asset routes of example.com. The paths are the targets that an escape
// form could reach after a decode or a clean. The last row is a template.
var exampleRoutes = []route{
	{"/", "index.html", html, "<p>index</p>\n"},
	{"/a/b", "ab.txt", text, "route a/b\n"},
	{"/b", "b.txt", text, "route b\n"},
	{"/x", "x.txt", text, "route x\n"},
	{"/secrets/token.seed", "note.txt", text, "route note\n"},
	{"/style.css", "style.css", "text/css; charset=utf-8", "p{color:red}\n"},
	{"/logo.png", "logo.png", "image/png", "\x89PNG\r\n\x1a\n\x00\xff\x00"},
	{"/t", "t.tmpl", html, "template\n"},
}

var kiloRoutes = []route{{"/", "kilo.txt", text, "kilo\n"}}

// zuluRoutes are the routes of a vhost whose name has the letter z.
var zuluRoutes = []route{{"/", "zulu.txt", text, "zulu\n"}}

func mustOK(tb testing.TB, err error) {
	tb.Helper()
	if err != nil {
		tb.Fatal(err)
	}
}

// routesJSON makes the route map of a vhost.
func routesJSON(host string, rs []route) string {
	var parts []string
	for _, r := range rs {
		kind := "asset"
		if strings.HasSuffix(r.file, ".tmpl") {
			kind = "template"
		}
		parts = append(parts, fmt.Sprintf(`{"path":%q,%q:"vhosts/%s/%s","type":%q}`, r.path, kind, host, r.file, r.typ))
	}
	return `{"routes":[` + strings.Join(parts, ",") + `]}`
}

// newBundle loads a signed bundle with two vhosts, a trap and files that no
// route names. It uses a new state directory.
func newBundle(tb testing.TB) *bundle.Bundle { return bundleWith(tb, "") }

// bundleWith is newBundle with tag in the root page of example.com.
func bundleWith(tb testing.TB, tag string) *bundle.Bundle {
	tb.Helper()
	files := map[string]string{
		"manifest.json": fmt.Sprintf(`{"version":"2026.11.01-1","min_engine":"1.0.0","created":%q,"expires":%q,"key_id":"t1"}`,
			time.Now().Add(-time.Hour).UTC().Format("2006-01-02T15:04:05Z"), time.Now().Add(24*time.Hour).UTC().Format("2006-01-02T15:04:05Z")),
		"secrets/token.seed":              strings.Repeat("\x09", 32),
		"score/a":                         "score\n",
		"fp/a":                            "fp\n",
		"traps/traps.json":                `[{"id":"a","slot":"hidden-p","surface":"path","visibility":"human-visible","instruction_template":"x"}]`,
		"vhosts/example.com/routes.json":  routesJSON("example.com", exampleRoutes),
		"vhosts/example.com/unrouted.txt": "unrouted\n",
		"vhosts/kilo.example/routes.json": routesJSON("kilo.example", kiloRoutes),
		"vhosts/kilo.example/only.txt":    "other vhost\n",
		"vhosts/zulu.example/routes.json": routesJSON("zulu.example", zuluRoutes),
	}
	for host, rs := range map[string][]route{"example.com": exampleRoutes, "kilo.example": kiloRoutes, "zulu.example": zuluRoutes} {
		for _, r := range rs {
			files["vhosts/"+host+"/"+r.file] = r.body
		}
	}
	files["vhosts/example.com/index.html"] = "<p>index" + tag + "</p>\n"
	var buf bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&buf, gzip.BestSpeed)
	tw := tar.NewWriter(zw)
	for name, data := range files {
		mustOK(tb, tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(data)), Format: tar.FormatUSTAR}))
		_, err := tw.Write([]byte(data))
		mustOK(tb, err)
	}
	mustOK(tb, tw.Close())
	mustOK(tb, zw.Close())

	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0xA5}, ed25519.SeedSize))
	trust := bundle.TrustSet{{KeyID: "t1", PublicKey: [32]byte(key.Public().(ed25519.PublicKey)), Class: bundle.ClassReference}}
	dir := tb.TempDir()
	sig := "t1 " + base64.StdEncoding.EncodeToString(ed25519.Sign(key, bundle.SigMessage(buf.Bytes()))) + "\n"
	mustOK(tb, os.MkdirAll(filepath.Join(dir, "bundle"), 0o700))
	mustOK(tb, os.WriteFile(filepath.Join(dir, "bundle/current.cbnd"), buf.Bytes(), 0o600))
	mustOK(tb, os.WriteFile(filepath.Join(dir, "bundle/current.sig"), []byte(sig), 0o600))
	root, err := os.OpenRoot(dir)
	mustOK(tb, err)
	tb.Cleanup(func() { root.Close() })
	b, err := bundle.NewLoader(root, "bundle/current.cbnd", trust, nil).Load(true)
	mustOK(tb, err)
	return b
}

// TestTU20SiteTable checks the table. It holds each route of each vhost and
// the asset view of each asset route. It holds the result of one Traps call.
// A new table comes only with a new bundle.
func TestTU20SiteTable(t *testing.T) {
	b := newBundle(t)
	s := buildSite(b)
	if len(s.hosts) != 3 || len(s.hosts["example.com"]) != len(exampleRoutes) || len(s.hosts["kilo.example"]) != 1 {
		t.Fatalf("hosts = %d, routes = %d", len(s.hosts), len(s.hosts["example.com"]))
	}
	for _, r := range exampleRoutes {
		e := s.hosts["example.com"][r.path]
		if e == nil || e.isAsset != (r.file != "t.tmpl") || e.isAsset && e.asset.Len() != len(r.body) {
			t.Errorf("route %q: entry %+v", r.path, e)
		}
	}
	if len(s.traps) != 1 || s.traps[0].ID != "a" {
		t.Errorf("traps = %v", s.traps)
	}

	h := New(&swap{list: []*bundle.Bundle{b}}, &fallbackFn{})
	for range 5 {
		if got := serve(t, h, get("/", "example.com")).Code; got != 200 {
			t.Fatalf("code = %d", got)
		}
	}
	if n := h.builds.Load(); n != 1 {
		t.Fatalf("builds after 5 requests = %d, want 1", n)
	}
	h.src = &swap{list: []*bundle.Bundle{newBundle(t)}}
	serve(t, h, get("/", "example.com"))
	serve(t, h, get("/", "example.com"))
	if n := h.builds.Load(); n != 2 {
		t.Fatalf("builds after a new bundle = %d, want 2", n)
	}
}

// rootLen is the size of the root page of example.com in a bundle with tag.
func rootLen(tag string) int { return len("<p>index" + tag + "</p>\n") }

// TestTU20SiteInterleave checks that a request for a replaced bundle installs
// nothing. The call gets a private site of its own bundle. Two bundles that
// alternate build two cached sites and two private sites.
func TestTU20SiteInterleave(t *testing.T) {
	b1, b2 := bundleWith(t, "-1"), bundleWith(t, "-22")
	h := New(&swap{}, &fallbackFn{})
	for i, c := range []struct {
		b    *bundle.Bundle
		tag  string
		want int64
	}{{b1, "-1", 1}, {b2, "-22", 2}, {b1, "-1", 3}, {b2, "-22", 3}, {b1, "-1", 4}} {
		s := h.siteOf(c.b)
		if e := s.hosts["example.com"]["/"]; e == nil || e.asset.Len() != rootLen(c.tag) {
			t.Errorf("call %d: the site is not the site of the bundle", i)
		}
		if i > 0 && h.sites.Load().cur.b != b2 {
			t.Errorf("call %d: the running bundle is not the second bundle", i)
		}
		if n := h.builds.Load(); n != c.want {
			t.Fatalf("call %d: builds = %d, want %d", i, n, c.want)
		}
	}
}

// TestTU20SiteRetired checks that the state remembers the last four replaced
// bundles, newest first.
func TestTU20SiteRetired(t *testing.T) {
	h := New(&swap{}, &fallbackFn{})
	var bs []*bundle.Bundle
	for range 6 {
		bs = append(bs, newBundle(t))
		h.siteOf(bs[len(bs)-1])
	}
	st := h.sites.Load()
	if st.cur.b != bs[5] {
		t.Fatal("the running bundle is not the last bundle")
	}
	for i, want := range []*bundle.Bundle{bs[4], bs[3], bs[2], bs[1]} {
		if st.retired[i] != weak.Make(want) {
			t.Errorf("retired[%d] is not the expected bundle", i)
		}
	}
}

// loadAndRelease makes two bundles and calls siteOf for both. It keeps no
// reference to the first bundle, and a cleanup closes done when the first
// bundle is gone.
func loadAndRelease(t *testing.T, h *Handler, done chan struct{}) {
	b1 := newBundle(t)
	runtime.AddCleanup(b1, func(struct{}) { close(done) }, struct{}{})
	h.siteOf(b1)
	h.siteOf(newBundle(t))
}

// TestTU20SiteRelease checks that the handler does not keep a replaced bundle.
func TestTU20SiteRelease(t *testing.T) {
	h := New(&swap{}, &fallbackFn{})
	defer runtime.KeepAlive(h)
	done := make(chan struct{})
	loadAndRelease(t, h, done)
	for range 10 {
		runtime.GC()
		select {
		case <-done:
			return
		default:
			runtime.Gosched()
		}
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the handler keeps the replaced bundle")
	}
}

// TestTU20SiteLostSwap checks a lost swap. Another bundle becomes cur between
// the Load and the CompareAndSwap of the first call. The call tries again and
// ends with its own bundle as cur and the other bundle as retired.
func TestTU20SiteLostSwap(t *testing.T) {
	b1, b2 := bundleWith(t, "-1"), bundleWith(t, "-22")
	h := New(&swap{}, &fallbackFn{})
	h.hook = func() {
		h.hook = nil
		h.siteOf(b2)
	}
	s := h.siteOf(b1)
	st := h.sites.Load()
	if st.cur.b != b1 || st.retired[0] != weak.Make(b2) {
		t.Fatal("the first call did not end with its bundle as cur and the other as retired")
	}
	if e := s.hosts["example.com"]["/"]; e == nil || e.asset.Len() != rootLen("-1") {
		t.Error("the site is not the site of the first bundle")
	}
	if n := h.builds.Load(); n != 2 {
		t.Errorf("builds = %d, want 2", n)
	}
}

// TestTU20SiteServe checks that each response has the content of the bundle
// that its request got, also when the source goes back to a replaced bundle.
func TestTU20SiteServe(t *testing.T) {
	b1, b2, b3 := bundleWith(t, "-1"), bundleWith(t, "-2"), bundleWith(t, "-3")
	list := []*bundle.Bundle{b1, b2, b1, b3, b2}
	tags := []string{"-1", "-2", "-1", "-3", "-2"}
	h := New(&swap{list: list}, &fallbackFn{})
	for i, tag := range tags {
		w := serve(t, h, get("/", "example.com"))
		if want := "<p>index" + tag + "</p>\n"; w.Body.String() != want {
			t.Errorf("request %d: body %q, want %q", i, w.Body.String(), want)
		}
	}
}

// TestTU20SiteParallel checks that parallel first requests for one new bundle
// build one site, in each of 50 rounds.
func TestTU20SiteParallel(t *testing.T) {
	const workers = 32
	h := New(&swap{}, &fallbackFn{})
	for round := 1; round <= 50; round++ {
		b := newBundle(t)
		start := make(chan struct{})
		got := make([]*site, workers)
		var wg sync.WaitGroup
		for i := range workers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				got[i] = h.siteOf(b)
			}()
		}
		close(start)
		wg.Wait()
		if n := h.builds.Load(); n != int64(round) {
			t.Fatalf("round %d: builds = %d, want %d", round, n, round)
		}
		for i, s := range got {
			if s != got[0] {
				t.Fatalf("round %d: worker %d got another site", round, i)
			}
		}
	}
}
