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
	"strings"
	"sync"
	"testing"
	"time"

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

// TestTU20SiteInterleave checks that a request for the previous bundle
// installs nothing. Two bundles that alternate build two sites.
func TestTU20SiteInterleave(t *testing.T) {
	b1, b2 := newBundle(t), newBundle(t)
	h := New(&swap{}, &fallbackFn{})
	var first *site
	for i, b := range []*bundle.Bundle{b1, b2, b1, b2, b1} {
		s := h.siteOf(b)
		if b == b1 {
			if first == nil {
				first = s
			} else if s != first {
				t.Errorf("call %d: another site for the first bundle", i)
			}
		}
	}
	if n := h.builds.Load(); n != 2 {
		t.Fatalf("builds = %d, want 2", n)
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
