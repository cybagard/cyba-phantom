package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"maps"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/html"

	"github.com/cybagard/cyba-phantom/internal/bundle"
	"github.com/cybagard/cyba-phantom/internal/token"
)

const (
	// refHost is vhost A of the reference bundle. refHostB is vhost B.
	// refKeyID is the key id of its manifest. refSrc is its source tree.
	refHost  = "shop.phantom-ref.internal"
	refHostB = "docs.phantom-ref.internal"
	refKeyID = "ref1"
	refSrc   = "../../bundles/reference/src"
)

// refPageSlots are the 8 slots in the page of vhost A. refOutSlots are the 4
// slots out of it: a robots.txt line, a JSON file, the 404 page and a header.
// refSlots are the 12 slots of vhost A. Each one has one trap.
var (
	refPageSlots = []string{"hidden-p", "html-comment", "meta-description", "alt", "aria-label",
		"nofollow-link", "json-ld", "noscript"}
	refOutSlots = []string{"robots-disallow", "ai-plugin", "not-found", "header"}
	refSlots    = slices.Concat(refPageSlots, refOutSlots)
)

// refRoutes gives the surface of each callback route of vhost A. refRoutesB
// does the same for vhost B.
var (
	refRoutes = map[string]string{"/phantom-reference-trap/cb": "path", "/ref/query": "query",
		"/ref/header": "header", "/ref/body": "body"}
	refRoutesB = map[string]string{"/ref/cb": "path", "/ref/query": "query", "/ref/body": "body"}
)

// refVhost is one vhost of the reference bundle. Its traps have the prefix in
// their id. title is the title of its page.
type refVhost struct {
	host, prefix, title string
	slots               []string
	routes              map[string]string
}

// refVhosts are the two vhosts. Vhost B has the slots of its page only.
var refVhosts = []refVhost{
	{refHost, "a-", "The tea shop", refSlots, refRoutes},
	{refHostB, "b-", "The shop guide", []string{"hidden-p", "html-comment", "alt", "aria-label"}, refRoutesB},
}

// refVisibility gives the visibility of each slot to a human in a browser. The
// value comes from the place of the slot in the reference templates. The tag
// of a trap must be the value of its slot. The table does not read the page.
var refVisibility = map[string]string{
	"hidden-p":         "human-invisible", // class hidden has display none
	"html-comment":     "human-invisible", // a browser draws no comment
	"meta-description": "human-invisible", // a meta element of the head
	"alt":              "human-visible",   // an img with no src shows its alt
	"aria-label":       "human-invisible", // a browser does not draw the label
	"nofollow-link":    "human-visible",   // a link in the body
	"json-ld":          "human-invisible", // a browser draws no script element
	"noscript":         "human-visible",   // a browser shows it, scripting off
	"robots-disallow":  "human-invisible", // a line of robots.txt
	"ai-plugin":        "human-invisible", // a JSON file for tools
	"not-found":        "human-visible",   // a paragraph of the 404 page
	"header":           "human-invisible", // a response header
}

// vhostOf gives the vhost that the trap id of a trap belongs to.
func vhostOf(tr refTrap) (refVhost, bool) {
	for _, v := range refVhosts {
		if strings.HasPrefix(tr.ID, v.prefix) {
			return v, true
		}
	}
	return refVhost{}, false
}

// refSeed returns the token seed of the source tree. The seed is public.
func refSeed(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(refSrc, "secrets/token.seed"))
	mustOK(t, err)
	return b
}

// refTrap is a trap of the source tree.
type refTrap struct {
	ID, Slot, Surface, Visibility string
	Template                      string `json:"instruction_template"`
}

// refRun is a started sensor with the source tree of the reference bundle.
type refRun struct {
	*baitSensor
	traps []refTrap
	// clock is the loader clock of the run: `created` + 1 h of the manifest.
	clock time.Time
}

// refTrustOf is a trust set with the one key pub. The key has class reference
// and the key id of the manifest. The release trust set has no such key.
func refTrustOf(pub ed25519.PublicKey) bundle.TrustSet {
	return bundle.TrustSet{{KeyID: refKeyID, PublicKey: [32]byte(pub), Class: bundle.ClassReference}}
}

// devKey makes a new signing key from crypto/rand. A test makes its own key and
// keeps it in memory. The repository holds no part of it.
func devKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, k, err := ed25519.GenerateKey(rand.Reader)
	mustOK(t, err)
	return k
}

// startReference packs the source tree in memory. It signs the archive with a
// new key of the test (devKey) and starts a sensor on it. The trust set has
// that key as its one key of class reference. The loader clock is `created` +
// 1 h of the manifest, through the loader seam. The tokens come from the real
// clock of the handler. The ring classes them by the loader clock. See
// refAgeClass.
func startReference(t *testing.T) *refRun {
	t.Helper()
	var files []tarFile
	src := os.DirFS(refSrc)
	mustOK(t, fs.WalkDir(src, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := fs.ReadFile(src, p)
		files = append(files, tarFile{p, b})
		return err
	}))
	var man struct{ Created, Expires time.Time }
	var traps []refTrap
	for _, f := range files {
		switch f.name {
		case "manifest.json":
			mustOK(t, json.Unmarshal(f.data, &man))
		case "traps/traps.json":
			mustOK(t, json.Unmarshal(f.data, &traps))
		}
	}
	clock := man.Created.Add(time.Hour)
	oldNew := newLoader
	t.Cleanup(func() { newLoader = oldNew })
	newLoader = func(s *os.Root, path string, ts bundle.TrustSet, k hpke.PrivateKey) *bundle.Loader {
		l := oldNew(s, path, ts, k)
		l.SetClock(func() time.Time { return clock }, time.Sleep)
		return l
	}
	key := devKey(t)
	arch := archiveOf(t, files...)
	seed := func(t *testing.T, p startParams) {
		putBundle(t, p.Root, p.BundlePath, arch, key)
		// putBundle names the key t1. The manifest names the reference key.
		sig := filepath.Join(p.Root, strings.TrimSuffix(p.BundlePath, ".cbnd")+".sig")
		b, err := os.ReadFile(sig)
		mustOK(t, err)
		mustOK(t, os.WriteFile(sig, bytes.Replace(b, []byte("t1 "), []byte(refKeyID+" "), 1), 0o600))
	}
	trust := func() bundle.TrustSet { return refTrustOf(key.Public().(ed25519.PublicKey)) }
	s := startBait(t, baitOpt{names: []string{refHost, refHostB}, trust: trust, seed: seed})
	s.arch = arch
	return &refRun{s, traps, clock}
}

// refAgeClass tells if the ring of the loader must class a token of the run as
// stale and as future. The ring reads the loader clock (r.clock). The mint
// reads the real clock of the handler. The age is the first minus the second,
// in units of 10 min. A token is future above 1 h ahead of the loader clock.
// It is stale above 25 h behind it, or when it is future. The tokens come from
// the window from t0 to t1. known is false when the window does not fix the
// classes. The unit of a token can then be on either side of a limit.
// The ring compares whole 10 min units. So a mint time 70 min or more ahead of
// the loader clock is always future.
func (r *refRun) refAgeClass(t0, t1 time.Time) (stale, future, known bool) {
	switch {
	case t0.Sub(r.clock) >= 70*time.Minute:
		return true, true, true
	case t1.Sub(r.clock) <= time.Hour && r.clock.Sub(t0) <= 25*time.Hour:
		return false, false, true
	}
	return false, false, false
}

// slotTexts returns the text of each in-page slot of the page in body, by the
// name of the slot. A slot that the page does not have is not in the map.
func slotTexts(t *testing.T, body string) map[string]string {
	t.Helper()
	doc, err := html.Parse(strings.NewReader(body))
	mustOK(t, err)
	out := map[string]string{}
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		attr := func(key string) string {
			for _, a := range n.Attr {
				if a.Key == key {
					return a.Val
				}
			}
			return ""
		}
		text := ""
		if n.FirstChild != nil {
			text = n.FirstChild.Data
		}
		switch {
		case n.Type == html.CommentNode:
			out["html-comment"] = strings.TrimSpace(n.Data)
		case n.Type != html.ElementNode:
		case n.Data == "meta" && attr("name") == "description":
			out["meta-description"] = attr("content")
		case n.Data == "img":
			out["alt"] = attr("alt")
		case n.Data == "p" && attr("class") == "hidden":
			out["hidden-p"] = text
		case attr("aria-label") != "":
			out["aria-label"] = attr("aria-label")
		case n.Data == "p" && strings.HasPrefix(text, "phantom-reference-trap. "):
			out["not-found"] = text
		case n.Data == "a" && attr("rel") == "nofollow":
			out["nofollow-link"] = attr("href")
		case n.Data == "noscript":
			out["noscript"] = text
		case n.Data == "script" && attr("type") == "application/ld+json":
			var ld struct{ Description string }
			mustOK(t, json.Unmarshal([]byte(text), &ld))
			out["json-ld"] = ld.Description
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return out
}

// tokenIn takes the token text out of the render of a trap. The template has
// the text before and after the token action. The render must have the same
// text around the token.
func tokenIn(tpl, render string) (string, bool) {
	before, after, ok := strings.Cut(tpl, "{{.Token}}")
	if !ok {
		return "", false
	}
	mid, ok := strings.CutPrefix(render, before)
	if !ok {
		return "", false
	}
	return strings.CutSuffix(mid, after)
}

// secondAddr is a second client address of the loopback.
var secondAddr = net.ParseIP("127.0.0.2")

// needSecondAddr skips the test on a host that is not Linux and has no client
// address 127.0.0.2.
func (r *refRun) needSecondAddr(t *testing.T) {
	t.Helper()
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: secondAddr}, Timeout: netWait}
	c, err := d.DialContext(t.Context(), "tcp", strings.TrimPrefix(r.https, "https://"))
	if runtime.GOOS != "linux" && errors.Is(err, syscall.EADDRNOTAVAIL) {
		t.Skipf("no client address 127.0.0.2 on %s: %v", runtime.GOOS, err)
	}
	mustOK(t, err)
	c.Close()
}

// outSlotTexts gets the 4 slots out of the page for the client address ip. page
// is the response for "/". The map key is the slot name, and the value is the
// text of the slot.
func (r *refRun) outSlotTexts(t *testing.T, ip net.IP, page baitResp) map[string]string {
	t.Helper()
	get := func(path string, status int, ctype string) baitResp {
		resp := fetchFrom(t, r.https, refHost, path, "", ip)
		if resp.status != status || resp.header.Get("Content-Type") != ctype {
			t.Errorf("GET %s: status %d, type %q; want %d and %q", path, resp.status, resp.header.Get("Content-Type"), status, ctype)
		}
		return resp
	}
	out := map[string]string{"header": page.header.Get("X-Note")}
	for _, l := range strings.Split(get("/robots.txt", 200, "text/plain; charset=utf-8").body, "\n") {
		if rest, ok := strings.CutPrefix(l, "Disallow: "); ok {
			out["robots-disallow"] = rest
		}
	}
	var plugin struct {
		Model string `json:"description_for_model"`
	}
	mustOK(t, json.Unmarshal([]byte(get("/.well-known/ai-plugin.json", 200, "application/json").body), &plugin))
	out["ai-plugin"] = plugin.Model
	// A path with no route gets the 404 decoy of the route map.
	out["not-found"] = slotTexts(t, get("/missing", 404, "text/html; charset=utf-8").body)["not-found"]
	return out
}

// tokensOf gives the token text of each trap of the vhost v, by trap id. texts
// has the text of each slot. A trap with no token in its slot fails the test.
func (r *refRun) tokensOf(t *testing.T, v refVhost, texts map[string]string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, tr := range r.traps {
		if !strings.HasPrefix(tr.ID, v.prefix) {
			continue
		}
		render, ok := texts[tr.Slot]
		if !ok {
			t.Errorf("trap %s: the response has no %s slot", tr.ID, tr.Slot)
			continue
		}
		if out[tr.ID], ok = tokenIn(tr.Template, render); !ok {
			t.Errorf("trap %s: slot %s has text %q; want the template %q with a token", tr.ID, tr.Slot, render, tr.Template)
		}
	}
	return out
}

// allTokens gets the page for "/" of the vhost v. For vhost A, it also gets the
// 4 slots out of the page. The client address is ip. It gives the token text of
// each trap of v, by trap id, and the page.
func (r *refRun) allTokens(t *testing.T, v refVhost, ip net.IP) (map[string]string, baitResp) {
	t.Helper()
	page := fetchFrom(t, r.https, v.host, "/", "", ip)
	if page.status != 200 {
		t.Fatalf("client %v, host %s: status %d; want 200", ip, v.host, page.status)
	}
	if want := "<title>" + v.title + "</title>"; !strings.Contains(page.body, want) {
		t.Errorf("host %s: page %q; want the title %q", v.host, page.body, want)
	}
	texts := slotTexts(t, page.body)
	if v.host == refHost {
		maps.Copy(texts, r.outSlotTexts(t, ip, page))
	}
	return r.tokensOf(t, v, texts), page
}

// TestTI02_ReferenceVhostServesEachSlot checks T-I-02 on the source tree of
// the reference bundle (FR-03, SEC-42). The test packs the tree in memory.
// A test key of class reference signs it. The sensor serves both vhosts, each
// with its own page. Vhost A has each of the 12 slots. Its page has 8 of them.
// The robots.txt file, the JSON file, the 404 page and the X-Note header of
// the page have the other 4. Vhost B has the slots of its own page. Each end
// tag of the HTML closes the element that is open last. Each token verifies to
// the trap of its slot. Two sessions get their own tokens. The request row of
// each page has the vhost that the Host header named. A host that is not Linux
// and has no 127.0.0.2 skips the test.
func TestTI02_ReferenceVhostServesEachSlot(t *testing.T) {
	r := startReference(t)
	r.needSecondAddr(t)
	var ids []string
	slots := map[string][]string{}
	for _, tr := range r.traps {
		v, ok := vhostOf(tr)
		if !ok {
			t.Fatalf("trap %s: no vhost has its prefix", tr.ID)
		}
		ids, slots[v.host] = append(ids, tr.ID), append(slots[v.host], tr.Slot)
	}
	for _, v := range refVhosts {
		if !slices.Equal(slices.Sorted(slices.Values(slots[v.host])), slices.Sorted(slices.Values(v.slots))) {
			t.Fatalf("vhost %s: trap slots %q; want one trap for each of %q", v.host, slots[v.host], v.slots)
		}
	}
	ks, err := token.NewKeySet(refSeed(t), sha256.Sum256(r.arch), ids, true)
	mustOK(t, err)
	seen := map[string]bool{}
	ips := []string{"127.0.0.1", "127.0.0.2"}
	for i, ip := range ips {
		for _, v := range refVhosts {
			toks, page := r.allTokens(t, v, net.ParseIP(ip))
			checkTags(t, page.body)
			for id, text := range toks {
				if text == "" { // tokensOf has reported it
					continue
				}
				tok, ok := token.Parse(text)
				if res := token.Verify([]*token.KeySet{ks}, tok); !ok || !res.OK || res.Trap != id || !res.Reference {
					t.Errorf("client %d, trap %s: text %q gives %+v; want a reference token of that trap", i, id, text, res)
				}
				if seen[text] {
					t.Errorf("client %d, trap %s: token %q repeats", i, id, text)
				}
				seen[text] = true
			}
		}
	}
	if len(seen) != 2*len(r.traps) {
		t.Errorf("%d tokens in the pages; want %d", len(seen), 2*len(r.traps))
	}
	r.stop(t)
	want := []string{r.keyedIDOf(t, ips[0]), r.keyedIDOf(t, ips[1])}
	slices.Sort(want)
	for _, v := range refVhosts {
		got := r.sessionsOn(t, v.host, "/")
		slices.Sort(got)
		if !slices.Equal(got, want) || want[0] == want[1] {
			t.Errorf("vhost %s: session ids of the two rows %q; want the two keyed ids %q", v.host, got, want)
		}
	}
}

// TestTI02_ReferenceTrapVisibility checks the visibility tag of each trap that
// T-I-02 serves (SEC-42). The tag must be the value of its slot in
// refVisibility. The test reads the traps of vhost A and of vhost B from the
// source tree. It starts no sensor.
func TestTI02_ReferenceTrapVisibility(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(refSrc, "traps/traps.json"))
	mustOK(t, err)
	var traps []refTrap
	mustOK(t, json.Unmarshal(b, &traps))
	for _, tr := range traps {
		want, ok := refVisibility[tr.Slot]
		if !ok {
			t.Errorf("trap %s: slot %q has no visibility in the table", tr.ID, tr.Slot)
		}
		if tr.Visibility != want {
			t.Errorf("trap %s in slot %s: visibility %q; want %q", tr.ID, tr.Slot, tr.Visibility, want)
		}
	}
	if len(traps) == 0 {
		t.Error("the source tree has no trap")
	}
}

// refRouteOf gives the callback route of the vhost v that the text of a trap
// names.
func refRouteOf(t *testing.T, v refVhost, tr refTrap) string {
	t.Helper()
	var named []string
	for route := range v.routes {
		if strings.Contains(tr.Template, route) {
			named = append(named, route)
		}
	}
	if len(named) != 1 {
		t.Fatalf("trap %s: text %q names the routes %q; want one", tr.ID, tr.Template, named)
	}
	return named[0]
}

// refCallbackRequest sends one callback request with the token text tok to
// the callback route of the vhost v. It uses its own connection from the client
// address ip.
func refCallbackRequest(t *testing.T, r *refRun, v refVhost, ip net.IP, route, tok, cookie string) {
	t.Helper()
	method, target, body, hdr := http.MethodGet, route, "", http.Header{"Cookie": {cookie}}
	switch v.routes[route] {
	case "path":
		target += "/" + tok
	case "query":
		target += "?part=" + tok
	case "header":
		hdr.Set("X-Ref", tok)
	case "body":
		method, body = http.MethodPost, `{"link":"`+tok+`"}`
	}
	req, err := http.NewRequestWithContext(t.Context(), method, r.https+target, strings.NewReader(body))
	mustOK(t, err)
	req.Host, req.Header = v.host, hdr
	cl := plainClient()
	cl.Transport.(*http.Transport).DialContext = (&net.Dialer{LocalAddr: &net.TCPAddr{IP: ip}}).DialContext
	resp, err := cl.Do(req)
	mustOK(t, err)
	defer resp.Body.Close()
	_, err = io.Copy(io.Discard, resp.Body)
	mustOK(t, err)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("callback at the route %s: status %d; want 204", route, resp.StatusCode)
	}
}

// TestTI04_ReferenceCallbackRoutes checks T-I-04 on the reference bundle
// (FR-04, SEC-37, SEC-42). The token of each trap goes to the callback route
// that the text of the trap names. The request has the host of the trap. The
// route gives a callback row. The surface of the row is the surface of the
// trap. The row has the trap of the token, the vhost of the trap and
// reference_seed: true. It has a leaf in the log, and the callback session. The
// token row has the session of the render and cb_count 1. The 4 surfaces of
// vhost A (path, query, header, body) are in the 16 traps. The classes stale
// and future follow the loader clock, which the run sets to `created` + 1 h.
// The key of the run is new for the test.
func TestTI04_ReferenceCallbackRoutes(t *testing.T) {
	r := startReference(t)
	r.needSecondAddr(t)
	db := readStore(t, r.baitSensor)
	toks := map[string]string{}
	t0 := time.Now()
	for _, v := range refVhosts {
		got, _ := r.allTokens(t, v, nil)
		maps.Copy(toks, got)
	}
	t1 := time.Now()
	wantStale, wantFuture, known := r.refAgeClass(t0, t1)
	renderSession := r.keyedID(t)
	var mints int
	pollRow(t, db, "SELECT count(*) FROM mint WHERE session_id = ? HAVING count(*) > 0", []any{renderSession}, &mints)
	cookie, cbSession := r.cookie(t)
	if cbSession == renderSession {
		t.Fatal("the callback session and the render session are the same")
	}
	for i, tr := range r.traps {
		parsed, ok := token.Parse(toks[tr.ID])
		if !ok {
			t.Fatalf("trap %s: text %q is not a token", tr.ID, toks[tr.ID])
		}
		v, ok := vhostOf(tr)
		if !ok {
			t.Fatalf("trap %s: no vhost has its prefix", tr.ID)
		}
		route := refRouteOf(t, v, tr)
		// The engine caps the callback events of one client address at 10
		// in a minute. So the 16 traps use 2 addresses, 8 each.
		ip := []net.IP{net.IPv4(127, 0, 0, 1), secondAddr}[i%2]
		refCallbackRequest(t, r, v, ip, route, toks[tr.ID], cookie)
		var got, trap, vhost, detail, session string
		var leaf sql.NullInt64
		id := token.ID(parsed)
		pollRow(t, db, "SELECT surface, trap_id, vhost, detail, session_id, leaf_index FROM event WHERE kind = 'callback' AND token_id = ?",
			[]any{id}, &got, &trap, &vhost, &detail, &session, &leaf)
		var d map[string]any
		mustOK(t, json.Unmarshal([]byte(detail), &d))
		// The ring sets stale and future. It reads the loader clock, which
		// is the clock of this run. The mint time is the real clock of the
		// handler. So the real clock alone does not give the age. The loader
		// clock is `created` + 1 h, so the tokens of a later day are future.
		if known {
			for k, want := range map[string]bool{"stale": wantStale, "future": wantFuture} {
				if _, has := d[k]; has != want {
					t.Errorf("trap %s: detail %s; want %s present: %v (loader clock %v, mint from %v to %v)",
						tr.ID, detail, k, want, r.clock, t0, t1)
				}
			}
		}
		if got != tr.Surface || trap != tr.ID || vhost != v.host || d["reference_seed"] != true {
			t.Errorf("trap %s at %s: row surface %q, trap %q, vhost %q, detail %s; want %q, %q, %q and reference_seed true",
				tr.ID, route, got, trap, vhost, detail, tr.Surface, tr.ID, v.host)
		}
		// The proof of the callback is the leaf of the event in the log.
		if !leaf.Valid || leaf.Int64 < 0 || session != cbSession {
			t.Errorf("trap %s: callback row leaf %v, session %q; want a leaf and the callback session %q",
				tr.ID, leaf, session, cbSession)
		}
		// The token row comes in the batch of the callback row.
		var tokSession, tokTrap string
		var count int64
		mustOK(t, db.QueryRowContext(t.Context(), "SELECT session_id, trap_id, cb_count FROM token WHERE token_id = ?", id).
			Scan(&tokSession, &tokTrap, &count))
		if tokSession != renderSession || tokTrap != tr.ID || count != 1 {
			t.Errorf("trap %s: token row session %q, trap %q, cb_count %d; want %q, %q, 1",
				tr.ID, tokSession, tokTrap, count, renderSession, tr.ID)
		}
	}
	r.stop(t)
}

// TestTI02_ReferenceBeaconScript checks T-I-02 for the beacon of the reference
// bundle (SEC-38, SEC-42). The route map names the script path /beacon.js and
// the post path /beacon. A GET of the script path gives the script of the
// engine, with the post path in it.
func TestTI02_ReferenceBeaconScript(t *testing.T) {
	r := startReference(t)
	got := fetch(t, r.https, refHost, "/beacon.js", "")
	if ct := got.header.Get("Content-Type"); got.status != 200 || ct != "text/javascript; charset=utf-8" {
		t.Errorf("GET /beacon.js: status %d, type %q; want 200 and text/javascript; charset=utf-8", got.status, ct)
	}
	if !strings.HasPrefix(got.body, `navigator.sendBeacon("/beacon","`) || !strings.HasSuffix(got.body, `")`) {
		t.Errorf("GET /beacon.js: body %q; want a sendBeacon call to /beacon", got.body)
	}
	r.stop(t)
}
