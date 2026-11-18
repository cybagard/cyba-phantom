package main

import (
	"bytes"
	"crypto/hpke"
	"crypto/sha256"
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
	// refHost is the vhost of the reference bundle. refKeyID is the key id of
	// its manifest. refSrc is its source tree.
	refHost  = "shop.phantom-ref.internal"
	refKeyID = "ref1"
	refSrc   = "../../bundles/reference/src"
)

// refPageSlots are the 8 slots in the page of the vhost. refOutSlots are the 4
// slots out of it: a robots.txt line, a JSON file, the 404 page and a header.
// refSlots are the 12 slots of the vhost. Each one has one trap.
var (
	refPageSlots = []string{"hidden-p", "html-comment", "meta-description", "alt", "aria-label",
		"nofollow-link", "json-ld", "noscript"}
	refOutSlots = []string{"robots-disallow", "ai-plugin", "not-found", "header"}
	refSlots    = slices.Concat(refPageSlots, refOutSlots)
)

// refRoutes gives the surface of each callback route of the vhost.
var refRoutes = map[string]string{"/phantom-reference-trap/cb": "path", "/ref/query": "query",
	"/ref/header": "header", "/ref/body": "body"}

// refSeed is the token seed of the tests. The source tree has no seed, so the
// tests add it to the files in memory.
var refSeed = bytes.Repeat([]byte{7}, 32)

// refTrap is a trap of the source tree.
type refTrap struct {
	ID, Slot, Surface string
	Template          string `json:"instruction_template"`
}

// refRun is a started sensor with the source tree of the reference bundle.
type refRun struct {
	*baitSensor
	traps []refTrap
	// clockHeld is true when the window of the manifest holds the loader
	// clock off the real clock. The tokens then look stale or future.
	clockHeld bool
}

// refTrust is a trust set with a test key of class reference and the key id of
// the manifest. The release trust set has no such key.
func refTrust() bundle.TrustSet {
	return bundle.TrustSet{{KeyID: refKeyID, PublicKey: pubOf(seedKey(goodSeed)), Class: bundle.ClassReference}}
}

// startReference packs the source tree in memory with the test seed. It signs
// the archive with the test key and starts a sensor on it. The manifest dates
// are fixed. So the loader clock is the real clock, held between `created`
// + 1 h and `expires` - 1 h.
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
	files = append(files, tarFile{"secrets/token.seed", refSeed})
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
	oldNew := newLoader
	t.Cleanup(func() { newLoader = oldNew })
	newLoader = func(s *os.Root, path string, ts bundle.TrustSet, k hpke.PrivateKey) *bundle.Loader {
		l := oldNew(s, path, ts, k)
		l.SetClock(func() time.Time {
			now, from, to := time.Now(), man.Created.Add(time.Hour), man.Expires.Add(-time.Hour)
			if now.Before(from) {
				return from
			}
			if now.After(to) {
				return to
			}
			return now
		}, time.Sleep)
		return l
	}
	arch := archiveOf(t, files...)
	seed := func(t *testing.T, p startParams) {
		putBundle(t, p.Root, p.BundlePath, arch, seedKey(goodSeed))
		// putBundle names the key t1. The manifest names the reference key.
		sig := filepath.Join(p.Root, strings.TrimSuffix(p.BundlePath, ".cbnd")+".sig")
		b, err := os.ReadFile(sig)
		mustOK(t, err)
		mustOK(t, os.WriteFile(sig, bytes.Replace(b, []byte("t1 "), []byte(refKeyID+" "), 1), 0o600))
	}
	s := startBait(t, baitOpt{name: refHost, trust: refTrust, seed: seed})
	s.arch = arch
	now := time.Now()
	return &refRun{s, traps, now.Before(man.Created.Add(time.Hour)) || now.After(man.Expires.Add(-time.Hour))}
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

// tokensOf gives the token text of each trap of the slots, by trap id. texts
// has the text of each slot. A trap with no token in its slot fails the test.
func (r *refRun) tokensOf(t *testing.T, texts map[string]string, slots []string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, tr := range r.traps {
		if !slices.Contains(slots, tr.Slot) {
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

// allTokens gets the page for "/" and the 4 slots out of it for the client
// address ip. It gives the token text of each trap, by trap id, and the page.
func (r *refRun) allTokens(t *testing.T, ip net.IP) (map[string]string, baitResp) {
	t.Helper()
	page := fetchFrom(t, r.https, refHost, "/", "", ip)
	if page.status != 200 {
		t.Fatalf("client %v: status %d; want 200", ip, page.status)
	}
	texts := slotTexts(t, page.body)
	maps.Copy(texts, r.outSlotTexts(t, ip, page))
	return r.tokensOf(t, texts, refSlots), page
}

// TestTI02_ReferenceVhostServesEachSlot checks T-I-02 on the source tree of
// the reference bundle (FR-03, SEC-42). The tree is packed in memory. A test
// key of class reference signs it. The vhost has each of the 12 slots. The
// page has 8 of them. The robots.txt file, the JSON file, the 404 page and the
// X-Note header of the page have the other 4. Each end tag of the HTML closes
// the element that is open last. Each token verifies to the trap of its slot.
// Two sessions get their own tokens. A host that is not Linux and has no
// 127.0.0.2 skips the test.
func TestTI02_ReferenceVhostServesEachSlot(t *testing.T) {
	r := startReference(t)
	r.needSecondAddr(t)
	var slots, ids []string
	for _, tr := range r.traps {
		slots, ids = append(slots, tr.Slot), append(ids, tr.ID)
	}
	if !slices.Equal(slices.Sorted(slices.Values(slots)), slices.Sorted(slices.Values(refSlots))) {
		t.Fatalf("trap slots %q; want one trap for each of %q", slots, refSlots)
	}
	ks, err := token.NewKeySet(refSeed, sha256.Sum256(r.arch), ids, true)
	mustOK(t, err)
	seen := map[string]bool{}
	ips := []string{"127.0.0.1", "127.0.0.2"}
	for i, ip := range ips {
		toks, page := r.allTokens(t, net.ParseIP(ip))
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
	if len(seen) != 2*len(r.traps) {
		t.Errorf("%d tokens in the two pages; want %d", len(seen), 2*len(r.traps))
	}
	r.stop(t)
	got := r.sessionsOn(t, refHost, "/")
	want := []string{r.keyedIDOf(t, ips[0]), r.keyedIDOf(t, ips[1])}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) || want[0] == want[1] {
		t.Errorf("session ids of the two rows %q; want the two keyed ids %q", got, want)
	}
}

// refRouteOf gives the callback route that the text of a trap names.
func refRouteOf(t *testing.T, tr refTrap) string {
	t.Helper()
	var named []string
	for route := range refRoutes {
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
// the callback route. It uses its own connection from the client address ip.
func refCallbackRequest(t *testing.T, r *refRun, ip net.IP, route, tok, cookie string) {
	t.Helper()
	method, target, body, hdr := http.MethodGet, route, "", http.Header{"Cookie": {cookie}}
	switch refRoutes[route] {
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
	req.Host, req.Header = refHost, hdr
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
// that the text of the trap names. The route gives a callback row. The surface
// of the row is the surface of the trap. The row has the trap of the token, the
// vhost and reference_seed: true.
func TestTI04_ReferenceCallbackRoutes(t *testing.T) {
	r := startReference(t)
	r.needSecondAddr(t)
	db := readStore(t, r.baitSensor)
	toks, _ := r.allTokens(t, nil)
	var mints int
	pollRow(t, db, "SELECT count(*) FROM mint WHERE session_id = ? HAVING count(*) > 0", []any{r.keyedID(t)}, &mints)
	cookie, _ := r.cookie(t)
	for i, tr := range r.traps {
		parsed, ok := token.Parse(toks[tr.ID])
		if !ok {
			t.Fatalf("trap %s: text %q is not a token", tr.ID, toks[tr.ID])
		}
		route := refRouteOf(t, tr)
		// The engine caps the callback events of one client address at 10
		// in a minute. So the traps use 2 addresses.
		ip := []net.IP{net.IPv4(127, 0, 0, 1), secondAddr}[i%2]
		refCallbackRequest(t, r, ip, route, toks[tr.ID], cookie)
		var got, trap, vhost, detail string
		pollRow(t, db, "SELECT surface, trap_id, vhost, detail FROM event WHERE kind = 'callback' AND token_id = ?",
			[]any{token.ID(parsed)}, &got, &trap, &vhost, &detail)
		var d map[string]any
		mustOK(t, json.Unmarshal([]byte(detail), &d))
		// With the real clock in the window, the token is not stale or future.
		for _, k := range []string{"stale", "future"} {
			if _, ok := d[k]; ok && !r.clockHeld {
				t.Errorf("trap %s: detail %s has %s", tr.ID, detail, k)
			}
		}
		if got != tr.Surface || trap != tr.ID || vhost != refHost || d["reference_seed"] != true {
			t.Errorf("trap %s at %s: row surface %q, trap %q, vhost %q, detail %s; want %q, %q, %q and reference_seed true",
				tr.ID, route, got, trap, vhost, detail, tr.Surface, tr.ID, refHost)
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
