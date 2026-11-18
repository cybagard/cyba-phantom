package main

import (
	"bytes"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
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

// refSlots are the 8 in-page slots of the vhost. Each one has one trap.
var refSlots = []string{"hidden-p", "html-comment", "meta-description", "alt", "aria-label",
	"nofollow-link", "json-ld", "noscript"}

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
}

// refTrust is a trust set with a test key of class reference and the key id of
// the manifest. The release trust set has no such key.
func refTrust() bundle.TrustSet {
	return bundle.TrustSet{{KeyID: refKeyID, PublicKey: pubOf(seedKey(goodSeed)), Class: bundle.ClassReference}}
}

// startReference packs the source tree in memory with the test seed. It signs
// the archive with the test key and starts a sensor on it. The manifest dates
// are fixed. So the loader clock starts one hour after `created` and runs on.
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
	var man struct{ Created time.Time }
	var traps []refTrap
	for _, f := range files {
		switch f.name {
		case "manifest.json":
			mustOK(t, json.Unmarshal(f.data, &man))
		case "traps/traps.json":
			mustOK(t, json.Unmarshal(f.data, &traps))
		}
	}
	begin := time.Now()
	oldNew := newLoader
	t.Cleanup(func() { newLoader = oldNew })
	newLoader = func(s *os.Root, path string, ts bundle.TrustSet, k hpke.PrivateKey) *bundle.Loader {
		l := oldNew(s, path, ts, k)
		l.SetClock(func() time.Time { return man.Created.Add(time.Hour + time.Since(begin)) }, time.Sleep)
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
	return &refRun{s, traps}
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

// pageTokensOf gives the token text of each trap on the page, by trap id. A
// trap with no token in its slot fails the test.
func (r *refRun) pageTokensOf(t *testing.T, page string) map[string]string {
	t.Helper()
	slots, out := slotTexts(t, page), map[string]string{}
	for _, tr := range r.traps {
		render, ok := slots[tr.Slot]
		if !ok {
			t.Errorf("trap %s: the page has no %s slot", tr.ID, tr.Slot)
			continue
		}
		if out[tr.ID], ok = tokenIn(tr.Template, render); !ok {
			t.Errorf("trap %s: slot %s has text %q; want the template %q with a token", tr.ID, tr.Slot, render, tr.Template)
		}
	}
	return out
}

// TestTI02_ReferenceVhostServesEachSlot checks T-I-02 on the source tree of
// the reference bundle (FR-03, SEC-42). The tree is packed in memory. A test
// key of class reference signs it. The page of the vhost has each declared
// in-page slot, and the HTML is valid. Each token verifies to the trap of its
// slot. Two sessions get their own tokens. A host that is not Linux and has no
// 127.0.0.2 skips the test.
func TestTI02_ReferenceVhostServesEachSlot(t *testing.T) {
	r := startReference(t)
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.2")}, Timeout: netWait}
	c, err := d.DialContext(t.Context(), "tcp", strings.TrimPrefix(r.https, "https://"))
	if runtime.GOOS != "linux" && errors.Is(err, syscall.EADDRNOTAVAIL) {
		t.Skipf("no client address 127.0.0.2 on %s: %v", runtime.GOOS, err)
	}
	mustOK(t, err)
	c.Close()
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
		page := fetchFrom(t, r.https, refHost, "/", "", net.ParseIP(ip))
		if page.status != 200 {
			t.Fatalf("client %s: status %d; want 200", ip, page.status)
		}
		checkTags(t, page.body)
		for id, text := range r.pageTokensOf(t, page.body) {
			if text == "" { // pageTokensOf has reported it
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

// refCallbackRequest sends one callback request with the token text tok to the
// route of the surface, on its own connection.
func refCallbackRequest(t *testing.T, r *refRun, surface, tok, cookie string) {
	t.Helper()
	method, target, body, hdr := http.MethodGet, "", "", http.Header{"Cookie": {cookie}}
	switch surface {
	case "path":
		target = "/phantom-reference-trap/cb/" + tok
	case "query":
		target = "/ref/query?part=" + tok
	case "header":
		target = "/ref/header"
		hdr.Set("X-Ref", tok)
	case "body":
		method, target, body = http.MethodPost, "/ref/body", `{"link":"`+tok+`"}`
	}
	req, err := http.NewRequestWithContext(t.Context(), method, r.https+target, strings.NewReader(body))
	mustOK(t, err)
	req.Host, req.Header = refHost, hdr
	resp, err := plainClient().Do(req)
	mustOK(t, err)
	defer resp.Body.Close()
	_, err = io.Copy(io.Discard, resp.Body)
	mustOK(t, err)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("callback at the %s route: status %d; want 204", surface, resp.StatusCode)
	}
}

// TestTI04_ReferenceCallbackRoutes checks T-I-04 on the reference bundle
// (FR-04, SEC-37, SEC-42). A token of the page goes to each of the 4 callback
// routes. The route gives a callback row of its surface. The row has the trap
// of the token, the vhost and reference_seed: true.
func TestTI04_ReferenceCallbackRoutes(t *testing.T) {
	r := startReference(t)
	db := readStore(t, r.baitSensor)
	page := fetch(t, r.https, refHost, "/", "")
	if page.status != 200 {
		t.Fatalf("page: status %d; want 200", page.status)
	}
	toks := r.pageTokensOf(t, page.body)
	var mints int
	pollRow(t, db, "SELECT count(*) FROM mint WHERE session_id = ? HAVING count(*) > 0", []any{r.keyedID(t)}, &mints)
	cookie, _ := r.cookie(t)
	for _, surface := range []string{"path", "query", "header", "body"} {
		i := slices.IndexFunc(r.traps, func(tr refTrap) bool { return tr.Surface == surface })
		if i < 0 {
			t.Fatalf("no trap with the surface %s", surface)
		}
		tr := r.traps[i]
		parsed, ok := token.Parse(toks[tr.ID])
		if !ok {
			t.Fatalf("trap %s: text %q is not a token", tr.ID, toks[tr.ID])
		}
		refCallbackRequest(t, r, surface, toks[tr.ID], cookie)
		var got, trap, vhost, detail string
		pollRow(t, db, "SELECT surface, trap_id, vhost, detail FROM event WHERE kind = 'callback' AND token_id = ?",
			[]any{token.ID(parsed)}, &got, &trap, &vhost, &detail)
		var d map[string]any
		mustOK(t, json.Unmarshal([]byte(detail), &d))
		if got != surface || trap != tr.ID || vhost != refHost || d["reference_seed"] != true {
			t.Errorf("%s route: row surface %q, trap %q, vhost %q, detail %s; want %q, %q, %q and reference_seed true",
				surface, got, trap, vhost, detail, surface, tr.ID, refHost)
		}
	}
	r.stop(t)
}
