package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/html"

	"github.com/cybagard/cyba-phantom/internal/config"
	"github.com/cybagard/cyba-phantom/internal/event"
	"github.com/cybagard/cyba-phantom/internal/listener"
	"github.com/cybagard/cyba-phantom/internal/session"
	"github.com/cybagard/cyba-phantom/internal/store"
	"github.com/cybagard/cyba-phantom/internal/token"
)

// noVhost is a decoy name for which the test bundle has no vhost.
const noVhost = "novhost.host.zz"

// baitFiles are the files of the test bundle. It has one vhost for decoyName.
// The vhost has a template route with a trap in a hidden paragraph. It also has
// a not_found template. The text is short and synthetic.
func baitFiles() []tarFile {
	dir := "vhosts/" + decoyName + "/"
	routes := `{"routes":[{"path":"/page","template":"` + dir + `page.tmpl","type":"text/html; charset=utf-8"}],` +
		`"not_found":"` + dir + `gone.tmpl"}`
	traps := `[{"id":"a","slot":"hidden-p","surface":"path","visibility":"human-visible","instruction_template":"bait note"}]`
	return referenceFiles(
		tarFile{"traps/traps.json", []byte(traps)},
		tarFile{dir + "routes.json", []byte(routes)},
		tarFile{dir + "page.tmpl", []byte(`<!doctype html><html><body><h1>page</h1><p hidden>{{index .Trap "a"}}</p></body></html>`)},
		tarFile{dir + "gone.tmpl", []byte(`<!doctype html><html><body><p>gone</p></body></html>`)})
}

// baitOpt sets the start of a sensor for the bait tests.
type baitOpt struct {
	cookie string    // privacy.session_cookie, or "" for the default
	bundle bool      // put the signed test bundle in the state directory
	refuse bool      // the store does not open, so no load runs
	files  []tarFile // the files of that bundle, or nil for baitFiles
}

// baitSensor is a started sensor with its two addresses (with scheme). dk is
// the day key holder that the writer got. probe is the response to a request
// that newServer served to its handler, before it returned. arch is the archive
// of the bundle in the state directory.
type baitSensor struct {
	*running
	arch         []byte
	p            startParams
	https, plain string
	dk           *session.DayKey
	probe        baitResp
}

// startBait starts serveWith with a cached certificate for decoyName and the
// test trust set.
func startBait(t *testing.T, o baitOpt) *baitSensor {
	t.Helper()
	httpsLn, plainLn, ca := openListeners(t)
	env := []string{"CKPT_TOKEN=" + strings.Repeat("t", 32), "PHANTOM_LISTEN_HTTPS=" + httpsLn.Addr().String(),
		"PHANTOM_LISTEN_HTTP=" + plainLn.Addr().String(), "PHANTOM_ACME_CA=https://" + ca + "/directory"}
	if o.cookie != "" {
		env = append(env, "PHANTOM_PRIVACY_SESSION_COOKIE="+o.cookie)
	}
	// noVhost is a second decoy name. The bundle has no vhost for it.
	body := strings.Replace(validBody(t), "names: [decoy.host.zz]", "names: [decoy.host.zz, "+noVhost+"]", 1)
	cfg, err := config.Load(writeFile(t, body), env)
	mustOK(t, err)
	s := &baitSensor{p: tempState(t, cfg), https: "https://" + httpsLn.Addr().String(), plain: "http://" + plainLn.Addr().String()}
	caURL, _ := cfg.Get("acme.ca")
	seedCache(t, s.p, caURL.Str)
	if o.bundle {
		if o.files == nil {
			o.files = baitFiles()
		}
		s.arch = archiveOf(t, o.files...)
		putBundle(t, s.p.Root, s.p.BundlePath, s.arch, seedKey(goodSeed))
	}
	oldTrust := bundleTrust
	t.Cleanup(func() { bundleTrust = oldTrust })
	bundleTrust = testTrust
	d := realDeps
	d.newWriter = func(db *sql.DB, q *event.Queue, bp bool, lg *slog.Logger, r store.Recovery, dk *session.DayKey) *store.Writer {
		s.dk = dk // read by the test after the start line
		return realDeps.newWriter(db, q, bp, lg, r, dk)
	}
	if o.refuse {
		d.openStore = func(*os.Root, string, store.Options) (*sql.DB, error) { return nil, errors.New("test") }
	}
	oldNew := newServer
	t.Cleanup(func() { newServer = oldNew })
	newServer = func(c listener.Config, h http.Handler) (*listener.Server, error) {
		// No Serve call has run yet. If the start code calls the switch
		// later, this response has a Set-Cookie. The test can miss a call
		// from another goroutine.
		req := httptest.NewRequest(http.MethodGet, "/page", nil)
		req.Host, req.RemoteAddr = decoyName, "127.0.0.1:4000"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		hd := rec.Result().Header
		s.probe = baitResp{rec.Code, rec.Body.String(), hd.Values("Set-Cookie"), hd}
		return oldNew(c, h)
	}
	s.running = launchServe(t, cfg, s.p, d)
	s.waitStarted(t)
	return s
}

// stop stops serveWith, which needs exit 0.
func (s *baitSensor) stop(t *testing.T) {
	t.Helper()
	s.cancel()
	<-s.done
	if s.code != 0 {
		t.Errorf("exit %d, stderr %q", s.code, s.err.String())
	}
}

// cookie returns a session cookie that the key of the writer accepts, and the
// session id that the cookie holds.
func (s *baitSensor) cookie(t *testing.T) (header, id string) {
	t.Helper()
	k := s.dk.At(time.Now())
	v := k.CookieValue([16]byte{7})
	id, ok := k.CheckCookie(v)
	if !ok {
		t.Fatal("the key of the writer does not accept its own cookie")
	}
	return "sid=" + v, id
}

// keyedID returns the keyed session id of the loopback client under the key of
// the writer.
func (s *baitSensor) keyedID(t *testing.T) string { return s.keyedIDOf(t, "127.0.0.1") }

// keyedIDOf returns the keyed session id of the client address ip under the key
// of the writer.
func (s *baitSensor) keyedIDOf(t *testing.T, ip string) string {
	t.Helper()
	id := s.dk.At(time.Now()).SessionID(ip, "")
	if id == nil {
		t.Fatalf("no keyed id for %s", ip)
	}
	return *id
}

// sessionOf returns the session id of the one stored request row for path. The
// sensor must be stopped.
func (s *baitSensor) sessionOf(t *testing.T, path string) string {
	t.Helper()
	ids := s.sessionsOf(t, path)
	if len(ids) != 1 {
		t.Fatalf("request rows for %s: %q; want one", path, ids)
	}
	return ids[0]
}

// sessionsOf returns the session ids of the stored request rows for path. The
// sensor must be stopped.
func (s *baitSensor) sessionsOf(t *testing.T, path string) []string {
	t.Helper()
	root, err := os.OpenRoot(s.p.Root)
	mustOK(t, err)
	defer root.Close()
	db, err := store.Open(root, s.p.StorePath, store.Options{Reserved: s.p.Reserved})
	mustOK(t, err)
	defer db.Close()
	rows, err := db.Query("SELECT COALESCE(session_id, '') FROM event WHERE kind = 'request' AND vhost = ? AND path = ?", decoyName, path)
	mustOK(t, err)
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		mustOK(t, rows.Scan(&id))
		ids = append(ids, id)
	}
	return ids
}

// baitResp is what a test needs of a response.
type baitResp struct {
	status  int
	body    string
	cookies []string // the Set-Cookie headers
	header  http.Header
}

// fetch makes a GET for path at base with the Host header host. TLS uses the
// name decoyName and no check of the certificate. It follows no redirect. It
// reports an error with Errorf, so a goroutine can call it.
func fetch(t *testing.T, base, host, path, cookie string) baitResp {
	t.Helper()
	return fetchFrom(t, base, host, path, cookie, nil)
}

// fetchFrom is fetch with the local address ip for the connection. With a nil
// ip, the system chooses the address.
func fetchFrom(t *testing.T, base, host, path, cookie string, ip net.IP) baitResp {
	t.Helper()
	tr := &http.Transport{DisableKeepAlives: true, TLSClientConfig: &tls.Config{ServerName: decoyName, InsecureSkipVerify: true}}
	if ip != nil {
		d := net.Dialer{LocalAddr: &net.TCPAddr{IP: ip}}
		tr.DialContext = d.DialContext
	}
	defer tr.CloseIdleConnections()
	cl := &http.Client{Transport: tr, Timeout: netWait, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, base+path, nil)
	req.Host = host
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	resp, err := cl.Do(req)
	if err != nil {
		t.Errorf("GET %s%s: %v", base, path, err)
		return baitResp{}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return baitResp{resp.StatusCode, string(body), resp.Header.Values("Set-Cookie"), resp.Header}
}

// elemOf returns the first element name of the page in body.
func elemOf(t *testing.T, body, name string) *html.Node {
	t.Helper()
	doc, err := html.Parse(strings.NewReader(body))
	mustOK(t, err)
	var find func(*html.Node) *html.Node
	find = func(n *html.Node) *html.Node {
		if n.Type == html.ElementNode && n.Data == name {
			return n
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			if f := find(c); f != nil {
				return f
			}
		}
		return nil
	}
	n := find(doc)
	if n == nil {
		t.Fatalf("no %s element in %q", name, body)
	}
	return n
}

// firstP returns the first p element of the page in body.
func firstP(t *testing.T, body string) *html.Node {
	t.Helper()
	p := elemOf(t, body, "p")
	if p.FirstChild == nil {
		t.Fatalf("no text in the p element of %q", body)
	}
	return p
}

// twoFiles are the files of a test bundle with one route and three trap slots.
// The slots are the text of a hidden p, the content of a meta element, and the
// header X-Note.
func twoFiles() []tarFile {
	dir := "vhosts/" + decoyName + "/"
	routes := `{"routes":[{"path":"/two","template":"` + dir + `two.tmpl","type":"text/html; charset=utf-8",` +
		`"headers":[{"name":"X-Note","trap":"h"}]}]}`
	trap := func(id, slot string) string {
		return `{"id":"` + id + `","slot":"` + slot + `","surface":"path","visibility":"human-visible","instruction_template":"{{.Token}}"}`
	}
	page := `<!doctype html><html><head><meta name="description" content="{{index .Trap "m"}}"></head>` +
		`<body><p hidden>{{index .Trap "p"}}</p></body></html>`
	return referenceFiles(
		tarFile{"traps/traps.json", []byte("[" + trap("p", "hidden-p") + "," + trap("m", "meta-description") + "," + trap("h", "header") + "]")},
		tarFile{dir + "routes.json", []byte(routes)},
		tarFile{dir + "two.tmpl", []byte(page)})
}

// TestTI02_TwoSessionsGetOwnTokens fetches one page from two clients with no
// cookie, from 127.0.0.1 and from 127.0.0.2 (FR-03). Each trap slot of the
// page is there and the HTML parses. Each token text verifies to the trap of
// its slot. No token repeats in or between the responses. The two request rows
// have the keyed ids of the two client addresses. A host with no 127.0.0.2
// skips the test.
func TestTI02_TwoSessionsGetOwnTokens(t *testing.T) {
	s := startBait(t, baitOpt{bundle: true, files: twoFiles()})
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.2")}, Timeout: netWait}
	c, err := d.DialContext(t.Context(), "tcp", strings.TrimPrefix(s.https, "https://"))
	if errors.Is(err, syscall.EADDRNOTAVAIL) {
		t.Skipf("no client address 127.0.0.2 on this host: %v", err)
	}
	mustOK(t, err)
	c.Close()
	ids := []string{"p", "m", "h"}
	ks, err := token.NewKeySet(bytes.Repeat([]byte{9}, 32), sha256.Sum256(s.arch), ids, true)
	mustOK(t, err)
	seen := map[string]bool{}
	ips := []string{"127.0.0.1", "127.0.0.2"}
	for i, ip := range ips {
		r := fetchFrom(t, s.https, decoyName, "/two", "", net.ParseIP(ip))
		if r.status != 200 {
			t.Fatalf("client %s: status %d; want 200", ip, r.status)
		}
		meta := ""
		for _, a := range elemOf(t, r.body, "meta").Attr {
			if a.Key == "content" {
				meta = a.Val
			}
		}
		texts := []string{firstP(t, r.body).FirstChild.Data, meta, r.header.Get("X-Note")}
		for j, text := range texts {
			tok, ok := token.Parse(text)
			if res := token.Verify([]*token.KeySet{ks}, tok); !ok || !res.OK || res.Trap != ids[j] {
				t.Errorf("client %d, slot %s: text %q gives %+v; want a token of trap %s", i, ids[j], text, res, ids[j])
			}
			if seen[text] {
				t.Errorf("client %d, slot %s: text %q repeats", i, ids[j], text)
			}
			seen[text] = true
		}
	}
	s.stop(t)
	got := s.sessionsOf(t, "/two")
	want := []string{s.keyedIDOf(t, ips[0]), s.keyedIDOf(t, ips[1])}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) || want[0] == want[1] {
		t.Errorf("session ids of the two rows %q; want the two keyed ids %q", got, want)
	}
}

// TestTI02_StartServesBait checks the decoy listener of a started sensor. A
// valid bundle gives its template route with the trap text in a hidden
// paragraph. It gives the not_found page with status 404. A Host with no vhost
// gets the fixed 404 page. With no bundle file, the hello page stays. With no
// load at all (the store does not open), the hello page stays and nothing
// panics.
func TestTI02_StartServesBait(t *testing.T) {
	s := startBait(t, baitOpt{bundle: true})
	page := fetch(t, s.https, decoyName, "/page", "")
	hidden := false
	for _, a := range firstP(t, page.body).Attr {
		hidden = hidden || a.Key == "hidden"
	}
	if text := firstP(t, page.body).FirstChild.Data; page.status != 200 || !hidden || text != "bait note" {
		t.Errorf("/page: status %d, hidden %v, text %q; want 200, true, %q", page.status, hidden, text, "bait note")
	}
	gone := fetch(t, s.https, decoyName, "/nothing", "")
	if text := firstP(t, gone.body).FirstChild.Data; gone.status != 404 || text != "gone" {
		t.Errorf("/nothing: status %d, text %q; want 404 and %q", gone.status, text, "gone")
	}
	if r := fetch(t, s.https, noVhost, "/page", ""); r.status != 404 || r.body != "not found\n" {
		t.Errorf("Host with no vhost: status %d, body %q; want the fixed 404 page", r.status, r.body)
	}
	s.stop(t)
	for name, o := range map[string]baitOpt{"no bundle file": {}, "no load ran": {refuse: true}} {
		t.Run(name, func(t *testing.T) {
			s := startBait(t, o)
			if r := fetch(t, s.https, decoyName, "/page", ""); r.status != 200 || r.body != "hello\n" {
				t.Errorf("status %d, body %q; want the hello page", r.status, r.body)
			}
			s.stop(t)
		})
	}
}

// TestTU24_SessionCookieSwitch starts a sensor with privacy.session_cookie
// false and with true (SEC-35). newServer serves one request to its handler
// before it returns. With false, that response and each later bait response
// have no Set-Cookie. So the start code sets the switch before newServer. The
// test does not always find a call from another goroutine. A valid cookie gets
// the keyed id of the client address. With true, the first response has one
// cookie, and the valid cookie keeps its id. A request with no cookie gets a
// cookie.
func TestTU24_SessionCookieSwitch(t *testing.T) {
	for _, c := range []struct {
		value string
		off   bool
	}{{"false", true}, {"true", false}} {
		t.Run(c.value, func(t *testing.T) {
			s := startBait(t, baitOpt{cookie: c.value, bundle: true})
			header, cookieID := s.cookie(t)
			keyed := s.keyedID(t)
			valid := fetch(t, s.https, decoyName, "/c-valid", header)
			none := fetch(t, s.https, decoyName, "/c-none", "")
			s.stop(t)
			if r := s.probe; r.status != 200 || (len(r.cookies) == 0) != c.off {
				t.Errorf("response before Serve: status %d, Set-Cookie %q; want 200 and a cookie only with true", r.status, r.cookies)
			}
			if valid.status != 404 || len(valid.cookies) != 0 {
				t.Errorf("valid cookie: status %d, Set-Cookie %q; want 404 and none", valid.status, valid.cookies)
			}
			if (len(none.cookies) == 0) != c.off || (!c.off && !strings.HasPrefix(none.cookies[0], "sid=")) {
				t.Errorf("no cookie: Set-Cookie %q; want one only with true", none.cookies)
			}
			want := cookieID
			if c.off {
				want = keyed
			}
			if cookieID == keyed {
				t.Fatal("the cookie id and the keyed id are the same")
			}
			if got := s.sessionOf(t, "/c-valid"); got != want {
				t.Errorf("valid cookie row has session %q, want %q", got, want)
			}
			if got := s.sessionOf(t, "/c-none"); got != keyed {
				t.Errorf("no cookie row has session %q, want the keyed id %q", got, keyed)
			}
		})
	}
}

// TestTU24_BaitSharesWriterDayKey checks that the bait handler uses the day key
// holder of the writer (SEC-35). A cookie that the writer key made is valid,
// and the row has its id. A cookie that is not valid gives the keyed id under
// the key of the writer. A handler with a holder of its own fails both rows.
func TestTU24_BaitSharesWriterDayKey(t *testing.T) {
	s := startBait(t, baitOpt{bundle: true})
	header, cookieID := s.cookie(t)
	keyed := s.keyedID(t)
	fetch(t, s.https, decoyName, "/k-valid", header)
	fetch(t, s.https, decoyName, "/k-bad", "sid=bad")
	s.stop(t)
	if got := s.sessionOf(t, "/k-valid"); got != cookieID {
		t.Errorf("valid cookie row has session %q, want the cookie id %q", got, cookieID)
	}
	if got := s.sessionOf(t, "/k-bad"); got != keyed {
		t.Errorf("bad cookie row has session %q, want the keyed id %q", got, keyed)
	}
}

// TestTU24_FixedPagesSetNoCookie checks three pages (SEC-35). They are the :80
// redirect, the fixed 404 page of a running bundle, and the hello page with no
// bundle. Each one has no Set-Cookie. This holds also for a request with a
// valid cookie.
func TestTU24_FixedPagesSetNoCookie(t *testing.T) {
	for _, c := range []struct {
		name       string
		bundle     bool
		plain      bool
		host, path string
		status     int
	}{
		{"redirect", true, true, decoyName, "/", http.StatusPermanentRedirect},
		{"fixed 404 page", true, false, noVhost, "/page", http.StatusNotFound},
		{"hello page", false, false, decoyName, "/page", http.StatusOK},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := startBait(t, baitOpt{bundle: c.bundle})
			header, _ := s.cookie(t)
			base := s.https
			if c.plain {
				base = s.plain
			}
			for _, cookie := range []string{"", header} {
				if r := fetch(t, base, c.host, c.path, cookie); r.status != c.status || len(r.cookies) != 0 {
					t.Errorf("cookie %q: status %d, Set-Cookie %q; want %d and none", cookie, r.status, r.cookies, c.status)
				}
			}
			s.stop(t)
		})
	}
}
