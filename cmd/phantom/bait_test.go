package main

import (
	"crypto/tls"
	"database/sql"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/html"

	"github.com/cybagard/cyba-phantom/internal/config"
	"github.com/cybagard/cyba-phantom/internal/event"
	"github.com/cybagard/cyba-phantom/internal/session"
	"github.com/cybagard/cyba-phantom/internal/store"
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
	cookie string // privacy.session_cookie, or "" for the default
	bundle bool   // put the signed test bundle in the state directory
	refuse bool   // the store does not open, so no load runs
	burst  int    // requests for /page, sent before the start line
}

// baitSensor is a started sensor with its two addresses (with scheme). dk is
// the day key holder that the writer got. burst holds the burst responses.
type baitSensor struct {
	*running
	p            startParams
	https, plain string
	dk           *session.DayKey
	burst        []baitResp
}

// startBait starts serveWith with a cached certificate for decoyName and the
// test trust set. The burst requests go out before the start line. They wait in
// the socket until the first Serve call. So they run at once with the start.
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
		putBundle(t, s.p.Root, s.p.BundlePath, archiveOf(t, baitFiles()...), seedKey(goodSeed))
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
	s.running = launchServe(t, cfg, s.p, d)
	var wg sync.WaitGroup
	s.burst = make([]baitResp, o.burst)
	for i := range s.burst {
		wg.Go(func() { s.burst[i] = fetch(t, s.https, decoyName, "/page", "") })
	}
	s.waitStarted(t)
	wg.Wait()
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
func (s *baitSensor) keyedID(t *testing.T) string {
	t.Helper()
	id := s.dk.At(time.Now()).SessionID("127.0.0.1", "")
	if id == nil {
		t.Fatal("no keyed id for the loopback address")
	}
	return *id
}

// sessionOf returns the session id of the one stored request row for path. The
// sensor must be stopped.
func (s *baitSensor) sessionOf(t *testing.T, path string) string {
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
	if len(ids) != 1 {
		t.Fatalf("request rows for %s: %q; want one", path, ids)
	}
	return ids[0]
}

// baitResp is what a test needs of a response.
type baitResp struct {
	status  int
	body    string
	cookies []string // the Set-Cookie headers
}

// fetch makes a GET for path at base with the Host header host. TLS uses the
// name decoyName and no check of the certificate. It follows no redirect. It
// reports an error with Errorf, so a goroutine can call it.
func fetch(t *testing.T, base, host, path, cookie string) baitResp {
	t.Helper()
	tr := &http.Transport{DisableKeepAlives: true, TLSClientConfig: &tls.Config{ServerName: decoyName, InsecureSkipVerify: true}}
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
	return baitResp{resp.StatusCode, string(body), resp.Header.Values("Set-Cookie")}
}

// firstP returns the first p element of the page in body.
func firstP(t *testing.T, body string) *html.Node {
	t.Helper()
	doc, err := html.Parse(strings.NewReader(body))
	mustOK(t, err)
	var find func(*html.Node) *html.Node
	find = func(n *html.Node) *html.Node {
		if n.Type == html.ElementNode && n.Data == "p" {
			return n
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			if f := find(c); f != nil {
				return f
			}
		}
		return nil
	}
	p := find(doc)
	if p == nil || p.FirstChild == nil {
		t.Fatalf("no p element with text in %q", body)
	}
	return p
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
// false and with true (SEC-35). The burst runs at the start. So -race sees a
// call of the switch after the first Serve call. With false, no bait response
// has Set-Cookie. A valid cookie gets the keyed id of the client address. With
// true, the valid cookie keeps its id. A request with no cookie gets a cookie.
func TestTU24_SessionCookieSwitch(t *testing.T) {
	for _, c := range []struct {
		value string
		off   bool
	}{{"false", true}, {"true", false}} {
		t.Run(c.value, func(t *testing.T) {
			s := startBait(t, baitOpt{cookie: c.value, bundle: true, burst: 8})
			header, cookieID := s.cookie(t)
			keyed := s.keyedID(t)
			valid := fetch(t, s.https, decoyName, "/c-valid", header)
			none := fetch(t, s.https, decoyName, "/c-none", "")
			s.stop(t)
			for i, r := range s.burst {
				if r.status != 200 || (len(r.cookies) == 0) != c.off {
					t.Errorf("burst %d: status %d, Set-Cookie %q; want 200 and a cookie only with true", i, r.status, r.cookies)
				}
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
