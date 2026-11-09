package main

import (
	"database/sql"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cybagard/cyba-phantom/internal/event"
	"github.com/cybagard/cyba-phantom/internal/store"
	"github.com/cybagard/cyba-phantom/internal/token"
)

const (
	// cbRoute is the callback route of the test bundle. It has the four
	// positions: a path segment, a query part, a header and a body member.
	cbRoute  = "/api/cb"
	cbHeader = "X-Request-Token"
	// cbRowWait is the bound of FR-04 between a response and its callback row.
	cbRowWait = 250 * time.Millisecond
)

// callbackFiles are the files of a test bundle with a page and a callback
// route. The page has four traps, each in its own slot. So it holds four
// tokens.
func callbackFiles() []tarFile {
	dir := "vhosts/" + decoyName + "/"
	routes := `{"routes":[{"path":"/slots","template":"` + dir + `slots.tmpl","type":"text/html; charset=utf-8",` +
		`"headers":[{"name":"X-Note","trap":"h"}]},` +
		`{"path":"` + cbRoute + `","callback":{"segment":true,"query":"ref","header":"` + cbHeader + `","body":"tok"}}]}`
	trap := func(id, slot string) string {
		return `{"id":"` + id + `","slot":"` + slot + `","surface":"path","visibility":"human-visible","instruction_template":"{{.Token}}"}`
	}
	traps := "[" + trap("p", "hidden-p") + "," + trap("m", "meta-description") + "," + trap("i", "alt") + "," + trap("h", "header") + "]"
	page := `<!doctype html><html><head><meta name="description" content="{{index .Trap "m"}}"></head>` +
		`<body><p hidden>{{index .Trap "p"}}</p><img src="/x.png" alt="{{index .Trap "i"}}"></body></html>`
	return referenceFiles(
		tarFile{"traps/traps.json", []byte(traps)},
		tarFile{dir + "routes.json", []byte(routes)},
		tarFile{dir + "slots.tmpl", []byte(page)})
}

// pageTokens returns the four token texts of a rendered page. The order is
// the order of the positions of the callback route: path, query, header, body.
func pageTokens(t *testing.T, r baitResp) [4]string {
	t.Helper()
	attr := func(n, key string) string {
		for _, a := range elemOf(t, r.body, n).Attr {
			if a.Key == key {
				return a.Val
			}
		}
		return ""
	}
	return [4]string{firstP(t, r.body).FirstChild.Data, attr("meta", "content"), attr("img", "alt"), r.header.Get("X-Note")}
}

// callbackAt sends one request to the callback route on its own connection. It
// returns the time at which the client has the whole response. The token goes
// to position pos. The cookie gives the callback a session of its own.
func callbackAt(t *testing.T, s *baitSensor, pos int, tok, cookie string) time.Time {
	t.Helper()
	var toks [4]string
	toks[pos] = tok
	return callbackWith(t, s, toks, cookie)
}

// callbackWith is callbackAt with a text for each position. An empty text
// leaves the position absent.
func callbackWith(t *testing.T, s *baitSensor, toks [4]string, cookie string) time.Time {
	t.Helper()
	method, target, body := http.MethodGet, cbRoute, ""
	hdr := http.Header{"Cookie": {cookie}}
	if toks[0] != "" {
		target += "/" + toks[0]
	}
	if toks[1] != "" {
		target += "?ref=" + toks[1]
	}
	if toks[2] != "" {
		hdr.Set(cbHeader, toks[2])
	}
	if toks[3] != "" {
		method, body = http.MethodPost, `{"tok":"`+toks[3]+`"}`
	}
	req, err := http.NewRequestWithContext(t.Context(), method, s.https+target, strings.NewReader(body))
	mustOK(t, err)
	req.Host, req.Header = decoyName, hdr
	resp, err := plainClient().Do(req)
	mustOK(t, err)
	defer resp.Body.Close()
	_, err = io.Copy(io.Discard, resp.Body)
	mustOK(t, err)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("callback request: status %d; want 204", resp.StatusCode)
	}
	return time.Now()
}

// plainClient returns a client that opens a new connection for each request
// and does not check the certificate.
func plainClient() *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.DisableKeepAlives = true
	tr.TLSClientConfig.InsecureSkipVerify, tr.TLSClientConfig.ServerName = true, decoyName
	return &http.Client{Transport: tr, Timeout: netWait}
}

// readStore opens the store of the running sensor for reads. The pool stays
// open until the sensor has stopped. A close of it drops the locks of the
// process on the database file.
func readStore(t *testing.T, s *baitSensor) *sql.DB {
	t.Helper()
	root, err := os.OpenRoot(s.p.Root)
	mustOK(t, err)
	db, err := store.Open(root, s.p.StorePath, store.Options{Reserved: s.p.Reserved})
	mustOK(t, err)
	t.Cleanup(func() {
		s.cancel()
		<-s.done
		db.Close()
		root.Close()
	})
	return db
}

// pollRow runs query until it returns a row, and scans the row into dest. It
// gives up after netWait. It returns the time at which the query found the row.
func pollRow(t *testing.T, db *sql.DB, query string, args []any, dest ...any) time.Time {
	t.Helper()
	for end := time.Now().Add(netWait); ; time.Sleep(time.Millisecond) {
		err := db.QueryRowContext(t.Context(), query, args...).Scan(dest...)
		if err == nil {
			return time.Now()
		}
		if err != sql.ErrNoRows || time.Now().After(end) {
			t.Fatalf("query %q: %v; no row in %v", query, err, netWait)
		}
	}
}

// TestTI04_CallbackRowsEndToEnd checks T-I-04 on a started sensor (FR-04,
// SEC-37). A page has four tokens. Each goes to one of the four positions of
// a callback route, on its own connection. The callback row of each token has
// the surface of its position and a leaf. It is in the store within 250 ms of
// the response, while the sensor runs. Each token has one token row with the
// session of the render and cb_count 1. The callbacks come with another
// session cookie, so a token row with the session of the callback fails.
func TestTI04_CallbackRowsEndToEnd(t *testing.T) {
	s := startBait(t, baitOpt{bundle: true, files: callbackFiles()})
	db := readStore(t, s)
	render := fetch(t, s.https, decoyName, "/slots", "")
	if render.status != 200 {
		t.Fatalf("page: status %d; want 200", render.status)
	}
	toks := pageTokens(t, render)
	renderSession := s.keyedID(t)
	cookie, cbSession := s.cookie(t)
	if cbSession == renderSession {
		t.Fatal("the callback session and the render session are the same")
	}
	// The token row needs the mint row of the render, so the callbacks wait
	// for the writer to store it.
	var mints int
	pollRow(t, db, "SELECT count(*) FROM mint WHERE session_id = ? HAVING count(*) > 0", []any{renderSession}, &mints)

	surfaces := [4]event.Surface{event.SurfacePath, event.SurfaceQuery, event.SurfaceHeader, event.SurfaceBody}
	traps := [4]string{"p", "m", "i", "h"}
	for pos, tok := range toks {
		parsed, ok := token.Parse(tok)
		if !ok {
			t.Fatalf("position %d: text %q is not a token", pos, tok)
		}
		id := token.ID(parsed)
		got := callbackAt(t, s, pos, tok, cookie)
		var surface, trap, session string
		var leaf int64
		found := pollRow(t, db, "SELECT surface, trap_id, session_id, leaf_index FROM event WHERE kind = 'callback' AND token_id = ?",
			[]any{id}, &surface, &trap, &session, &leaf)
		if d := found.Sub(got); d > cbRowWait {
			t.Errorf("position %d: callback row after %v; want at most %v", pos, d, cbRowWait)
		}
		if surface != string(surfaces[pos]) || trap != traps[pos] || session != cbSession || leaf < 0 {
			t.Errorf("position %d: callback row surface %q, trap %q, session %q, leaf %d; want %q, %q, %q and a leaf",
				pos, surface, trap, session, leaf, surfaces[pos], traps[pos], cbSession)
		}
		// The token row comes in the batch of the callback row.
		var tokSession, tokTrap string
		var count int64
		mustOK(t, db.QueryRowContext(t.Context(), "SELECT session_id, trap_id, cb_count FROM token WHERE token_id = ?", id).
			Scan(&tokSession, &tokTrap, &count))
		if tokSession != renderSession || tokTrap != traps[pos] || count != 1 {
			t.Errorf("position %d: token row session %q, trap %q, cb_count %d; want %q, %q, 1",
				pos, tokSession, tokTrap, count, renderSession, traps[pos])
		}
	}
	var rows int
	mustOK(t, db.QueryRowContext(t.Context(), "SELECT count(*) FROM token").Scan(&rows))
	if rows != 4 {
		t.Errorf("token rows: %d; want 4", rows)
	}
	s.stop(t)
}

// cbCount returns the number of callback rows and the cb_count of the token
// row for the token id. A missing token row gives -1.
func cbCount(t *testing.T, db *sql.DB, id string) (rows, count int64) {
	t.Helper()
	ctx := t.Context()
	mustOK(t, db.QueryRowContext(ctx, "SELECT count(*) FROM event WHERE kind = 'callback' AND token_id = ?", id).Scan(&rows))
	err := db.QueryRowContext(ctx, "SELECT cb_count FROM token WHERE token_id = ?", id).Scan(&count)
	if err == sql.ErrNoRows {
		return rows, -1
	}
	mustOK(t, err)
	return rows, count
}

// TestTI04_SameTokenOnceAndRepeatCapped checks two rules of T-I-04 on a
// started sensor (SEC-37). One token at all four positions of one request
// gives one callback row and cb_count 1. A repeat of a token that has its row
// gives no second row and no second count. The request row of the repeat holds
// the trap, the token id and the surface of the token. The callbacks come from
// one client address. The cap for one client key is 10 in 60 s. The test makes
// 3, so only the cap for each token can refuse.
func TestTI04_SameTokenOnceAndRepeatCapped(t *testing.T) {
	s := startBait(t, baitOpt{bundle: true, files: callbackFiles()})
	db := readStore(t, s)
	// Each render has new tokens. Each render makes one mint row.
	first := pageTokens(t, fetch(t, s.https, decoyName, "/slots", ""))
	second := pageTokens(t, fetch(t, s.https, decoyName, "/slots", ""))
	renderSession := s.keyedID(t)
	cookie, _ := s.cookie(t)
	var mints int
	pollRow(t, db, "SELECT count(*) FROM mint WHERE session_id = ? HAVING count(*) >= 2", []any{renderSession}, &mints)
	idOf := func(text string) string {
		tok, ok := token.Parse(text)
		if !ok {
			t.Fatalf("text %q is not a token", text)
		}
		return token.ID(tok)
	}

	// One token at the four positions of one request.
	once := idOf(second[0])
	got := callbackWith(t, s, [4]string{second[0], second[0], second[0], second[0]}, cookie)
	var surface string
	found := pollRow(t, db, "SELECT surface FROM event WHERE kind = 'callback' AND token_id = ?", []any{once}, &surface)
	if d := found.Sub(got); d > cbRowWait {
		t.Errorf("four positions: callback row after %v; want at most %v", d, cbRowWait)
	}

	// A token with one row, sent again at another position.
	rep := idOf(first[1])
	got = callbackAt(t, s, 1, first[1], cookie)
	found = pollRow(t, db, "SELECT surface FROM event WHERE kind = 'callback' AND token_id = ?", []any{rep}, &surface)
	if d := found.Sub(got); d > cbRowWait {
		t.Errorf("first callback: row after %v; want at most %v", d, cbRowWait)
	}
	callbackAt(t, s, 2, first[1], cookie)
	// The request row of the repeat is the barrier. The request event of a
	// capped token has the token fields. Its surface is the one of the
	// position of the repeat (the header). The request row of the first
	// callback has no token id.
	var trap, repSurface string
	pollRow(t, db, "SELECT trap_id, surface FROM event WHERE kind = 'request' AND token_id = ?", []any{rep}, &trap, &repSurface)
	if trap != "m" || repSurface != string(event.SurfaceHeader) {
		t.Errorf("request row of the repeat: trap %q, surface %q; want %q and %q", trap, repSurface, "m", event.SurfaceHeader)
	}
	for name, id := range map[string]string{"four positions": once, "repeat": rep} {
		if rows, count := cbCount(t, db, id); rows != 1 || count != 1 {
			t.Errorf("%s: %d callback rows and cb_count %d; want 1 and 1", name, rows, count)
		}
	}
	s.stop(t)
}
