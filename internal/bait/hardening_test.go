package bait

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"go/build"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cybagard/cyba-phantom/internal/bundle"
)

// cbRoute is a callback route of example.com with a body position. It has an
// asset, so a GET gets its bytes. cbJSON is its member of routes.json.
var cbRoute = route{"/cb", "cb.txt", text, "callback\n"}

const cbJSON = `{"path":"/cb","asset":"vhosts/example.com/cb.txt","type":"text/plain; charset=utf-8","callback":{"body":"tok"}}`

// hbScript and hbPost are the beacon paths of example.com in the hardening
// bundle.
const (
	hbScript = "/hb.js"
	hbPost   = "/hb/p"
)

// nfPage is the page of the 404 template of example.com.
const nfPage = "<h1>missing</h1>"

// hardHosts are the routes of each vhost of the hardening bundle.
var hardHosts = map[string][]route{
	"example.com":  append(slices.Clone(exampleRoutes), cbRoute),
	"kilo.example": kiloRoutes,
	"zulu.example": zuluRoutes,
}

// trapsJSON makes traps/traps.json for specs.
func trapsJSON(specs []trapSpec) string {
	var traps []map[string]string
	for _, s := range specs {
		traps = append(traps, map[string]string{"id": s.id, "slot": s.slot, "surface": "path",
			"visibility": "human-visible", "instruction_template": s.text})
	}
	b, err := json.Marshal(traps)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// hardBundle loads the bundle of the hardening tests. The route map of
// example.com has the routes of exampleRoutes and the callback route. It also
// has a 404 template with the text nf. A file of extra replaces a file of the
// bundle.
func hardBundle(tb testing.TB, nf string, extra map[string]string) *bundle.Bundle {
	tb.Helper()
	rm := strings.TrimSuffix(routesJSON("example.com", exampleRoutes), "]}") + "," + cbJSON +
		`],"not_found":"vhosts/example.com/nf.tmpl","beacon":{"script":"` + hbScript + `","post":"` + hbPost + `"}}`
	files := map[string]string{
		"vhosts/example.com/routes.json": rm,
		"vhosts/example.com/cb.txt":      cbRoute.body,
		"vhosts/example.com/nf.tmpl":     nf,
	}
	maps.Copy(files, extra)
	return bundleFiles(tb, "", files)
}

// hardHandler returns a handler for the hardening bundle.
func hardHandler(tb testing.TB) *Handler {
	return New(fixedSource{hardBundle(tb, nfPage, nil)}, &fallbackFn{}, testQueue(tb))
}

// served is a request that the bundle answers: a route with its bytes, or a
// path with no route.
type served struct {
	host, path string
	code       int
	body       string
}

// hardServed lists each route of the bundle, the 404 template of example.com
// and the fixed 404 page of kilo.example.
func hardServed() []served {
	var out []served
	for host, rs := range hardHosts {
		for _, r := range rs {
			out = append(out, served{host, r.path, 200, r.body})
		}
	}
	return append(out, served{"example.com", "/nope", 404, nfPage}, served{"kilo.example", "/nope", 404, notFoundPage})
}

// forbidden are the bytes of the files of the bundle. A response to a form must
// not hold them. No route names some of the files. The others are other routes.
func forbidden() []string {
	out := []string{"unrouted\n", "other vhost\n", "score\n", "fp\n", strings.Repeat("\x09", 32), "min_engine", "instruction_template"}
	for _, rs := range hardHosts {
		for _, r := range rs {
			out = append(out, r.body)
		}
	}
	return out
}

// exchange writes req on a new connection and reads one response. A timeout
// on the status line and the headers fails the test: it is not a close. A
// different read error there, such as EOF or a reset, is a close and gives
// status 0. The body read does not check for a timeout.
func exchange(t *testing.T, addr, req string) (status int, body string) {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	mustOK(t, err)
	defer c.Close()
	mustOK(t, c.SetDeadline(time.Now().Add(10*time.Second)))
	_, _ = c.Write([]byte(req))
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			t.Fatalf("no response to %q: %v", strings.SplitN(req, "\r\n", 2)[0], err)
		}
		return 0, ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	return resp.StatusCode, string(b)
}

// form is a request for the route path p of the vhost host. want is the status.
type form struct {
	name, target, host string
	want               int
}

// hardForms are the forms of T-S-02 for the route path p of host. The handler
// gives 404, as no route has the target or the host. net/http gives 400 before
// the handler for a raw NUL in the request line. It also gives 400 for a Host
// header with a byte of 0x80 or more. An absolute-form target sets the host of
// the request. So the handler gives 404 for another host and for such a byte.
func hardForms(host, p string) []form {
	bare := strings.TrimPrefix(p, "/")
	out := []form{
		{"dot dot after", p + "/../x", host, 404},
		{"dot dot before", "/../" + bare, host, 404},
		{"encoded dot dot", "/%2e%2e" + p, host, 404},
		{"encoded dot dot, upper case", "/%2E%2E" + p, host, 404},
		{"encoded dot dot, mixed", "/.%2e/" + bare, host, 404},
		{"encoded dot dot after", p + "/%2e%2e/x", host, 404},
		{"open braces", p + "{{", host, 404},
		{"action", p + "/{{.T}}", host, 404},
		{"encoded NUL", p[:1] + "%00" + p[1:], host, 404},
		{"raw NUL", p[:1] + "\x00" + p[1:], host, 400},
		{"double slash", "/" + p, host, 404},
		{"triple slash", "//" + p, host, 404},
		{"absolute form, other host", "http://other.example" + p, host, 404},
		{"absolute form, byte over 0x7f", "http://exampl\xe9.com" + p, host, 404},
		{"trailing dot host", p, host + ".", 404},
		{"host byte over 0x7f", p, host + "\xe9", 400},
		{"unknown vhost", p, "other.example", 404},
	}
	// The handler matches the escaped path, so an encoded byte is no route.
	if strings.Contains(p[1:], "/") {
		out = append(out, form{"encoded slash", p[:1] + strings.ReplaceAll(p[1:], "/", "%2F"), host, 404})
	}
	if len(p) > 1 {
		out = append(out, form{"encoded letter", p[:1] + fmt.Sprintf("%%%02X", p[1]) + p[2:], host, 404})
	}
	return out
}

// TestTS02Forms sends each form of hardForms for each route to a real server.
// The request is raw, because httptest.NewRequest and http.ReadRequest refuse
// or change a raw NUL and an absolute form. Each form gets its status, never
// 200. Its body holds no byte of another route or of an unrouted file. First,
// the plain request of each route gets the route.
func TestTS02Forms(t *testing.T) {
	srv := httptest.NewServer(hardHandler(t))
	defer srv.Close()
	addr := srv.Listener.Addr().String()
	req := func(target, host string) string {
		return "GET " + target + " HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n"
	}
	for _, c := range hardServed() {
		if code, body := exchange(t, addr, req(c.path, c.host)); code != c.code || body != c.body {
			t.Errorf("plain %s%s: status %d body %q, want %d %q", c.host, c.path, code, body, c.code, c.body)
		}
		for _, f := range hardForms(c.host, c.path) {
			code, body := exchange(t, addr, req(f.target, f.host))
			if code != f.want {
				t.Errorf("%s: %q on %q: status %d, want %d", f.name, f.target, f.host, code, f.want)
			}
			for _, bad := range forbidden() {
				if strings.Contains(body, bad) {
					t.Errorf("%s: %q on %q: the body holds %q", f.name, f.target, f.host, bad)
				}
			}
		}
	}
}

// TestTS02DirectImports checks the direct imports of the files of the package
// that are not tests. None is os, io/fs, path/filepath, syscall or net. So the
// engine has no way to read the disk or to open a connection. net/http and
// net/netip are other paths. The imports of other packages are not in the list,
// as net/http imports os. The check reads the files of each GOOS and GOARCH.
func TestTS02DirectImports(t *testing.T) {
	ctx := build.Default
	ctx.UseAllFiles = true
	pkg, err := ctx.ImportDir(".", 0)
	mustOK(t, err)
	if !slices.Contains(pkg.Imports, "net/http") {
		t.Fatalf("imports %v do not hold net/http", pkg.Imports)
	}
	for _, imp := range pkg.Imports {
		if slices.Contains([]string{"os", "io/fs", "path/filepath", "syscall", "net"}, imp) {
			t.Errorf("a file of the package imports %q", imp)
		}
	}
}

// bodyReq is a request with n body bytes, with Content-Length or chunked. A
// ctype that is not empty is the Content-Type header.
func bodyReq(method, target, host, ctype string, n int, chunked bool) string {
	head := method + " " + target + " HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n"
	if ctype != "" {
		head += "Content-Type: " + ctype + "\r\n"
	}
	body := strings.Repeat("a", n)
	if chunked {
		return head + "Transfer-Encoding: chunked\r\n\r\n" + fmt.Sprintf("%x\r\n%s\r\n0\r\n\r\n", n, body)
	}
	return head + fmt.Sprintf("Content-Length: %d\r\n\r\n%s", n, body)
}

// TestTS02PostBodies sends a POST with 1 000 and with 65 537 body bytes to a
// real server. The body has Content-Length or is chunked. The POST has no
// Content-Type, or the type of a form, or the type of a multipart body. The
// targets are the routes of each vhost of hardHosts, with the callback route
// that has a body position. They are also the two beacon paths, a path with no
// route and an unknown host. A known host gets the fixed 405 page. The post
// path of the beacon gets 204, not the fixed 405 page. An unknown host gets
// the fixed 404 page. A close is also right. A GET and a HEAD with a body of
// 65 537 bytes get the status of the target. A wrapper that the server handler
// puts around the body counts the bytes that the bait handler reads. The handler
// reads 0 bytes. A POST to the callback route with a body position gets its
// fixed response (ADR-039 decision 19). That route reads at most 4 097 bytes.
// A POST to the beacon post path gets 204 and reads at most 64 bytes. A POST to
// the beacon script path gets 405 and reads 0 bytes.
func TestTS02PostBodies(t *testing.T) {
	h := hardHandler(t)
	var mu sync.Mutex
	var reads, cbReads, bpReads []int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rb := &tallyBody{ReadCloser: r.Body}
		r.Body = rb
		h.ServeHTTP(w, r)
		mu.Lock()
		if r.URL.Path == cbRoute.path && r.Method == http.MethodPost {
			cbReads = append(cbReads, rb.got)
		} else if r.URL.Path == hbPost && r.Method == http.MethodPost {
			bpReads = append(bpReads, rb.got)
		} else {
			reads = append(reads, rb.got)
		}
		mu.Unlock()
	}))
	// code is the status of a GET.
	type target struct {
		host, path string
		code       int
	}
	targets := []target{{"example.com", "/nope", 404}, {"other.example", "/", 404},
		{"example.com", hbScript, 200}, {"example.com", hbPost, 405}}
	for host, rs := range hardHosts {
		for _, r := range rs {
			targets = append(targets, target{host, r.path, 200})
		}
	}
	addr := srv.Listener.Addr().String()
	ctypes := []string{"", "application/x-www-form-urlencoded", "multipart/form-data; boundary=x"}
	n := 0
	for _, c := range targets {
		want := 405
		if _, known := hardHosts[c.host]; !known {
			want = 404
		} else if c.path == cbRoute.path {
			want = 200 // a POST to a callback route with a body position
		} else if c.path == hbPost {
			want = 204 // a POST to the beacon post path
		}
		for _, size := range []int{1000, 65537} {
			for _, chunked := range []bool{false, true} {
				for _, ctype := range ctypes {
					n++
					code, _ := exchange(t, addr, bodyReq("POST", c.path, c.host, ctype, size, chunked))
					if code != want && code != 0 {
						t.Errorf("POST %s on %s, %d bytes, chunked %v, type %q: status %d, want %d or a close", c.path, c.host, size, chunked, ctype, code, want)
					}
				}
			}
		}
		for _, method := range []string{"GET", "HEAD"} {
			n++
			if code, _ := exchange(t, addr, bodyReq(method, c.path, c.host, "", 65537, false)); code != c.code {
				t.Errorf("%s %s on %s with a body: status %d, want %d", method, c.path, c.host, code, c.code)
			}
		}
	}
	srv.Close()
	if len(reads)+len(cbReads)+len(bpReads) != n {
		t.Fatalf("the handler ran %d times for %d requests", len(reads)+len(cbReads)+len(bpReads), n)
	}
	if total := slices.Max(bpReads); total > beaconBodyMax {
		t.Errorf("a POST to the beacon post path read %d body bytes, want at most %d", total, beaconBodyMax)
	}
	if total := slices.Max(reads); total != 0 {
		t.Errorf("a request made the handler read %d body bytes, want 0", total)
	}
	if total := slices.Max(cbReads); total > bodyMax+1 {
		t.Errorf("a POST to the callback route read %d body bytes, want at most %d", total, bodyMax+1)
	}
}
