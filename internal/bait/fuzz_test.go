package bait

import (
	"bufio"
	"net/http"
	"strings"
	"testing"
)

// fuzzSeeds are the forms of T-S-02 for the routes of example.com, as the
// target and the Host header.
func fuzzSeeds() [][2]string {
	var out [][2]string
	for _, c := range hardServed() {
		out = append(out, [2]string{c.path, c.host})
		for _, f := range hardForms(c.host, c.path) {
			out = append(out, [2]string{f.target, f.host})
		}
	}
	return append(out, [2]string{"/x?y=1", "EXAMPLE.com:443"}, [2]string{"*", "example.com"},
		[2]string{"/a%2Fb", "example.com"}, [2]string{"/%73tyle.css", "example.com"})
}

// declared gives the bytes of the route with the escaped path p of the vhost
// that host names. It folds the host by its own rule: no byte of 0x80 or more,
// no port, A-Z to a-z.
func declared(host, p string) (string, bool) {
	if i := strings.LastIndexByte(host, ':'); i >= 0 && strings.Trim(host[i+1:], "0123456789") == "" {
		host = host[:i]
	}
	var folded []byte
	for i := 0; i < len(host); i++ {
		c := host[i]
		if c >= 0x80 {
			return "", false
		}
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		folded = append(folded, c)
	}
	for _, r := range hardHosts[string(folded)] {
		if r.path == p {
			return r.body, true
		}
	}
	return "", false
}

// FuzzServe sends a request target and a host to the hardening bundle. The
// status is 200 only when the escaped path is a route path of the vhost that
// the host names. The body is then the bytes of the route. Else the status is
// 400, 404 or 405. The body then holds no byte of a route or of an unrouted
// file. The seeds are the forms of T-S-02.
func FuzzServe(f *testing.F) {
	for _, s := range fuzzSeeds() {
		f.Add(s[0], s[1])
	}
	h := hardHandler(f)
	f.Fuzz(func(t *testing.T, target, host string) {
		if strings.ContainsAny(target+host, " \r\n") {
			t.Skip()
		}
		head := "GET " + target + " HTTP/1.1\r\nHost: " + host + "\r\n\r\n"
		r, err := http.ReadRequest(bufio.NewReader(strings.NewReader(head)))
		if err != nil {
			t.Skip()
		}
		w := serve(t, h, r)
		want, ok := declared(r.Host, r.URL.EscapedPath())
		body := w.Body.String()
		switch {
		case ok && (w.Code != 200 || body != want):
			t.Errorf("route %q on %q: status %d body %q, want 200 %q", target, host, w.Code, body, want)
		case !ok && w.Code != 400 && w.Code != 404 && w.Code != 405:
			t.Errorf("target %q on %q: status %d", target, host, w.Code)
		case !ok:
			for _, bad := range forbidden() {
				if strings.Contains(body, bad) {
					t.Errorf("target %q on %q: the body holds %q", target, host, bad)
				}
			}
		}
	})
}
