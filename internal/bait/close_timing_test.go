package bait

import (
	"bytes"
	"cmp"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cybagard/cyba-phantom/internal/event"
	"github.com/cybagard/cyba-phantom/internal/listener"
)

// probeLimit bounds each wait of the close tests: a dial, a read and a wait
// for an event.
const probeLimit = 5 * time.Second

// pipelinedTail is a second request. A client without "Connection: close"
// sends it in the same write as the first request.
const pipelinedTail = "GET /t HTTP/1.1\r\nHost: example.com\r\n\r\n"

// servePlainLoopback serves h through the listener on a plain socket of
// 127.0.0.1 and returns the address.
func servePlainLoopback(tb testing.TB, h *Handler, q *event.Queue) string {
	tb.Helper()
	srv, err := listener.New(listener.Config{
		TLS: &tls.Config{}, MaxConns: 64, HeaderBytes: 8192, Queue: q, Counters: q.Counters(),
	}, h)
	mustOK(tb, err)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	mustOK(tb, err)
	go func() { _ = srv.ServePlain(ln, h) }()
	tb.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String()
}

// serveTLSLoopback serves h through listener.Serve on 127.0.0.1 with a
// self-signed certificate that the test makes. It returns the address and a
// client config that trusts the certificate.
func serveTLSLoopback(tb testing.TB, h *Handler, q *event.Queue) (string, *tls.Config) {
	tb.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mustOK(tb, err)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: tlsName},
		DNSNames:     []string{tlsName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	mustOK(tb, err)
	leaf, err := x509.ParseCertificate(der)
	mustOK(tb, err)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	srv, err := listener.New(listener.Config{
		TLS:      &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}}},
		MaxConns: 64, HeaderBytes: 8192, Queue: q, Counters: q.Counters(),
	}, h)
	mustOK(tb, err)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	mustOK(tb, err)
	go func() { _ = srv.Serve(ln) }()
	tb.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String(), &tls.Config{RootCAs: pool, ServerName: tlsName}
}

// tlsName is the name in the certificate of serveTLSLoopback.
const tlsName = "decoy.test"

// callbackRequest is a POST to the callback route with the tokens toks at the
// positions path, query, header and body. With no tokens it sends a body with
// no token and no other position.
func callbackRequest(toks [4]string, closeHdr bool) []byte {
	return callbackRequestTo(cbRoutePath, toks, closeHdr)
}

// callbackRequestTo is callbackRequest for the route with the path route.
func callbackRequestTo(route string, toks [4]string, closeHdr bool) []byte {
	target, body, hdr := route, `{"x":1}`, ""
	if toks[0] != "" {
		target += "/" + toks[0] + "?ref=" + toks[1]
		hdr = cbHeaderKey + ": " + toks[2] + "\r\n"
		body = `{"tok":"` + toks[3] + `"}`
	}
	return withClose("POST "+target+" HTTP/1.1\r\nHost: example.com\r\n"+hdr+
		"Content-Type: application/json\r\nContent-Length: "+strconv.Itoa(len(body))+"\r\n\r\n"+body, closeHdr)
}

// beaconRequest is a POST of body to the post path of the beacon.
func beaconRequest(body string, closeHdr bool) []byte {
	return withClose("POST "+bcPost+" HTTP/1.1\r\nHost: example.com\r\n"+
		"Content-Type: text/plain\r\nContent-Length: "+strconv.Itoa(len(body))+"\r\n\r\n"+body, closeHdr)
}

// withClose gives the bytes of a request. With closeHdr it adds the header
// "Connection: close". Else it adds a pipelined second request.
func withClose(req string, closeHdr bool) []byte {
	if closeHdr {
		return []byte(strings.Replace(req, "\r\n", "\r\nConnection: close\r\n", 1))
	}
	return []byte(req + pipelinedTail)
}

// responseEnd gives the end offset of the first response in b. It gives -1 when
// b holds only a part.
func responseEnd(b []byte) int {
	h := bytes.Index(b, []byte("\r\n\r\n"))
	if h < 0 {
		return -1
	}
	cl := 0
	if i := bytes.Index(b[:h], []byte("Content-Length: ")); i >= 0 {
		j := bytes.IndexByte(b[i:], '\r')
		cl, _ = strconv.Atoi(string(b[i+len("Content-Length: ") : i+j]))
	}
	if len(b) < h+4+cl {
		return -1
	}
	return h + 4 + cl
}

// closeProbe sends req on a new connection and reads to the end of the stream.
// It gives two values. The first is the time from the read that ends the first
// response to the read that gives EOF. The second is the number of bytes after
// the first response. It fails the test when the response is not whole. It also
// fails when the stream does not end within probeLimit.
func closeProbe(tb testing.TB, addr string, req []byte) (time.Duration, int) {
	tb.Helper()
	c, err := net.DialTimeout("tcp", addr, probeLimit)
	mustOK(tb, err)
	return closeProbeOn(tb, c, req)
}

// closeProbeOn is closeProbe on the open connection c. It closes c.
func closeProbeOn(tb testing.TB, c net.Conn, req []byte) (time.Duration, int) {
	tb.Helper()
	defer c.Close()
	mustOK(tb, c.SetDeadline(time.Now().Add(probeLimit)))
	_, err := c.Write(req)
	mustOK(tb, err)
	var acc []byte
	buf := make([]byte, 4096)
	var last time.Time
	end := -1
	for {
		n, err := c.Read(buf)
		now := time.Now()
		acc = append(acc, buf[:n]...)
		if end < 0 && n > 0 {
			if end = responseEnd(acc); end >= 0 {
				last = now
			}
		}
		if errors.Is(err, io.EOF) {
			if end < 0 {
				tb.Fatalf("EOF before the end of the response: %q", acc)
			}
			return now.Sub(last), len(acc) - end
		}
		if err != nil {
			tb.Fatalf("read after %d bytes (response end %d): %v", len(acc), end, err)
		}
	}
}

// waitRequests drains q until it has n request events. It gives their records
// and the records of the other events. The request event of a request comes
// after its callback or beacon event. A wait of more than probeLimit fails
// the test.
func waitRequests(tb testing.TB, q *event.Queue, n int) (reqs, rest []event.Record) {
	tb.Helper()
	for end := time.Now().Add(probeLimit); len(reqs) < n; time.Sleep(time.Millisecond) {
		if time.Now().After(end) {
			tb.Fatalf("%d request events in %v, want %d", len(reqs), probeLimit, n)
		}
		for _, ev := range q.Drain() {
			if r := ev.Record(); r.Kind == event.KindRequest {
				reqs = append(reqs, r)
			} else {
				rest = append(rest, r)
			}
		}
	}
	return reqs, rest
}

// TestTS32CloseBeforeCheck serves the handler through the listener on
// 127.0.0.1. A hook blocks the handler after the close and before the check.
// The client must read the end of the response and then EOF while the hook
// blocks. The cases are a callback route and the beacon post path. Each has
// good tokens and bad tokens. Each runs with and without "Connection: close" in
// the request. A request without that header has a second request in the same
// write, which gets no response. While the hook blocks, the queue has no event.
// After the hook returns, a good token gives its event and a bad token gives
// none. More cases are a callback route with no asset and a beacon post with
// no body. Each case runs on a plain socket and over TLS. Over TLS the client
// must read the end of the stream while the hook blocks.
func TestTS32CloseBeforeCheck(t *testing.T) {
	for _, tc := range []struct {
		name         string
		beacon, good bool
		route        string // the callback route, or "" for the one with an asset
		noBody       bool   // a beacon post with no body
	}{
		{name: "callback, good tokens", good: true},
		{name: "callback, bad tokens"},
		{name: "callback, no asset, good tokens", good: true, route: "/nc"},
		{name: "callback, no asset, bad tokens", route: "/nc"},
		{name: "beacon, good ticket", beacon: true, good: true},
		{name: "beacon, bad ticket", beacon: true},
		{name: "beacon, no body", beacon: true, noBody: true},
	} {
		for _, useTLS := range []bool{false, true} {
			for _, closeHdr := range []bool{true, false} {
				name := tc.name + ", plain"
				if useTLS {
					name = tc.name + ", TLS"
				}
				if closeHdr {
					name += ", request with Connection: close"
				} else {
					name += ", request without Connection: close"
				}
				t.Run(name, func(t *testing.T) {
					var h *Handler
					var q *event.Queue
					var req []byte
					var kind event.Kind
					if tc.beacon {
						e := newBC(t, bcPost)
						tk := e.ticket(t, "127.0.0.1:1", "")
						if !tc.good {
							b := []byte(tk)
							b[12] ^= 1
							tk = string(b)
						}
						if tc.noBody {
							tk = ""
						}
						h, q, req, kind = e.h, e.q, beaconRequest(tk, closeHdr), event.KindBeacon
					} else {
						e := newCBEnv(t)
						toks := [4]string{}
						for i := range toks {
							if toks[i] = strings.Repeat("a", candidateLen); tc.good {
								toks[i] = e.mint(t, time.Now())
							}
						}
						route := cmp.Or(tc.route, cbRoutePath)
						h, q, req, kind = e.h, e.q, callbackRequestTo(route, toks, closeHdr), event.KindCallback
					}
					hooked, release := make(chan struct{}, 1), make(chan struct{})
					h.flushHook = func() {
						hooked <- struct{}{}
						<-release
					}
					var once sync.Once
					open := func() { once.Do(func() { close(release) }) }
					t.Cleanup(open)

					// The hook blocks until the client has read EOF. A check
					// before the close leaves the client without EOF.
					var extra int
					if useTLS {
						addr, cfg := serveTLSLoopback(t, h, q)
						c, err := tls.DialWithDialer(&net.Dialer{Timeout: probeLimit}, "tcp", addr, cfg)
						mustOK(t, err)
						_, extra = closeProbeOn(t, c, req)
					} else {
						_, extra = closeProbe(t, servePlainLoopback(t, h, q), req)
					}
					if extra != 0 {
						t.Errorf("%d bytes after the first response, want 0", extra)
					}
					select {
					case <-hooked:
					case <-time.After(probeLimit):
						t.Fatal("the handler did not reach the hook")
					}
					if evs := q.Drain(); len(evs) != 0 {
						t.Errorf("%d events on the queue while the check is blocked, want 0", len(evs))
					}
					open()
					reqs, rest := waitRequests(t, q, 1)
					// A request has 4 good tokens, one at each position.
					want := 0
					if tc.good {
						want = map[bool]int{false: 4, true: 1}[tc.beacon]
					}
					if len(reqs) != 1 || len(rest) != want || slices.ContainsFunc(rest, func(r event.Record) bool { return r.Kind != kind }) {
						t.Errorf("after the hook: %d request events and %d other events, want 1 and %d of kind %v", len(reqs), len(rest), want, kind)
					}
				})
			}
		}
	}
}

// drained counts the events that a test queue takes.
type drained struct{ cb, beacon, req atomic.Int64 }

// drainQueue takes the events of q until the test ends.
func drainQueue(tb testing.TB, q *event.Queue) *drained {
	tb.Helper()
	d, stop, done := &drained{}, make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			case <-q.Ready():
				for _, ev := range q.Drain() {
					switch ev.Kind() {
					case event.KindCallback:
						d.cb.Add(1)
					case event.KindBeacon:
						d.beacon.Add(1)
					default:
						d.req.Add(1)
					}
				}
			}
		}
	}()
	tb.Cleanup(func() { close(stop); <-done })
	return d
}

// reportClose reports the p10 and the p50 of the close times of one run.
func reportClose(b *testing.B, times []time.Duration) {
	b.Helper()
	slices.Sort(times)
	us := func(p float64) float64 { return float64(times[int(p*float64(len(times)-1))].Nanoseconds()) / 1000 }
	b.ReportMetric(us(0.1), "p10-µs")
	b.ReportMetric(us(0.5), "p50-µs")
}

// BenchmarkTS32CallbackClose reports the time from the end of the response to
// EOF for a callback route with 4 positions. It runs through the listener on
// 127.0.0.1, and the request has "Connection: close". There are four classes.
// They are no candidate and 4 bad tokens. Then 4 good tokens over the
// admission cap, and 4 good tokens that it admits. Each run gives p10 and p50.
// The bench is not part of make all.
func BenchmarkTS32CallbackClose(b *testing.B) {
	e := newCBEnv(b)
	var tick atomic.Int64
	// A step of two token windows lets each token pass the cap again.
	e.h.mono = func() time.Duration { return time.Duration(tick.Load()) * 2 * capTokenWindow }
	d := drainQueue(b, e.q)
	addr := servePlainLoopback(b, e.h, e.q)
	var good, bad [4]string
	for i := range good {
		good[i] = e.mint(b, time.Now())
		bad[i] = strings.Repeat("a", candidateLen)
	}
	// Admit the tokens once, so that the same time makes the next requests
	// capped. The wait ends when the callback events are taken.
	prime := func() {
		before := d.cb.Load()
		tick.Add(1)
		closeProbe(b, addr, callbackRequest(good, true))
		for end := time.Now().Add(probeLimit); d.cb.Load() == before; time.Sleep(time.Millisecond) {
			if time.Now().After(end) {
				b.Fatal("the priming request gave no callback event")
			}
		}
	}
	for _, c := range []struct {
		name  string
		toks  [4]string
		admit bool
	}{
		{"none", [4]string{}, false}, {"bad", bad, false}, {"good-capped", good, false}, {"good-admitted", good, true},
	} {
		b.Run(c.name, func(b *testing.B) {
			if c.name == "good-capped" {
				prime()
			}
			req := callbackRequest(c.toks, true)
			times := make([]time.Duration, 0, b.N)
			b.ResetTimer()
			for range b.N {
				if c.admit {
					tick.Add(1)
				}
				t, _ := closeProbe(b, addr, req)
				times = append(times, t)
			}
			b.StopTimer()
			reportClose(b, times)
		})
	}
}

// BenchmarkTS32BeaconClose is BenchmarkTS32CallbackClose for the beacon post
// path. The classes are no body, a ticket with one bit changed and a good
// ticket.
func BenchmarkTS32BeaconClose(b *testing.B) {
	e := newBC(b, bcPost)
	tk := e.ticket(b, "127.0.0.1:1", "")
	bit := []byte(tk)
	bit[12] ^= 1
	drainQueue(b, e.q)
	addr := servePlainLoopback(b, e.h, e.q)
	for _, c := range []struct{ name, body string }{{"none", ""}, {"bad", string(bit)}, {"good", tk}} {
		b.Run(c.name, func(b *testing.B) {
			req := beaconRequest(c.body, true)
			times := make([]time.Duration, 0, b.N)
			b.ResetTimer()
			for range b.N {
				t, _ := closeProbe(b, addr, req)
				times = append(times, t)
			}
			b.StopTimer()
			reportClose(b, times)
		})
	}
}
