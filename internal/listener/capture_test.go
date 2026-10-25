package listener

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"net"
	"net/http"
	"slices"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"
)

// rawHello writes the bytes of a ClientHello record. crypto/tls cannot send
// 300 cipher suites, GREASE values or a hello with no supported_versions.
type rawHello struct {
	version uint16
	suites  []uint16
	exts    []rawExt
}

type rawExt struct {
	id   uint16
	data []byte
}

func u16s(v ...uint16) []byte {
	var b []byte
	for _, x := range v {
		b = binary.BigEndian.AppendUint16(b, x)
	}
	return b
}

// list16 and list8 prefix b with its length in two bytes or one byte.
func list16(b []byte) []byte { return append(u16s(uint16(len(b))), b...) }
func list8(b []byte) []byte  { return append([]byte{byte(len(b))}, b...) }

func extSNI(name string) rawExt {
	return rawExt{0, list16(append([]byte{0}, list16([]byte(name))...))}
}
func extGroups(g ...uint16) rawExt { return rawExt{10, list16(u16s(g...))} }
func extSigs(s ...uint16) rawExt   { return rawExt{13, list16(u16s(s...))} }
func extVersions(v ...uint16) rawExt {
	return rawExt{43, list8(u16s(v...))}
}
func extALPN(p ...string) rawExt {
	var b []byte
	for _, s := range p {
		b = append(b, list8([]byte(s))...)
	}
	return rawExt{16, list16(b)}
}

func (h rawHello) bytes() []byte {
	body := u16s(h.version)
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0)                   // empty session ID
	body = append(body, list16(u16s(h.suites...))...)
	body = append(body, 1, 0) // compression: null
	var exts []byte
	for _, e := range h.exts {
		exts = append(exts, u16s(e.id)...)
		exts = append(exts, list16(e.data)...)
	}
	body = append(body, list16(exts)...)
	hs := append([]byte{1, 0, byte(len(body) >> 8), byte(len(body))}, body...)
	return append([]byte{0x16, 3, 1, byte(len(hs) >> 8), byte(len(hs))}, hs...)
}

// capRig is a server whose callback also reports the stored value.
type capRig struct {
	*rig
	got   chan *Hello
	calls atomic.Int32
}

func newCapRig(t *testing.T, h http.Handler) *capRig {
	t.Helper()
	c := &capRig{rig: newRig(t, 8, testHeaderBytes, defaultTimeouts, h), got: make(chan *Hello, 32)}
	c.s.tls.GetConfigForClient = func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
		c.calls.Add(1)
		cfg, err := captureHello(chi)
		select {
		case c.got <- HelloFrom(chi.Context()):
		default: // the buffer is full: drop the value, do not block
		}
		return cfg, err
	}
	return c
}

// capture sends the hello on a plain TCP connection. The handshake can fail;
// the copy is there after the callback.
func (c *capRig) capture(t *testing.T, h rawHello) *Hello {
	t.Helper()
	conn, err := net.Dial("tcp", c.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write(h.bytes()); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-c.got:
		return got
	case <-time.After(5 * time.Second):
		t.Fatal("no capture")
		return nil
	}
}

func seq(from uint16, n int) []uint16 {
	s := make([]uint16, n)
	for i := range s {
		s[i] = from + uint16(i)
	}
	return s
}

// T-U-19: each list is in wire order with GREASE values, and the first ALPN
// value is kept.
func TestTU19WireOrderGreaseALPN(t *testing.T) {
	c := newCapRig(t, okHandler)
	c.serve(t)
	suites := []uint16{0x0a0a, 0x1302, 0x1301, 0xc02b}
	groups := []uint16{0x4a4a, 29, 23}
	sigs := []uint16{0x0804, 0x0403, 0x5a5a}
	versions := []uint16{0x6a6a, 0x0304, 0x0303}
	exts := []rawExt{{0x2a2a, nil}, extSNI(testName), extGroups(groups...), extSigs(sigs...), extALPN("h2", "http/1.1"), extVersions(versions...), {0x3a3a, nil}}
	h := c.capture(t, rawHello{version: 0x0303, suites: suites, exts: exts})
	for name, p := range map[string][2][]uint16{
		"suites": {h.CipherSuites(), suites}, "groups": {h.SupportedGroups(), groups},
		"sigs": {h.SignatureSchemes(), sigs}, "versions": {h.SupportedVersions(), versions},
		"extensions": {h.Extensions(), {0x2a2a, 0, 10, 13, 16, 43, 0x3a3a}},
	} {
		if !slices.Equal(p[0], p[1]) {
			t.Errorf("%s: %x, want %x", name, p[0], p[1])
		}
	}
	if h.ALPN() != "h2" || !h.HasServerName() || h.Cut() {
		t.Errorf("alpn %q, server name %v, cut %v", h.ALPN(), h.HasServerName(), h.Cut())
	}
}

// T-U-19: a list over its cap keeps the first entries and sets the cut flag;
// a list at its cap does not set it.
func TestTU19ListCaps(t *testing.T) {
	c := newCapRig(t, okHandler)
	c.serve(t)
	base := func() rawHello {
		return rawHello{version: 0x0303, suites: []uint16{0xc02b}, exts: []rawExt{extVersions(0x0303)}}
	}
	// addExts adds n extensions with no data, after the supported_versions one.
	addExts := func(n int) func(*rawHello) {
		return func(h *rawHello) {
			for _, id := range seq(0x4000, n) {
				h.exts = append(h.exts, rawExt{id, nil})
			}
		}
	}
	for _, tc := range []struct {
		name string
		mod  func(*rawHello)
		get  func(*Hello) []uint16
		want []uint16
		cut  bool
	}{
		{"suites", func(h *rawHello) { h.suites = seq(0x1000, 300) }, (*Hello).CipherSuites, seq(0x1000, maxCipherSuites), true},
		{"suites at cap", func(h *rawHello) { h.suites = seq(0x1000, maxCipherSuites) }, (*Hello).CipherSuites, seq(0x1000, maxCipherSuites), false},
		{"extensions", addExts(300), (*Hello).Extensions, append([]uint16{43}, seq(0x4000, maxExtensions-1)...), true},
		{"extensions at cap", addExts(maxExtensions - 1), (*Hello).Extensions, append([]uint16{43}, seq(0x4000, maxExtensions-1)...), false},
		{"signature schemes", func(h *rawHello) { h.exts = append(h.exts, extSigs(seq(0x0100, 100)...)) }, (*Hello).SignatureSchemes, seq(0x0100, maxSigSchemes), true},
		{"signature schemes at cap", func(h *rawHello) { h.exts = append(h.exts, extSigs(seq(0x0100, maxSigSchemes)...)) }, (*Hello).SignatureSchemes, seq(0x0100, maxSigSchemes), false},
		{"groups", func(h *rawHello) { h.exts = append(h.exts, extGroups(seq(0x0100, 100)...)) }, (*Hello).SupportedGroups, seq(0x0100, maxGroups), true},
		{"groups at cap", func(h *rawHello) { h.exts = append(h.exts, extGroups(seq(0x0100, maxGroups)...)) }, (*Hello).SupportedGroups, seq(0x0100, maxGroups), false},
		{"versions", func(h *rawHello) { h.exts = []rawExt{extVersions(seq(0x0300, 20)...)} }, (*Hello).SupportedVersions, seq(0x0300, maxVersions), true},
		{"versions at cap", func(h *rawHello) { h.exts = []rawExt{extVersions(seq(0x0300, maxVersions)...)} }, (*Hello).SupportedVersions, seq(0x0300, maxVersions), false},
	} {
		h := base()
		tc.mod(&h)
		got := c.capture(t, h)
		if !slices.Equal(tc.get(got), tc.want) || got.Cut() != tc.cut {
			t.Errorf("%s: %d entries, cut %v; want %d, %v", tc.name, len(tc.get(got)), got.Cut(), len(tc.want), tc.cut)
		}
		if got.HasServerName() { // no row has a server_name extension
			t.Errorf("%s: HasServerName is true with no server_name", tc.name)
		}
	}
}

// T-U-19: a ClientHello with no supported_versions keeps the versions that
// crypto/tls extrapolates from the legacy version.
func TestTU19NoSupportedVersions(t *testing.T) {
	c := newCapRig(t, okHandler)
	c.serve(t)
	h := c.capture(t, rawHello{version: 0x0303, suites: []uint16{0xc02b}, exts: []rawExt{extSNI(testName)}})
	if want := []uint16{tls.VersionTLS12, tls.VersionTLS11, tls.VersionTLS10}; !slices.Equal(h.SupportedVersions(), want) {
		t.Errorf("versions %x, want %x", h.SupportedVersions(), want)
	}
	if slices.Contains(h.Extensions(), 43) {
		t.Errorf("extensions %v hold 43", h.Extensions())
	}
}

// T-U-19: a handshake with a HelloRetryRequest gives one capture, the first
// ClientHello. The test forces the retry: the client key share is for X25519
// and the server accepts only P-256. The retried hello has the same lists as
// the first, so TestTU19FirstWins proves that the first copy stays.
func TestTU19HelloRetryRequestKeepsFirst(t *testing.T) {
	seen := make(chan bool, 4) // HelloRetryRequest flag of each GetCertificate call: crypto/tls calls it only for the second hello
	var got atomic.Pointer[Hello]
	c := newCapRig(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got.Store(HelloFrom(r.Context())) }))
	cert := c.s.tls.Certificates[0]
	c.s.tls.Certificates = nil
	c.s.tls.GetCertificate = func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
		seen <- chi.HelloRetryRequest
		return &cert, nil
	}
	c.s.tls.CurvePreferences = []tls.CurveID{tls.CurveP256}
	c.serve(t)
	cc := c.clientConfig()
	cc.CurvePreferences = []tls.CurveID{tls.X25519, tls.CurveP256}
	conn, err := tls.Dial("tcp", c.addr, cc)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if status(conn, 0) != 200 {
		t.Fatal("request failed")
	}
	if len(seen) != 1 || !<-seen {
		t.Fatal("GetCertificate did not run once for the retried hello")
	}
	first := <-c.got
	if n := c.calls.Load(); n != 1 {
		t.Fatalf("capture callback ran %d times", n)
	}
	if want := []uint16{uint16(tls.X25519), uint16(tls.CurveP256)}; !slices.Equal(first.SupportedGroups(), want) || got.Load() != first {
		t.Errorf("groups %v; handler value is the first capture: %v", first.SupportedGroups(), got.Load() == first)
	}
}

// T-U-19: a second ClientHello on the same connection does not replace the
// first copy.
func TestTU19FirstWins(t *testing.T) {
	ctx := withConnState(context.Background())
	s := ctx.Value(stateKey{}).(*connState)
	s.capture(&tls.ClientHelloInfo{CipherSuites: []uint16{1}})
	first := HelloFrom(ctx)
	s.capture(&tls.ClientHelloInfo{CipherSuites: []uint16{2}})
	if HelloFrom(ctx) != first || first.CipherSuites()[0] != 1 {
		t.Fatal("the second hello replaced the first")
	}
	if HelloFrom(context.Background()) != nil {
		t.Fatal("hello without a connection")
	}
}

// helloSize is the size of a Hello: 1064 bytes. The uint16 arrays take 800. The
// ALPN array takes 255. Five counts, the ALPN length and two flags take 8. One
// pad byte keeps the 2-byte alignment.
const helloSize = 2*(maxCipherSuites+maxExtensions+maxSigSchemes+maxGroups+maxVersions) + maxALPN + 8 + 1

// T-U-19: the copy has a fixed size. The requirement is 1152 bytes or less, so
// helloSize is in the limit.
func TestTU19FixedSize(t *testing.T) {
	if got := unsafe.Sizeof(Hello{}); got != helloSize || got > 1152 {
		t.Fatalf("size %d, want %d (at most 1152)", got, helloSize)
	}
}

// T-U-19: a capture with a stored copy allocates nothing.
func TestTU19StoredCopyAllocatesNothing(t *testing.T) {
	s := withConnState(context.Background()).Value(stateKey{}).(*connState)
	chi := &tls.ClientHelloInfo{CipherSuites: []uint16{1}}
	s.capture(chi)
	if n := testing.AllocsPerRun(100, func() { s.capture(chi) }); n != 0 {
		t.Fatalf("%v allocations in capture with a stored copy", n)
	}
}

// ioCount counts Read and Write calls on ioListener conns while on is set.
type ioCount struct {
	on atomic.Bool
	n  atomic.Int32
}

type ioListener struct {
	net.Listener
	*ioCount
}

type ioConn struct {
	net.Conn
	*ioCount
}

func (l ioListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	return ioConn{c, l.ioCount}, err
}

func (c ioConn) Read(p []byte) (int, error) {
	if c.on.Load() {
		c.n.Add(1)
	}
	return c.Conn.Read(p)
}

func (c ioConn) Write(p []byte) (int, error) {
	if c.on.Load() {
		c.n.Add(1)
	}
	return c.Conn.Write(p)
}

// T-U-19: the callback does no I/O on the connection. The count runs only
// while captureHello does.
func TestTU19CallbackDoesNoIO(t *testing.T) {
	var cnt ioCount
	c := newCapRig(t, okHandler)
	hook := c.s.tls.GetConfigForClient
	c.s.tls.GetConfigForClient = func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
		cnt.on.Store(true)
		defer cnt.on.Store(false)
		return hook(chi)
	}
	ln := listenLoopback(t)
	c.addr = ln.Addr().String()
	c.serveOn(t, ioListener{ln, &cnt})
	if h := c.capture(t, rawHello{version: 0x0303, suites: []uint16{0xc02b}, exts: []rawExt{extSNI(testName)}}); !h.HasServerName() {
		t.Fatal("no server name in the copy")
	}
	if got := cnt.n.Load(); got != 0 {
		t.Fatalf("%d reads and writes on the connection in the callback, want 0", got)
	}
}

// T-U-19: the handshake cost with and without the capture callback.
func BenchmarkHandshake(b *testing.B) {
	cert, pool := testCert(b)
	for _, bc := range []struct {
		name string
		cb   func(*tls.ClientHelloInfo) (*tls.Config, error)
	}{{"without capture", nil}, {"with capture", captureHello}} {
		b.Run(bc.name, func(b *testing.B) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				b.Fatal(err)
			}
			defer ln.Close()
			cfg := &tls.Config{Certificates: []tls.Certificate{cert}, GetConfigForClient: bc.cb}
			go func() {
				for {
					c, err := ln.Accept()
					if err != nil {
						return
					}
					go func() {
						defer c.Close()
						_ = tls.Server(c, cfg).HandshakeContext(withConnState(context.Background()))
					}()
				}
			}()
			cc := &tls.Config{RootCAs: pool, ServerName: testName}
			b.ReportAllocs()
			for b.Loop() {
				c, err := tls.Dial("tcp", ln.Addr().String(), cc)
				if err != nil {
					b.Fatal(err)
				}
				_ = c.Close()
			}
		})
	}
}
