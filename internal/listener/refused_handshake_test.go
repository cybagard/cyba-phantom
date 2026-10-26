package listener

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
)

const (
	markerName = "marker-sni.example"
	markerALPN = "marker-alpn"
	otherName  = "other.test"
	noCertName = "nocert.test"
)

// gateRig is a server with the real name gate, set up as cmd/phantom does. It
// has the configured name testName with a cached certificate, and the
// configured name noCertName with none.
type gateRig struct {
	*rig
	a      *ACME
	closed <-chan struct{}
}

// newGateRig serves a gate rig. pre can change the server before it serves.
func newGateRig(t *testing.T, tm timeouts, pre func(*Server)) *gateRig {
	t.Helper()
	a := newTestACME(t, func(p *ACMEParams) { p.Names = []string{testName, noCertName} })
	seedCert(t, a, testName)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	mustNil(t, a.Start(ctx))
	q, c := testSinks(t, 16)
	s, err := newServer(Config{TLS: &tls.Config{GetCertificate: a.GetCertificate}, MaxConns: 8, HeaderBytes: testHeaderBytes, Queue: q, Counters: c}, okHandler, tm)
	mustNil(t, err)
	g := &gateRig{rig: &rig{s: s}, a: a, closed: watchClosed(s.srv)}
	if pre != nil {
		pre(s)
	}
	g.serve(t)
	return g
}

// raw opens a TCP connection that stays open until the test ends.
func (g *gateRig) raw(t *testing.T) net.Conn {
	t.Helper()
	c, err := dialTCP(g.addr)
	mustNil(t, err)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// write sends b on a new connection. The connection stays open.
func (g *gateRig) write(t *testing.T, b []byte) {
	t.Helper()
	_, _ = g.raw(t).Write(b)
}

// handshake does a client handshake that can fail. The connection stays open.
func (g *gateRig) handshake(t *testing.T, cfg *tls.Config) {
	t.Helper()
	_ = tls.Client(g.raw(t), cfg).Handshake()
}

// want waits for the close of the connection. It checks the refused events:
// one with the reason, or none when reason is "". An event has no status, the
// address 127.0.0.1 and no marker text in its record. It also checks the count
// of the name gate and that the error log has exactly 1 line.
func (g *gateRig) want(t *testing.T, reason string, gate uint64) {
	t.Helper()
	waitClosed(t, g.closed)
	evs := g.s.refused.q.Drain()
	if reason == "" {
		if len(evs) != 0 {
			t.Fatalf("%d refused events, want none", len(evs))
		}
	} else {
		if len(evs) != 1 {
			t.Fatalf("%d refused events, want 1 with reason %s", len(evs), reason)
		}
		rec := evs[0].Record()
		if j, _ := rec.Detail.JSON(); string(j) != fmt.Sprintf(`{"reason":%q}`, reason) || rec.Status != nil || evs[0].IP() != "127.0.0.1" {
			t.Errorf("detail %s, address %s; want reason %s, no status, 127.0.0.1", j, evs[0].IP(), reason)
		}
		if s := fmt.Sprintf("%+v", rec); strings.Contains(s, "marker") {
			t.Errorf("the event holds client text: %s", s)
		}
	}
	if n := g.a.Refused(); n != gate {
		t.Errorf("the name gate refused %d, want %d", n, gate)
	}
	if n := g.s.ErrorLines(); n != 1 {
		t.Errorf("%d error log lines, want 1", n)
	}
}

func clientCfg(name string, protos ...string) *tls.Config {
	return &tls.Config{ServerName: name, NextProtos: protos, InsecureSkipVerify: true}
}

// T-S-22: the name gate gives the reason, and its count goes up by one.
func TestTS22GateReasons(t *testing.T) {
	for _, tc := range []struct {
		name, sni, reason string
		alpn              []string
	}{
		{"no server name", "", "no_server_name", nil},
		{"unknown name", otherName, "unknown_name", nil},
		{"byte of 0x80 or more", "café.test", "unknown_name", nil},
		{"unknown name with acme-tls/1", otherName, "unknown_name", []string{challengeProto}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := newGateRig(t, defaultTimeouts, nil)
			g.handshake(t, clientCfg(tc.sni, tc.alpn...))
			g.want(t, tc.reason, 1)
		})
	}
}

// T-S-22: a failure that the name gate did not refuse gives bad_hello when the
// client still sends. An unknown name keeps unknown_name only when the gate ran
// before the failure. The gate count shows this order.
func TestTS22BadHello(t *testing.T) {
	hello := func(name string, h rawHello) []byte {
		h.exts = append([]rawExt{extSNI(name)}, h.exts...)
		return h.bytes()
	}
	// The hello has version 0x0301 and no supported_versions, so it offers only
	// TLS 1.0. The version check runs before the gate.
	noVersion := rawHello{version: 0x0301, suites: []uint16{0xc02f}}
	// supported_versions holds only 0x0302: the TLS 1.3 form with no shared
	// version. This check also runs before the gate.
	noVersion13 := rawHello{version: 0x0303, suites: []uint16{0x1301}, exts: []rawExt{extVersions(0x0302), extGroups(29), extSigs(0x0804)}}
	// TLS 1.3 picks the suite before the gate. TLS 1.2 picks it after the gate.
	noSuite13 := rawHello{version: 0x0303, suites: []uint16{0xc02f}, exts: []rawExt{extVersions(0x0304), extGroups(29), extSigs(0x0804)}}
	noSuite12 := rawHello{version: 0x0303, suites: []uint16{0x1301}, exts: []rawExt{extGroups(23), extSigs(0x0403)}}
	for _, tc := range []struct {
		name   string
		noName bool // the case has no server name
		send   func(*testing.T, *gateRig, string)
		reason map[string]string // by name
		gate   map[string]uint64
	}{
		{"not TLS", true, func(t *testing.T, g *gateRig, _ string) { g.write(t, []byte("GET / HTTP/1.0\r\n\r\n")) }, nil, nil},
		{"hello that does not parse", true, func(t *testing.T, g *gateRig, _ string) { g.write(t, []byte{22, 3, 1, 0, 4, 1, 0, 0, 0}) }, nil, nil},
		{"no shared version", false, func(t *testing.T, g *gateRig, n string) { g.write(t, hello(n, noVersion)) }, nil, nil},
		{"no shared version, TLS 1.3 form", false, func(t *testing.T, g *gateRig, n string) { g.write(t, hello(n, noVersion13)) }, nil, nil},
		{"no shared suite, TLS 1.3", false, func(t *testing.T, g *gateRig, n string) { g.write(t, hello(n, noSuite13)) }, nil, nil},
		{"no shared suite, TLS 1.2", false, func(t *testing.T, g *gateRig, n string) { g.write(t, hello(n, noSuite12)) },
			map[string]string{otherName: "unknown_name"}, map[string]uint64{otherName: 1}},
		{"ALPN that is not offered", false, func(t *testing.T, g *gateRig, n string) { g.handshake(t, clientCfg(n, "h2")) }, nil, nil},
		{"ALPN that is not offered, TLS 1.2", false, func(t *testing.T, g *gateRig, n string) {
			cfg := clientCfg(n, "h2")
			cfg.MaxVersion = tls.VersionTLS12
			g.handshake(t, cfg)
		}, nil, nil},
	} {
		for _, name := range []string{testName, otherName} {
			if tc.noName && name == otherName {
				continue // these have no name
			}
			t.Run(tc.name+", "+name, func(t *testing.T) {
				g := newGateRig(t, defaultTimeouts, nil)
				tc.send(t, g, name)
				reason := "bad_hello"
				if r, ok := tc.reason[name]; ok {
					reason = r
				}
				g.want(t, reason, tc.gate[name])
			})
		}
	}
}

// T-S-22: a TLS alert from the client after its ClientHello gives bad_hello, in
// TLS 1.2 and in TLS 1.3. The client verifies the certificate. The verify
// fails, because the test certificate has no trusted root, so the client sends
// a bad_certificate alert. The connection stays open until the event is read.
func TestTS22ClientAlertAfterHello(t *testing.T) {
	for name, ver := range map[string]uint16{"TLS 1.2": tls.VersionTLS12, "TLS 1.3": tls.VersionTLS13} {
		t.Run(name, func(t *testing.T) {
			g := newGateRig(t, defaultTimeouts, nil)
			g.handshake(t, &tls.Config{ServerName: testName, MinVersion: ver, MaxVersion: ver})
			g.want(t, "bad_hello", 0)
		})
	}
}

// hookConn keeps the bytes of each Write and fails it, so a client handshake
// gives its ClientHello and stops.
type hookConn struct {
	net.Conn
	sent []byte
}

func (h *hookConn) Write(p []byte) (int, error) {
	h.sent = append(h.sent, p...)
	return 0, net.ErrClosed
}

// T-S-22: a client that resets after a full ClientHello gives no event, in TLS
// 1.2 and in TLS 1.3. The certificate callback waits until the reset is sent.
// Then the flight write of the server fails, or a later read fails.
func TestTS22ResetAfterHelloGivesNoEvent(t *testing.T) {
	for name, ver := range map[string]uint16{"TLS 1.2": tls.VersionTLS12, "TLS 1.3": tls.VersionTLS13} {
		t.Run(name, func(t *testing.T) {
			a, b := net.Pipe()
			t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
			hc := &hookConn{Conn: a}
			_ = tls.Client(hc, &tls.Config{ServerName: testName, MinVersion: ver, MaxVersion: ver}).Handshake()
			entered, release := make(chan struct{}), make(chan struct{})
			g := newGateRig(t, defaultTimeouts, func(s *Server) {
				get := s.tls.GetCertificate
				s.tls.GetCertificate = func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
					close(entered)
					<-release
					return get(h)
				}
			})
			c := g.raw(t)
			_, err := c.Write(hc.sent)
			mustNil(t, err)
			<-entered
			mustNil(t, c.(*net.TCPConn).SetLinger(0))
			mustNil(t, c.Close())
			close(release)
			g.want(t, "", 0)
		})
	}
}

// T-S-22: these give no event. A connection that read no byte. A partial
// ClientHello with a close, or with a handshake deadline. A configured name
// with no cached certificate. A failure at shutdown.
func TestTS22HandshakeGuards(t *testing.T) {
	part := hello13()[:20]
	for _, tc := range []struct {
		name string
		tm   timeouts
		pre  func(*Server)
		send func(*testing.T, *gateRig)
	}{
		{"no byte, close", defaultTimeouts, nil, func(t *testing.T, g *gateRig) { _ = g.raw(t).Close() }},
		{"partial hello, close", defaultTimeouts, nil, func(t *testing.T, g *gateRig) {
			c := g.raw(t)
			_, _ = c.Write(part)
			_ = c.Close()
		}},
		{"partial hello, deadline", shortTimeouts(), nil, func(t *testing.T, g *gateRig) {
			c := g.raw(t)
			_, _ = c.Write(part)
			closesWithin(t, c)
		}},
		{"no cached certificate", defaultTimeouts, nil, func(t *testing.T, g *gateRig) { g.handshake(t, clientCfg(noCertName)) }},
		{"shutdown", defaultTimeouts, func(s *Server) {
			hook := s.srv.ConnState
			s.srv.ConnState = func(c net.Conn, st http.ConnState) {
				if st == http.StateClosed {
					_ = s.Close()
				}
				hook(c, st)
			}
		}, func(t *testing.T, g *gateRig) { g.write(t, []byte("GET / HTTP/1.0\r\n\r\n")) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := newGateRig(t, tc.tm, tc.pre)
			tc.send(t, g)
			waitClosed(t, g.closed)
			if n := len(g.s.refused.q.Drain()); n != 0 {
				t.Fatalf("%d refused events, want none", n)
			}
		})
	}
}

// hello13 returns the bytes of a ClientHello for testName.
func hello13() []byte {
	return rawHello{version: 0x0303, suites: []uint16{0x1301}, exts: []rawExt{extSNI(testName), extVersions(0x0304)}}.bytes()
}

// T-S-17: a server name and an ALPN value of the client are in no event and no
// log line. The error log counts the failed handshakes and keeps no text. The
// answer to a good request does not change.
func TestTS17HandshakeMarkers(t *testing.T) {
	g := newGateRig(t, defaultTimeouts, nil)
	if g.s.srv.ErrorLog.Writer() != &g.s.errLines {
		t.Fatal("the server error log does not write only to the counter")
	}
	g.handshake(t, clientCfg(markerName, "http/1.1", markerALPN))
	g.want(t, "unknown_name", 1)
	if got := roundTrip(g.dialOK(t), goodHead); got != 200 {
		t.Fatalf("status %d, want 200", got)
	}
}

// dialOK does a TLS handshake for the configured name.
func (g *gateRig) dialOK(t *testing.T) *tls.Conn {
	t.Helper()
	c, err := dialTLS(g.addr, clientCfg(testName))
	mustNil(t, err)
	t.Cleanup(func() { _ = c.Close() })
	return c
}
