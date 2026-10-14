package listener

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	"go.uber.org/zap/zapcore"
)

// syncBuf is a bytes.Buffer that many goroutines can write.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// countingStorage counts the reads of the storage under it.
type countingStorage struct {
	certmagic.Storage
	reads atomic.Int64
}

func (c *countingStorage) Load(ctx context.Context, k string) ([]byte, error) {
	c.reads.Add(1)
	return c.Storage.Load(ctx, k)
}

func (c *countingStorage) Stat(ctx context.Context, k string) (certmagic.KeyInfo, error) {
	c.reads.Add(1)
	return c.Storage.Stat(ctx, k)
}

func (c *countingStorage) Exists(ctx context.Context, k string) bool {
	c.reads.Add(1)
	return c.Storage.Exists(ctx, k)
}

func (c *countingStorage) List(ctx context.Context, p string, r bool) ([]string, error) {
	c.reads.Add(1)
	return c.Storage.List(ctx, p, r)
}

// newTestACME builds an ACME with test values. mod changes the values first. The
// test stops the cache when it ends.
func newTestACME(t *testing.T, mod func(*ACMEParams)) *ACME {
	t.Helper()
	st, _ := newStore(t)
	p := ACMEParams{
		Names:   []string{"decoy.test"},
		CA:      "https://ca.test/dir",
		Email:   "ops@example.test",
		Storage: st,
		Host:    "127.0.0.1",
		Port:    8443,
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	if mod != nil {
		mod(&p)
	}
	a, err := NewACME(p)
	mustNil(t, err)
	t.Cleanup(a.Stop)
	return a
}

// handshake makes a TLS handshake over a pipe with the GetCertificate of a. The
// client does not check the certificate.
func handshake(a *ACME, serverName string, protos ...string) (tls.ConnectionState, error) {
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()
	dl := time.Now().Add(10 * time.Second)
	c.SetDeadline(dl)
	s.SetDeadline(dl)
	done := make(chan struct{})
	go func() {
		defer close(done)
		tls.Server(s, &tls.Config{GetCertificate: a.GetCertificate}).Handshake()
	}()
	cl := tls.Client(c, &tls.Config{ServerName: serverName, NextProtos: protos, InsecureSkipVerify: true})
	err := cl.Handshake()
	c.Close()
	<-done
	return cl.ConnectionState(), err
}

// issuerProxyRefuses reports whether the proxy function of iss refuses a request
// to another host, with a proxy in the environment.
func issuerProxyRefuses(t *testing.T, iss *certmagic.ACMEIssuer) bool {
	t.Helper()
	t.Setenv("HTTPS_PROXY", "http://proxy.test:3128")
	if iss.HTTPProxy == nil {
		return false
	}
	req, err := http.NewRequest(http.MethodGet, "https://other.test/dir", nil)
	mustNil(t, err)
	u, err := iss.HTTPProxy(req)
	return errors.Is(err, errEgress) && u == nil
}

func TestTS16ConfigHasOneIssuerForTheCA(t *testing.T) {
	st, _ := newStore(t)
	a := newTestACME(t, func(p *ACMEParams) { p.Storage = st; p.Port = 9443 })
	cfg := a.cfg
	if cfg.Storage != certmagic.Storage(st) || len(cfg.Issuers) != 1 {
		t.Fatalf("storage is the given storage: %v, issuers: %d", cfg.Storage == certmagic.Storage(st), len(cfg.Issuers))
	}
	iss, ok := cfg.Issuers[0].(*certmagic.ACMEIssuer)
	if !ok {
		t.Fatalf("issuer type %T", cfg.Issuers[0])
	}
	for name, ok := range map[string]bool{
		"CA":                   iss.CA == "https://ca.test/dir",
		"TestCA equals CA":     iss.TestCA == iss.CA,
		"Email":                iss.Email == "ops@example.test",
		"Agreed":               iss.Agreed,
		"no external account":  iss.ExternalAccount == nil,
		"no DNS-01 solver":     iss.DNS01Solver == nil,
		"HTTP-01 off":          iss.DisableHTTPChallenge,
		"distributed off":      iss.DisableDistributedSolvers,
		"TLS-ALPN-01 on":       !iss.DisableTLSALPNChallenge,
		"listen host":          iss.ListenHost == "127.0.0.1",
		"TLS-ALPN port":        iss.AltTLSALPNPort == 9443,
		"OCSP stapling off":    cfg.OCSP.DisableStapling,
		"no Must-Staple":       !cfg.MustStaple,
		"no on-demand":         cfg.OnDemand == nil,
		"renewal ratio":        cfg.RenewalWindowRatio == 0.35,
		"ARI on":               !cfg.DisableARI,
		"OCSP proxy is set":    cfg.OCSP.HTTPProxy != nil,
		"issuer proxy refuses": issuerProxyRefuses(t, iss),
		"config log is off":    !cfg.Logger.Core().Enabled(zapcore.ErrorLevel),
		"issuer log is off":    !iss.Logger.Core().Enabled(zapcore.ErrorLevel),
	} {
		if !ok {
			t.Errorf("%s is wrong", name)
		}
	}
}

func TestTS16EgressGuardRefusesOtherRequests(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://proxy.test:3128")
	t.Setenv("HTTP_PROXY", "http://proxy.test:3128")
	var mu sync.Mutex
	var seen []string
	a := newTestACME(t, func(p *ACMEParams) {
		p.CA = "https://CA.test:443/dir"
		p.OnEgress = func(h string) { mu.Lock(); seen = append(seen, h); mu.Unlock() }
	})
	iss := a.cfg.Issuers[0].(*certmagic.ACMEIssuer)
	for who, proxy := range map[string]func(*http.Request) (*url.URL, error){"acme": iss.HTTPProxy, "ocsp": a.cfg.OCSP.HTTPProxy} {
		for _, c := range []struct {
			url    string
			refuse bool
		}{
			{"https://ca.test/dir", false},
			{"https://Ca.Test:443/acme/new-order", false},
			{"https://other.test/dir", true},
			{"https://ca.test:8443/dir", true},
			{"http://ca.test/dir", true},
			{"http://ca.test:443/dir", true},
		} {
			req, err := http.NewRequest(http.MethodGet, c.url, nil)
			mustNil(t, err)
			u, err := proxy(req)
			if (err != nil) != c.refuse || u != nil {
				t.Errorf("%s: %s: proxy = %v, %v; refuse = %v", who, c.url, u, err, c.refuse)
			}
			if err != nil && strings.Contains(err.Error(), "other.test") {
				t.Errorf("%s: error text holds the host: %v", who, err)
			}
		}
	}
	if len(seen) != 12 || !slices.Contains(seen, "other.test") {
		t.Errorf("the hook saw %v", seen)
	}
}

func TestTS16NameGateRefusesBeforeCertmagic(t *testing.T) {
	var logs, std syncBuf
	old := log.Writer()
	log.SetOutput(&std)
	t.Cleanup(func() { log.SetOutput(old) })
	var egress atomic.Int64
	st, _ := newStore(t)
	cs := &countingStorage{Storage: st}
	a := newTestACME(t, func(p *ACMEParams) {
		p.Storage = cs
		p.Logger = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
		p.OnEgress = func(string) { egress.Add(1) }
	})
	names := []string{"", "decoy.test.evil", "xdecoy.test"}
	for range 1000 {
		names = append(names, fmt.Sprintf("%016x.test", rand.Uint64()))
	}
	for _, n := range names {
		for _, protos := range [][]string{nil, {"acme-tls/1"}} {
			if _, err := handshake(a, n, protos...); err == nil {
				t.Fatalf("handshake for %q with %v worked", n, protos)
			}
		}
	}
	if r := cs.reads.Load(); r != 0 {
		t.Errorf("storage reads: %d", r)
	}
	if e := egress.Load(); e != 0 {
		t.Errorf("guard calls: %d", e)
	}
	if logs.String() != "" || std.String() != "" {
		t.Errorf("log output: %q %q", logs.String(), std.String())
	}
	if got := a.Refused(); got != uint64(2*len(names)) {
		t.Errorf("refused = %d", got)
	}
}

func TestTS16NameGateAcceptsConfiguredNameVariants(t *testing.T) {
	a := newTestACME(t, nil)
	want := seedCert(t, a, "decoy.test")
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	mustNil(t, a.Start(ctx))
	if st, err := handshake(a, "DECOY.Test"); err != nil || !bytes.Equal(st.PeerCertificates[0].Raw, want) {
		t.Fatalf("upper-case name: %v", err)
	}
	// The Go TLS client removes a trailing dot from the server name. Thus this
	// test calls GetCertificate directly.
	c, s := net.Pipe()
	t.Cleanup(func() { c.Close(); s.Close() })
	cert, err := a.GetCertificate(&tls.ClientHelloInfo{ServerName: "decoy.test.", Conn: s})
	if err != nil || !bytes.Equal(cert.Certificate[0], want) {
		t.Fatalf("name with a trailing dot: %v", err)
	}
	if a.Refused() != 0 {
		t.Errorf("refused = %d", a.Refused())
	}
	// The gate removes one trailing dot only.
	if _, err := a.GetCertificate(&tls.ClientHelloInfo{ServerName: "decoy.test..", Conn: s}); !errors.Is(err, errName) {
		t.Errorf("name with two trailing dots: %v", err)
	}
}

func TestTS16NameGateRefusesAByteAbove0x7f(t *testing.T) {
	st, _ := newStore(t)
	cs := &countingStorage{Storage: st}
	a := newTestACME(t, func(p *ACMEParams) { p.Names = []string{"kiosk.test"}; p.Storage = cs })
	// U+212A KELVIN SIGN: a Unicode-aware ToLower maps it to "k".
	names := []string{"Kiosk.test", "kiosk.testé", "\xffkiosk.test"}
	for _, n := range names {
		for _, protos := range [][]string{nil, {"acme-tls/1"}} {
			if _, err := handshake(a, n, protos...); err == nil {
				t.Errorf("handshake for %q with %v worked", n, protos)
			}
		}
	}
	if r := cs.reads.Load(); r != 0 {
		t.Errorf("storage reads: %d", r)
	}
	if got := a.Refused(); got != uint64(2*len(names)) {
		t.Errorf("refused = %d", got)
	}
}

func TestTS16NewACMERefusesBadInput(t *testing.T) {
	st, _ := newStore(t)
	for _, c := range []struct {
		name string
		mod  func(*ACMEParams)
	}{
		{"no name", func(p *ACMEParams) { p.Names = nil }},
		{"17 names", func(p *ACMEParams) {
			p.Names = nil
			for i := range 17 {
				p.Names = append(p.Names, fmt.Sprintf("n%d.test", i))
			}
		}},
		{"empty name", func(p *ACMEParams) { p.Names = []string{"decoy.test", ""} }},
		{"upper-case letter", func(p *ACMEParams) { p.Names = []string{"Decoy.test"} }},
		{"byte above 0x7f", func(p *ACMEParams) { p.Names = []string{"décoy.test"} }},
		{"trailing dot", func(p *ACMEParams) { p.Names = []string{"decoy.test."} }},
		{"duplicate name", func(p *ACMEParams) { p.Names = []string{"decoy.test", "other.test", "decoy.test"} }},
		{"CA with http", func(p *ACMEParams) { p.CA = "http://ca.test/dir" }},
		{"CA with user info", func(p *ACMEParams) { p.CA = "https://u:p@ca.test/dir" }},
		{"CA with a fragment", func(p *ACMEParams) { p.CA = "https://ca.test/dir#frag" }},
		{"CA with an empty fragment", func(p *ACMEParams) { p.CA = "https://ca.test/dir#" }},
		{"CA port 0", func(p *ACMEParams) { p.CA = "https://ca.test:0/dir" }},
		{"CA port 65536", func(p *ACMEParams) { p.CA = "https://ca.test:65536/dir" }},
		{"CA port 99999", func(p *ACMEParams) { p.CA = "https://ca.test:99999/dir" }},
		{"no storage", func(p *ACMEParams) { p.Storage = nil }},
		{"no logger", func(p *ACMEParams) { p.Logger = nil }},
		{"port 0", func(p *ACMEParams) { p.Port = 0 }},
		{"port 65536", func(p *ACMEParams) { p.Port = 65536 }},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := ACMEParams{
				Names: []string{"decoy.test"}, CA: "https://ca.test/dir", Email: "ops@example.test",
				Storage: st, Host: "127.0.0.1", Port: 8443, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
			}
			c.mod(&p)
			a, err := NewACME(p)
			if err == nil {
				a.Stop()
				t.Fatal("NewACME accepted the input")
			}
		})
	}
	// A CA URL with the highest port is valid.
	newTestACME(t, func(p *ACMEParams) { p.CA = "https://ca.test:65535/dir" })
}

func TestTS16StopCanBeCalledTwice(t *testing.T) {
	a := newTestACME(t, nil)
	a.Stop()
	a.Stop() // the cleanup of newTestACME calls Stop a third time
}

func TestTS16EventLinesAreWrittenForThreeEventsOnly(t *testing.T) {
	var logs syncBuf
	a := newTestACME(t, func(p *ACMEParams) {
		p.CA = "https://" + closedAddr(t)
		p.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	})
	seedCert(t, a, "decoy.test")
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	// Start loads the cached certificate. certmagic emits cached_managed_cert.
	mustNil(t, a.Start(ctx))
	if _, err := handshake(a, "decoy.test"); err != nil {
		t.Fatal(err)
	}
	for _, event := range []string{"cached_managed_cert", "cached_unmanaged_cert", "cert_ocsp_revoked", "tls_get_certificate"} {
		mustNil(t, a.cfg.OnEvent(ctx, event, map[string]any{"identifier": "decoy.test", "sans": []string{"decoy.test"}}))
	}
	if out := logs.String(); out != "" {
		t.Errorf("log output: %q", out)
	}
}

func TestTS16EventLinesHoldTheConfiguredNameOnly(t *testing.T) {
	var logs syncBuf
	a := newTestACME(t, func(p *ACMEParams) { p.Logger = slog.New(slog.NewTextHandler(&logs, nil)) })
	mustNil(t, a.cfg.OnEvent(context.Background(), "cert_failed", map[string]any{
		"identifier": "decoy.test", "error": "dial 203.0.113.9: /private/path",
	}))
	mustNil(t, a.cfg.OnEvent(context.Background(), "cert_obtaining", map[string]any{"identifier": "client-chosen.test"}))
	out := logs.String()
	if !strings.Contains(out, "event=cert_failed name=decoy.test") || strings.Contains(out, "203.0.113.9") ||
		strings.Contains(out, "/private/path") || strings.Contains(out, "client-chosen") {
		t.Errorf("log lines: %q", out)
	}
	if a.cfg.ShouldEmitFunc("tls_get_certificate") || !a.cfg.ShouldEmitFunc("cert_obtained") {
		t.Error("ShouldEmitFunc gives the wrong answer")
	}
}
