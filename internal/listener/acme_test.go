package listener

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	"go.uber.org/zap/zapcore"

	"github.com/cybagard/cyba-phantom/internal/egress"
	"github.com/cybagard/cyba-phantom/internal/egress/egresstest"
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

// countingStorage counts the reads of the storage under it, and the calls of
// every method.
type countingStorage struct {
	certmagic.Storage
	reads atomic.Int64
	calls atomic.Int64
}

func (c *countingStorage) Load(ctx context.Context, k string) ([]byte, error) {
	c.reads.Add(1)
	c.calls.Add(1)
	return c.Storage.Load(ctx, k)
}

func (c *countingStorage) Stat(ctx context.Context, k string) (certmagic.KeyInfo, error) {
	c.reads.Add(1)
	c.calls.Add(1)
	return c.Storage.Stat(ctx, k)
}

func (c *countingStorage) Exists(ctx context.Context, k string) bool {
	c.reads.Add(1)
	c.calls.Add(1)
	return c.Storage.Exists(ctx, k)
}

func (c *countingStorage) List(ctx context.Context, p string, r bool) ([]string, error) {
	c.reads.Add(1)
	c.calls.Add(1)
	return c.Storage.List(ctx, p, r)
}

func (c *countingStorage) Store(ctx context.Context, k string, v []byte) error {
	c.calls.Add(1)
	return c.Storage.Store(ctx, k, v)
}

func (c *countingStorage) Delete(ctx context.Context, k string) error {
	c.calls.Add(1)
	return c.Storage.Delete(ctx, k)
}

func (c *countingStorage) Lock(ctx context.Context, name string) error {
	c.calls.Add(1)
	return c.Storage.Lock(ctx, name)
}

func (c *countingStorage) Unlock(ctx context.Context, name string) error {
	c.calls.Add(1)
	return c.Storage.Unlock(ctx, name)
}

// errStorage is a storage whose methods return err, except Exists. Exists returns true.
type errStorage struct{ err error }

func (e errStorage) Lock(context.Context, string) error                   { return e.err }
func (e errStorage) Unlock(context.Context, string) error                 { return e.err }
func (e errStorage) Store(context.Context, string, []byte) error          { return e.err }
func (e errStorage) Load(context.Context, string) ([]byte, error)         { return nil, e.err }
func (e errStorage) Delete(context.Context, string) error                 { return e.err }
func (e errStorage) Exists(context.Context, string) bool                  { return true }
func (e errStorage) List(context.Context, string, bool) ([]string, error) { return nil, e.err }
func (e errStorage) Stat(context.Context, string) (certmagic.KeyInfo, error) {
	return certmagic.KeyInfo{}, e.err
}

// loadRecorder records the keys of the Load calls that reach the storage under it.
type loadRecorder struct {
	certmagic.Storage
	mu    sync.Mutex
	loads []string
}

func (l *loadRecorder) Load(ctx context.Context, k string) ([]byte, error) {
	l.mu.Lock()
	l.loads = append(l.loads, k)
	l.mu.Unlock()
	return l.Storage.Load(ctx, k)
}

func (l *loadRecorder) count(k string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, got := range l.loads {
		if got == k {
			n++
		}
	}
	return n
}

// tokenKeyOf returns the key of the challenge token file of name, from the
// values of certmagic. The issuer key goes through Safe, as in certmagic.
func tokenKeyOf(a *ACME, name string) string {
	issuer := certmagic.StorageKeys.Safe(a.cfg.Issuers[0].IssuerKey())
	return path.Join("acme", issuer, "challenge_tokens", certmagic.StorageKeys.Safe(name)+".json")
}

// prodHandshake is a handshake over a pipe with the server ALPN list of the
// decoy listener.
func prodHandshake(a *ACME, sni string, protos ...string) error {
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()
	dl := time.Now().Add(10 * time.Second)
	c.SetDeadline(dl)
	s.SetDeadline(dl)
	done := make(chan struct{})
	go func() {
		defer close(done)
		tls.Server(s, &tls.Config{GetCertificate: a.GetCertificate, NextProtos: []string{"http/1.1", challengeProto}}).Handshake()
	}()
	cl := tls.Client(c, &tls.Config{ServerName: sni, NextProtos: protos, InsecureSkipVerify: true})
	err := cl.Handshake()
	c.Close()
	<-done
	return err
}

// permitLoopback is the test address rule: the production rule, and also all
// loopback addresses.
func permitLoopback(a netip.Addr) bool { return a.IsLoopback() || egress.Permitted(a) }

// testNames returns a name set. The default CA name has a global address.
func testNames(t testing.TB) *egresstest.Names {
	n := egresstest.NewNames(t)
	n.Set("ca.test.", netip.MustParseAddr("1.1.1.1"))
	return n
}

// newTestACME builds an ACME with test values and a new store. mod changes the
// values first. The test rule permits loopback. The test resolver answers for
// the default CA name only, with a global address. A seeded certificate that
// needs no renewal makes no request. A test of the production rule sets
// egressRule to nil. It sets egressResolver to nil or to a test resolver. The
// test stops the cache when it ends.
func newTestACME(t testing.TB, mod func(*ACMEParams)) *ACME {
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

		egressRule:     permitLoopback,
		egressResolver: testNames(t).Resolver(),
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

// BenchmarkGetCertificateRefused measures one GetCertificate call for a name that
// the name gate refuses.
func BenchmarkGetCertificateRefused(b *testing.B) {
	a := newTestACME(b, nil)
	hello := &tls.ClientHelloInfo{ServerName: "other.test"}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := a.GetCertificate(hello); err == nil {
			b.Fatal("the gate accepted the name")
		}
	}
}

// BenchmarkGetCertificateAccepted measures one GetCertificate call for a
// configured name with a cached certificate.
func BenchmarkGetCertificateAccepted(b *testing.B) {
	a := newTestACME(b, nil)
	seedCert(b, a, "decoy.test")
	ctx, cancel := context.WithCancel(context.Background())
	b.Cleanup(cancel)
	mustNil(b, a.Start(ctx))
	c, s := net.Pipe()
	b.Cleanup(func() { c.Close(); s.Close() })
	hello := &tls.ClientHelloInfo{ServerName: "decoy.test", Conn: s}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := a.GetCertificate(hello); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkGetCertificateNoChallenge measures one GetCertificate call for a
// configured name with the single ALPN acme-tls/1 and no active challenge.
func BenchmarkGetCertificateNoChallenge(b *testing.B) {
	a := newTestACME(b, nil)
	hello := &tls.ClientHelloInfo{ServerName: "decoy.test", SupportedProtos: []string{"acme-tls/1"}}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := a.GetCertificate(hello); !errors.Is(err, errNoChallenge) {
			b.Fatal("the check did not refuse the handshake")
		}
	}
}

// BenchmarkGetCertificateTokenKeyRefused measures one GetCertificate call for a
// configured name with the single ALPN acme-tls/1. The lookup says that a
// challenge is active, but the certmagic map holds none. The storage refuses the
// token key.
func BenchmarkGetCertificateTokenKeyRefused(b *testing.B) {
	a := newTestACME(b, nil)
	a.challenge = func(string) (certmagic.Challenge, bool) { return certmagic.Challenge{}, true }
	c, s := net.Pipe()
	b.Cleanup(func() { c.Close(); s.Close() })
	hello := &tls.ClientHelloInfo{ServerName: "decoy.test", SupportedProtos: []string{"acme-tls/1"}, Conn: s}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := a.GetCertificate(hello); err == nil || errors.Is(err, errNoChallenge) {
			b.Fatal("the handshake did not reach the storage")
		}
	}
}

// issuerProxyRefuses reports whether the proxy function of iss refuses a
// request to another host. It does not set a proxy in the environment.
// net/http reads that environment one time for each process. So a test that
// sets it depends on the order of the tests. The guard does not read the
// environment. A guard that calls http.ProxyFromEnvironment never gives
// errEgress, so this check returns false.
func issuerProxyRefuses(t *testing.T, iss *certmagic.ACMEIssuer) bool {
	t.Helper()
	if iss.HTTPProxy == nil {
		return false
	}
	req, err := http.NewRequest(http.MethodGet, "https://other.test/dir", nil)
	mustNil(t, err)
	u, err := iss.HTTPProxy(req)
	return errors.Is(err, errEgress) && u == nil
}

func TestTS16ConfigHasOneIssuerForTheCA(t *testing.T) {
	// given is the store that newTestACME made.
	var given certmagic.Storage
	a := newTestACME(t, func(p *ACMEParams) { given = p.Storage; p.Port = 9443 })
	cfg := a.cfg
	wrap, _ := cfg.Storage.(*noTokenStorage)
	if wrap == nil || given == nil || wrap.Storage != given || len(cfg.Issuers) != 1 {
		t.Fatalf("storage is the wrapper of the given storage: %v, issuers: %d", wrap != nil && wrap.Storage == given, len(cfg.Issuers))
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

// egressGuardChildEnv tells the test binary to run the checks of the egress
// guard test in this process.
const egressGuardChildEnv = "PHANTOM_TEST_EGRESS_GUARD_CHILD"

// TestTS16EgressGuardRefusesOtherRequests: the guard allows the CA and refuses
// all other requests. net/http reads the proxy environment one time for each
// process. An earlier test can make it read the environment first. Then a proxy
// that this test sets later is not seen. So the checks run in a child process
// of the test binary. The parent sets the proxy variables in the environment
// of the child, and net/http reads them fresh there. In that case, a guard
// that reads the environment gives the proxy URL, and the child fails. The
// parent fails when the child fails, and it prints the output of the child.
// The pattern of the child comes from the name of this test. The parent also
// fails when the output of the child has no PASS line for this test. So a
// child that ran no test cannot pass.
func TestTS16EgressGuardRefusesOtherRequests(t *testing.T) {
	if os.Getenv(egressGuardChildEnv) == "" {
		cmd := exec.Command(os.Args[0],
			"-test.run=^"+regexp.QuoteMeta(t.Name())+"$", "-test.count=1",
			"-test.v=true")
		cmd.Env = append(os.Environ(), egressGuardChildEnv+"=1",
			"HTTPS_PROXY=http://proxy.test:3128", "HTTP_PROXY=http://proxy.test:3128",
			"NO_PROXY=", "no_proxy=")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("the child process failed: %v\n%s", err, out)
		}
		if !bytes.Contains(out, []byte("--- PASS: "+t.Name())) {
			t.Fatalf("the child process did not run the checks:\n%s", out)
		}
		t.Logf("child output:\n%s", out)
		return
	}
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

// TestTS21GuardComparesLiteralsAsAddresses: an IP-literal host is the same
// authority when it parses to the same unmapped address. Then the rule sees
// that address. A zone is refused before the rule.
func TestTS21GuardComparesLiteralsAsAddresses(t *testing.T) {
	global, other := netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("2001:db8::1")
	for _, c := range []struct {
		ca, req string
		calls   []netip.Addr // the addresses that the rule saw
		refuse  bool
	}{
		{"https://[2001:DB8:0::1]/", "https://[2001:db8::1]/", []netip.Addr{other}, true},
		{"https://[::ffff:8.8.8.8]/", "https://8.8.8.8/", []netip.Addr{global}, false},
		{"https://8.8.8.8/", "https://[::ffff:8.8.8.8]/", []netip.Addr{global}, false},
		{"https://8.8.8.8/", "https://8.8.4.4/", nil, true},
		{"https://[fe80::1%25eth0]/", "https://[fe80::1%25eth0]/", nil, true},
		{"https://[fe80::1%25eth0]/", "https://[fe80::1]/", nil, true},
	} {
		var calls []netip.Addr
		rule := func(a netip.Addr) bool { calls = append(calls, a); return a == global }
		ca, err := url.Parse(c.ca)
		mustNil(t, err)
		req, err := http.NewRequest(http.MethodGet, c.req, nil)
		mustNil(t, err)
		u, err := egressGuard(ca, nil, rule, testNames(t).Resolver())(req)
		if (err != nil) != c.refuse || u != nil || !slices.Equal(calls, c.calls) {
			t.Errorf("%s vs %s: proxy = %v, %v; rule saw %v; want refuse = %v, %v", c.ca, c.req, u, err, calls, c.refuse, c.calls)
		}
		if err != nil && err != errEgress {
			t.Errorf("%s vs %s: error is not the fixed error: %v", c.ca, c.req, err)
		}
	}
}

// TestTS21GuardChecksEveryAddressOfAName: a name passes only when the lookup
// works and every address passes the production rule.
func TestTS21GuardChecksEveryAddressOfAName(t *testing.T) {
	names := egresstest.NewNames(t)
	names.Set("ok.test.", netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("2001:4860:4860::8888"))
	names.Set("mixed.test.", netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("10.0.0.1"))
	names.Set("mapped.test.", netip.MustParseAddr("::ffff:127.0.0.1"))
	names.Set("empty.test.")
	for _, c := range []struct {
		name   string
		refuse bool
	}{{"ok.test", false}, {"OK.test", false}, {"mixed.test", true}, {"mapped.test", true}, {"empty.test", true}, {"gone.test", true}} {
		ca, err := url.Parse("https://" + c.name + "/")
		mustNil(t, err)
		req, err := http.NewRequest(http.MethodGet, "https://"+c.name+"/dir", nil)
		mustNil(t, err)
		u, err := egressGuard(ca, nil, egress.Permitted, names.Resolver())(req)
		if (err != nil) != c.refuse || u != nil || (err != nil && err != errEgress) {
			t.Errorf("%s: proxy = %v, %v; want refuse = %v", c.name, u, err, c.refuse)
		}
	}
}

func TestTS16NameGateRefusesBeforeCertmagic(t *testing.T) {
	var logs, std syncBuf
	old := log.Writer()
	log.SetOutput(&std)
	t.Cleanup(func() { log.SetOutput(old) })
	var egress atomic.Int64
	var cs *countingStorage
	a := newTestACME(t, func(p *ACMEParams) {
		cs = &countingStorage{Storage: p.Storage}
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

func TestTS16ACMETLSALPNForAConfiguredNameNeedsAnActiveChallenge(t *testing.T) {
	var logs, std syncBuf
	old := log.Writer()
	log.SetOutput(&std)
	t.Cleanup(func() { log.SetOutput(old) })
	var egress atomic.Int64
	var cs *countingStorage
	a := newTestACME(t, func(p *ACMEParams) {
		cs = &countingStorage{Storage: p.Storage}
		p.Storage = cs
		p.Logger = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
		p.OnEgress = func(string) { egress.Add(1) }
	})
	// No issuance runs, so no challenge is active for the name.
	for range 100 {
		if _, err := handshake(a, "decoy.test", "acme-tls/1"); err == nil {
			t.Fatal("handshake with ALPN acme-tls/1 and no active challenge worked")
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
	if got := a.Refused(); got != 100 {
		t.Errorf("refused = %d", got)
	}
}

func TestTS16NoStorageReadWhenTheChallengeEndsBeforeTheLookup(t *testing.T) {
	var logs, std syncBuf
	old := log.Writer()
	log.SetOutput(&std)
	t.Cleanup(func() { log.SetOutput(old) })
	var egress atomic.Int64
	var cs *countingStorage
	a := newTestACME(t, func(p *ACMEParams) {
		cs = &countingStorage{Storage: p.Storage}
		p.Storage = cs
		p.Logger = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
		p.OnEgress = func(string) { egress.Add(1) }
	})
	// The recorder sees each key that certmagic gives to the storage.
	rec := &loadRecorder{Storage: a.cfg.Storage}
	a.cfg.Storage = rec
	// The seam says that the challenge is active, but the map of certmagic has no
	// entry. This is the state of the window after the end of a challenge.
	a.challenge = func(name string) (certmagic.Challenge, bool) { return certmagic.Challenge{}, name == "decoy.test" }
	const total, workers = 4000, 8
	var next, worked atomic.Int64
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			for next.Add(1) <= total {
				if prodHandshake(a, "decoy.test", "acme-tls/1") == nil {
					worked.Add(1)
				}
			}
		})
	}
	wg.Wait()
	if w := worked.Load(); w != 0 {
		t.Errorf("handshakes that worked: %d", w)
	}
	if r := cs.reads.Load(); r != 0 {
		t.Errorf("storage reads: %d", r)
	}
	if got := a.Refused(); got != 0 {
		t.Errorf("refused = %d: the gate did not let each handshake through", got)
	}
	if e := egress.Load(); e != 0 {
		t.Errorf("guard calls: %d", e)
	}
	if logs.String() != "" || std.String() != "" {
		t.Errorf("log output: %q %q", logs.String(), std.String())
	}
	if n := rec.count(tokenKeyOf(a, "decoy.test")); n != total {
		t.Errorf("the token key reached the wrapper %d times; want %d, one for each handshake", n, total)
	}
}

func TestTS16StorageRefusesTokenKeysAndPassesOtherKeys(t *testing.T) {
	a := newTestACME(t, nil)
	rawIssuer := a.cfg.Issuers[0].IssuerKey()
	issuer := certmagic.StorageKeys.Safe(rawIssuer)
	wrap := func(under certmagic.Storage) *noTokenStorage { return newNoTokenStorage(under, rawIssuer) }
	sentinel := errors.New("storage under the wrapper")
	ctx := context.Background()
	tokenKeys := []string{
		tokenKeyOf(a, "decoy.test"),
		path.Join("acme", issuer, "challenge_tokens"), // the prefix, as List gets it
		"acme/" + issuer + "/challenge_tokens/",
		"acme/" + issuer + "/challenge_tokens/a/b.json",
	}
	for _, k := range tokenKeys {
		under := &countingStorage{Storage: errStorage{sentinel}}
		w := wrap(under)
		if _, err := w.Load(ctx, k); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("Load(%q) = %v", k, err)
		}
		if _, err := w.Stat(ctx, k); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("Stat(%q) = %v", k, err)
		}
		if _, err := w.List(ctx, k, true); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("List(%q) = %v", k, err)
		}
		if w.Exists(ctx, k) {
			t.Errorf("Exists(%q) = true", k)
		}
		if err := w.Store(ctx, k, []byte("x")); err != errTokenStore {
			t.Errorf("Store(%q) = %v", k, err)
		}
		if err := w.Delete(ctx, k); err != errTokenStore {
			t.Errorf("Delete(%q) = %v", k, err)
		}
		if strings.Contains(errTokenStore.Error(), "challenge_tokens/") {
			t.Errorf("error text holds a key: %v", errTokenStore)
		}
		if n := under.calls.Load(); n != 0 {
			t.Errorf("%q: the storage under the wrapper got %d calls", k, n)
		}
	}
	passKeys := []string{
		"certificates/" + issuer + "/challenge_tokens.example/x.crt",
		"acme/" + issuer + "/accounts/acct/key.json",
		"acme/" + issuer + "/challenge_tokensx/decoy.test.json",
		"challenge_tokens/decoy.test.json",
		// Not the key that certmagic builds for this CA, so it passes. The exact
		// prefix test refuses this form for a CA whose issuer element collapses.
		"acme/challenge_tokens/decoy.test.json",
		"certificates/" + issuer + "/challenge_tokens/x.crt", // the first element is not "acme"
		"acme",
		"",
	}
	for _, k := range passKeys {
		for _, c := range []struct {
			name string
			call func(w *noTokenStorage) error
		}{
			{"Load", func(w *noTokenStorage) error { _, err := w.Load(ctx, k); return err }},
			{"Stat", func(w *noTokenStorage) error { _, err := w.Stat(ctx, k); return err }},
			{"List", func(w *noTokenStorage) error { _, err := w.List(ctx, k, false); return err }},
			{"Store", func(w *noTokenStorage) error { return w.Store(ctx, k, nil) }},
			{"Delete", func(w *noTokenStorage) error { return w.Delete(ctx, k) }},
		} {
			under := &countingStorage{Storage: errStorage{sentinel}}
			if err := c.call(wrap(under)); err != sentinel {
				t.Errorf("%s(%q) = %v; want the error of the storage under the wrapper", c.name, k, err)
			}
			if n := under.calls.Load(); n != 1 {
				t.Errorf("%s(%q): the storage under the wrapper got %d calls", c.name, k, n)
			}
		}
		under := &countingStorage{Storage: errStorage{sentinel}}
		if !wrap(under).Exists(ctx, k) || under.calls.Load() != 1 {
			t.Errorf("Exists(%q) did not pass through", k)
		}
	}
	under := &countingStorage{Storage: errStorage{sentinel}}
	w := wrap(under)
	if err := w.Lock(ctx, tokenKeys[0]); err != sentinel {
		t.Errorf("Lock = %v", err)
	}
	if err := w.Unlock(ctx, tokenKeys[0]); err != sentinel {
		t.Errorf("Unlock = %v", err)
	}
	if n := under.calls.Load(); n != 2 {
		t.Errorf("Lock and Unlock: the storage under the wrapper got %d calls", n)
	}
	// A missing key of the storage under the wrapper comes back unchanged.
	missing := wrap(errStorage{fs.ErrNotExist})
	if _, err := missing.Load(ctx, "acme/"+issuer+"/accounts/acct/key.json"); err != fs.ErrNotExist {
		t.Errorf("Load of a missing key = %v", err)
	}
	var sink bool
	if n := testing.AllocsPerRun(100, func() { sink = w.refuses(tokenKeys[0]) }); n != 0 || !sink {
		t.Errorf("allocations of the match: %v", n)
	}
	if n := testing.AllocsPerRun(100, func() { sink = w.refuses(passKeys[0]) }); n != 0 || sink {
		t.Errorf("allocations of the match for a key that passes: %v", n)
	}
}

// TestTS16StorageRefusesTheExactIssuerPrefix: path.Join can collapse the issuer
// element of a token key. For a CA whose host is ".", "..", or has no word
// character, the key that certmagic builds has no issuer element. The wrapper
// refuses that key because it holds the exact token prefix of the issuer.
func TestTS16StorageRefusesTheExactIssuerPrefix(t *testing.T) {
	sentinel := errors.New("storage under the wrapper")
	ctx := context.Background()
	for _, c := range []struct {
		ca        string
		collapsed bool // the issuer element is empty after Safe and path.Join
	}{
		{"https://ca.test/dir", false},
		{"https://CA.Test/a/b/", false},
		{"https://.", true},
		{"https://..", true},
		{"https://!", true},
		{"https://!/", true},
	} {
		t.Run(c.ca, func(t *testing.T) {
			under := &countingStorage{Storage: errStorage{sentinel}}
			a := newTestACME(t, func(p *ACMEParams) { p.CA, p.Storage = c.ca, under })
			iss := a.cfg.Issuers[0]
			if got, want := (&certmagic.ACMEIssuer{CA: c.ca}).IssuerKey(), iss.IssuerKey(); got != want {
				t.Fatalf("issuer key before certmagic.New = %q; the issuer has %q", got, want)
			}
			w, _ := a.cfg.Storage.(*noTokenStorage)
			if w == nil {
				t.Fatalf("storage is %T", a.cfg.Storage)
			}
			want := path.Join("acme", certmagic.StorageKeys.Safe(iss.IssuerKey()), "challenge_tokens")
			if w.prefix != want || w.prefixSlash != want+"/" {
				t.Fatalf("prefix = %q and %q; want %q", w.prefix, w.prefixSlash, want)
			}
			key := tokenKeyOf(a, "decoy.test")
			if collapsed := key == "acme/challenge_tokens/decoy.test.json"; collapsed != c.collapsed {
				t.Fatalf("key = %q; collapsed = %v, want %v", key, collapsed, c.collapsed)
			}
			for _, k := range []string{key, w.prefix, w.prefixSlash} {
				if _, err := w.Load(ctx, k); !errors.Is(err, fs.ErrNotExist) {
					t.Errorf("Load(%q) = %v", k, err)
				}
				if _, err := w.Stat(ctx, k); !errors.Is(err, fs.ErrNotExist) {
					t.Errorf("Stat(%q) = %v", k, err)
				}
				if _, err := w.List(ctx, k, true); !errors.Is(err, fs.ErrNotExist) {
					t.Errorf("List(%q) = %v", k, err)
				}
				if w.Exists(ctx, k) {
					t.Errorf("Exists(%q) = true", k)
				}
				if err := w.Store(ctx, k, nil); err != errTokenStore {
					t.Errorf("Store(%q) = %v", k, err)
				}
				if err := w.Delete(ctx, k); err != errTokenStore {
					t.Errorf("Delete(%q) = %v", k, err)
				}
			}
			if n := under.calls.Load(); n != 0 {
				t.Errorf("the storage under the wrapper got %d calls", n)
			}
			var sink bool
			if n := testing.AllocsPerRun(100, func() { sink = w.refuses(key) }); n != 0 || !sink {
				t.Errorf("allocations of the match: %v", n)
			}
			// A key next to the prefix is not a token key.
			for _, k := range []string{w.prefix + "x", w.prefix + "x/decoy.test.json"} {
				if err := w.Store(ctx, k, nil); err != sentinel {
					t.Errorf("Store(%q) = %v; want the error of the storage under the wrapper", k, err)
				}
			}
		})
	}
}

func TestTS16ACMETLSALPNWithTwoProtocolsIsNotRefused(t *testing.T) {
	a := newTestACME(t, nil)
	want := seedCert(t, a, "decoy.test")
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	mustNil(t, a.Start(ctx))
	for _, protos := range [][]string{{"acme-tls/1", "http/1.1"}, {"http/1.1", "acme-tls/1"}} {
		if st, err := handshake(a, "decoy.test", protos...); err != nil || !bytes.Equal(st.PeerCertificates[0].Raw, want) {
			t.Fatalf("handshake with %v: %v", protos, err)
		}
	}
	if got := a.Refused(); got != 0 {
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
	var cs *countingStorage
	a := newTestACME(t, func(p *ACMEParams) {
		cs = &countingStorage{Storage: p.Storage}
		p.Names = []string{"kiosk.test"}
		p.Storage = cs
	})
	// U+212A KELVIN SIGN: a Unicode-aware ToLower maps it to "k".
	names := []string{string(rune(0x212a)) + "iosk.test", "kiosk.testé", "\xffkiosk.test"}
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

func TestTS16ACMETLSALPNLooksUpTheNormalizedName(t *testing.T) {
	a := newTestACME(t, nil)
	// A new ACME has the lookup of certmagic. With no issuance, no challenge is active.
	if a.challenge == nil {
		t.Fatal("the lookup of an active challenge is not set")
	}
	if _, active := a.challenge("decoy.test"); active {
		t.Fatal("a challenge is active with no issuance")
	}
	var calls []string
	a.challenge = func(name string) (certmagic.Challenge, bool) {
		calls = append(calls, name)
		return certmagic.Challenge{}, false
	}
	// The Go TLS client removes a trailing dot from the server name. Thus this
	// test calls GetCertificate directly.
	for _, form := range []string{"decoy.test", "DECOY.TEST", "decoy.test.", "Decoy.Test."} {
		calls = nil
		hello := &tls.ClientHelloInfo{ServerName: form, SupportedProtos: []string{"acme-tls/1"}}
		if _, err := a.GetCertificate(hello); !errors.Is(err, errNoChallenge) {
			t.Errorf("%q: error = %v", form, err)
		}
		if !slices.Equal(calls, []string{"decoy.test"}) {
			t.Errorf("%q: the lookup got %q", form, calls)
		}
	}
	// The lookup is not called for two protocols, nor for a name that is not configured.
	seedCert(t, a, "decoy.test")
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	mustNil(t, a.Start(ctx))
	c, s := net.Pipe()
	t.Cleanup(func() { c.Close(); s.Close() })
	calls = nil
	two := &tls.ClientHelloInfo{ServerName: "decoy.test", SupportedProtos: []string{"acme-tls/1", "http/1.1"}, Conn: s}
	other := &tls.ClientHelloInfo{ServerName: "other.test", SupportedProtos: []string{"acme-tls/1"}, Conn: s}
	if _, err := a.GetCertificate(two); err != nil {
		t.Errorf("two protocols: %v", err)
	}
	if _, err := a.GetCertificate(other); !errors.Is(err, errName) {
		t.Errorf("name that is not configured: %v", err)
	}
	if len(calls) != 0 {
		t.Errorf("the lookup got %q", calls)
	}
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
