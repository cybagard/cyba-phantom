package listener

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"maps"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/letsencrypt/pebble/v2/core"

	"github.com/cybagard/cyba-phantom/internal/egress/egresstest"
	"github.com/cybagard/cyba-phantom/internal/testutil"
)

const issueLimit = 120 * time.Second // the most time that the listener can take to obtain a certificate

// issueWait is the wait of a test that needs a certificate, but does not check
// the time limit. A normal issuance takes about 1 s. A test fails after this
// wait.
const issueWait = 30 * time.Second

// startIssue calls Start with the context of the test.
func startIssue(t *testing.T, f *issueFixture) time.Time {
	t.Helper()
	begin := time.Now()
	mustNil(t, f.a.Start(t.Context()))
	return begin
}

// refuseFirstOrder answers the first new-order request with an ACME error. It
// counts the new-order requests in orders.
func refuseFirstOrder(next http.Handler, orders *atomic.Int64) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == newOrderPath && orders.Add(1) == 1 {
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(http.StatusForbidden)
			io.WriteString(w, `{"type":"urn:ietf:params:acme:error:rejectedIdentifier","detail":"first order refused","status":403}`)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// TestTI01ObtainsACertificateFromPebble: Pebble in the test process on loopback
// and no other network. After Start, a handshake with the test name gets a
// certificate that ends at the root of Pebble, in 120 s or less. The guard sees
// the authority of Pebble only.
func TestTI01ObtainsACertificateFromPebble(t *testing.T) {
	f := newIssueFixture(t, "obtain.phantom.test", nil, nil)
	begin := startIssue(t, f)
	chain := f.waitChain(t, issueLimit, func(*x509.Certificate) bool { return true })
	elapsed := time.Since(begin)
	t.Logf("certificate served %v after Start", elapsed)
	if elapsed > issueLimit {
		t.Errorf("obtain took %v", elapsed)
	}
	f.verifyToPebble(t, chain)
	f.onlyPebble(t, "after obtain")
	f.requireALPN(t)
	if got := f.a.Refused(); got != 0 {
		t.Errorf("name gate refused %d handshakes", got)
	}
}

// holdStorage counts every call by key. It holds the first Store of a key that
// starts with "certificates/": it closes held one time, then waits for release.
type holdStorage struct {
	certmagic.Storage
	held, release chan struct{}
	once          sync.Once
	mu            sync.Mutex
	byKey         map[string]int
}

func (h *holdStorage) note(k string) {
	h.mu.Lock()
	h.byKey[k]++
	h.mu.Unlock()
}

// calls returns the number of calls and a copy of the counts for each key.
func (h *holdStorage) calls() (int, map[string]int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	total := 0
	for _, n := range h.byKey {
		total += n
	}
	return total, maps.Clone(h.byKey)
}

func (h *holdStorage) Lock(ctx context.Context, k string) error {
	h.note(k)
	return h.Storage.Lock(ctx, k)
}

func (h *holdStorage) Unlock(ctx context.Context, k string) error {
	h.note(k)
	return h.Storage.Unlock(ctx, k)
}

func (h *holdStorage) Load(ctx context.Context, k string) ([]byte, error) {
	h.note(k)
	return h.Storage.Load(ctx, k)
}

func (h *holdStorage) Stat(ctx context.Context, k string) (certmagic.KeyInfo, error) {
	h.note(k)
	return h.Storage.Stat(ctx, k)
}

func (h *holdStorage) Exists(ctx context.Context, k string) bool {
	h.note(k)
	return h.Storage.Exists(ctx, k)
}

func (h *holdStorage) List(ctx context.Context, p string, r bool) ([]string, error) {
	h.note(p)
	return h.Storage.List(ctx, p, r)
}

func (h *holdStorage) Delete(ctx context.Context, k string) error {
	h.note(k)
	return h.Storage.Delete(ctx, k)
}

func (h *holdStorage) Store(ctx context.Context, k string, v []byte) error {
	h.note(k)
	if strings.HasPrefix(k, "certificates/") {
		h.once.Do(func() {
			close(h.held)
			<-h.release
		})
	}
	return h.Storage.Store(ctx, k, v)
}

// TestTS16NoStorageReadForAcmeTLSDuringARealIssuance (T-S-16): Pebble issues a
// certificate while 4 000 acme-tls/1 handshakes for the name go to the listener.
// The first Store of a certificate key holds the issuance. At that point the
// solver is cleaned up, no request is in flight, and the certificate is not yet
// served. This is the window after the end of a challenge. The hold is in the
// storage, not in the CA handler: a held request could make the ACME client
// retry. The handshakes use pipes and GetCertificate, not the decoy socket. The
// connection limit of the socket gives a slot back after the client sees the end
// of a connection. Pebble validates on the decoy socket.
func TestTS16NoStorageReadForAcmeTLSDuringARealIssuance(t *testing.T) {
	var logs, std syncBuf
	old := log.Writer()
	log.SetOutput(&std)
	t.Cleanup(func() { log.SetOutput(old) })
	hold := &holdStorage{held: make(chan struct{}), release: make(chan struct{}), byKey: map[string]int{}}
	f := newIssueFixture(t, "window.phantom.test", nil, func(p *ACMEParams) {
		hold.Storage, p.Storage = p.Storage, hold
		p.Logger = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	})
	var releaseOnce sync.Once
	open := func() { releaseOnce.Do(func() { close(hold.release) }) }
	t.Cleanup(open) // a failed check must not leave the issuance held
	// The recorder sees each key that certmagic gives to the wrapper.
	rec := &loadRecorder{Storage: f.a.cfg.Storage}
	f.a.cfg.Storage = rec
	key := tokenKeyOf(f.a, f.name)
	startIssue(t, f)

	timer := time.NewTimer(issueWait)
	defer timer.Stop()
	select {
	case <-hold.held:
	case <-timer.C:
		t.Fatalf("the issuance did not store a certificate within %v", issueWait)
	}
	if _, active := certmagic.GetACMEChallenge(f.name); active {
		t.Fatal("the challenge is still active at the hold")
	}
	if _, err := f.chain(); err == nil {
		t.Fatal("the listener serves a certificate before the issuance stored it")
	}
	f.requireALPN(t) // Pebble validated on the decoy socket before the hold

	total0, keys0 := hold.calls()
	loads0, refused0 := rec.count(key), f.a.Refused()
	logs0, std0 := logs.String(), std.String()
	// The window: the lookup says that a challenge is active, as it does just
	// before the end of a challenge. The map of certmagic holds none.
	f.a.challenge = func(name string) (certmagic.Challenge, bool) { return certmagic.Challenge{}, name == f.name }
	const handshakes, workers = 4000, 8
	var next, worked atomic.Int64
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			for next.Add(1) <= handshakes {
				if prodHandshake(f.a, f.name, "acme-tls/1") == nil {
					worked.Add(1)
				}
			}
		})
	}
	wg.Wait()
	f.a.challenge = certmagic.GetACMEChallenge

	if w := worked.Load(); w != 0 {
		t.Errorf("handshakes that worked: %d", w)
	}
	total1, keys1 := hold.calls()
	if total1 != total0 {
		for k, n := range keys1 {
			if n != keys0[k] {
				t.Errorf("the storage under the wrapper got %d calls for %q during the handshakes", n-keys0[k], k)
			}
		}
	}
	if n := rec.count(key) - loads0; n != handshakes {
		t.Errorf("the token key reached the wrapper %d times; want %d, one for each handshake", n, handshakes)
	}
	if got := f.a.Refused(); got != refused0 {
		t.Errorf("refused changed from %d to %d: the gate did not let each handshake through", refused0, got)
	}
	if logs.String() != logs0 || std.String() != std0 {
		t.Errorf("log output during the handshakes: %q %q", strings.TrimPrefix(logs.String(), logs0), strings.TrimPrefix(std.String(), std0))
	}
	f.onlyPebble(t, "during the handshakes")

	open()
	chain := f.waitChain(t, issueWait, func(*x509.Certificate) bool { return true })
	f.verifyToPebble(t, chain)
	f.onlyPebble(t, "after the issuance")
	_, keys := hold.calls()
	for k, n := range keys {
		if strings.Contains(k, "challenge_tokens") {
			t.Errorf("the storage under the wrapper got %d calls for the token key %q", n, k)
		}
	}
}

// TestTI01RenewsACachedCertificateWithTwentyNineDaysLeft seeds a certificate of
// 90 days with 29 days left, so it is in the renewal window. Start serves it. At
// a maintenance tick, Pebble issues a new certificate, and the next handshake
// gets it. The guard sees the authority of Pebble only.
func TestTI01RenewsACachedCertificateWithTwentyNineDaysLeft(t *testing.T) {
	f := newIssueFixture(t, "renew.phantom.test", nil, func(p *ACMEParams) { p.maintenanceInterval = time.Second })
	now := time.Now()
	seeded, err := x509.ParseCertificate(seedCertFor(t, f.a, f.name, now.Add(-61*24*time.Hour), now.Add(29*24*time.Hour), nil))
	mustNil(t, err)
	startIssue(t, f)
	f.requireServes(t, seeded, "after Start")
	begin := time.Now()
	chain := f.waitChain(t, issueWait, func(leaf *x509.Certificate) bool { return !leaf.Equal(seeded) })
	t.Logf("replacement served %v after the first handshake", time.Since(begin))
	if leaf := chain[0]; leaf.SerialNumber.Cmp(seeded.SerialNumber) == 0 || !leaf.NotAfter.After(seeded.NotAfter) {
		t.Errorf("replacement has serial %v and ends %v; the cached one ends %v", leaf.SerialNumber, leaf.NotAfter, seeded.NotAfter)
	}
	f.verifyToPebble(t, chain)
	f.onlyPebble(t, "after renewal")
	f.requireALPN(t)
}

// retryAfterOneSecond is a ResponseWriter that sets Retry-After to 1 s.
type retryAfterOneSecond struct{ http.ResponseWriter }

func (w retryAfterOneSecond) WriteHeader(code int) {
	w.Header().Set("Retry-After", "1")
	w.ResponseWriter.WriteHeader(code)
}

func (w retryAfterOneSecond) Write(b []byte) (int, error) {
	w.Header().Set("Retry-After", "1")
	return w.ResponseWriter.Write(b)
}

// shortRenewalInfoPoll makes Pebble ask the client to read renewalInfo again
// after 1 s, not after 6 hours. A change of the renewal window then reaches
// the client in the run time of a test. The rest of the answer is the one
// of Pebble.
func shortRenewalInfoPoll(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "renewalInfo") {
			w = retryAfterOneSecond{w}
		}
		next.ServeHTTP(w, r)
	})
}

// TestTI01RenewsAPebbleCertificateThroughARIWithoutReplaces: Pebble issues a
// certificate. Then Pebble tells the client, in the renewalInfo answer for
// that certificate, that the renewal window is in the past. This is the same
// override as the management endpoint /set-renewal-info/. The certificate has
// 90 days of life, so only this window can start a renewal. At a maintenance
// tick, the client reads the new window and renews. The order of the new
// certificate has no replaces field. NewACME sets the test directory of the
// issuer to the CA directory. certmagic sends no replaces in an order to its
// test directory. The maintenance loop still reads renewalInfo.
func TestTI01RenewsAPebbleCertificateThroughARIWithoutReplaces(t *testing.T) {
	f := newIssueFixture(t, "ari.phantom.test", shortRenewalInfoPoll, func(p *ACMEParams) { p.maintenanceInterval = time.Second })
	startIssue(t, f)
	first := f.waitChain(t, issueWait, func(*x509.Certificate) bool { return true })[0]
	now := time.Now().UTC()
	window := fmt.Sprintf(`{"suggestedWindow":{"start":%q,"end":%q}}`, now.Add(-2*time.Hour).Format(time.RFC3339), now.Add(-time.Hour).Format(time.RFC3339))
	mustNil(t, f.rig.db.SetARIResponse(first.SerialNumber, window))
	chain := f.waitChain(t, issueWait, func(leaf *x509.Certificate) bool { return !leaf.Equal(first) })
	f.verifyToPebble(t, chain)
	// Pebble stores the order by serial after it issues the certificate.
	var order *core.Order
	testutil.WaitFor(t, func() bool {
		var err error
		order, err = f.rig.db.GetOrderByIssuedSerial(hex.EncodeToString(chain[0].SerialNumber.Bytes()))
		return err == nil
	}, issueWait)
	order.RLock()
	defer order.RUnlock()
	if order.Replaces != "" {
		t.Errorf("the renewal order has replaces %q; want none", order.Replaces)
	}
	f.onlyPebble(t, "after the renewal through ARI")
}

// TestTS16RetryAfterARefusedOrderStaysOnThePebbleAuthority: Pebble refuses the
// first order. certmagic retries after one minute. The guard sees the authority
// of Pebble only, after the refusal and after the certificate.
func TestTS16RetryAfterARefusedOrderStaysOnThePebbleAuthority(t *testing.T) {
	var orders atomic.Int64
	f := newIssueFixture(t, "retry.phantom.test", func(next http.Handler) http.Handler { return refuseFirstOrder(next, &orders) }, nil)
	begin := startIssue(t, f)
	for orders.Load() < 1 && time.Since(begin) < 10*time.Second {
		time.Sleep(10 * time.Millisecond)
	}
	if orders.Load() != 1 {
		t.Fatalf("new-order requests after 10 s: %d", orders.Load())
	}
	f.onlyPebble(t, "after the refused order")
	// The wait is the first retry interval of certmagic (retryIntervals[0], one
	// minute in certmagic v0.25.6, async.go). A new value there changes the run
	// time and the 55 s check below.
	chain := f.waitChain(t, 3*time.Minute, func(*x509.Certificate) bool { return true })
	elapsed := time.Since(begin)
	t.Logf("certificate served %v after Start", elapsed)
	if n := orders.Load(); n != 2 || elapsed < 55*time.Second {
		t.Errorf("new-order requests: %d, time to the certificate: %v; want 2 and a wait of about 1 minute", n, elapsed)
	}
	f.verifyToPebble(t, chain)
	f.onlyPebble(t, "after the retry")
}

// TestTS27ClientTrustsOnlyTheConfiguredRoots: with the certificate of the
// directory server as root, the client gets a certificate. With another root,
// the TLS handshake fails and Pebble gets no HTTP request.
func TestTS27ClientTrustsOnlyTheConfiguredRoots(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), issueLimit)
	t.Cleanup(cancel)
	t.Run("configured root", func(t *testing.T) {
		f := newIssueFixture(t, "root.phantom.test", nil, nil)
		mustNil(t, f.a.cfg.ObtainCertSync(ctx, f.name))
		_, err := f.a.cfg.CacheManagedCertificate(ctx, f.name)
		mustNil(t, err)
		f.verifyToPebble(t, f.waitChain(t, 10*time.Second, func(*x509.Certificate) bool { return true }))
	})
	t.Run("other root", func(t *testing.T) {
		var reqs atomic.Int64
		front := func(h http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reqs.Add(1); h.ServeHTTP(w, r) })
		}
		other := mustRoots(t, pemOf("CERTIFICATE", testCertDER(t, 9, nil), nil))
		f := newIssueFixture(t, "other.phantom.test", front, func(p *ACMEParams) { p.CARoots = other })
		err := f.a.cfg.ObtainCertSync(ctx, f.name)
		if err == nil || errors.Is(err, errEgress) || strings.Contains(err.Error(), errEgress.Error()) {
			t.Fatalf("obtain error is not a TLS error: %v", err)
		}
		if !strings.Contains(err.Error(), "unknown authority") {
			t.Errorf("obtain error is not an unknown authority error: %v", err)
		}
		if n := reqs.Load(); n != 0 {
			t.Errorf("Pebble got %d HTTP requests", n)
		}
	})
}

// TestTS16RedirectToAnotherPortIsRefused: the CA answers the directory request
// with a redirect to another loopback port. The guard sees that authority and
// refuses it, so the target gets no connection.
func TestTS16RedirectToAnotherPortIsRefused(t *testing.T) {
	var hits, conns atomic.Int64
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	target.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			conns.Add(1)
		}
	}
	target.StartTLS()
	t.Cleanup(target.Close)
	redirector := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/dir", http.StatusFound)
	}))
	t.Cleanup(redirector.Close)
	// The target would be trusted, so only the guard can refuse it.
	roots := mustRoots(t, slices.Concat(certPEM(redirector.Certificate()), certPEM(target.Certificate())))
	var egress egressRecorder
	a := newTestACME(t, func(p *ACMEParams) {
		p.CA, p.OnEgress, p.CARoots = redirector.URL+"/dir", egress.record, roots
	})
	err := a.cfg.ObtainCertSync(context.Background(), "decoy.test")
	if !errors.Is(err, errEgress) && (err == nil || !strings.Contains(err.Error(), errEgress.Error())) {
		t.Errorf("obtain error is not the guard error: %v", err)
	}
	if hits.Load() != 0 || conns.Load() != 0 {
		t.Errorf("target got %d requests on %d connections", hits.Load(), conns.Load())
	}
	want := []string{strings.TrimPrefix(redirector.URL, "https://"), strings.TrimPrefix(target.URL, "https://")}
	slices.Sort(want)
	if got := egress.hosts(); !slices.Equal(got, want) {
		t.Errorf("guard saw %v, want %v", got, want)
	}
}

// requireSnapshot fails the test unless the snapshot of the listening sockets
// holds the decoy socket, Pebble and the DNS server. It is from before Start.
func requireSnapshot(t *testing.T, before map[string]string, decoy string) {
	t.Helper()
	if len(before) < 3 || !slices.Contains(slices.Collect(maps.Values(before)), decoy) {
		t.Fatalf("the snapshot before Start is %v; want the decoy %s, Pebble and the DNS server", before, decoy)
	}
}

// TestTS16NoListenerBesideTheDecoySocketAfterTheChallenge samples the listening
// TCP sockets of the process from before Start until the certificate is served.
// Only the sockets that existed before Start may listen. The solver address of
// the issuer is the address of the decoy socket, and that socket holds it, so a
// new bind fails.
func TestTS16NoListenerBesideTheDecoySocketAfterTheChallenge(t *testing.T) {
	f := newIssueFixture(t, "sockets.phantom.test", nil, nil)
	// The HTTP challenge is off, so the TLS-ALPN solver address is the only
	// address on which certmagic can listen.
	iss := f.a.cfg.Issuers[0].(*certmagic.ACMEIssuer)
	if !iss.DisableHTTPChallenge {
		t.Fatal("the issuer has the HTTP challenge on")
	}
	solver := net.JoinHostPort(iss.ListenHost, strconv.Itoa(iss.AltTLSALPNPort))
	if solver != f.addr {
		t.Fatalf("solver address %s is not the address of the decoy socket %s", solver, f.addr)
	}
	requireBindRefused(t, solver, "before Start")
	if runtime.GOOS != "linux" {
		t.Skip("the check reads /proc, which only Linux has")
	}
	before := mustListeningSockets(t)
	requireSnapshot(t, before, f.addr)
	finish := watchListeners(t, before)
	startIssue(t, f)
	f.waitChain(t, issueWait, func(*x509.Certificate) bool { return true })
	finish()
	// Pebble ran a real TLS-ALPN validation on the decoy socket in the window.
	f.requireALPN(t)
	requireBindRefused(t, solver, "after the certificate")
	for inode, addr := range mustListeningSockets(t) {
		if _, ok := before[inode]; !ok {
			t.Errorf("new listening socket %s (inode %s) after the certificate", addr, inode)
		}
	}
}

// TestTS16WildcardDecoyAnswersTheChallenge: the decoy socket listens on a
// wildcard address, and Host is empty, as a wildcard HTTPS listen gives. No
// certificate is stored, so the issuer runs a real TLS-ALPN-01 validation with
// Pebble. The solver address is ":<port>". The decoy socket holds it, so
// certmagic binds no socket of its own. A bind of that address is refused
// before Start and after the certificate. No sample of the listening sockets
// shows a new socket, from before Start until the certificate is served. The
// decoy socket completes a handshake with acme-tls/1, so the challenge ran
// there. It serves a chain that Pebble issued.
func TestTS16WildcardDecoyAnswersTheChallenge(t *testing.T) {
	// On Linux, with the network "tcp", Go binds the three forms as one
	// dual-stack [::] socket. The sensor does the same with a wildcard
	// listen.
	for _, listen := range []string{"0.0.0.0:0", "[::]:0", ":0"} {
		t.Run(listen, func(t *testing.T) {
			f := newIssueFixtureOn(t, listen, "", "wildcard.phantom.test", nil, nil)
			iss := f.a.cfg.Issuers[0].(*certmagic.ACMEIssuer)
			if !iss.DisableHTTPChallenge {
				t.Fatal("the issuer has the HTTP challenge on")
			}
			// The decoy socket must be on a wildcard address. Else the
			// test checks a loopback socket.
			ap, err := netip.ParseAddrPort(f.listen)
			mustNil(t, err)
			if !ap.Addr().IsUnspecified() {
				t.Fatalf("the decoy socket listens on %s; want a wildcard address", f.listen)
			}
			port := strconv.Itoa(int(ap.Port()))
			// The checks below run also when this one fails. Then they show
			// what a wrong solver address does.
			if iss.ListenHost != "" || strconv.Itoa(iss.AltTLSALPNPort) != port {
				t.Errorf("solver host %q, port %d; want host \"\" and port %s", iss.ListenHost, iss.AltTLSALPNPort, port)
			}
			// This is the solver address that a wildcard listen must give.
			solver := ":" + port
			requireBindRefused(t, solver, "before Start")
			if runtime.GOOS != "linux" {
				t.Skip("the check reads /proc, which only Linux has")
			}
			before := mustListeningSockets(t)
			requireSnapshot(t, before, f.listen)
			finish := watchListeners(t, before)
			startIssue(t, f)
			chain := f.waitChain(t, issueWait, func(*x509.Certificate) bool { return true })
			finish()
			f.requireALPN(t) // Present ran on the decoy socket
			f.verifyToPebble(t, chain)
			requireBindRefused(t, solver, "after the certificate")
		})
	}
}

// seedOCSPChain stores a chain of two certificates for name: a leaf with the
// OCSP server URL and no issuer URL, and the test issuer certificate that
// signed it. It returns the leaf.
func seedOCSPChain(t *testing.T, a *ACME, name, ocspURL string) *x509.Certificate {
	t.Helper()
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mustNil(t, err)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "test issuer"}, NotBefore: now.Add(-time.Hour),
		NotAfter: now.Add(365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	mustNil(t, err)
	ca, err := x509.ParseCertificate(caDER)
	mustNil(t, err)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mustNil(t, err)
	leafDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(90 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, OCSPServer: []string{ocspURL}}, ca, &key.PublicKey, caKey)
	mustNil(t, err)
	leaf, err := x509.ParseCertificate(leafDER)
	mustNil(t, err)
	chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})...)
	storeSeed(t, a, name, chain, key)
	return leaf
}

// TestTS16OCSPStaysOffAfterMaintenanceTicks seeds a chain of two certificates.
// The leaf has an OCSP server URL on loopback and no issuer URL, so an OCSP
// client goes straight to that server. After Start and many maintenance ticks,
// the server got no request and the guard did not see its authority.
func TestTS16OCSPStaysOffAfterMaintenanceTicks(t *testing.T) {
	var hits atomic.Int64
	ocsp := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	t.Cleanup(ocsp.Close)
	// certmagic requests the config of the certificate at the start of each
	// OCSP check. It does this before the work of that check. Only the OCSP
	// interval is short here, so the renewal check does not run. Each request
	// is then one OCSP check. When the count is above ticks, the checks before
	// the last one have done their work.
	const ticks = 20
	var requests atomic.Int64
	f := newIssueFixture(t, "ocsp.phantom.test", nil, func(p *ACMEParams) {
		p.ocspInterval = 50 * time.Millisecond
		p.onMaintenance = func() { requests.Add(1) }
	})
	seeded := seedOCSPChain(t, f.a, f.name, ocsp.URL)
	startIssue(t, f)
	f.requireServes(t, seeded, "after Start")
	testutil.WaitFor(t, func() bool { return requests.Load() > ticks }, issueLimit)
	if hits.Load() != 0 {
		t.Errorf("OCSP server got %d requests", hits.Load())
	}
	if got := f.egress.hosts(); len(got) != 0 && !slices.Equal(got, []string{f.rig.host}) {
		t.Errorf("guard saw %v, want nothing or only %s", got, f.rig.host)
	}
}

// TestTS21ProductionRuleRefusesLoopbackCA: with the production rule, a CA on
// a loopback address gets no request. This holds for an IP literal. It also
// holds for a name that the resolver maps to loopback, or to a mix of
// addresses. Start gives no error. The log text holds no address and no name.
func TestTS21ProductionRuleRefusesLoopbackCA(t *testing.T) {
	const caName = "pebble.test"
	for _, c := range []struct {
		label string
		addrs []netip.Addr // answers for caName; nil: the CA is the IP literal
	}{
		{"literal", nil},
		{"name for loopback", []netip.Addr{netip.MustParseAddr("127.0.0.1")}},
		{"name for global and loopback", []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("127.0.0.1")}},
	} {
		t.Run(c.label, func(t *testing.T) {
			var reqs atomic.Int64
			var logs syncBuf
			names := egresstest.NewNames(t)
			names.Set(caName+".", c.addrs...)
			front := func(h http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reqs.Add(1); h.ServeHTTP(w, r) })
			}
			var wantHost string // the host:port of the CA that the guard sees
			f := newIssueFixture(t, "refused.phantom.test", front, func(p *ACMEParams) {
				p.egressRule, p.egressResolver = nil, nil // production values
				p.Logger = slog.New(slog.NewTextHandler(&logs, nil))
				if c.addrs != nil { // p.CA is the IP-literal URL here
					ca, err := url.Parse(p.CA)
					mustNil(t, err)
					p.CA, p.egressResolver = "https://"+caName+":"+ca.Port()+"/dir", names.Resolver()
				}
				ca, err := url.Parse(p.CA)
				mustNil(t, err)
				wantHost = ca.Host
			})
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			mustNil(t, f.a.Start(ctx))
			for deadline := time.Now().Add(10 * time.Second); len(f.egress.hosts()) == 0 && time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
			}
			if got := f.egress.hosts(); !slices.Equal(got, []string{wantHost}) {
				t.Fatalf("the guard saw %v, want only %s", got, wantHost)
			}
			// While Start retries, it holds the lock for
			// refused.phantom.test. Thus the synchronous obtain uses
			// another name.
			err := f.a.cfg.ObtainCertSync(ctx, "sync.phantom.test")
			if err == nil || !strings.Contains(err.Error(), errEgress.Error()) {
				t.Fatalf("obtain error is not the guard error: %v", err)
			}
			if n := reqs.Load(); n != 0 {
				t.Errorf("Pebble got %d requests", n)
			}
			// The library wraps the error with the CA URL. That is the
			// configured value, so the error text may hold the configured
			// host. It holds no resolved address. The log holds neither.
			for _, tried := range []string{"8.8.8.8", "127.0.0.1"} {
				if c.addrs != nil && strings.Contains(err.Error(), tried) {
					t.Errorf("error text holds %q: %v", tried, err)
				}
			}
			for _, tried := range []string{"8.8.8.8", "127.0.0.1", caName} {
				if strings.Contains(logs.String(), tried) {
					t.Errorf("log text holds %q: %s", tried, logs.String())
				}
			}
		})
	}
}
