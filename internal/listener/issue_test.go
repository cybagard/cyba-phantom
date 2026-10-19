package listener

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"log/slog"
	"maps"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
)

const issueLimit = 120 * time.Second // the most time that the listener can take to obtain a certificate

// startIssue calls Start with a context that ends with the test.
func startIssue(t *testing.T, f *issueFixture) time.Time {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	begin := time.Now()
	mustNil(t, f.a.Start(ctx))
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

	timer := time.NewTimer(issueLimit)
	defer timer.Stop()
	select {
	case <-hold.held:
	case <-timer.C:
		t.Fatalf("the issuance did not store a certificate within %v", issueLimit)
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
	chain := f.waitChain(t, issueLimit, func(*x509.Certificate) bool { return true })
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
	if ch, err := f.chain(); err != nil || !ch[0].Equal(seeded) {
		t.Fatalf("Start did not serve the cached certificate: %v", err)
	}
	begin := time.Now()
	chain := f.waitChain(t, issueLimit, func(leaf *x509.Certificate) bool { return !leaf.Equal(seeded) })
	t.Logf("replacement served %v after the first handshake", time.Since(begin))
	if leaf := chain[0]; leaf.SerialNumber.Cmp(seeded.SerialNumber) == 0 || !leaf.NotAfter.After(seeded.NotAfter) {
		t.Errorf("replacement has serial %v and ends %v; the cached one ends %v", leaf.SerialNumber, leaf.NotAfter, seeded.NotAfter)
	}
	f.verifyToPebble(t, chain)
	f.onlyPebble(t, "after renewal")
	f.requireALPN(t)
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
	roots := x509.NewCertPool()
	roots.AddCert(redirector.Certificate())
	roots.AddCert(target.Certificate()) // the target would be trusted, so only the guard can refuse it
	var egress egressSet
	a := newTestACME(t, func(p *ACMEParams) {
		p.CA, p.OnEgress, p.trustedRoots = redirector.URL+"/dir", egress.record, roots
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
	decoyHoldsSolver := func(when string) {
		t.Helper()
		if l, err := net.Listen("tcp", solver); err == nil {
			l.Close()
			t.Fatalf("%s: a second listener bound the solver address %s", when, solver)
		} else if !strings.Contains(err.Error(), "address already in use") {
			t.Fatalf("%s: second bind: %v", when, err)
		}
	}
	decoyHoldsSolver("before Start")
	if runtime.GOOS != "linux" {
		t.Skip("the check reads /proc, which only Linux has")
	}
	before := listeningInodes(t)
	if len(before) < 3 || !slices.Contains(slices.Collect(maps.Values(before)), f.addr) {
		t.Fatalf("the snapshot before Start is %v; want the decoy %s, Pebble and the DNS server", before, f.addr)
	}
	var samples int
	var extra []string
	quit, done := make(chan struct{}), make(chan struct{})
	go func() { // no t.Fatal here
		defer close(done)
		for stop := false; !stop; {
			select {
			case <-quit:
				stop = true
			case <-time.After(time.Millisecond):
			}
			if now, err := listeningSockets(); err == nil {
				samples++
				for inode, addr := range now {
					if _, ok := before[inode]; !ok && !slices.Contains(extra, addr) {
						extra = append(extra, addr)
					}
				}
			}
		}
	}()
	var once sync.Once
	finish := func() {
		once.Do(func() {
			close(quit)
			<-done
			t.Logf("%d samples of the listening sockets", samples)
			if len(extra) != 0 {
				t.Errorf("new listening sockets since before Start: %v", extra)
			}
		})
	}
	t.Cleanup(finish)
	startIssue(t, f)
	f.waitChain(t, issueLimit, func(*x509.Certificate) bool { return true })
	finish()
	decoyHoldsSolver("after the certificate")
	for inode, addr := range listeningInodes(t) {
		if _, ok := before[inode]; !ok {
			t.Errorf("new listening socket %s (inode %s) after the certificate", addr, inode)
		}
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
	keyDER, err := x509.MarshalECPrivateKey(key)
	mustNil(t, err)
	meta, err := json.Marshal(certmagic.CertificateResource{SANs: []string{name}})
	mustNil(t, err)
	chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})...)
	ik := a.cfg.Issuers[0].(*certmagic.ACMEIssuer).IssuerKey()
	for k, v := range map[string][]byte{
		certmagic.StorageKeys.SiteCert(ik, name):       chain,
		certmagic.StorageKeys.SitePrivateKey(ik, name): pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
		certmagic.StorageKeys.SiteMeta(ik, name):       meta,
	} {
		mustNil(t, a.cfg.Storage.Store(context.Background(), k, v))
	}
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
	f := newIssueFixture(t, "ocsp.phantom.test", nil, func(p *ACMEParams) { p.maintenanceInterval = 50 * time.Millisecond })
	seeded := seedOCSPChain(t, f.a, f.name, ocsp.URL)
	startIssue(t, f)
	if ch, err := f.chain(); err != nil || !ch[0].Equal(seeded) {
		t.Fatalf("Start did not serve the seeded certificate: %v", err)
	}
	time.Sleep(time.Second) // about 20 ticks
	if hits.Load() != 0 {
		t.Errorf("OCSP server got %d requests", hits.Load())
	}
	if got := f.egress.hosts(); len(got) != 0 && !slices.Equal(got, []string{f.rig.host}) {
		t.Errorf("guard saw %v, want nothing or only %s", got, f.rig.host)
	}
}
