package listener

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const issueLimit = 120 * time.Second // the time that the listener has to obtain a certificate

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
	if got := f.a.Refused(); got != 0 {
		t.Errorf("name gate refused %d handshakes", got)
	}
}

// TestTI01RenewsACachedCertificateWithTwentyNineDaysLeft seeds a certificate of
// 90 days with 29 days left, so it is in the renewal window. Start serves it. At
// a maintenance tick, Pebble issues a new certificate, and the next handshake
// gets it. The guard sees the authority of Pebble only.
func TestTI01RenewsACachedCertificateWithTwentyNineDaysLeft(t *testing.T) {
	f := newIssueFixture(t, "renew.phantom.test", nil, func(p *ACMEParams) { p.MaintenanceInterval = time.Second })
	now := time.Now()
	seeded, err := x509.ParseCertificate(seedCertFor(t, f.a, f.name, now.Add(-61*24*time.Hour), now.Add(29*24*time.Hour), nil))
	mustNil(t, err)
	startIssue(t, f)
	if ch, err := f.chain(); err != nil || !ch[0].Equal(seeded) {
		t.Fatalf("Start did not serve the cached certificate: %v", err)
	}
	begin := time.Now()
	chain := f.waitChain(t, issueLimit, func(leaf *x509.Certificate) bool { return !leaf.Equal(seeded) })
	t.Logf("replacement served %v after Start", time.Since(begin))
	if leaf := chain[0]; leaf.SerialNumber.Cmp(seeded.SerialNumber) == 0 || !leaf.NotAfter.After(seeded.NotAfter) {
		t.Errorf("replacement has serial %v and ends %v; the cached one ends %v", leaf.SerialNumber, leaf.NotAfter, seeded.NotAfter)
	}
	f.verifyToPebble(t, chain)
	f.onlyPebble(t, "after renewal")
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
		p.CA, p.OnEgress, p.TrustedRoots = redirector.URL+"/dir", egress.record, roots
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

// TestTS16NoListenerBesideTheDecoySocketAfterTheChallenge compares the listening
// TCP sockets of the process before Start with those after the certificate. The
// sockets of the rig exist before Start. The decoy socket holds its address, so
// a new bind fails.
func TestTS16NoListenerBesideTheDecoySocketAfterTheChallenge(t *testing.T) {
	f := newIssueFixture(t, "sockets.phantom.test", nil, nil)
	decoyHoldsAddress := func(when string) {
		t.Helper()
		if l, err := net.Listen("tcp", f.addr); err == nil {
			l.Close()
			t.Fatalf("%s: a second listener bound the address of the decoy socket", when)
		} else if !strings.Contains(err.Error(), "address already in use") {
			t.Fatalf("%s: second bind: %v", when, err)
		}
	}
	decoyHoldsAddress("before Start")
	if runtime.GOOS != "linux" {
		t.Skip("the check reads /proc, which only Linux has")
	}
	before := listeningInodes(t)
	startIssue(t, f)
	f.waitChain(t, issueLimit, func(*x509.Certificate) bool { return true })
	decoyHoldsAddress("after the certificate")
	for inode, addr := range listeningInodes(t) {
		if _, ok := before[inode]; !ok {
			t.Errorf("new listening socket %s (inode %s)", addr, inode)
		}
	}
	if len(before) < 3 {
		t.Errorf("the snapshot before Start has %d sockets; expected the decoy, Pebble and the DNS server", len(before))
	}
}

// TestTS16OCSPStaysOffAfterMaintenanceTicks seeds a certificate with an OCSP
// server URL on loopback. After Start and many maintenance ticks, the server got
// no request and the guard did not see its authority.
func TestTS16OCSPStaysOffAfterMaintenanceTicks(t *testing.T) {
	var hits atomic.Int64
	ocsp := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	t.Cleanup(ocsp.Close)
	f := newIssueFixture(t, "ocsp.phantom.test", nil, func(p *ACMEParams) { p.MaintenanceInterval = 50 * time.Millisecond })
	now := time.Now()
	seedCertFor(t, f.a, f.name, now.Add(-time.Hour), now.Add(90*24*time.Hour), []string{ocsp.URL})
	startIssue(t, f)
	time.Sleep(time.Second) // 20 ticks
	if hits.Load() != 0 {
		t.Errorf("OCSP server got %d requests", hits.Load())
	}
	// The seeded certificate names an issuer on another host, so an OCSP client
	// reaches the guard with that host before it reaches the OCSP server.
	if got := f.egress.hosts(); len(got) != 0 && !slices.Equal(got, []string{f.rig.host}) {
		t.Errorf("guard saw %v, want nothing or only %s", got, f.rig.host)
	}
}
