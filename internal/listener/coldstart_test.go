package listener

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log/slog"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
)

// seedCert stores a certificate for name in the storage of a, at the keys that
// certmagic reads for the issuer of a. It returns the DER bytes of the leaf.
func seedCert(t testing.TB, a *ACME, name string) []byte {
	t.Helper()
	now := time.Now()
	return seedCertFor(t, a, name, now.Add(-time.Hour), now.Add(90*24*time.Hour), nil)
}

// seedCertFor is seedCert with the validity period and the OCSP server URLs of
// the leaf.
func seedCertFor(t testing.TB, a *ACME, name string, notBefore, notAfter time.Time, ocspServer []string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mustNil(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		OCSPServer:   ocspServer,
	}
	if len(ocspServer) > 0 {
		// With no issuer in the chain, an OCSP client fetches the issuer first.
		tmpl.IssuingCertificateURL = []string{"http://issuer.other.test/ca.der"}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	mustNil(t, err)
	keyDER, err := x509.MarshalECPrivateKey(key)
	mustNil(t, err)
	meta, err := json.Marshal(certmagic.CertificateResource{SANs: []string{name}})
	mustNil(t, err)
	ik := a.cfg.Issuers[0].(*certmagic.ACMEIssuer).IssuerKey()
	for k, v := range map[string][]byte{
		certmagic.StorageKeys.SiteCert(ik, name):       pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		certmagic.StorageKeys.SitePrivateKey(ik, name): pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
		certmagic.StorageKeys.SiteMeta(ik, name):       meta,
	} {
		mustNil(t, a.cfg.Storage.Store(context.Background(), k, v))
	}
	return der
}

// closedAddr returns a loopback address with no listener. A connection to it is
// refused at once.
func closedAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	mustNil(t, err)
	addr := l.Addr().String()
	mustNil(t, l.Close())
	return addr
}

func TestTI03ColdStartServesTheCachedCertificateWithoutNetwork(t *testing.T) {
	var mu sync.Mutex
	var egress []string
	addr := closedAddr(t)
	a := newTestACME(t, func(p *ACMEParams) {
		p.CA = "https://" + addr
		p.OnEgress = func(h string) { mu.Lock(); egress = append(egress, h); mu.Unlock() }
	})
	want := seedCert(t, a, "decoy.test")

	begin := time.Now()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	mustNil(t, a.Start(ctx))
	st, err := handshake(a, "decoy.test")
	elapsed := time.Since(begin)
	mustNil(t, err)
	if !bytes.Equal(st.PeerCertificates[0].Raw, want) {
		t.Fatal("the handshake did not serve the cached certificate")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("start to the end of the handshake took %v", elapsed)
	}
	// The background work may call the guard. It may name the closed CA port only.
	mu.Lock()
	defer mu.Unlock()
	for _, h := range egress {
		if h != addr {
			t.Errorf("a request went to %q, not to the CA", h)
		}
	}
}

// blackholeAddr returns the address of a loopback listener that accepts each
// connection and never answers. The test closes the connections at the end.
func blackholeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	mustNil(t, err)
	var mu sync.Mutex
	var conns []net.Conn
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		l.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			c.Close()
		}
	})
	return l.Addr().String()
}

func TestTI03StartDoesNotWaitForTheCA(t *testing.T) {
	now := time.Now()
	for _, c := range []struct {
		name                string
		seed                bool
		notBefore, notAfter time.Time
	}{
		{"empty cache", false, time.Time{}, time.Time{}},
		{"cached certificate in the renewal window", true, now.Add(-85 * 24 * time.Hour), now.Add(5 * 24 * time.Hour)},
	} {
		t.Run(c.name, func(t *testing.T) {
			a := newTestACME(t, func(p *ACMEParams) { p.CA = "https://" + blackholeAddr(t) + "/dir" })
			var want []byte
			if c.seed {
				want = seedCertFor(t, a, "decoy.test", c.notBefore, c.notAfter, nil)
			}
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			done := make(chan error, 1)
			go func() { done <- a.Start(ctx) }()
			select {
			case err := <-done:
				mustNil(t, err)
			case <-time.After(time.Second):
				t.Fatal("Start did not return within 1 s: it waits for the CA")
			}
			if !c.seed {
				return
			}
			begin := time.Now()
			st, err := handshake(a, "decoy.test")
			mustNil(t, err)
			if !bytes.Equal(st.PeerCertificates[0].Raw, want) {
				t.Fatal("the handshake did not serve the cached certificate")
			}
			if d := time.Since(begin); d > 2*time.Second {
				t.Fatalf("the handshake took %v", d)
			}
		})
	}
}

// T-I-01: a cached certificate that is due for renewal starts its renewal when
// Start runs, and Start does not wait for the CA. The CA accepts connections and
// never answers. Start returns within 500 ms, the guard sees a request to the CA
// within 5 s (the maintenance tick of the cache is 10 minutes away), and a
// handshake still gets the cached certificate.
func TestTI01StartWithADueCertificateStartsTheRenewalWithoutWaiting(t *testing.T) {
	ca := blackholeAddr(t)
	seen := make(chan string, 16)
	a := newTestACME(t, func(p *ACMEParams) {
		p.CA = "https://" + ca + "/dir"
		p.OnEgress = func(h string) {
			select {
			case seen <- h:
			default:
			}
		}
	})
	now := time.Now()
	want := seedCertFor(t, a, "decoy.test", now.Add(-61*24*time.Hour), now.Add(29*24*time.Hour), nil)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() { done <- a.Start(ctx) }()
	select {
	case err := <-done:
		mustNil(t, err)
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Start did not return within 500 ms: it waits for the CA")
	}
	select {
	case h := <-seen:
		if h != ca {
			t.Errorf("the first request went to %q, not to the CA", h)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no request to the CA within 5 s of Start: the renewal did not start")
	}
	st, err := handshake(a, "decoy.test")
	mustNil(t, err)
	if !bytes.Equal(st.PeerCertificates[0].Raw, want) {
		t.Fatal("the handshake did not serve the cached certificate")
	}
}

// T-I-01: with a maintenance tick far away, a cached certificate that is due for
// renewal gets a Pebble certificate right after Start, and the new certificate
// replaces the cached one.
func TestTI01StartRenewsADueCertificateBeforeTheFirstTick(t *testing.T) {
	f := newIssueFixture(t, "due.phantom.test", nil, func(p *ACMEParams) { p.maintenanceInterval = time.Hour })
	now := time.Now()
	seeded, err := x509.ParseCertificate(seedCertFor(t, f.a, f.name, now.Add(-61*24*time.Hour), now.Add(29*24*time.Hour), nil))
	mustNil(t, err)
	begin := startIssue(t, f)
	chain := f.waitChain(t, 30*time.Second, func(leaf *x509.Certificate) bool { return !leaf.Equal(seeded) })
	t.Logf("renewed certificate served %v after Start", time.Since(begin))
	f.verifyToPebble(t, chain)
	f.onlyPebble(t, "after the renewal at start")
	f.requireALPN(t)
	if n := len(f.a.cache.AllMatchingCertificates(f.name)); n != 1 {
		t.Errorf("%d certificates for the name in the cache, want 1", n)
	}
}

// TestTI03StartWithAnEmptyCacheStartsTheManagement uses a closed CA port. Start
// writes no load line for a name with no cached certificate. The guard sees a
// request to the CA within 5 s: the background management started.
func TestTI03StartWithAnEmptyCacheStartsTheManagement(t *testing.T) {
	var logs syncBuf
	addr := closedAddr(t)
	seen := make(chan string, 16)
	a := newTestACME(t, func(p *ACMEParams) {
		p.CA = "https://" + addr
		p.Logger = slog.New(slog.NewTextHandler(&logs, nil))
		p.OnEgress = func(h string) {
			select {
			case seen <- h:
			default:
			}
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	mustNil(t, a.Start(ctx))
	if strings.Contains(logs.String(), "acme certificate load failed") {
		t.Errorf("an empty cache wrote a load line: %q", logs.String())
	}
	select {
	case h := <-seen:
		if h != addr {
			t.Errorf("the first request went to %q, not to the CA", h)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no request to the CA within 5 s of Start: the management did not start")
	}
}

// slowStorage delays each read of the storage under it.
type slowStorage struct {
	certmagic.Storage
	delay time.Duration
}

func (s *slowStorage) Load(ctx context.Context, k string) ([]byte, error) {
	time.Sleep(s.delay)
	return s.Storage.Load(ctx, k)
}

// failingStorage fails each read with an error that is not fs.ErrNotExist.
type failingStorage struct{ certmagic.Storage }

func (failingStorage) Load(context.Context, string) ([]byte, error) {
	return nil, errors.New("disk failure in /private/path")
}

func TestTI03StartLoadsTheCacheBeforeItReturns(t *testing.T) {
	st, _ := newStore(t)
	a := newTestACME(t, func(p *ACMEParams) {
		p.CA = "https://" + closedAddr(t)
		p.Storage = &slowStorage{Storage: st, delay: 300 * time.Millisecond}
	})
	want := seedCert(t, a, "decoy.test")
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	mustNil(t, a.Start(ctx))
	// No sleep and no retry: the certificate is in the cache when Start returns.
	c, s := net.Pipe()
	t.Cleanup(func() { c.Close(); s.Close() })
	cert, err := a.GetCertificate(&tls.ClientHelloInfo{ServerName: "decoy.test", Conn: s})
	if err != nil || !bytes.Equal(cert.Certificate[0], want) {
		t.Fatalf("GetCertificate right after Start: %v", err)
	}
}

func TestTI03StartLoadErrorWritesOneFixedLine(t *testing.T) {
	var logs syncBuf
	st, _ := newStore(t)
	a := newTestACME(t, func(p *ACMEParams) {
		p.CA = "https://" + closedAddr(t)
		p.Storage = failingStorage{st}
		p.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	mustNil(t, a.Start(ctx))
	out := logs.String()
	if !strings.Contains(out, `msg="acme certificate load failed" name=decoy.test`) || strings.Contains(out, "/private/path") {
		t.Errorf("log output: %q", out)
	}
}
