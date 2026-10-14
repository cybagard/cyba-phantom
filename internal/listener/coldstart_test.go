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
func seedCert(t *testing.T, a *ACME, name string) []byte {
	t.Helper()
	now := time.Now()
	return seedCertFor(t, a, name, now.Add(-time.Hour), now.Add(90*24*time.Hour), nil)
}

// seedCertFor is seedCert with the validity period and the OCSP server URLs of
// the leaf.
func seedCertFor(t *testing.T, a *ACME, name string, notBefore, notAfter time.Time, ocspServer []string) []byte {
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
