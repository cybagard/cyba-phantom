package listener

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
)

// seedCert stores a certificate for name in the storage of a, at the keys that
// certmagic reads for the issuer of a. It returns the DER bytes of the leaf.
func seedCert(t *testing.T, a *ACME, name string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mustNil(t, err)
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
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
