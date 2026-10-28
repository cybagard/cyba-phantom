// ParseStatic (SEC-31, SEC-21) makes one tls.Certificate.
// Its input is the bytes of a certificate file and of a key file.
// It opens no file. It does not serve, log or warn.
// Each refusal is a fixed error. No error text holds a byte of a file,
// a PEM type line, a library error text or a key.
// CertSource (below) serves the result and warns about its expiry.

package listener

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log/slog"
	"slices"
	"sync/atomic"
	"time"

	"github.com/cybagard/cyba-phantom/internal/event"
)

// ParseStatic returns these refusals. A caller tests them with errors.Is.
var (
	ErrStaticText     = errors.New("static certificate: text outside the PEM blocks")
	ErrStaticHeader   = errors.New("static certificate: PEM block has a header")
	ErrStaticCount    = errors.New("static certificate: wrong number of PEM blocks")
	ErrStaticType     = errors.New("static certificate: wrong type of PEM block")
	ErrStaticCert     = errors.New("static certificate: certificate does not parse")
	ErrStaticKey      = errors.New("static certificate: key does not parse")
	ErrStaticCA       = errors.New("static certificate: leaf is a CA certificate")
	ErrStaticKeyKind  = errors.New("static certificate: key type or size is not permitted")
	ErrStaticName     = errors.New("static certificate: leaf is not valid for the name")
	ErrStaticExpired  = errors.New("static certificate: leaf is expired")
	ErrStaticNotYet   = errors.New("static certificate: leaf is not valid yet")
	ErrStaticMismatch = errors.New("static certificate: key does not match the leaf")
)

const (
	pemBegin   = "-----BEGIN "
	pkcs8Type  = "PRIVATE KEY"
	pkcs1Type  = "RSA PRIVATE KEY"
	sec1Type   = "EC PRIVATE KEY"
	minRSABits = 2048
	maxRSABits = 4096
)

// ParseStatic reads the files of one static certificate.
// The certificate file holds CERTIFICATE blocks only, the leaf first.
// The key file holds one block, a private key.
// The block type is PRIVATE KEY (PKCS8), RSA PRIVATE KEY (PKCS1) or
// EC PRIVATE KEY (SEC1). The type names the form of the key.
// The key must encode back to the same bytes in that form.
// In both files, a block has no header.
// Outside the blocks, only the bytes space, tab, CR and LF are permitted.
// The leaf is valid for name at now. Only the SAN entries (DNS names and IP
// addresses) count, not the Common Name.
// The leaf is not a CA certificate. The public key of the leaf is RSA with
// 2048 to 4096 bits, ECDSA P-256 or P-384, or Ed25519.
// The private key of the key file matches the leaf.
// The result has the leaf parsed.
func ParseStatic(
	name string, certPEM, keyPEM []byte, now time.Time,
) (tls.Certificate, error) {
	certBlocks, err := readBlocks(certPEM)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyBlocks, err := readBlocks(keyPEM)
	if err != nil {
		return tls.Certificate{}, err
	}
	if len(certBlocks) == 0 || len(keyBlocks) != 1 {
		return tls.Certificate{}, ErrStaticCount
	}
	var out tls.Certificate
	var leaf *x509.Certificate
	for _, b := range certBlocks {
		if b.Type != "CERTIFICATE" {
			return tls.Certificate{}, ErrStaticType
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return tls.Certificate{}, ErrStaticCert
		}
		if leaf == nil {
			leaf = c
		}
		out.Certificate = append(out.Certificate, b.Bytes)
	}
	if leaf.IsCA || leaf.KeyUsage&x509.KeyUsageCertSign != 0 {
		return tls.Certificate{}, ErrStaticCA
	}
	if !permittedKey(leaf.PublicKey) {
		return tls.Certificate{}, ErrStaticKeyKind
	}
	key, err := parseStaticKey(keyBlocks[0].Type, keyBlocks[0].Bytes)
	if err != nil {
		return tls.Certificate{}, err
	}
	if leaf.VerifyHostname(name) != nil {
		return tls.Certificate{}, ErrStaticName
	}
	if now.Before(leaf.NotBefore) {
		return tls.Certificate{}, ErrStaticNotYet
	}
	if now.After(leaf.NotAfter) {
		return tls.Certificate{}, ErrStaticExpired
	}
	if !matches(key, leaf.PublicKey) {
		return tls.Certificate{}, ErrStaticMismatch
	}
	out.PrivateKey = key
	out.Leaf = leaf
	return out, nil
}

// readBlocks decodes all PEM blocks of data.
// pem.Decode skips text before a block, also a BEGIN line with a bad body.
// So each block must start at the first byte after the white space.
// The text that pem.Decode reads for a block must also hold one BEGIN line.
func readBlocks(data []byte) ([]*pem.Block, error) {
	var blocks []*pem.Block
	for {
		data = bytes.TrimLeft(data, " \t\r\n")
		if len(data) == 0 {
			return blocks, nil
		}
		if !bytes.HasPrefix(data, []byte(pemBegin)) {
			return nil, ErrStaticText
		}
		b, rest := pem.Decode(data)
		read := data[:len(data)-len(rest)]
		if b == nil || bytes.Count(read, []byte(pemBegin)) != 1 {
			return nil, ErrStaticText
		}
		if len(b.Headers) != 0 {
			return nil, ErrStaticHeader
		}
		blocks = append(blocks, b)
		data = rest
	}
}

// parseStaticKey reads the key in the one form that the block type names:
// PKCS8, PKCS1 or SEC1. It does not try another form.
// The PKCS8 and SEC1 parsers ignore bytes and elements after the key.
// So parseStaticKey encodes the key again in the same form and refuses
// a key whose encoding differs from der.
// A block type that names no form gives ErrStaticType.
// It does not return the library error, which can hold the text of the key.
func parseStaticKey(typ string, der []byte) (any, error) {
	var key any
	var again []byte
	var err error
	switch typ {
	case pkcs8Type:
		key, err = x509.ParsePKCS8PrivateKey(der)
		if err != nil {
			return nil, ErrStaticKey
		}
		switch key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
		default:
			return nil, ErrStaticKey
		}
		again, err = x509.MarshalPKCS8PrivateKey(key)
	case pkcs1Type:
		var k *rsa.PrivateKey
		k, err = x509.ParsePKCS1PrivateKey(der)
		if err != nil {
			return nil, ErrStaticKey
		}
		key, again = k, x509.MarshalPKCS1PrivateKey(k)
	case sec1Type:
		var k *ecdsa.PrivateKey
		k, err = x509.ParseECPrivateKey(der)
		if err != nil {
			return nil, ErrStaticKey
		}
		key = k
		again, err = x509.MarshalECPrivateKey(k)
	default:
		return nil, ErrStaticType
	}
	if err != nil {
		return nil, ErrStaticKey
	}
	if !bytes.Equal(again, der) {
		return nil, ErrStaticKey
	}
	return key, nil
}

// permittedKey is true for RSA of 2048 to 4096 bits, ECDSA P-256 or P-384,
// and Ed25519. The RSA size is the bit length of the modulus, not the
// rounded size.
func permittedKey(pub any) bool {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		n := k.N.BitLen()
		return n >= minRSABits && n <= maxRSABits
	case *ecdsa.PublicKey:
		return k.Curve == elliptic.P256() || k.Curve == elliptic.P384()
	case ed25519.PublicKey:
		return true
	}
	return false
}

// matches is true when the public key of priv is pub.
func matches(priv, pub any) bool {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return k.PublicKey.Equal(pub)
	case *ecdsa.PrivateKey:
		return k.PublicKey.Equal(pub)
	case ed25519.PrivateKey:
		p, _ := k.Public().(ed25519.PublicKey)
		return p.Equal(pub)
	}
	return false
}

// CertSource errors. They are fixed and hold no name, file text or key.
var (
	ErrSourceEntry   = errors.New("certificate source: an entry has no name or no parsed leaf")
	ErrSourceDup     = errors.New("certificate source: a static name comes two times")
	ErrSourceOverlap = errors.New("certificate source: a name is both a static name and an ACME name")
	errStaticALPN    = errors.New("listener: static certificate: acme-tls/1 is not served for a static name")
)

const (
	// expiryWarnWithin is the time left below which a leaf gets the warning.
	expiryWarnWithin = 14 * 24 * time.Hour
	// expiryWarnEvery is the time between two rounds of warnings.
	expiryWarnEvery = 24 * time.Hour
)

// StaticEntry is one static certificate: the decoy name and the result of
// ParseStatic for it (with Leaf set).
type StaticEntry struct {
	Name string
	Cert tls.Certificate
}

// CertSource is the certificate source of the decoy listener. The decoy names
// are its static names and the names of its ACME client. A static name gets its
// stored certificate, with no call to the ACME client or its cache. It opens no
// file.
type CertSource struct {
	static  map[string]*tls.Certificate
	order   []string // static names, in the order of the entries
	acme    *ACME    // nil when there is no ACME name
	refused atomic.Uint64

	// now and newTicker are test hooks. Only tests in this package set them.
	// They are time.Now and a time.Ticker in production. No config key, flag or
	// environment variable sets them.
	now       func() time.Time
	newTicker func(time.Duration) (<-chan time.Time, func())
}

// NewCertSource returns the source for entries and for acme.
// The acme value is nil when there is no acme.names entry.
// The source keeps its own copy of the entries.
// It refuses an entry with no name or with no Leaf.
// It refuses a static name that comes two times.
// It refuses a static name that is also an ACME name.
func NewCertSource(entries []StaticEntry, acme *ACME) (*CertSource, error) {
	s := &CertSource{static: make(map[string]*tls.Certificate, len(entries)), acme: acme}
	for _, e := range entries {
		name, ok := normalizeServerName(e.Name)
		if !ok || name == "" || e.Cert.Leaf == nil {
			return nil, ErrSourceEntry
		}
		if _, dup := s.static[name]; dup {
			return nil, ErrSourceDup
		}
		if acme != nil {
			if _, both := acme.allowed[name]; both {
				return nil, ErrSourceOverlap
			}
		}
		c := e.Cert
		c.Certificate = slices.Clone(c.Certificate)
		s.static[name] = &c
		s.order = append(s.order, name)
	}
	return s, nil
}

// Refused returns the number of handshakes that the source refused.
// It counts the name gate refusals, the acme-tls/1 handshakes for a static
// name, and the refusals of the ACME client.
func (s *CertSource) Refused() uint64 {
	n := s.refused.Load()
	if s.acme != nil {
		n += s.acme.Refused()
	}
	return n
}

// GetCertificate is the tls.Config.GetCertificate function of the decoy
// listener.
// A name that is not a decoy name gets a fixed error. It makes no storage
// call, no request and no log line. It records the reason on the connection.
// A static name gets its stored certificate at once, also after the leaf
// expired.
// A static name that negotiates acme-tls/1 fails and records no gate reason.
// An ACME name goes to the ACME client.
func (s *CertSource) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	name, ok := normalizeServerName(hello.ServerName)
	if !ok {
		return nil, s.refuseName(hello, event.ReasonUnknownName)
	}
	if cert, isStatic := s.static[name]; isStatic {
		if negotiatesChallenge(hello) {
			s.refused.Add(1)
			return nil, errStaticALPN
		}
		return cert, nil
	}
	if s.acme != nil {
		if _, isACME := s.acme.allowed[name]; isACME {
			return s.acme.GetCertificate(hello)
		}
	}
	reason := event.ReasonUnknownName
	if hello.ServerName == "" {
		reason = event.ReasonNoServerName
	}
	return nil, s.refuseName(hello, reason)
}

func (s *CertSource) refuseName(hello *tls.ClientHelloInfo, reason event.RefusedReason) error {
	s.refused.Add(1)
	recordGate(hello, reason)
	return errName
}

// WarnExpiry writes the expiry warnings to logger at once.
// It writes them again each 24 hours until ctx ends.
// A leaf with less than 14 days left gets one Warn line.
// An expired leaf gets the same line.
// The line has a fixed message and the attribute name.
// The line holds no date, serial or file text.
// WarnExpiry starts one goroutine.
func (s *CertSource) WarnExpiry(ctx context.Context, logger *slog.Logger) {
	s.warnExpiry(ctx, logger)
}

// warnExpiry is WarnExpiry. The channel that it returns closes when the
// goroutine has ended.
func (s *CertSource) warnExpiry(ctx context.Context, logger *slog.Logger) <-chan struct{} {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	now, newTicker := s.now, s.newTicker
	if now == nil {
		now = time.Now
	}
	if newTicker == nil {
		newTicker = func(d time.Duration) (<-chan time.Time, func()) {
			t := time.NewTicker(d)
			return t.C, t.Stop
		}
	}
	s.warnOnce(logger, now())
	tick, stop := newTicker(expiryWarnEvery)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick:
				s.warnOnce(logger, now())
			}
		}
	}()
	return done
}

func (s *CertSource) warnOnce(logger *slog.Logger, now time.Time) {
	for _, name := range s.order {
		if s.static[name].Leaf.NotAfter.Sub(now) < expiryWarnWithin {
			logger.Warn("static certificate expires in less than 14 days", "name", name)
		}
	}
}
