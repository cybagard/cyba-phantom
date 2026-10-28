// The static certificate read (SEC-31, SEC-21) makes one tls.Certificate.
// Its input is the bytes of a certificate file and of a key file.
// It opens no file. It does not serve, log or warn.
// Each refusal is a fixed error. No error text holds a byte of a file,
// a PEM type line, a library error text or a key.

package listener

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"time"
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
// The key file holds one block, a private key. The block type is
// PRIVATE KEY (PKCS8), RSA PRIVATE KEY (PKCS1) or EC PRIVATE KEY (SEC1),
// and the type names the form of the key. The key must encode back to the
// same bytes in that form.
// In both files, a block has no header.
// Outside the blocks, only the bytes space, tab, CR and LF are permitted.
// The leaf is valid for name at now. Only the SAN entries (DNS names and IP
// addresses) count, not the Common Name.
// The leaf is not a CA certificate. Its key is RSA with 2048 to 4096 bits,
// ECDSA P-256 or P-384, or Ed25519. The key matches the leaf.
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
	switch keyBlocks[0].Type {
	case pkcs8Type, pkcs1Type, sec1Type:
	default:
		return tls.Certificate{}, ErrStaticType
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
// The Go parsers ignore bytes and ASN.1 elements at the end of a sequence.
// So parseStaticKey encodes the key again in the same form and refuses
// a key whose encoding differs from der.
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
		k, perr := x509.ParsePKCS1PrivateKey(der)
		if perr != nil {
			return nil, ErrStaticKey
		}
		key, again = k, x509.MarshalPKCS1PrivateKey(k)
	case sec1Type:
		k, perr := x509.ParseECPrivateKey(der)
		if perr != nil {
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
