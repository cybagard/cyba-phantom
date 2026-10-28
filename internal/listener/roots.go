package listener

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

// The fixed errors of ParseACMERoots. The text never holds file bytes, a PEM
// type line or the text of a library error.
var (
	errRootsEmpty  = errors.New("listener: acme: the root file has no certificate")
	errRootsText   = errors.New("listener: acme: the root file has text outside the certificate blocks")
	errRootsType   = errors.New("listener: acme: the root file has a block that is not a certificate")
	errRootsHeader = errors.New("listener: acme: a certificate block of the root file has a header")
	errRootsParse  = errors.New("listener: acme: a certificate block of the root file does not parse")
	errRootsNotCA  = errors.New("listener: acme: a certificate of the root file is not a CA certificate")
)

// ACMERoots are the root certificates that the ACME client trusts for the CA.
// Only ParseACMERoots makes a value that holds roots.
type ACMERoots struct {
	pool *x509.CertPool
}

const (
	pemBegin   = "-----BEGIN "
	pemSpace   = " \t\r\n"
	pemCertTyp = "CERTIFICATE"
)

// ParseACMERoots parses the bytes of the acme.ca_root file. The file has one or
// more certificate blocks. Each block has no header, and each certificate is a
// CA certificate. Only space, tab, CR and LF can be outside the blocks. It
// opens no file.
func ParseACMERoots(data []byte) (*ACMERoots, error) {
	pool := x509.NewCertPool()
	count := 0
	for rest := data; ; count++ {
		rest = bytes.TrimLeft(rest, pemSpace)
		if len(rest) == 0 {
			break
		}
		// pem.Decode skips text before a block, so check each block start.
		if !bytes.HasPrefix(rest, []byte(pemBegin)) {
			return nil, errRootsText
		}
		block, after := pem.Decode(rest)
		if block == nil || bytes.Count(rest[:len(rest)-len(after)], []byte(pemBegin)) != 1 {
			return nil, errRootsText
		}
		rest = after
		switch {
		case block.Type != pemCertTyp:
			return nil, errRootsType
		case len(block.Headers) != 0:
			return nil, errRootsHeader
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, errRootsParse
		}
		if !cert.BasicConstraintsValid || !cert.IsCA {
			return nil, errRootsNotCA
		}
		pool.AddCert(cert)
	}
	if count == 0 {
		return nil, errRootsEmpty
	}
	return &ACMERoots{pool: pool}, nil
}
