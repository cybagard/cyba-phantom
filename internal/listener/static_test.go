package listener

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"
)

const staticHost = "decoy.internal"

// staticNow is far from the real clock.
// A read of the real clock then fails the tests.
var staticNow = time.Date(2030, 6, 15, 12, 0, 0, 0, time.UTC)

// staticKeys are the keys of the tests.
type staticKeys struct {
	rsa2048, rsa4096  *rsa.PrivateKey
	p256, p256b, p384 *ecdsa.PrivateKey
	p224, p521        *ecdsa.PrivateKey
	ed, ed2           ed25519.PrivateKey
	issuer            *ecdsa.PrivateKey
	issuerDER         []byte
}

// staticKeySet makes the keys one time for the binary, as RSA keys are slow.
var staticKeySet = sync.OnceValue(func() *staticKeys {
	must := func(err error) {
		if err != nil {
			panic(err)
		}
	}
	k := &staticKeys{}
	var err error
	k.rsa2048, err = rsa.GenerateKey(rand.Reader, 2048)
	must(err)
	k.rsa4096, err = rsa.GenerateKey(rand.Reader, 4096)
	must(err)
	for p, c := range map[**ecdsa.PrivateKey]elliptic.Curve{
		&k.p256: elliptic.P256(), &k.p256b: elliptic.P256(), &k.p384: elliptic.P384(),
		&k.p224: elliptic.P224(), &k.p521: elliptic.P521(), &k.issuer: elliptic.P256(),
	} {
		*p, err = ecdsa.GenerateKey(c, rand.Reader)
		must(err)
	}
	_, k.ed, err = ed25519.GenerateKey(rand.Reader)
	must(err)
	_, k.ed2, err = ed25519.GenerateKey(rand.Reader)
	must(err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test issuer"},
		NotBefore: staticNow.Add(-time.Hour), NotAfter: staticNow.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	k.issuerDER, err = x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.issuer.PublicKey, k.issuer)
	must(err)
	return k
})

// fakeRSA is a public key with a modulus of bits bits. It has no private key.
func fakeRSA(bits int) *rsa.PublicKey {
	n := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))
	return &rsa.PublicKey{N: n.Add(n, big.NewInt(1)), E: 65537}
}

// leafSpec describes a leaf. The zero value is a valid leaf of the key p256.
type leafSpec struct {
	pub       any // public key of the leaf; nil is the key of the key file
	key       any // private key in the key file; nil is p256
	dns       []string
	cn        string
	isCA      bool
	usage     x509.KeyUsage
	notBefore time.Duration // from staticNow; zero is one hour before
	notAfter  time.Duration // from staticNow; zero is one hour after
}

func (s leafSpec) build(t *testing.T) (certDER, keyPEM []byte) {
	t.Helper()
	ks := staticKeySet()
	if s.key == nil {
		s.key = ks.p256
	}
	if s.pub == nil {
		s.pub = s.key.(crypto.Signer).Public()
	}
	if s.dns == nil && s.cn == "" {
		s.dns = []string{staticHost}
	}
	if s.notBefore == 0 {
		s.notBefore = -time.Hour
	}
	if s.notAfter == 0 {
		s.notAfter = time.Hour
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: s.cn}, DNSNames: s.dns,
		NotBefore: staticNow.Add(s.notBefore), NotAfter: staticNow.Add(s.notAfter),
		IsCA: s.isCA, BasicConstraintsValid: s.isCA, KeyUsage: s.usage,
	}
	issuer, err := x509.ParseCertificate(ks.issuerDER)
	if err != nil {
		t.Fatal(err)
	}
	certDER, err = x509.CreateCertificate(rand.Reader, tmpl, issuer, s.pub, ks.issuer)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(s.key)
	if err != nil {
		t.Fatal(err)
	}
	return certDER, blockPEM("PRIVATE KEY", keyDER)
}

// blockPEM returns the PEM text of one block with no header.
func blockPEM(typ string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}

// noFileText checks that err is the fixed error want.
// Its text holds no PEM marker and none of the markers that the test put
// in the files.
func noFileText(t *testing.T, err, want error, markers ...string) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}
	text := err.Error()
	for _, m := range append([]string{"-----", "PRIVATE", "CERTIFICATE"}, markers...) {
		if strings.Contains(text, m) {
			t.Fatalf("error text %q holds %q", text, m)
		}
	}
}

// T-S-27: the PEM reader refuses text outside the blocks and a header.
// It also refuses a block of the wrong type and a wrong number of blocks.
// This is true for both files.
func TestTS27StaticPEMRefusals(t *testing.T) {
	const marker = "MARKERTEXT7"
	der, keyPEM := leafSpec{}.build(t)
	certPEM := blockPEM("CERTIFICATE", der)
	other := blockPEM(marker, []byte("x"))
	junk := []byte("-----BEGIN JUNK-----\n" + marker + "!!\n")
	withHeader := pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: der, Headers: map[string]string{marker: marker},
	})
	kb, _ := pem.Decode(keyPEM)
	keyWithHeader := pem.EncodeToMemory(&pem.Block{
		Type: "PRIVATE KEY", Bytes: kb.Bytes, Headers: map[string]string{marker: marker},
	})
	cat := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }
	badDER := blockPEM("CERTIFICATE", []byte(marker))
	rows := []struct {
		name      string
		cert, key []byte
		want      error
	}{
		{"key block in cert file", cat(certPEM, keyPEM), keyPEM, ErrStaticType},
		{"other block in cert file", cat(certPEM, other), keyPEM, ErrStaticType},
		{"text before block", cat([]byte(marker+"\n"), certPEM), keyPEM, ErrStaticText},
		{"text after last block", cat(certPEM, []byte(marker+"\n")), keyPEM, ErrStaticText},
		{"bad begin line above a block", cat(junk, certPEM), keyPEM, ErrStaticText},
		{"no-break space before block", cat([]byte("\u00a0"), certPEM), keyPEM, ErrStaticText},
		{"no-break space and line before block", cat([]byte("\u00a0\n"), certPEM), keyPEM, ErrStaticText},
		{"unfinished block after the last block", cat(certPEM, []byte("-----BEGIN X-----\n"+marker+"\n")), keyPEM, ErrStaticText},
		{"vertical tab before block", cat([]byte("\v"), certPEM), keyPEM, ErrStaticText},
		{"form feed after block", cat(certPEM, []byte("\f")), keyPEM, ErrStaticText},
		{"header in cert file", withHeader, keyPEM, ErrStaticHeader},
		{"empty cert file", nil, keyPEM, ErrStaticCount},
		{"white space only cert file", []byte(" \t\r\n \n"), keyPEM, ErrStaticCount},
		{"certificate does not parse", badDER, keyPEM, ErrStaticCert},
		{"two keys in key file", certPEM, cat(keyPEM, keyPEM), ErrStaticCount},
		{"empty key file", certPEM, nil, ErrStaticCount},
		{"certificate as key file", certPEM, certPEM, ErrStaticType},
		{"other block in key file", certPEM, other, ErrStaticType},
		{"key type with a longer suffix", certPEM, blockPEM("PRIVATE KEYS", []byte("x")), ErrStaticType},
		{"public key as key file", certPEM, blockPEM("PUBLIC KEY", []byte("x")), ErrStaticType},
		{"key type with a shorter suffix", certPEM, blockPEM("E KEY", []byte("x")), ErrStaticType},
		{"text before key", certPEM, cat([]byte(marker+"\n"), keyPEM), ErrStaticText},
		{"header in key file", certPEM, keyWithHeader, ErrStaticHeader},
		{"white space only key file", certPEM, []byte(" \t\r\n \n"), ErrStaticCount},
		{"encrypted key type", certPEM, blockPEM("ENCRYPTED PRIVATE KEY", []byte(marker)), ErrStaticType},
		{"key type with a prefix word", certPEM, blockPEM("IGNORE THIS PRIVATE KEY", kb.Bytes), ErrStaticType},
		{"unknown key type with a valid body", certPEM, blockPEM("X PRIVATE KEY", kb.Bytes), ErrStaticType},
		{"key type with a CR", certPEM, blockPEM("\rRSA PRIVATE KEY", kb.Bytes), ErrStaticType},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			cert, err := ParseStatic(staticHost, r.cert, r.key, staticNow)
			noFileText(t, err, r.want, marker)
			if len(cert.Certificate) != 0 || cert.PrivateKey != nil {
				t.Fatal("result is not empty on error")
			}
		})
	}
	t.Run("white space around blocks passes", func(t *testing.T) {
		c := cat([]byte("\r\n \t"), certPEM, []byte("\n\t "))
		if _, err := ParseStatic(staticHost, c, cat([]byte(" "), keyPEM, []byte("\r\n")), staticNow); err != nil {
			t.Fatal(err)
		}
	})
}

// T-S-27: the leaf checks give fixed errors, and the key rules pass at their
// bounds.
func TestTS27StaticLeafChecks(t *testing.T) {
	ks := staticKeySet()
	hour := time.Hour
	rows := []struct {
		name string
		spec leafSpec
		host string
		now  time.Time
		want error
	}{
		{"other name", leafSpec{}, "other.internal", staticNow, ErrStaticName},
		{"name only in the common name", leafSpec{cn: staticHost, dns: []string{}}, staticHost, staticNow, ErrStaticName},
		{"name in the SAN, other common name", leafSpec{cn: "other.internal", dns: []string{staticHost}}, staticHost, staticNow, nil},
		{"key of another leaf, same type", leafSpec{pub: &ks.p256b.PublicKey}, staticHost, staticNow, ErrStaticMismatch},
		{"key of another leaf, other type", leafSpec{pub: ks.ed.Public()}, staticHost, staticNow, ErrStaticMismatch},
		{"RSA key of another RSA leaf", leafSpec{key: ks.rsa2048, pub: fakeRSA(2048)}, staticHost, staticNow, ErrStaticMismatch},
		{"Ed25519 key of another Ed25519 leaf", leafSpec{key: ks.ed, pub: ks.ed2.Public()}, staticHost, staticNow, ErrStaticMismatch},
		{"expired", leafSpec{}, staticHost, staticNow.Add(hour + time.Second), ErrStaticExpired},
		{"not valid yet", leafSpec{}, staticHost, staticNow.Add(-hour - time.Second), ErrStaticNotYet},
		{"valid at not before", leafSpec{}, staticHost, staticNow.Add(-hour), nil},
		{"valid at not after", leafSpec{}, staticHost, staticNow.Add(hour), nil},
		{"CA leaf", leafSpec{isCA: true}, staticHost, staticNow, ErrStaticCA},
		{"cert sign leaf", leafSpec{usage: x509.KeyUsageCertSign}, staticHost, staticNow, ErrStaticCA},
		{"digital signature leaf", leafSpec{usage: x509.KeyUsageDigitalSignature}, staticHost, staticNow, nil},
		{"RSA 1024", leafSpec{pub: fakeRSA(1024)}, staticHost, staticNow, ErrStaticKeyKind},
		{"RSA 2047", leafSpec{pub: fakeRSA(2047)}, staticHost, staticNow, ErrStaticKeyKind},
		{"RSA 4097", leafSpec{pub: fakeRSA(4097)}, staticHost, staticNow, ErrStaticKeyKind},
		{"RSA 8192", leafSpec{pub: fakeRSA(8192)}, staticHost, staticNow, ErrStaticKeyKind},
		{"ECDSA P-224", leafSpec{key: ks.p224}, staticHost, staticNow, ErrStaticKeyKind},
		{"ECDSA P-521", leafSpec{key: ks.p521}, staticHost, staticNow, ErrStaticKeyKind},
		{"RSA 2048", leafSpec{key: ks.rsa2048}, staticHost, staticNow, nil},
		{"RSA 4096", leafSpec{key: ks.rsa4096}, staticHost, staticNow, nil},
		{"ECDSA P-256", leafSpec{key: ks.p256}, staticHost, staticNow, nil},
		{"ECDSA P-384", leafSpec{key: ks.p384}, staticHost, staticNow, nil},
		{"Ed25519", leafSpec{key: ks.ed}, staticHost, staticNow, nil},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			der, keyPEM := r.spec.build(t)
			cert, err := ParseStatic(r.host, blockPEM("CERTIFICATE", der), keyPEM, r.now)
			if r.want != nil {
				noFileText(t, err, r.want, staticHost, "other.internal")
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cert.Leaf == nil || !bytes.Equal(cert.Leaf.Raw, der) || cert.PrivateKey == nil {
				t.Fatal("result has no leaf or no key")
			}
		})
	}
}

// T-S-27: the CA check and the key size check of the leaf run before the
// key parse.
// A weak leaf or a CA leaf gives its own error, also when the key block does
// not parse.
func TestTS27StaticCheckOrder(t *testing.T) {
	badKey := blockPEM("PRIVATE KEY", []byte("not a key"))
	rows := []struct {
		name string
		spec leafSpec
		want error
	}{
		{"RSA 1024 leaf and a key that does not parse", leafSpec{pub: fakeRSA(1024)}, ErrStaticKeyKind},
		{"CA leaf and a key that does not parse", leafSpec{isCA: true}, ErrStaticCA},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			der, _ := r.spec.build(t)
			_, err := ParseStatic(staticHost, blockPEM("CERTIFICATE", der), badKey, staticNow)
			noFileText(t, err, r.want)
		})
	}
}

// T-S-27: ParseStatic reads the PKCS1 and SEC1 key forms.
// It takes the leaf from the first block of a chain.
func TestTS27StaticChainAndForms(t *testing.T) {
	ks := staticKeySet()
	der, keyPEM := leafSpec{}.build(t)
	leafPEM, issuerPEM := blockPEM("CERTIFICATE", der), blockPEM("CERTIFICATE", ks.issuerDER)
	cert, err := ParseStatic(staticHost, append(bytes.Clone(leafPEM), issuerPEM...), keyPEM, staticNow)
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.Certificate) != 2 || !bytes.Equal(cert.Certificate[0], der) || !bytes.Equal(cert.Leaf.Raw, der) {
		t.Fatal("the leaf is not the first block")
	}
	_, err = ParseStatic(staticHost, append(bytes.Clone(issuerPEM), leafPEM...), keyPEM, staticNow)
	noFileText(t, err, ErrStaticCA)

	rsaDER, _ := leafSpec{key: ks.rsa2048}.build(t)
	pkcs1 := blockPEM("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(ks.rsa2048))
	if _, err := ParseStatic(staticHost, blockPEM("CERTIFICATE", rsaDER), pkcs1, staticNow); err != nil {
		t.Fatalf("PKCS1 key: %v", err)
	}
	ecDER, _ := leafSpec{key: ks.p384}.build(t)
	sec1, err := x509.MarshalECPrivateKey(ks.p384)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseStatic(staticHost, blockPEM("CERTIFICATE", ecDER), blockPEM("EC PRIVATE KEY", sec1), staticNow); err != nil {
		t.Fatalf("SEC1 key: %v", err)
	}
}

// T-S-27: the block type selects one key form.
// ParseStatic refuses a key that does not encode back to the block bytes.
func TestTS27StaticKeyEncoding(t *testing.T) {
	ks := staticKeySet()
	must := func(der []byte, err error) []byte {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	extra := asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagOctetString, Bytes: []byte("extra")}

	type pkcs8Form struct {
		Version int
		Algo    pkix.AlgorithmIdentifier
		Key     []byte
	}
	type pkcs8Extra struct {
		Version int
		Algo    pkix.AlgorithmIdentifier
		Key     []byte
		Extra   asn1.RawValue
	}
	type sec1Form struct {
		Version int
		Key     []byte
		Curve   asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
		Public  asn1.BitString        `asn1:"optional,explicit,tag:1"`
	}
	type sec1Extra struct {
		Version int
		Key     []byte
		Curve   asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
		Public  asn1.BitString        `asn1:"optional,explicit,tag:1"`
		Extra   asn1.RawValue
	}

	p8 := must(x509.MarshalPKCS8PrivateKey(ks.p256))
	sec1 := must(x509.MarshalECPrivateKey(ks.p256))
	pkcs1 := x509.MarshalPKCS1PrivateKey(ks.rsa2048)
	rsaP8 := must(x509.MarshalPKCS8PrivateKey(ks.rsa2048))
	x25519, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	x25519P8 := must(x509.MarshalPKCS8PrivateKey(x25519))

	var p8Form pkcs8Form
	if _, err := asn1.Unmarshal(p8, &p8Form); err != nil {
		t.Fatal(err)
	}
	var sec1Parsed sec1Form
	if _, err := asn1.Unmarshal(sec1, &sec1Parsed); err != nil {
		t.Fatal(err)
	}
	// The inner key octets of the PKCS8 key hold the SEC1 key and a second one.
	innerTwice := p8Form
	innerTwice.Key = append(bytes.Clone(sec1), sec1...)
	p8ExtraElem := pkcs8Extra{p8Form.Version, p8Form.Algo, p8Form.Key, extra}
	sec1ExtraElem := sec1Extra{sec1Parsed.Version, sec1Parsed.Key, sec1Parsed.Curve, sec1Parsed.Public, extra}

	rows := []struct {
		name string
		key  any // the key of the leaf
		typ  string
		der  []byte
		want error // nil: the key passes
	}{
		{"PKCS8 key passes", ks.p256, "PRIVATE KEY", p8, nil},
		{"PKCS1 key passes", ks.rsa2048, "RSA PRIVATE KEY", pkcs1, nil},
		{"SEC1 key passes", ks.p256, "EC PRIVATE KEY", sec1, nil},
		{"two PKCS8 keys in one block", ks.p256, "PRIVATE KEY", append(bytes.Clone(p8), p8...), ErrStaticKey},
		{"two SEC1 keys in one block", ks.p256, "EC PRIVATE KEY", append(bytes.Clone(sec1), sec1...), ErrStaticKey},
		{"PKCS8 key and trailing bytes", ks.p256, "PRIVATE KEY", append(bytes.Clone(p8), 0), ErrStaticKey},
		{"PKCS1 key and trailing bytes", ks.rsa2048, "RSA PRIVATE KEY", append(bytes.Clone(pkcs1), 0), ErrStaticKey},
		{"PKCS8 key with a second key in the inner key octets", ks.p256, "PRIVATE KEY", must(asn1.Marshal(innerTwice)), ErrStaticKey},
		{"PKCS8 key with an extra element in the sequence", ks.p256, "PRIVATE KEY", must(asn1.Marshal(p8ExtraElem)), ErrStaticKey},
		{"SEC1 key with an extra element in the sequence", ks.p256, "EC PRIVATE KEY", must(asn1.Marshal(sec1ExtraElem)), ErrStaticKey},
		{"PKCS1 key under the PKCS8 type", ks.rsa2048, "PRIVATE KEY", pkcs1, ErrStaticKey},
		{"PKCS8 key under the PKCS1 type", ks.rsa2048, "RSA PRIVATE KEY", rsaP8, ErrStaticKey},
		{"PKCS8 key under the SEC1 type", ks.p256, "EC PRIVATE KEY", p8, ErrStaticKey},
		{"SEC1 key under the PKCS8 type", ks.p256, "PRIVATE KEY", sec1, ErrStaticKey},
		{"PKCS8 X25519 key", ks.p256, "PRIVATE KEY", x25519P8, ErrStaticKey},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			der, _ := leafSpec{key: r.key}.build(t)
			_, err := ParseStatic(staticHost, blockPEM("CERTIFICATE", der), blockPEM(r.typ, r.der), staticNow)
			if r.want == nil {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			noFileText(t, err, r.want)
		})
	}
}
