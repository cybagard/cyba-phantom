package listener

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
)

const (
	maxNames = 16 // the most configured names

	// A 90-day certificate renews about 31.5 days before it ends. The ratio 1/3
	// would start the renewal just below 30 days (FR-01).
	renewalRatio = 0.35
)

// The fixed errors of the ACME client. The text never holds a name, a host or
// the data of a request.
var (
	errEgress = errors.New("listener: acme: request is not for the configured CA")
	errName   = errors.New("listener: acme: server name is not configured")

	errNoChallenge = errors.New("listener: acme: no active challenge for the server name")
)

// ACMEParams are the inputs of NewACME.
type ACMEParams struct {
	Names   []string          // 1 to 16 DNS names in lower case; the config loader checks the DNS syntax
	CA      string            // the directory URL of the CA, https (acme.ca)
	Email   string            // the account contact (acme.email)
	Storage certmagic.Storage // the certificate cache, for example a *Store
	Host    string            // the host of listen.https
	Port    int               // the port of listen.https
	Logger  *slog.Logger      // gets the fixed event lines

	// OnEgress is a test hook. The egress guard calls it with the host of each
	// request that it sees, before it decides. It is nil in production.
	OnEgress func(host string)

	// trustedRoots is the pool of root certificates that the ACME client trusts
	// for the CA. It is a test hook; only tests in this package set it. It is nil
	// in production, and then the client uses the roots of the system.
	trustedRoots *x509.CertPool

	// maintenanceInterval is the time between two renewal checks, and between two
	// OCSP checks, of the certificate cache. It is a test hook; only tests in this
	// package set it. It is zero in production, and then certmagic uses its default
	// intervals.
	maintenanceInterval time.Duration
}

// ACME is the certmagic configuration of the decoy listener. It has one issuer.
// It makes no request to a host other than the CA, and it manages certificates
// for the configured names only.
type ACME struct {
	cfg     *certmagic.Config
	cache   *certmagic.Cache
	names   []string
	allowed map[string]struct{}
	logger  *slog.Logger
	refused atomic.Uint64
	stop    sync.Once

	challenge func(string) (certmagic.Challenge, bool) // the lookup of an active challenge; tests replace it
}

// NewACME builds the configuration from p. It makes the certmagic cache, which
// runs a maintenance goroutine. The caller must call Stop. NewACME does not read
// the storage and makes no request. It sets the fields that the decoy listener
// depends on. The other fields come from certmagic.Default and
// certmagic.DefaultACME, which the sensor does not change.
func NewACME(p ACMEParams) (*ACME, error) {
	ca, err := url.Parse(p.CA)
	switch {
	case len(p.Names) < 1 || len(p.Names) > maxNames:
		return nil, errors.New("listener: acme: the number of names is not 1 to 16")
	case err != nil || ca.Scheme != "https" || ca.Hostname() == "":
		return nil, errors.New("listener: acme: the CA URL is not an https URL")
	case ca.User != nil || strings.Contains(p.CA, "#") || !validPort(ca.Port()):
		return nil, errors.New("listener: acme: the CA URL has user info, a fragment or a port that is not 1 to 65535")
	case p.Storage == nil || p.Logger == nil || p.Port < 1 || p.Port > 65535:
		return nil, errors.New("listener: acme: storage or logger is not set, or the port is not 1 to 65535")
	}
	a := &ACME{names: slices.Clone(p.Names), allowed: map[string]struct{}{}, logger: p.Logger, challenge: certmagic.GetACMEChallenge}
	for _, n := range a.names {
		if !validName(n) {
			return nil, errors.New("listener: acme: a name is empty, has an upper-case letter or a byte above 0x7f, or ends with a dot")
		}
		if _, dup := a.allowed[n]; dup {
			return nil, errors.New("listener: acme: a name is in the list more than one time")
		}
		a.allowed[n] = struct{}{}
	}
	guard := egressGuard(ca, p.OnEgress)
	var cfg atomic.Pointer[certmagic.Config] // the cache needs the config, the config needs the cache
	a.cache = certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert:   func(certmagic.Certificate) (*certmagic.Config, error) { return cfg.Load(), nil },
		RenewCheckInterval: p.maintenanceInterval,
		OCSPCheckInterval:  p.maintenanceInterval,
		Logger:             zap.NewNop(),
	})
	a.cfg = certmagic.New(a.cache, certmagic.Config{
		RenewalWindowRatio: renewalRatio,
		MustStaple:         false,
		OCSP:               certmagic.OCSPConfig{DisableStapling: true, HTTPProxy: guard},
		Issuers:            []certmagic.Issuer{}, // not nil: New would make an issuer from the package defaults
		Storage:            p.Storage,
		Logger:             zap.NewNop(),
		ShouldEmitFunc:     isLoggedEvent,
		OnEvent: func(ctx context.Context, event string, data map[string]any) error {
			// certmagic calls OnEvent for each event. Only three events get a line.
			if !isLoggedEvent(event) {
				return nil
			}
			// Only a configured name goes into the line.
			name, _ := data["identifier"].(string)
			if _, ok := a.allowed[name]; !ok {
				name = ""
			}
			level := slog.LevelInfo
			if event == "cert_failed" {
				level = slog.LevelWarn
			}
			a.logger.LogAttrs(ctx, level, "acme certificate event", slog.String("event", event), slog.String("name", name))
			return nil
		},
	})
	cfg.Store(a.cfg)
	a.cfg.Issuers = []certmagic.Issuer{certmagic.NewACMEIssuer(a.cfg, certmagic.ACMEIssuer{
		CA:                        p.CA,
		TestCA:                    p.CA, // if not set, certmagic uses the staging host of a known CA
		Email:                     p.Email,
		Agreed:                    true, // the sensor accepts the CA terms; certmagic must not ask
		DisableHTTPChallenge:      true,
		DisableDistributedSolvers: true,
		ListenHost:                p.Host,
		AltTLSALPNPort:            p.Port,
		Logger:                    zap.NewNop(),
		HTTPProxy:                 guard,
		TrustedRoots:              p.trustedRoots,
	})}
	return a, nil
}

// validPort reports whether s is empty or a port from 1 to 65535.
func validPort(s string) bool {
	if s == "" {
		return true
	}
	n, err := strconv.Atoi(s)
	return err == nil && n >= 1 && n <= 65535
}

// validName reports whether n can be a configured name: not empty, ASCII, no
// upper-case letter and no trailing dot.
func validName(n string) bool {
	if n == "" || strings.HasSuffix(n, ".") {
		return false
	}
	for i := 0; i < len(n); i++ {
		if c := n[i]; c >= 0x80 || ('A' <= c && c <= 'Z') {
			return false
		}
	}
	return true
}

// isLoggedEvent reports whether an event of certmagic gets a log line.
func isLoggedEvent(event string) bool {
	return event == "cert_obtaining" || event == "cert_obtained" || event == "cert_failed"
}

// egressGuard returns the proxy function for the ACME client and the OCSP
// client. It refuses each request whose scheme, host or port differs from ca. It
// never gives a proxy, so it never uses a proxy from the environment. seen may be
// nil.
//
// The transport calls the function for each new connection and for each
// HTTP/1.1 request. A request on a pooled HTTP/2 connection to the same
// authority does not call it. The function allowed that authority when the
// transport made the connection.
func egressGuard(ca *url.URL, seen func(host string)) func(*http.Request) (*url.URL, error) {
	scheme, host, port := strings.ToLower(ca.Scheme), strings.ToLower(ca.Hostname()), portOf(ca)
	return func(r *http.Request) (*url.URL, error) {
		if seen != nil {
			seen(r.URL.Host)
		}
		if strings.ToLower(r.URL.Scheme) != scheme || strings.ToLower(r.URL.Hostname()) != host || portOf(r.URL) != port {
			return nil, errEgress
		}
		return nil, nil
	}
}

// portOf returns the port of u. A URL with no port gets the port of its scheme.
func portOf(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return "443"
	case "http":
		return "80"
	}
	return ""
}

// GetCertificate is the tls.Config.GetCertificate function of the decoy
// listener. It calls certmagic only for a configured name. For no name or another
// name, it returns a fixed error at once: no storage call, no request and no log
// line. This also holds for ALPN acme-tls/1, which certmagic would answer with a
// storage read for any name.
//
// A handshake for a configured name whose ALPN list is exactly acme-tls/1 goes
// to certmagic only while an in-memory challenge for that name is active. If no
// challenge is active, the handshake fails at once with errNoChallenge: no
// storage call, no request and no log line. Refused counts these refusals
// together with the refusals of the name gate. The condition is the same as the
// condition of certmagic (one protocol, the exact string). Thus this check does
// not refuse a handshake with two protocols. This process writes no distributed
// token file (DisableDistributedSolvers), so only an in-memory challenge can be
// valid. If a challenge ends between this check and the lookup of certmagic,
// certmagic reads the storage one time for the token file of the name.
func (a *ACME) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	// ToLower maps U+212A KELVIN SIGN to "k". The loop refuses each byte of 0x80
	// or more first, so ToLower changes only ASCII letters.
	name := hello.ServerName
	for i := 0; i < len(name); i++ {
		if name[i] >= 0x80 {
			a.refused.Add(1)
			return nil, errName
		}
	}
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	if _, ok := a.allowed[name]; !ok {
		a.refused.Add(1)
		return nil, errName
	}
	if len(hello.SupportedProtos) == 1 && hello.SupportedProtos[0] == challengeProto {
		if _, active := a.challenge(name); !active {
			a.refused.Add(1)
			return nil, errNoChallenge
		}
	}
	h := *hello
	h.ServerName = name
	return a.cfg.GetCertificate(&h)
}

// Refused returns the number of handshakes that GetCertificate refused: the
// handshakes that the name gate refused, and the acme-tls/1 handshakes for a
// configured name with no active challenge.
func (a *ACME) Refused() uint64 { return a.refused.Load() }

// Start loads the cached certificates of the configured names, then starts
// their management. A handshake that follows Start gets the cached certificate
// of its name, if that certificate loaded.
// The load reads the storage only: stapling is off, and the ARI data comes from
// the stored resource. A name with no cached certificate is not an error. Any
// other load error writes one fixed line and does not fail Start.
//
// A certificate that Start loaded and that is due for renewal starts its renewal
// in the background at once. The old certificate stays in the cache until the
// new one is stored, then the new one replaces it. ManageAsync does the obtain
// work for the other names in the background. Those jobs stop when ctx ends.
// The maintenance of the cache runs until Stop. A certificate that is not due
// gets its first renew or ARI check at the first maintenance tick. The reason is
// that certmagic manageOne returns at once for a managed certificate. An ACME
// error does not fail Start. Start does not wait for the network.
func (a *ACME) Start(ctx context.Context) error {
	for _, n := range a.names {
		cert, err := a.cfg.CacheManagedCertificate(ctx, n)
		switch {
		case err != nil && !errors.Is(err, fs.ErrNotExist):
			a.logger.LogAttrs(ctx, slog.LevelWarn, "acme certificate load failed", slog.String("name", n))
		case err == nil && cert.NeedsRenewal(a.cfg):
			go a.renewDue(ctx, n, cert)
		}
	}
	return a.cfg.ManageAsync(ctx, a.names)
}

// renewDue renews the cached certificate old of name. The renewal tries again
// after a failure. It stops when it succeeds, when its retry time ends, or when
// ctx ends, so it runs in its own goroutine. A renewal only writes the storage,
// so on success the new certificate goes into the cache and replaces old. A
// failure writes no line here. While it runs, a renewal of the same name at a
// maintenance tick waits for it.
func (a *ACME) renewDue(ctx context.Context, name string, old certmagic.Certificate) {
	if err := a.cfg.RenewCertAsync(ctx, name, false); err != nil {
		return
	}
	if cert, err := a.cfg.CacheManagedCertificate(ctx, name); err == nil && cert.Hash() != old.Hash() {
		a.cache.Remove([]string{old.Hash()})
	}
}

// Stop stops the maintenance goroutine of the certmagic cache. It waits for the
// goroutine to end. A second call does nothing.
func (a *ACME) Stop() { a.stop.Do(a.cache.Stop) }
