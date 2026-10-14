package listener

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"

	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
)

const (
	maxNames = 16 // the most configured names

	// The ALPN name of the TLS-ALPN-01 challenge.
	alpnACME = "acme-tls/1"

	// A 90-day certificate renews about 31.5 days before it ends. The ratio 1/3
	// would start the renewal just below 30 days (FR-01).
	renewalRatio = 0.35
)

// The fixed errors of the ACME client. The text never holds a name, a host or
// the data of a request.
var (
	errEgress = errors.New("listener: acme: request is not for the configured CA")
	errName   = errors.New("listener: acme: server name is not configured")
)

// ACMEParams are the inputs of NewACME.
type ACMEParams struct {
	Names   []string          // 1 to 16 DNS names, valid and in lower case (acme.names)
	CA      string            // the directory URL of the CA, https (acme.ca)
	Email   string            // the account contact (acme.email)
	Storage certmagic.Storage // the certificate cache, for example a *Store
	Host    string            // the host of listen.https
	Port    int               // the port of listen.https
	Logger  *slog.Logger      // gets the fixed event lines

	// OnEgress is a test hook. The egress guard calls it with the host of each
	// request that it sees, before it decides. It is nil in production.
	OnEgress func(host string)
}

// ACME is the certmagic configuration of the decoy listener. It has one issuer.
// It makes no request to a host other than the CA, and it manages certificates
// for the configured names only.
type ACME struct {
	cfg     *certmagic.Config
	cache   *certmagic.Cache
	names   []string
	allowed map[string]struct{}
	refused atomic.Uint64
}

// NewACME builds the configuration from p. It makes the certmagic cache, which
// runs a maintenance goroutine. The caller must call Stop. NewACME does not read
// the storage and makes no request. It sets each field that certmagic would else
// take from its package variables.
func NewACME(p ACMEParams) (*ACME, error) {
	ca, err := url.Parse(p.CA)
	switch {
	case len(p.Names) < 1 || len(p.Names) > maxNames:
		return nil, errors.New("listener: acme: the number of names is not 1 to 16")
	case err != nil || ca.Scheme != "https" || ca.Hostname() == "":
		return nil, errors.New("listener: acme: the CA URL is not an https URL")
	case p.Storage == nil || p.Logger == nil || p.Port < 1 || p.Port > 65535:
		return nil, errors.New("listener: acme: storage, logger or port is not set")
	}
	a := &ACME{names: slices.Clone(p.Names), allowed: map[string]struct{}{}}
	for _, n := range a.names {
		a.allowed[n] = struct{}{}
	}
	guard := egressGuard(ca, p.OnEgress)
	var cfg atomic.Pointer[certmagic.Config] // the cache needs the config, the config needs the cache
	a.cache = certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) { return cfg.Load(), nil },
		Logger:           zap.NewNop(),
	})
	log := p.Logger
	a.cfg = certmagic.New(a.cache, certmagic.Config{
		RenewalWindowRatio: renewalRatio,
		MustStaple:         false,
		OCSP:               certmagic.OCSPConfig{DisableStapling: true, HTTPProxy: guard},
		Issuers:            []certmagic.Issuer{}, // not nil: New would make an issuer from the package defaults
		Storage:            p.Storage,
		Logger:             zap.NewNop(),
		ShouldEmitFunc: func(event string) bool {
			return event == "cert_obtaining" || event == "cert_obtained" || event == "cert_failed"
		},
		OnEvent: func(ctx context.Context, event string, data map[string]any) error {
			// Only a configured name goes into the line.
			name, _ := data["identifier"].(string)
			if _, ok := a.allowed[name]; !ok {
				name = ""
			}
			level := slog.LevelInfo
			if event == "cert_failed" {
				level = slog.LevelWarn
			}
			log.LogAttrs(ctx, level, "acme certificate event", slog.String("event", event), slog.String("name", name))
			return nil
		},
	})
	cfg.Store(a.cfg)
	a.cfg.Issuers = []certmagic.Issuer{certmagic.NewACMEIssuer(a.cfg, certmagic.ACMEIssuer{
		CA:                        p.CA,
		TestCA:                    p.CA, // else certmagic takes the staging host of a known CA
		Email:                     p.Email,
		Agreed:                    true, // else certmagic asks on stdin
		DisableHTTPChallenge:      true,
		DisableDistributedSolvers: true,
		ListenHost:                p.Host,
		AltTLSALPNPort:            p.Port,
		Logger:                    zap.NewNop(),
		HTTPProxy:                 guard,
	})}
	return a, nil
}

// egressGuard returns the proxy function for the ACME client and the OCSP
// client. It refuses each request whose scheme, host or port differs from ca. It
// never gives a proxy, so the environment is not used. seen may be nil.
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
func (a *ACME) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	name := strings.TrimSuffix(strings.ToLower(hello.ServerName), ".")
	if _, ok := a.allowed[name]; !ok {
		a.refused.Add(1)
		return nil, errName
	}
	h := *hello
	h.ServerName = name
	return a.cfg.GetCertificate(&h)
}

// Refused returns the number of handshakes that the name gate refused.
func (a *ACME) Refused() uint64 { return a.refused.Load() }

// Start starts the management of the configured names. Cached certificates load
// in the call. Obtain, renew and ARI run in the background until ctx ends. An
// ACME error does not fail Start, and Start does not wait for the network.
func (a *ACME) Start(ctx context.Context) error {
	return a.cfg.ManageAsync(ctx, a.names)
}

// Stop stops the maintenance goroutine of the certmagic cache. It waits for the
// goroutine to end.
func (a *ACME) Stop() { a.cache.Stop() }
