// Package fetch is the HTTPS client of the bundle fetch (SEC-34). It gets the
// archive and the signature file of one bundle. It dials only through the
// egress guard, with the private list of bundle.fetch_url. It uses no proxy, no
// redirect, no compression and only HTTP/1.1. It reads at most 8 MiB for the
// archive and 1 KiB for the signature file. A failure has a fixed class
// (Class), one log line, and a counter. The schedule, the change check and the
// load of the bytes belong to the callers.
package fetch

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/cybagard/cyba-phantom/internal/egress"
)

const (
	maxArchive       = 8 << 20
	maxSignature     = 1 << 10
	archiveTimeout   = 120 * time.Second
	signatureTimeout = 30 * time.Second
	headerTimeout    = 30 * time.Second
	handshakeTimeout = 10 * time.Second
	dialTimeout      = 10 * time.Second
	maxHeader        = 16 << 10
	idleTimeout      = 30 * time.Second
)

var errURL = errors.New("bundle fetch: the URL must be https with a path that ends in .cbnd")

// settings are the bounds of a client. New uses the production values. Only a
// test in this package sets another value, through newClient.
type settings struct {
	archiveCap, sigCap         int
	archiveTimeout, sigTimeout time.Duration
	headerTimeout              time.Duration
	dialer                     *net.Dialer         // replaces the item dialer
	dialAddr                   func(string) string // rewrites the dial address
	roots                      *x509.CertPool      // nil: the system roots
	now                        func() time.Time
}

// Client gets the two files of one bundle. It is safe for concurrent use.
type Client struct {
	archiveURL, sigURL string
	archive, sig       *http.Client
	transport          *http.Transport
	itemDialer         *net.Dialer // always from egress.ItemDialer
	dialer             *net.Dialer // the dialer that the transport calls
	log                *slog.Logger
	now                func() time.Time
	cfg                settings
	counts             [len(classes)]atomic.Uint64
	lastGood           atomic.Int64
}

// New makes the client for fetchURL (bundle.fetch_url). private is the list of
// bundle.fetch_private. The URL must be https. Its path must end in .cbnd, with
// at least one character before it in the last part. The signature file is the
// same URL with .sig in place of that .cbnd. The errors have no URL.
func New(fetchURL string, private []netip.Prefix, log *slog.Logger) (*Client, error) {
	return newClient(fetchURL, private, log, settings{})
}

func newClient(fetchURL string, private []netip.Prefix, log *slog.Logger, s settings) (*Client, error) {
	u, err := url.Parse(fetchURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return nil, errURL
	}
	last := u.Path[strings.LastIndexByte(u.Path, '/')+1:]
	if !strings.HasSuffix(last, ".cbnd") || len(last) == len(".cbnd") {
		return nil, errURL
	}
	sig := *u
	sig.Path = strings.TrimSuffix(u.Path, ".cbnd") + ".sig"
	if u.RawPath != "" {
		sig.RawPath = strings.TrimSuffix(u.RawPath, ".cbnd") + ".sig"
	}
	port := uint64(443)
	if p := u.Port(); p != "" {
		if port, err = strconv.ParseUint(p, 10, 16); err != nil {
			return nil, errURL
		}
	}
	itemDialer, err := egress.ItemDialer(private, uint16(port), "tcp", dialTimeout)
	if err != nil {
		return nil, errors.New("bundle fetch: the port or the private list is not valid")
	}
	dialer := itemDialer
	s.defaults()
	if s.dialer != nil {
		dialer = s.dialer
	}
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		if s.dialAddr != nil {
			addr = s.dialAddr(addr)
		}
		return dialer.DialContext(ctx, network, addr)
	}
	tr := &http.Transport{
		Proxy:                  nil,
		DialContext:            dial,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: s.roots},
		TLSHandshakeTimeout:    handshakeTimeout,
		ResponseHeaderTimeout:  s.headerTimeout,
		MaxResponseHeaderBytes: maxHeader,
		DisableCompression:     true,
		DisableKeepAlives:      true,
		// No effect with keep-alive off; if on, at most one idle connection.
		IdleConnTimeout:     idleTimeout,
		MaxIdleConns:        1,
		MaxIdleConnsPerHost: 1,
		ForceAttemptHTTP2:   false,
		TLSNextProto:        map[string]func(string, *tls.Conn) http.RoundTripper{},
	}
	refuse := func(*http.Request, []*http.Request) error { return errRedirect }
	return &Client{
		archiveURL: u.String(), sigURL: sig.String(),
		archive:   &http.Client{Transport: tr, CheckRedirect: refuse, Timeout: s.archiveTimeout},
		sig:       &http.Client{Transport: tr, CheckRedirect: refuse, Timeout: s.sigTimeout},
		transport: tr, itemDialer: itemDialer, dialer: dialer, log: log, now: s.now, cfg: s,
	}, nil
}

// defaults fills each unset field with the production value.
func (s *settings) defaults() {
	if s.archiveCap == 0 {
		s.archiveCap = maxArchive
	}
	if s.sigCap == 0 {
		s.sigCap = maxSignature
	}
	if s.archiveTimeout == 0 {
		s.archiveTimeout = archiveTimeout
	}
	if s.sigTimeout == 0 {
		s.sigTimeout = signatureTimeout
	}
	if s.headerTimeout == 0 {
		s.headerTimeout = headerTimeout
	}
	if s.now == nil {
		s.now = time.Now
	}
}

// Archive gets the archive. It gives the bytes (at most 8 MiB) or a Class.
func (c *Client) Archive(ctx context.Context) ([]byte, error) {
	return c.get(ctx, c.archive, c.archiveURL, c.cfg.archiveCap)
}

// Signature gets the signature file. It gives the bytes (at most 1 KiB) or a
// Class.
func (c *Client) Signature(ctx context.Context) ([]byte, error) {
	return c.get(ctx, c.sig, c.sigURL, c.cfg.sigCap)
}

// get does one GET and reads the body into one buffer of limit + 1 bytes. Only
// status 200 passes. A body that fills the buffer is over the limit.
func (c *Client) get(ctx context.Context, hc *http.Client, target string, limit int) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, c.Record(ClassTransport, 0)
	}
	resp, err := hc.Do(req)
	status := 0
	if resp != nil { // also set for a refused redirect, with the body closed
		status = resp.StatusCode
		defer resp.Body.Close()
	}
	switch {
	case err != nil:
		return nil, c.Record(classify(err), status)
	case status != http.StatusOK:
		return nil, c.Record(ClassStatus, status)
	case resp.ContentLength > int64(limit):
		return nil, c.Record(ClassSize, status)
	}
	buf := make([]byte, limit+1)
	n := 0
	for n < len(buf) && err == nil {
		var k int
		k, err = resp.Body.Read(buf[n:])
		n += k
	}
	switch {
	case n == len(buf):
		return nil, c.Record(ClassSize, status)
	case err != io.EOF:
		return nil, c.Record(classify(err), status)
	}
	return buf[:n], nil
}
