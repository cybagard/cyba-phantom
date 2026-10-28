package tlog

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/cybagard/cyba-phantom/internal/egress"
)

// Limits of the publisher (SEC-17).
const (
	publishTimeout       = 30 * time.Second
	publishHeaderTimeout = 10 * time.Second
	maxPublishResponse   = 4 << 10
	backoffStart         = 30 * time.Second
	backoffMax           = time.Hour
	backoffJitter        = 0.2
	idleConnTimeout      = 90 * time.Second
	maxResponseHeader    = 16 << 10
)

// publishError is an error of a fixed class. It has no URL, host, token, or
// response text, so the spool can wrap it and a log line can show it.
type publishError string

func (e publishError) Error() string { return "publish: " + string(e) }

const (
	errPublishTransport = publishError("transport failed")
	errPublishRedirect  = publishError("redirect refused")
	errPublishStatus    = publishError("status not 2xx")
	errPublishTimeout   = publishError("timeout")
	errPublishAddress   = publishError("address refused")
	errPublishNotConfig = publishError("target not configured")
)

// PublishTarget is one tlog.publish entry. TokenEnv names the variable that
// holds the bearer token. Private is the private list of the target. The
// publisher applies it to this target only. A nil or empty list means no list.
type PublishTarget struct {
	URL, TokenEnv string
	Private       []netip.Prefix
}

// publishOption changes the publisher. Only the tests use it, through
// newPublisher. It sets the clock, the jitter, the timeout, the trusted roots,
// the dial address, and the dialers. NewPublisher takes no option, so no caller
// outside the package can change a dialer. The dialer of each target in
// NewPublisher is egress.ItemDialer with the list of that target.
type publishOption func(*publishConfig)

type publishConfig struct {
	roots    *x509.CertPool // nil: the system roots
	timeout  time.Duration
	now      func() time.Time
	jitter   func() float64 // in [0, 1)
	dialAddr func(string) string
	// A dialer that is not nil replaces each dialer. Then dialerFor, if it is
	// not nil, changes the dialer of target i.
	dialer    *net.Dialer
	dialerFor func(int, *net.Dialer) *net.Dialer
}

// endpoint is a target with the token that NewPublisher read.
type endpoint struct{ url, token string }

// backoffState is the retry state of one target. next is the earliest time of
// the next try.
type backoffState struct {
	delay time.Duration
	next  time.Time
}

// Publisher sends the spooled checkpoints to the targets with an HTTPS PUT. One
// goroutine (Run) serves all targets. It implements Sender.
type Publisher struct {
	spool    *Spool
	targets  []endpoint
	state    []backoffState // only the Run goroutine uses this field; Send also runs on the Run goroutine
	clients  []*http.Client // one for each target, each with its own transport
	interval time.Duration
	timeout  time.Duration
	log      *slog.Logger
	now      func() time.Time
	jitter   func() float64
	wake     chan struct{}
}

// NewPublisher makes the publisher for the targets of spool, in the same order.
// It reads each token from its environment variable one time. It returns an
// error if the interval is below 30 s. It returns an error if two targets have
// the same URL. It returns an error if a token is empty or not set. It uses its
// own transport for each target, with no proxy and no redirect. The transport
// verifies TLS 1.2 or later. Each target has its own item dialer
// (egress.ItemDialer). The dialer has the port of the URL and the private list
// of that target. The guard refuses a resolved address that the rules do not
// permit (SEC-26). It returns an error if the URL or the port of a target is
// not valid. It returns an error if ItemDialer refuses the port or the list.
func NewPublisher(spool *Spool, targets []PublishTarget, interval time.Duration, log *slog.Logger) (*Publisher, error) {
	return newPublisher(spool, targets, interval, log)
}

// refuse makes the error of a constructor that refuses its input.
func refuse(format string, args ...any) error {
	return fmt.Errorf("publisher: "+format, args...)
}

func newPublisher(spool *Spool, targets []PublishTarget, interval time.Duration, log *slog.Logger, opts ...publishOption) (*Publisher, error) {
	cfg := publishConfig{timeout: publishTimeout, now: time.Now, jitter: rand.Float64}
	for _, o := range opts {
		o(&cfg)
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	if interval < backoffStart {
		return nil, refuse("the checkpoint interval must be %v or more", backoffStart)
	}
	if len(targets) != len(spool.targets) {
		return nil, refuse("the targets are not the targets of the spool")
	}
	p := &Publisher{spool: spool, interval: interval, timeout: cfg.timeout, log: log, now: cfg.now, jitter: cfg.jitter,
		state: make([]backoffState, len(targets)), wake: make(chan struct{}, 1)}
	seen := make(map[string]bool, len(targets))
	for i, t := range targets {
		if t.URL != spool.targets[i] {
			return nil, refuse("the targets are not the targets of the spool")
		}
		if seen[t.URL] {
			return nil, refuse("target %d has the same URL as an earlier target", i)
		}
		seen[t.URL] = true
		token := os.Getenv(t.TokenEnv)
		if token == "" {
			return nil, refuse("the token of target %d is empty or not set", i)
		}
		p.targets = append(p.targets, endpoint{t.URL, token})
		c, err := targetClient(i, t, &cfg)
		if err != nil {
			return nil, err
		}
		p.clients = append(p.clients, c)
	}
	return p, nil
}

// targetClient makes the client of target i. Its dialer has the private list of
// that target only. Its transport is its own, so no idle connection moves from
// one target to another. The errors have no URL, address, or token.
func targetClient(i int, t PublishTarget, cfg *publishConfig) (*http.Client, error) {
	port := uint64(443)
	u, err := url.Parse(t.URL)
	if err != nil {
		return nil, refuse("the URL of target %d is not valid", i)
	}
	if s := u.Port(); s != "" {
		if port, err = strconv.ParseUint(s, 10, 16); err != nil {
			return nil, refuse("the port of target %d is not valid", i)
		}
	}
	dialer, err := egress.ItemDialer(t.Private, uint16(port), "tcp", dialTimeout)
	if err != nil {
		return nil, refuse("the port or the private list of target %d is not valid", i)
	}
	if cfg.dialer != nil {
		dialer = cfg.dialer
	}
	if cfg.dialerFor != nil {
		dialer = cfg.dialerFor(i, dialer)
	}
	dial := dialer.DialContext
	if cfg.dialAddr != nil {
		dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, cfg.dialAddr(addr))
		}
	}
	return &http.Client{
		Transport: &http.Transport{
			Proxy:                  nil,
			DialContext:            dial,
			TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: cfg.roots},
			TLSHandshakeTimeout:    publishHeaderTimeout,
			ResponseHeaderTimeout:  publishHeaderTimeout,
			MaxResponseHeaderBytes: maxResponseHeader,
			IdleConnTimeout:        idleConnTimeout,
			MaxIdleConns:           1,
			MaxIdleConnsPerHost:    1,
			ForceAttemptHTTP2:      true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return errPublishRedirect },
	}, nil
}

// Send puts one note to target. It returns nil only for a 2xx response. Every
// error has a fixed class (publishError). The timeout bounds the call. The
// spool calls Send with no lock held, on the goroutine that calls Publish. A 2xx
// response resets the backoff of the target.
func (p *Publisher) Send(target string, _ uint64, note []byte) error {
	i := -1
	for j, t := range p.targets {
		if t.url == target {
			i = j
			break
		}
	}
	if i < 0 { // only the configured URLs are contacted
		return p.fail(-1, 0, errPublishNotConfig)
	}
	ctx, cancel := context.WithTimeout(context.Background(), p.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, target, bytes.NewReader(note))
	if err != nil {
		return p.fail(i, 0, errPublishTransport)
	}
	req.Header.Set("Content-Type", "text/plain; charset=utf-8")
	req.Header.Set("Authorization", "Bearer "+p.targets[i].token)
	resp, err := p.clients[i].Do(req)
	status := 0
	if resp != nil { // also set for a refused redirect, with the body closed
		status = resp.StatusCode
		drainBody(resp.Body)
	}
	switch {
	case err != nil:
		return p.fail(i, status, classify(err))
	case status < 200 || status > 299:
		return p.fail(i, status, errPublishStatus)
	}
	p.state[i] = backoffState{}
	p.log.Info("checkpoint published", "target", i, "status", status)
	return nil
}

// drainBody reads at most 4 KiB of the body and closes it.
func drainBody(body io.ReadCloser) {
	_, _ = io.Copy(io.Discard, io.LimitReader(body, maxPublishResponse))
	_ = body.Close()
}

// classify maps an error of the client to a fixed class. It drops the error,
// which holds the URL.
func classify(err error) publishError {
	var ne net.Error
	switch {
	case errors.Is(err, errPublishRedirect):
		return errPublishRedirect
	case errors.Is(err, egress.ErrRefused):
		return errPublishAddress
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return errPublishTimeout
	}
	return errPublishTransport
}

func (p *Publisher) fail(target, status int, class publishError) error {
	p.log.Warn("checkpoint publish failed", "target", target, "status", status, "class", string(class))
	return class
}

// Notify tells Run that the spool has a new note. It never blocks.
func (p *Publisher) Notify() {
	select {
	case p.wake <- struct{}{}:
	default:
	}
}

// Run publishes until ctx ends. It starts with one pass, then waits for Notify
// or for the next target whose backoff ends. When it returns, it closes the idle
// connections of the transport of each target.
func (p *Publisher) Run(ctx context.Context) {
	defer func() {
		for _, c := range p.clients {
			c.CloseIdleConnections()
		}
	}()
	for {
		wait, pending := p.pass()
		var tick <-chan time.Time
		if pending {
			tick = time.After(wait)
		}
		select {
		case <-ctx.Done():
			return
		case <-p.wake:
		case <-tick:
		}
	}
}

// pass publishes to each target whose backoff has ended. It returns the time to
// the next backoff end, if a target waits. A target whose backoff ended during
// the pass is due: the wait is 0, so Run starts the next pass at once. A target
// with no backoff state is never pending. A failed target does not stop the
// others. The next try of a failed target starts at the end of its send.
func (p *Publisher) pass() (wait time.Duration, pending bool) {
	for i := range p.targets {
		if p.now().Before(p.state[i].next) {
			continue
		}
		err := p.spool.Publish(i, p)
		entries := entryCount(err)
		if err == nil || entries > 0 { // every send got a 2xx
			p.state[i] = backoffState{}
			if entries > 0 { // an entry error is not a fault of the target
				p.log.Warn("checkpoint spool refused an entry that is not a note", "target", i, "entries", entries)
			}
			continue
		}
		if !errors.As(err, new(publishError)) { // Send logged the others
			p.log.Warn("checkpoint publish failed", "target", i, "status", 0, "class", "spool", "error", spoolText(err))
		}
		p.backoff(i, p.now())
	}
	now := p.now()
	for _, st := range p.state {
		if st.next.IsZero() {
			continue
		}
		if d := max(st.next.Sub(now), 0); !pending || d < wait {
			wait, pending = d, true
		}
	}
	return wait, pending
}

// spoolText returns the text of the spool errors in err, one after the other
// with "; " between them. Each text has the relative name and the rule, with no
// absolute path. It leaves out each publishError. Each error of Publisher.Send
// has that type, and Send logs it.
func spoolText(err error) string {
	var texts []string
	var walk func(error)
	walk = func(e error) {
		if joined, ok := e.(interface{ Unwrap() []error }); ok {
			for _, part := range joined.Unwrap() {
				walk(part)
			}
		} else if !errors.As(e, new(publishError)) {
			texts = append(texts, e.Error())
		}
	}
	walk(err)
	return strings.Join(texts, "; ")
}

// entryCount returns the number of errors in err if Spool.Publish returned only
// entry errors. If not, it returns 0.
func entryCount(err error) int {
	joined, ok := err.(interface{ Unwrap() []error })
	if !ok {
		return 0
	}
	errs := joined.Unwrap()
	for _, e := range errs {
		if !errors.As(e, new(entryError)) {
			return 0
		}
	}
	return len(errs)
}

// backoff doubles the delay of target i, from 30 s up to the smaller of the
// checkpoint interval and 1 h. The wait is the delay with a jitter of plus or
// minus 20 %. The wait is never below 30 s and never above that cap.
func (p *Publisher) backoff(i int, now time.Time) {
	st := &p.state[i]
	ceiling := min(p.interval, backoffMax)
	st.delay = min(max(2*st.delay, backoffStart), ceiling)
	wait := time.Duration(float64(st.delay) * (1 - backoffJitter + 2*backoffJitter*p.jitter()))
	st.next = now.Add(min(max(wait, backoffStart), ceiling))
}
