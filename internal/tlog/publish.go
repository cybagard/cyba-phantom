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
	"os"
	"time"
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
// holds the bearer token.
type PublishTarget struct{ URL, TokenEnv string }

// PublishOption changes the publisher. The tests use it for the clock, the
// jitter, the timeout, and the trusted roots.
type PublishOption func(*publishConfig)

type publishConfig struct {
	roots    *x509.CertPool // nil: the system roots
	timeout  time.Duration
	now      func() time.Time
	jitter   func() float64 // in [0, 1)
	dialAddr func(string) string
}

type publishTarget struct{ url, token string }

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
	targets  []publishTarget
	state    []backoffState // only the Run goroutine uses this field; Send also runs on the Run goroutine
	client   *http.Client
	interval time.Duration
	timeout  time.Duration
	log      *slog.Logger
	now      func() time.Time
	jitter   func() float64
	wake     chan struct{}
}

// NewPublisher makes the publisher for the targets of spool, in the same order.
// It reads each token from its environment variable one time. It returns an
// error if the interval is not positive or if a token is empty or not set. It
// uses its own transport: no proxy, no redirect, verified TLS 1.2 or later, and
// no connect to an unspecified, link-local, or multicast address.
func NewPublisher(spool *Spool, targets []PublishTarget, interval time.Duration, log *slog.Logger, opts ...PublishOption) (*Publisher, error) {
	cfg := publishConfig{timeout: publishTimeout, now: time.Now, jitter: rand.Float64}
	for _, o := range opts {
		o(&cfg)
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	if interval <= 0 {
		return nil, errors.New("publisher: the checkpoint interval must be positive")
	}
	if len(targets) != len(spool.targets) {
		return nil, errors.New("publisher: the targets are not the targets of the spool")
	}
	p := &Publisher{spool: spool, interval: interval, timeout: cfg.timeout, log: log, now: cfg.now, jitter: cfg.jitter,
		state: make([]backoffState, len(targets)), wake: make(chan struct{}, 1)}
	for i, t := range targets {
		if t.URL != spool.targets[i] {
			return nil, errors.New("publisher: the targets are not the targets of the spool")
		}
		token := os.Getenv(t.TokenEnv)
		if token == "" {
			return nil, fmt.Errorf("publisher: the token of target %d is empty or not set", i)
		}
		p.targets = append(p.targets, publishTarget{t.URL, token})
	}
	dial := newDialer().DialContext
	if cfg.dialAddr != nil {
		dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return newDialer().DialContext(ctx, network, cfg.dialAddr(addr))
		}
	}
	p.client = &http.Client{
		Transport: &http.Transport{
			Proxy:                  nil,
			DialContext:            dial,
			TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: cfg.roots},
			TLSHandshakeTimeout:    publishHeaderTimeout,
			ResponseHeaderTimeout:  publishHeaderTimeout,
			MaxResponseHeaderBytes: maxResponseHeader,
			IdleConnTimeout:        idleConnTimeout,
			MaxIdleConns:           len(targets),
			MaxIdleConnsPerHost:    1,
			ForceAttemptHTTP2:      true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return errPublishRedirect },
	}
	return p, nil
}

// Send puts one note to target. It returns nil only for a 2xx response. Every
// error has a fixed class (publishError). The timeout bounds the call. The
// caller (the spool) holds its lock while Send runs. A 2xx response resets the
// backoff of the target.
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
	resp, err := p.client.Do(req)
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
	case errors.Is(err, errPublishAddress):
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
// connections of the transport.
func (p *Publisher) Run(ctx context.Context) {
	defer p.client.CloseIdleConnections()
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
		if err == nil {
			p.state[i] = backoffState{}
			continue
		}
		if !errors.As(err, new(publishError)) { // Send logged the others
			p.log.Warn("checkpoint publish failed", "target", i, "status", 0, "class", "spool")
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

// backoff doubles the delay of target i, from 30 s up to the smaller of the
// checkpoint interval and 1 h. The wait is the delay with a jitter of plus or
// minus 20 %.
func (p *Publisher) backoff(i int, now time.Time) {
	st := &p.state[i]
	st.delay = min(max(2*st.delay, backoffStart), min(p.interval, backoffMax))
	st.next = now.Add(time.Duration(float64(st.delay) * (1 - backoffJitter + 2*backoffJitter*p.jitter())))
}
