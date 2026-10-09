package tlog

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/note"
)

const (
	tokenMarker = "tok-MARKER-7f3a91"
	tokenVar    = "TLOG_TEST_PUBLISH_TOKEN"
	respText    = "RESPONSE-TEXT-do-not-log"
)

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }

// fakeTarget is an HTTPS target on an ephemeral port. It records the size in the
// body of each request and the Authorization header.
type fakeTarget struct {
	*httptest.Server
	mu       sync.Mutex
	status   int    // 0: 200
	queue    []int  // the status of the next requests, before status; 0: 200
	open     int    // connections that are not closed
	location string // sent with a 3xx status
	big      bool   // a response body of 1 MiB
	stall    chan struct{}
	alias    string // the URL that the spool uses, if it is not the server URL
	attempts []uint64
	stored   []uint64
	auth     []string
}

func newTarget(t *testing.T) *fakeTarget {
	t.Helper()
	f := &fakeTarget{}
	f.Server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
		lines := strings.Split(string(body), "\n")
		size, _ := strconv.ParseUint(lines[min(1, len(lines)-1)], 10, 64)
		f.mu.Lock()
		status, stall := f.status, f.stall
		if len(f.queue) > 0 {
			status, f.queue = f.queue[0], f.queue[1:]
		}
		f.attempts = append(f.attempts, size)
		f.auth = append(f.auth, r.Header.Get("Authorization"))
		if status == 0 {
			f.stored = append(f.stored, size)
		}
		f.mu.Unlock()
		switch {
		case stall != nil:
			select {
			case <-stall:
			case <-r.Context().Done():
			}
		case status != 0:
			if f.location != "" {
				w.Header().Set("Location", f.location)
			}
			w.WriteHeader(status)
			_, _ = io.WriteString(w, respText)
		case f.big:
			_, _ = w.Write(make([]byte, 1<<20))
		}
	}))
	f.Config.ErrorLog = log.New(io.Discard, "", 0)
	f.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		f.mu.Lock()
		defer f.mu.Unlock()
		switch s {
		case http.StateNew:
			f.open++
		case http.StateClosed, http.StateHijacked:
			f.open--
		}
	}
	f.StartTLS()
	t.Cleanup(f.Close)
	return f
}

func (f *fakeTarget) setStatus(status int) {
	f.mu.Lock()
	f.status = status
	f.mu.Unlock()
}

func (f *fakeTarget) got() (attempts, stored []uint64, auth []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.attempts), slices.Clone(f.stored), slices.Clone(f.auth)
}

func (f *fakeTarget) openConns() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.open
}

func (f *fakeTarget) url() string {
	if f.alias != "" {
		return f.alias
	}
	return f.URL + "/put"
}

type pubEnv struct {
	spool  *Spool
	dir    string
	signer note.Signer
	logs   *bytes.Buffer
	clock  *fakeClock
	pub    *Publisher
	urls   []string
}

// newPub makes a spool and a publisher for the targets. The publisher trusts the
// certificates of the targets; the clock is fixed and the jitter is 0.5, which
// gives the delay with no change.
func newPub(t *testing.T, interval time.Duration, targets []*fakeTarget, opts ...PublishOption) *pubEnv {
	t.Helper()
	root, dir := newState(t)
	if os.Getenv(tokenVar) == "" { // the constructor needs a token
		t.Setenv(tokenVar, tokenMarker)
	}
	signer, verifier := noteKeys(t, testOrigin, 1)
	lg, buf := testLogger()
	pool := x509.NewCertPool()
	e := &pubEnv{dir: dir, signer: signer, logs: buf, clock: &fakeClock{time.Unix(1_700_000_000, 0)}}
	var pt []PublishTarget
	for _, f := range targets {
		pool.AddCert(f.Certificate())
		e.urls = append(e.urls, f.url())
		pt = append(pt, PublishTarget{f.url(), tokenVar})
	}
	var err error
	e.spool, err = OpenSpool(root, lg, testOrigin, verifier, e.urls)
	must(t, err)
	base := func(c *publishConfig) {
		c.roots, c.now, c.jitter = pool, e.clock.now, func() float64 { return 0.5 }
	}
	e.pub, err = NewPublisher(e.spool, pt, interval, lg, append([]PublishOption{base}, opts...)...)
	must(t, err)
	return e
}

func (e *pubEnv) add(t *testing.T, size uint64) {
	t.Helper()
	msg, err := SignCheckpoint(e.signer, size, testRoot())
	must(t, err)
	must(t, e.spool.Add(size, msg))
}

// assertClean fails if s has the token, the response text, or a part of a URL.
func (e *pubEnv) assertClean(t *testing.T, what, s string) {
	t.Helper()
	bad := []string{tokenMarker, respText}
	for _, raw := range e.urls {
		u, err := url.Parse(raw)
		must(t, err)
		bad = append(bad, raw, u.Host, u.Hostname())
	}
	for _, b := range bad {
		if strings.Contains(s, b) {
			t.Errorf("%s has %q: %s", what, b, s)
		}
	}
}

func withTimeout(d time.Duration) PublishOption { return func(c *publishConfig) { c.timeout = d } }

// T-I-09: a target that is down for 3 intervals gets the 3 notes in order on
// recovery. The cursor moves only after a 2xx response.
func TestTI09_RecoverInOrder(t *testing.T) {
	a := newTarget(t)
	a.setStatus(http.StatusServiceUnavailable)
	e := newPub(t, time.Minute, []*fakeTarget{a})
	for size := uint64(1); size <= 3; size++ {
		e.add(t, size)
		e.pub.pass()
		e.clock.t = e.clock.t.Add(2 * time.Minute) // more than one interval and the backoff
	}
	attempts, stored, _ := a.got()
	if len(stored) != 0 || !slices.Equal(attempts, []uint64{1, 1, 1}) {
		t.Fatalf("while down: attempts %v, stored %v", attempts, stored)
	}
	if _, err := os.Stat(filepath.Join(e.dir, e.spool.cursorName(0))); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the cursor moved before a 2xx response: %v", err)
	}
	a.setStatus(0)
	e.pub.pass()
	if _, stored, _ = a.got(); !slices.Equal(stored, []uint64{1, 2, 3}) {
		t.Fatalf("stored after recovery = %v, want 1 2 3 in order", stored)
	}
	if b, err := os.ReadFile(filepath.Join(e.dir, e.spool.cursorName(0))); err != nil || string(b) != "3" {
		t.Fatalf("cursor = %q, %v, want 3", b, err)
	}
}

// T-I-09: a target in backoff after a failure does not stop the publish to the
// other target. The down target waits for its backoff and is then tried again.
func TestTI09_DownTargetDoesNotBlockOthers(t *testing.T) {
	down, up := newTarget(t), newTarget(t)
	down.setStatus(http.StatusInternalServerError)
	e := newPub(t, time.Minute, []*fakeTarget{down, up})
	e.add(t, 1)
	e.pub.pass()
	e.add(t, 2)
	e.pub.pass() // the backoff of the down target has not ended
	downAttempts, _, _ := down.got()
	if _, stored, _ := up.got(); !slices.Equal(stored, []uint64{1, 2}) || !slices.Equal(downAttempts, []uint64{1}) {
		t.Fatalf("up stored %v, down attempts %v, want 1 2 and 1", stored, downAttempts)
	}
	e.clock.t = e.clock.t.Add(backoffStart)
	e.pub.pass()
	if downAttempts, _, _ = down.got(); !slices.Equal(downAttempts, []uint64{1, 1}) {
		t.Fatalf("down attempts = %v, want a new try after the backoff", downAttempts)
	}
}

// T-I-09: the backoff of target 0 ends while the pass sends to target 1. The
// pass returns a wait of 0, so Run does not need a Notify to try target 0. With
// no failed target, the pass is not pending, so Run does not loop.
func TestTI09_BackoffEndDuringOtherSend(t *testing.T) {
	a, b := newTarget(t), newTarget(t)
	e := newPub(t, time.Minute, []*fakeTarget{a, b})
	e.pub.backoff(0, e.clock.t) // target 0 waits 30 s
	e.add(t, 1)
	base, reads := e.clock.t, 0
	e.pub.now = func() time.Time {
		reads++
		if reads <= 2 { // the checks of target 0 and of target 1
			return base
		}
		return base.Add(2 * backoffStart) // after the send to target 1
	}
	wait, pending := e.pub.pass()
	if _, stored, _ := b.got(); !slices.Equal(stored, []uint64{1}) {
		t.Fatalf("target 1 stored %v, want 1", stored)
	}
	if !pending || wait != 0 {
		t.Fatalf("pass = %v, %v, want a wait of 0 and pending", wait, pending)
	}
	e.pub.now = e.clock.now
	e.clock.t = base.Add(2 * backoffStart)
	if wait, pending = e.pub.pass(); pending || wait != 0 {
		t.Fatalf("pass with no failed target = %v, %v, want not pending", wait, pending)
	}
	if _, stored, _ := a.got(); !slices.Equal(stored, []uint64{1}) {
		t.Fatalf("target 0 stored %v, want 1", stored)
	}
}

// T-I-09: backoff of 30 s that doubles up to min(interval, 1 h), jitter of
// plus or minus 20 %, and a reset after a success.
func TestTI09_Backoff(t *testing.T) {
	a := newTarget(t)
	a.setStatus(http.StatusBadGateway)
	e := newPub(t, 5*time.Minute, []*fakeTarget{a})
	e.add(t, 1)
	for i, want := range []time.Duration{30, 60, 120, 240, 300, 300} {
		e.pub.pass()
		got := e.pub.state[0].next.Sub(e.clock.t)
		if d := got - want*time.Second; d < -time.Microsecond || d > time.Microsecond {
			t.Fatalf("wait %d = %v, want %v", i, got, want*time.Second)
		}
		e.clock.t = e.pub.state[0].next
	}
	a.setStatus(0)
	e.pub.pass()
	if e.pub.state[0] != (backoffState{}) {
		t.Fatalf("a success must reset the backoff: %+v", e.pub.state[0])
	}
	a.setStatus(http.StatusBadGateway)
	e.add(t, 2)
	e.pub.pass()
	if got := e.pub.state[0].next.Sub(e.clock.t); got < 29*time.Second || got > 31*time.Second {
		t.Fatalf("first wait after the reset = %v, want 30 s", got)
	}
}

// T-I-09: a 2xx response resets the backoff, also when a later note of the same
// call fails. The next wait is then 30 s and not a doubled value.
func TestTI09_SuccessResetsBackoffBeforeLaterFailure(t *testing.T) {
	a := newTarget(t)
	e := newPub(t, 5*time.Minute, []*fakeTarget{a})
	e.pub.backoff(0, e.clock.t)
	e.pub.backoff(0, e.clock.t)
	if e.pub.state[0].delay != 2*backoffStart {
		t.Fatalf("delay before the call = %v, want 60 s", e.pub.state[0].delay)
	}
	e.clock.t = e.pub.state[0].next
	e.add(t, 1)
	e.add(t, 2)
	a.queue = []int{0, http.StatusInternalServerError} // note 1: 2xx, note 2: fails
	e.pub.pass()
	if _, stored, _ := a.got(); !slices.Equal(stored, []uint64{1}) {
		t.Fatalf("stored = %v, want only note 1", stored)
	}
	if got := e.pub.state[0].delay; got != backoffStart {
		t.Fatalf("delay = %v, want %v after a 2xx and a failure", got, backoffStart)
	}
	if got := e.pub.state[0].next.Sub(e.clock.t); got < 29*time.Second || got > 31*time.Second {
		t.Fatalf("wait = %v, want 30 s", got)
	}
}

// T-I-09: the time of the next try starts at the end of the send and not at the
// start of the pass. The test clock moves 10 s each time that it is read.
func TestTI09_BackoffStartsAfterSend(t *testing.T) {
	a := newTarget(t)
	a.setStatus(http.StatusInternalServerError)
	e := newPub(t, 5*time.Minute, []*fakeTarget{a})
	e.add(t, 1)
	base, reads := e.clock.t, 0
	e.pub.now = func() time.Time {
		reads++
		return base.Add(time.Duration(reads-1) * 10 * time.Second)
	}
	e.pub.pass()
	if got := e.pub.state[0].next.Sub(base); got < 40*time.Second-time.Microsecond {
		t.Fatalf("next try is %v after the start of the pass, want 40 s or more", got)
	}
}

func TestTI09_BackoffCapAndJitter(t *testing.T) {
	a := newTarget(t)
	e := newPub(t, 24*time.Hour, []*fakeTarget{a})
	for range 12 {
		e.pub.backoff(0, e.clock.t)
	}
	if e.pub.state[0].delay != time.Hour {
		t.Fatalf("delay = %v, want the cap of 1 h for a 24 h interval", e.pub.state[0].delay)
	}
	for _, j := range []float64{0, 0.25, 0.5, 0.75, 0.999999} {
		e.pub.jitter = func() float64 { return j }
		e.pub.backoff(0, e.clock.t)
		lo, hi := 48*time.Minute-time.Microsecond, 72*time.Minute+time.Microsecond
		if got := e.pub.state[0].next.Sub(e.clock.t); got < lo || got > hi {
			t.Fatalf("jitter %v: wait %v is not within 20%% of 1 h", j, got)
		}
	}
	e.pub.jitter = func() float64 { return 0 }
	e.pub.backoff(0, e.clock.t)
	if got := e.pub.state[0].next.Sub(e.clock.t); got < 48*time.Minute-time.Microsecond || got > 48*time.Minute+time.Microsecond {
		t.Fatalf("lowest wait = %v, want 48m0s", got)
	}
}

// T-I-09: the defaults are the limits of SEC-17.
func TestTI09_Limits(t *testing.T) {
	a := newTarget(t)
	e := newPub(t, time.Minute, []*fakeTarget{a})
	p, err := NewPublisher(e.spool, []PublishTarget{{a.url(), tokenVar}}, time.Minute, nil)
	must(t, err)
	tr := p.client.Transport.(*http.Transport)
	if p.timeout != 30*time.Second || tr.TLSHandshakeTimeout != 10*time.Second || tr.ResponseHeaderTimeout != 10*time.Second || tr.MaxIdleConnsPerHost != 1 {
		t.Fatalf("limits: %v %v %v %v", p.timeout, tr.TLSHandshakeTimeout, tr.ResponseHeaderTimeout, tr.MaxIdleConnsPerHost)
	}
	if tr.IdleConnTimeout != 90*time.Second || tr.MaxResponseHeaderBytes != 16<<10 {
		t.Fatalf("limits: idle timeout %v, header bytes %d, want 90 s and 16 KiB", tr.IdleConnTimeout, tr.MaxResponseHeaderBytes)
	}
	if tr.Proxy != nil || p.client.CheckRedirect == nil || tr.TLSClientConfig.MinVersion != tls.VersionTLS12 ||
		tr.TLSClientConfig.InsecureSkipVerify || tr.TLSClientConfig.RootCAs != nil {
		t.Fatal("the transport must have no proxy, no redirect, verified TLS 1.2 or later, and the system roots")
	}
	if _, err := NewPublisher(e.spool, nil, time.Minute, nil); err == nil {
		t.Fatal("targets that differ from the spool must be an error")
	}
}

// T-I-09: the constructor refuses an interval that is not positive and a token
// that is empty or not set. The error names neither the variable nor a token.
func TestTI09_NewPublisherRefusesBadInput(t *testing.T) {
	a := newTarget(t)
	e := newPub(t, time.Minute, []*fakeTarget{a})
	for _, interval := range []time.Duration{0, -time.Minute} {
		if _, err := NewPublisher(e.spool, []PublishTarget{{a.url(), tokenVar}}, interval, nil); err == nil {
			t.Errorf("interval %v: want an error", interval)
		}
	}
	const unsetVar, emptyVar = "TLOG_TEST_PUBLISH_NOT_SET", "TLOG_TEST_PUBLISH_EMPTY"
	t.Setenv(emptyVar, "")
	for _, name := range []string{unsetVar, emptyVar} {
		_, err := NewPublisher(e.spool, []PublishTarget{{a.url(), name}}, time.Minute, nil)
		if err == nil {
			t.Fatalf("token variable %s: want an error", name)
		}
		for _, bad := range []string{name, tokenMarker, "TLOG_TEST"} {
			if strings.Contains(err.Error(), bad) {
				t.Errorf("error has %q: %v", bad, err)
			}
		}
		if !strings.Contains(err.Error(), "target 0") {
			t.Errorf("error does not name the target index: %v", err)
		}
	}
}

// T-I-09: a target that stalls gives a timeout error with a fixed class.
func TestTI09_PublishTimeout(t *testing.T) {
	a := newTarget(t)
	a.stall = make(chan struct{})
	t.Cleanup(func() { close(a.stall) }) // runs before the close of the server
	e := newPub(t, time.Minute, []*fakeTarget{a}, withTimeout(50*time.Millisecond))
	e.add(t, 1)
	if err := e.spool.Publish(0, e.pub); !errors.Is(err, errPublishTimeout) {
		t.Fatalf("err = %v, want a timeout", err)
	}
}

// T-S-13: a redirect is a failed publish and the second server gets no request.
func TestTS13_NoRedirect(t *testing.T) {
	second := newTarget(t)
	a := newTarget(t)
	a.location = second.URL + "/put"
	a.setStatus(http.StatusTemporaryRedirect)
	e := newPub(t, time.Minute, []*fakeTarget{a})
	e.add(t, 1)
	err := e.spool.Publish(0, e.pub)
	if !errors.Is(err, errPublishRedirect) {
		t.Fatalf("err = %v, want a refused redirect", err)
	}
	if attempts, _, _ := second.got(); len(attempts) != 0 {
		t.Fatal("the redirect target got a request")
	}
	if !strings.Contains(e.logs.String(), "status=307") {
		t.Fatalf("log has no status of the redirect: %s", e.logs)
	}
}

// T-S-13: Send contacts only a configured URL. A URL that is not configured has
// its own error class and one log line with no URL.
func TestTS13_OnlyConfiguredURLs(t *testing.T) {
	a := newTarget(t)
	e := newPub(t, time.Minute, []*fakeTarget{a})
	err := e.pub.Send(a.URL+"/other", 1, []byte("x\n1\n"))
	if !errors.Is(err, errPublishNotConfig) || err.Error() != "publish: target not configured" {
		t.Fatalf("err = %v, want the class target not configured", err)
	}
	if attempts, _, _ := a.got(); len(attempts) != 0 {
		t.Fatal("a URL that is not configured got a request")
	}
	if want := `target=-1 status=0 class="target not configured"`; strings.Count(e.logs.String(), want) != 1 {
		t.Fatalf("log = %q, want one line with %q", e.logs, want)
	}
	e.assertClean(t, "error", err.Error())
	e.assertClean(t, "log", e.logs.String())
}

// T-S-13: the proxy of the environment is not used. The target has a name that
// the proxy rule does not skip (a loopback host is skipped), and the dial goes
// to the test server.
func TestTS13_NoProxy(t *testing.T) {
	var proxied int
	var mu sync.Mutex
	proxy := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		mu.Lock()
		proxied++
		mu.Unlock()
	}))
	t.Cleanup(proxy.Close)
	t.Setenv("HTTPS_PROXY", proxy.URL)
	a := newTarget(t)
	_, port, _ := strings.Cut(strings.TrimPrefix(a.URL, "https://"), ":")
	a.alias = "https://example.com:" + port + "/put" // example.com is in the certificate of the test server
	req, _ := http.NewRequest(http.MethodPut, a.alias, nil)
	if u, err := http.ProxyFromEnvironment(req); err != nil || u == nil {
		t.Fatalf("the test needs a proxy for %s: %v, %v", a.alias, u, err)
	}
	e := newPub(t, time.Minute, []*fakeTarget{a}, func(c *publishConfig) { c.dialAddr = func(string) string { return a.Listener.Addr().String() } })
	e.add(t, 1)
	must(t, e.spool.Publish(0, e.pub))
	mu.Lock()
	defer mu.Unlock()
	if _, stored, _ := a.got(); proxied != 0 || !slices.Equal(stored, []uint64{1}) {
		t.Fatalf("proxy got %d requests, target stored %v", proxied, stored)
	}
}

// T-S-13: a certificate that the roots do not trust is a failed publish.
func TestTS13_UntrustedCertificate(t *testing.T) {
	a := newTarget(t)
	e := newPub(t, time.Minute, []*fakeTarget{a}, func(c *publishConfig) { c.roots = x509.NewCertPool() })
	e.add(t, 1)
	err := e.spool.Publish(0, e.pub)
	if !errors.Is(err, errPublishTransport) {
		t.Fatalf("err = %v, want a transport failure", err)
	}
	if attempts, _, _ := a.got(); len(attempts) != 0 {
		t.Fatal("the target got a request over an untrusted connection")
	}
	e.assertClean(t, "error", err.Error())
}

// T-S-13: a connect to a link-local address is refused before the connect, and
// the error has a fixed class.
func TestTS13_LinkLocalRefused(t *testing.T) {
	a := newTarget(t)
	a.alias = "https://169.254.169.254/put"
	e := newPub(t, time.Minute, []*fakeTarget{a})
	e.add(t, 1)
	err := e.spool.Publish(0, e.pub)
	if !errors.Is(err, errPublishAddress) {
		t.Fatalf("err = %v, want a refused address", err)
	}
	e.assertClean(t, "error", err.Error())
}

// T-S-13: the publisher reads at most 4 KiB of a response body and closes it.
type endless struct {
	read   int
	closed bool
}

func (r *endless) Read(p []byte) (int, error) { r.read += len(p); return len(p), nil }
func (r *endless) Close() error               { r.closed = true; return nil }

func TestTS13_ResponseBodyLimit(t *testing.T) {
	r := &endless{}
	drainBody(r)
	if r.read > 4096 || !r.closed {
		t.Fatalf("read %d bytes, closed %v, want at most 4096 and closed", r.read, r.closed)
	}
	a := newTarget(t)
	a.big = true
	e := newPub(t, time.Minute, []*fakeTarget{a})
	e.add(t, 1)
	must(t, e.spool.Publish(0, e.pub)) // a body of 1 MiB does not break the publish
}

// T-S-13: the token is in the Authorization header only. It is read one time at
// start. The token, the URLs, and the response text are in no log line and no
// error, and a log line has the target index, the status, and the error class.
func TestTS13_TokenAndErrors(t *testing.T) {
	t.Setenv(tokenVar, tokenMarker)
	ok, status500, redirect, stall, linkLocal := newTarget(t), newTarget(t), newTarget(t), newTarget(t), newTarget(t)
	status500.setStatus(http.StatusInternalServerError)
	redirect.setStatus(http.StatusFound)
	redirect.location = ok.URL
	stall.stall = make(chan struct{})
	t.Cleanup(func() { close(stall.stall) })
	linkLocal.alias = "https://169.254.169.254:8443/put"
	e := newPub(t, time.Minute, []*fakeTarget{ok, status500, redirect, stall, linkLocal}, withTimeout(50*time.Millisecond))
	t.Setenv(tokenVar, "changed-after-start")
	e.add(t, 1)
	for i := range e.urls {
		err := e.spool.Publish(i, e.pub)
		if (err == nil) != (i == 0) {
			t.Fatalf("target %d: err = %v", i, err)
		}
		if err != nil {
			e.assertClean(t, "error of target "+strconv.Itoa(i), err.Error())
		}
	}
	for i, f := range []*fakeTarget{ok, status500, redirect, stall} {
		if _, _, auth := f.got(); !slices.Equal(auth, []string{"Bearer " + tokenMarker}) {
			t.Errorf("target %d: Authorization = %q, want the token that was read at start", i, auth)
		}
	}
	e.assertClean(t, "log", e.logs.String())
	for _, want := range []string{`target=1 status=500 class="status not 2xx"`, `target=2 status=302 class="redirect refused"`,
		"target=3 status=0 class=timeout", `target=4 status=0 class="address refused"`} {
		if !strings.Contains(e.logs.String(), want) {
			t.Errorf("log has no %q: %s", want, e.logs)
		}
	}
}

// T-I-09: Run publishes after Notify and ends when the context ends.
func TestTI09_RunPublishesAndStops(t *testing.T) {
	a := newTarget(t)
	e := newPub(t, time.Minute, []*fakeTarget{a})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.pub.Run(ctx); close(done) }()
	e.add(t, 1)
	e.pub.Notify()
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(time.Millisecond) {
		if _, stored, _ := a.got(); len(stored) == 1 {
			break
		} else if time.Now().After(deadline) {
			t.Fatal("Run did not publish the note")
		}
	}
	if n := a.openConns(); n != 1 {
		t.Fatalf("open connections while Run waits = %d, want the 1 idle connection", n)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not stop")
	}
	for deadline := time.Now().Add(10 * time.Second); a.openConns() != 0; time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("Run did not close the idle connection")
		}
	}
}
