package listener

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// closeProbe is the request pair of the probe. First comes a POST with a body
// of bodyLen bytes. Then comes a GET with a token and "Connection: close". The
// client sends both in one write.
func closeProbe(bodyLen int) string {
	return fmt.Sprintf("POST /p HTTP/1.1\r\nHost: a\r\nContent-Length: %d\r\n\r\n%s",
		bodyLen, strings.Repeat("a", bodyLen)) +
		"GET /g HTTP/1.1\r\nHost: a\r\nX-Token: t\r\nConnection: close\r\n\r\n"
}

// probeEnd writes req on c. It requires a 200 for the first request. It
// returns the error of the next read, or nil if more bytes came.
func probeEnd(t *testing.T, c net.Conn, req string) error {
	t.Helper()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(c, req); err != nil {
		t.Fatalf("write: %v", err)
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("first response: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("first status %d, want 200", resp.StatusCode)
	}
	_, err = br.ReadByte()
	return err
}

// settle waits up to 300 ms until n reaches want. The plain socket has no hook
// for the end of the connection goroutine. So a handler that runs late shows
// up here.
func settle(n *atomic.Int32, want int32) {
	for end := time.Now().Add(300 * time.Millisecond); n.Load() < want && time.Now().Before(end); {
		time.Sleep(5 * time.Millisecond)
	}
}

// T-S-22: a period that read more than 4096 bytes closes at its idle state.
// Then a request that net/http parses from its buffer does not reach the
// handler. It gives no handler run, no event and no response. A POST with a
// body of 5000 bytes and a pipelined GET come in one write. On the TLS socket,
// the close gives no refused event.
func TestTS22PipelinedRequestAfterBudgetCloseGetsNoHandler(t *testing.T) {
	const bodyLen = 5000
	var n atomic.Int32
	r := newRig(t, 8, testHeaderBytes, defaultTimeouts, countingHandler(&n))
	closed := make(chan struct{}, 1)
	hook := r.s.srv.ConnState
	r.s.srv.ConnState = func(c net.Conn, st http.ConnState) {
		hook(c, st)
		if st == http.StateClosed {
			closed <- struct{}{}
		}
	}
	r.serve(t)
	plain, _ := r.servePlain(t, countingHandler(&n))

	err := probeEnd(t, r.dialWhole(t), closeProbe(bodyLen))
	if err == nil || !connEnded(err) {
		t.Fatalf("TLS: read after the first response: %v; want the end of the connection", err)
	}
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("TLS: connection not closed")
	}
	if got := n.Load(); got != 1 {
		t.Errorf("TLS: handler ran %d times, want 1 (the POST)", got)
	}
	if evs := r.s.refused.q.Drain(); len(evs) != 0 {
		t.Errorf("TLS: %d events on the queue, want none (first kind %v)", len(evs), evs[0].Kind())
	}
	if counts, overflow := r.s.refused.c.Snapshot(); len(counts) != 0 || overflow != 0 {
		t.Errorf("TLS: refused counters %v and %d, want none", counts, overflow)
	}

	n.Store(0)
	err = probeEnd(t, dialPlain(t, plain, 1), closeProbe(bodyLen))
	if err == nil || !connEnded(err) {
		t.Fatalf("plain: read after the first response: %v; want the end of the connection", err)
	}
	settle(&n, 2)
	if got := n.Load(); got != 1 {
		t.Errorf("plain: handler ran %d times, want 1 (the POST)", got)
	}
}

// T-S-22: the probe closes only when the first period reads more than 4096
// bytes. With a smaller body, the connection stays open and the GET gets its
// response. So the test above reaches the close path. The bytes of the TLS
// handshake count in the first period, so the body is small.
func TestTS22PipelinedRequestAfterSmallPeriodIsServed(t *testing.T) {
	var n atomic.Int32
	r := newRig(t, 8, testHeaderBytes, defaultTimeouts, countingHandler(&n))
	r.serve(t)
	c := r.dialWhole(t)
	if err := probeEnd(t, c, closeProbe(1000)); err != nil {
		t.Fatalf("read after the first response: %v; want the second response (n=%d)", err, n.Load())
	}
	if got := n.Load(); got != 2 {
		t.Errorf("handler ran %d times, want 2", got)
	}
}

// T-S-32: a hijack-and-close handler with a second request in the same write.
// net/http stops after the hijack, so the second request never reaches the
// handler.
func TestTS32HijackedCloseIgnoresPipelinedRequest(t *testing.T) {
	h := &hijackCloser{}
	r := newRig(t, 1, testHeaderBytes, defaultTimeouts, h)
	r.serve(t)
	if err := probeEnd204(t, r, goodHead+head(0)); err != nil {
		t.Fatal(err)
	}
	waitSlotsFree(t, r)
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.hijack != 1 || len(h.errs) != 0 {
		t.Errorf("handler took %d connections with %d errors, want 1 and 0", h.hijack, len(h.errs))
	}
	if evs := r.s.refused.q.Drain(); len(evs) != 0 {
		t.Errorf("%d events on the queue, want none (first kind %v)", len(evs), evs[0].Kind())
	}
}

// probeEnd204 is probeEnd for the 204 of hijackCloser. It returns the error of
// the read after the response, which must be an end of the connection.
func probeEnd204(t *testing.T, r *rig, req string) error {
	t.Helper()
	c := r.dial(t)
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(c, req); err != nil {
		t.Fatalf("write: %v", err)
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != http.StatusNoContent {
		t.Fatalf("response: %v (%v)", resp, err)
	}
	if _, err = br.ReadByte(); err == nil || !connEnded(err) {
		return fmt.Errorf("want the end of the connection: %v", err)
	}
	return nil
}
