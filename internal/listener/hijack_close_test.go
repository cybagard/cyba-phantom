package listener

import (
	"bufio"
	"errors"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/cybagard/cyba-phantom/internal/event"
)

// hijackCloser is a handler that writes a 204 with "Connection: close",
// flushes it, takes the connection from net/http and closes it. The handler of
// a callback route does this before it checks its tokens. It records each
// Hijack error, before it closes the connection, for the test to read.
type hijackCloser struct {
	mu     sync.Mutex
	errs   []error
	hijack int // the number of connections that it took and closed
}

func (h *hijackCloser) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Connection", "close")
	w.WriteHeader(http.StatusNoContent)
	rc := http.NewResponseController(w)
	_ = rc.Flush()
	c, _, err := rc.Hijack()
	h.mu.Lock()
	if err != nil {
		h.errs = append(h.errs, err)
	} else {
		h.hijack++
	}
	h.mu.Unlock()
	if err == nil {
		_ = c.Close()
	}
}

// waitSlotsFree waits until the server holds no connection slot. The close of a
// connection ends the socket before it gives the slot back, so a client that
// dials at once can meet a full listener.
func waitSlotsFree(t *testing.T, r *rig) {
	t.Helper()
	for end := time.Now().Add(5 * time.Second); len(r.s.sem) != 0; time.Sleep(time.Millisecond) {
		if time.Now().After(end) {
			t.Fatalf("%d slots still held after 5s", len(r.s.sem))
		}
	}
}

// closedByServer sends goodHead on a new TLS connection to addr. It fails the
// test unless the client reads a 204 with "Connection: close" and then EOF
// within the time limit.
func closedByServer(t *testing.T, r *rig, addr string) {
	t.Helper()
	c, err := dialTLS(addr, r.clientConfig())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(c, goodHead); err != nil {
		t.Fatalf("write: %v", err)
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp.StatusCode != http.StatusNoContent || !resp.Close {
		t.Fatalf("status %d, close %v; want 204 and close", resp.StatusCode, resp.Close)
	}
	if _, err := br.ReadByte(); !errors.Is(err, io.EOF) {
		t.Fatalf("read after the response: %v; want EOF", err)
	}
}

// T-S-32: a handler writes "Connection: close", flushes, hijacks and closes
// the connection. That gives no refused event. The refused counters do not
// change. The close frees the slot: with one slot, a second connection gets its
// response after the first one closed. Every Hijack must succeed.
func TestTS32HijackedCloseGivesNoRefused(t *testing.T) {
	h := &hijackCloser{}
	r := newRig(t, 1, testHeaderBytes, defaultTimeouts, h)
	addr := r.serve(t)
	closedByServer(t, r, addr)
	waitSlotsFree(t, r)
	closedByServer(t, r, addr)
	h.mu.Lock()
	for _, err := range h.errs {
		t.Errorf("Hijack failed: %v", err)
	}
	if h.hijack != 2 {
		t.Errorf("the handler took %d connections, want 2", h.hijack)
	}
	h.mu.Unlock()
	if evs := r.s.refused.q.Drain(); len(evs) != 0 {
		t.Errorf("%d events on the queue, want none (first kind %v)", len(evs), evs[0].Kind())
	}
	if n := r.s.RefusedEventErrors(); n != 0 {
		t.Errorf("%d refused event errors, want 0", n)
	}
	if d := r.s.refused.q.Dropped(); d != (event.Dropped{}) {
		t.Errorf("dropped events %+v, want none", d)
	}
	if counts, overflow := r.s.refused.c.Snapshot(); len(counts) != 0 || overflow != 0 {
		t.Errorf("overflow counters %v and %d, want none", counts, overflow)
	}
}
