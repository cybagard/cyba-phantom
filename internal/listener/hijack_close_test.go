package listener

import (
	"bufio"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/cybagard/cyba-phantom/internal/event"
)

// closeHijackHandler writes a 204 with "Connection: close", flushes it, takes
// the connection from net/http and closes it. The handler of a callback route
// does this before it checks its tokens.
var closeHijackHandler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Connection", "close")
	w.WriteHeader(http.StatusNoContent)
	rc := http.NewResponseController(w)
	_ = rc.Flush()
	if c, _, err := rc.Hijack(); err == nil {
		_ = c.Close()
	}
})

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

// T-S-22: a handler writes "Connection: close", flushes, hijacks and closes
// the connection. That gives no refused event. The refused counters do not
// change. The close frees the slot: with one slot, a second connection gets its
// response after the first one closed.
func TestTS22HijackedCloseGivesNoRefused(t *testing.T) {
	r := newRig(t, 1, testHeaderBytes, defaultTimeouts, closeHijackHandler)
	addr := r.serve(t)
	closedByServer(t, r, addr)
	// The slot is free when the next connection gets its response. The retry
	// only waits for the server goroutine that gives the slot back.
	var last any
	for end := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(end) {
			t.Fatalf("no response on a second connection after the first one closed: %v", last)
		}
		if func() (ok bool) {
			c, err := dialTLS(addr, r.clientConfig())
			if err != nil {
				last = err
				return false
			}
			defer c.Close()
			code, err := roundTripErr(c, goodHead)
			last = err
			return err == nil && code == http.StatusNoContent
		}() {
			break
		}
	}
	closedByServer(t, r, addr)
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
