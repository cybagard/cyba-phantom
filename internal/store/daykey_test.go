package store

import (
	"testing"
	"time"

	"github.com/cybagard/cyba-phantom/internal/event"
	"github.com/cybagard/cyba-phantom/internal/session"
)

// hmacOf writes a request event of a new session for the address ip. The writer
// clock reads `at`. It returns the ip_hmac of the session row. The value must
// not be empty, and it must not be the overflow text.
func hmacOf(t *testing.T, r *rig, id, ip string, at time.Time) string {
	t.Helper()
	r.w.clock = func() time.Time { return at }
	r.writeOK(sessEvent(t, event.KindRequest, id, ip, "", at.UnixMilli()))
	s, ok := r.session(id)
	if !ok || s.hmac == "" || s.hmac == overflowHMAC {
		t.Fatalf("session %q: found %v, ip_hmac %q", id, ok, s.hmac)
	}
	return s.hmac
}

// T-U-15 (C8): the same client address on two UTC dates gives two ip_hmac
// values. Two times of one UTC date give one value, with one day key holder.
func TestTU15SameAddressOnTwoDatesGivesTwoValues(t *testing.T) {
	const ip = "198.51.100.7"
	r := newRig(t, 100)
	d1 := hmacOf(t, r, "d1", ip, day("2026-03-01T00:00:01Z"))
	d1again := hmacOf(t, r, "d1again", ip, day("2026-03-01T23:59:59Z"))
	d2 := hmacOf(t, r, "d2", ip, day("2026-03-02T00:00:01Z"))
	if d1 != d1again {
		t.Errorf("one holder, one date, two batches: %q and %q, want one value", d1, d1again)
	}
	if d1 == d2 {
		t.Errorf("two dates gave the value %q two times", d1)
	}
}

// T-U-15 (C8): two day key holders on one date, as after a restart, give two
// ip_hmac values. The address is the same. The two writers share one database.
func TestTU15TwoHoldersOnOneDateGiveTwoValues(t *testing.T) {
	const ip = "198.51.100.7"
	at := day("2026-03-01T10:00:00Z")
	r := newRig(t, 100)
	first := hmacOf(t, r, "h1", ip, at)
	r.w = NewWriterWithDayKey(r.db, r.q, false, nil, Recovery{State: r.root, Origin: "origin", Log: r.lg}, session.NewDayKey())
	if second := hmacOf(t, r, "h2", ip, at); first == second {
		t.Errorf("two holders gave the value %q two times", first)
	}
}
