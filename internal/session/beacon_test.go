package session

import (
	"crypto/hmac"
	"crypto/sha256"
	"strings"
	"testing"
	"time"
)

const alphabet = "abcdefghijklmnopqrstuvwxyz234567"

var beaconTime = time.UnixMilli(1_800_000_000_123)

func decodeTicket(t testing.TB, v string) []byte {
	t.Helper()
	b, err := sessionEncoding.DecodeString(strings.ToUpper(v))
	if err != nil || len(b) != ticketBytes {
		t.Fatalf("decode %q: %v", v, err)
	}
	return b
}

func encodeTicket(b []byte) string {
	return strings.ToLower(sessionEncoding.EncodeToString(b))
}

// refTag is the reference HMAC tag, made with crypto/hmac.
func refTag(key []byte, sid string, ms []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte("phantom-beacon-v1"))
	m.Write([]byte{0})
	m.Write([]byte(sid))
	m.Write(ms)
	return m.Sum(nil)[:10]
}

// T-U-25: a ticket has 26 bytes of the alphabet and checks in the window.
func TestTU25RoundTrip(t *testing.T) {
	k := seqKey()
	v := k.BeaconTicket(knownID, beaconTime)
	if len(v) != 26 || strings.Trim(v, alphabet) != "" {
		t.Fatalf("ticket %q has a bad form", v)
	}
	for _, d := range []int{0, 1, 5000} {
		now := beaconTime.Add(time.Duration(d) * time.Millisecond)
		if !k.CheckBeaconTicket(v, knownID, now) {
			t.Errorf("refused at age %d ms", d)
		}
	}
}

// T-U-25: a ticket made at time zero checks at time zero and in the window.
func TestTU25EpochZero(t *testing.T) {
	k := seqKey()
	v := k.BeaconTicket(knownID, time.UnixMilli(0))
	if v == "" {
		t.Fatal("no ticket at time zero")
	}
	for _, ms := range []int64{0, 5000} {
		if !k.CheckBeaconTicket(v, knownID, time.UnixMilli(ms)) {
			t.Errorf("refused at %d ms", ms)
		}
	}
}

// T-U-25: the tag is the HMAC of the defined input, after 6 bytes of ms.
func TestTU25MatchesHMAC(t *testing.T) {
	for n := 0; n < 200; n++ {
		sum := sha256.Sum256([]byte{byte(n)})
		s := &state{}
		copy(s.key[:], sum[:])
		sid := encodeTicket(sum[:16])[:26]
		ms := int64(n)*7_777_777_777 + int64(n)
		b := decodeTicket(t, keyOf(s).BeaconTicket(sid, time.UnixMilli(ms)))
		for i := 0; i < 6; i++ {
			if want := byte(ms >> (8 * (5 - i))); b[i] != want {
				t.Fatalf("n=%d: time byte %d = %x, want %x", n, i, b[i], want)
			}
		}
		if want := refTag(s.key[:], sid, b[:6]); !hmac.Equal(b[6:], want) {
			t.Fatalf("n=%d: tag differs from crypto/hmac", n)
		}
	}
}

type refusal struct {
	name   string
	key    Key
	ticket string
	sid    string
	now    time.Time
}

func refusals(t testing.TB) []refusal {
	k := seqKey()
	v := k.BeaconTicket(knownID, beaconTime)
	b := decodeTicket(t, v)
	other := NewDayKey().At(beaconTime)
	last := alphaIndex(v[25])
	rs := []refusal{
		{"another session", k, v, "aaaqeayeaudaocajbifqydiob5", beaconTime},
		{"another key", k, other.BeaconTicket(knownID, beaconTime), knownID, beaconTime},
		{"age 5001 ms", k, v, knownID, beaconTime.Add(5001 * time.Millisecond)},
		{"future 1 ms", k, v, knownID, beaconTime.Add(-time.Millisecond)},
		{"before epoch", k, v, knownID, time.UnixMilli(-1)},
		{"non-canonical last", k, v[:25] + string(alphabet[last|1]), knownID, beaconTime},
		{"25 bytes", k, v[:25], knownID, beaconTime},
		{"27 bytes", k, v + "a", knownID, beaconTime},
		{"upper case", k, strings.ToUpper(v), knownID, beaconTime},
		{"outside alphabet", k, v[:5] + "1" + v[6:], knownID, beaconTime},
		{"sid 25 bytes", k, v, knownID[:25], beaconTime},
		{"sid 27 bytes", k, v, knownID + "a", beaconTime},
		{"zero Key", Key{}, v, knownID, beaconTime},
	}
	for i := 0; i < 128; i++ {
		m := append([]byte(nil), b...)
		m[i/8] ^= 1 << (i % 8)
		rs = append(rs, refusal{"flip", k, encodeTicket(m), knownID, beaconTime})
	}
	return rs
}

// T-U-25: each bad ticket, session, key or time is refused.
func TestTU25Refused(t *testing.T) {
	for _, r := range refusals(t) {
		if r.key.CheckBeaconTicket(r.ticket, r.sid, r.now) {
			t.Errorf("%s: accepted %q", r.name, r.ticket)
		}
	}
}

// T-U-25: the make function gives no ticket for a bad input.
func TestTU25MakeRefused(t *testing.T) {
	k := seqKey()
	for name, v := range map[string]string{
		"zero Key":     Key{}.BeaconTicket(knownID, beaconTime),
		"sid 25":       k.BeaconTicket(knownID[:25], beaconTime),
		"sid 27":       k.BeaconTicket(knownID+"a", beaconTime),
		"before epoch": k.BeaconTicket(knownID, time.UnixMilli(-1)),
		"2^48 ms":      k.BeaconTicket(knownID, time.UnixMilli(1<<48)),
	} {
		if v != "" {
			t.Errorf("%s: made %q", name, v)
		}
	}
	if k.BeaconTicket(knownID, time.UnixMilli(1<<48-1)) == "" {
		t.Error("no ticket for the last valid time")
	}
}

// T-U-25: the check allocates nothing.
func TestTU25NoAllocations(t *testing.T) {
	k := seqKey()
	v := k.BeaconTicket(knownID, beaconTime)
	n := testing.AllocsPerRun(100, func() { k.CheckBeaconTicket(v, knownID, beaconTime) })
	if n != 0 {
		t.Errorf("valid ticket: %v allocations, want 0", n)
	}
	for _, r := range refusals(t) {
		n := testing.AllocsPerRun(20, func() { r.key.CheckBeaconTicket(r.ticket, r.sid, r.now) })
		if n != 0 {
			t.Errorf("%s: %v allocations, want 0", r.name, n)
		}
	}
}

func BenchmarkCheckBeaconTicket(b *testing.B) {
	k := seqKey()
	v := k.BeaconTicket(knownID, beaconTime)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		k.CheckBeaconTicket(v, knownID, beaconTime)
	}
}
