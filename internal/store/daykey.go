package store

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"net/netip"
	"strings"

	"github.com/cybagard/cyba-phantom/internal/event"
)

// dayLayout is the layout of the UTC date that keys ip_counter.day.
const dayLayout = "2006-01-02"

// overflowHMAC is the ip_hmac value of the overflow bucket of the counters.
const overflowHMAC = "overflow"

// dayKey holds the day key: 32 random bytes that live in memory only. The key
// is for one UTC date. The key never goes to a file, a log, an error or a
// metric. Only the writer goroutine uses a dayKey.
//
// fmt cannot call Format on the unexported dk field of a Writer. It prints all
// fields of a struct there. For a verb that does not fit, such as %s, it also
// prints the target of a pointer. Thus the state is behind a func. fmt prints
// only the address of a func, for every verb.
type dayKey struct {
	s func() *dayState
}

type dayState struct {
	date string // the UTC date of the key; empty before the first batch
	key  [32]byte
}

// newDayKey returns a dayKey with no date and a zero key.
func newDayKey() dayKey {
	s := new(dayState)
	return dayKey{s: func() *dayState { return s }}
}

// use selects the key for date. When date is not the date of the current key,
// in either direction, it makes a new key and drops the old one. Thus a clock
// step back never brings an old key back.
func (d *dayKey) use(date string) {
	s := d.s()
	if s.date == date {
		return
	}
	s.date = date
	_, _ = rand.Read(s.key[:]) // since Go 1.24 Read does not return an error
}

// ipHMAC returns the ip_hmac text of a client key. It is the lower-case hex of
// HMAC-SHA256. The input is the 4 bytes of an IPv4 key or the 16 bytes of an
// IPv6 key. The key is already unmapped and masked to /64 by the counters.
func (d *dayKey) ipHMAC(a netip.Addr) string {
	m := hmac.New(sha256.New, d.s().key[:])
	if a.Is4() {
		b := a.As4()
		m.Write(b[:])
	} else {
		b := a.As16()
		m.Write(b[:])
	}
	return hex.EncodeToString(m.Sum(nil))
}

// sessionPrefix makes the session id differ from ip_hmac for one client key.
const sessionPrefix = "phantom-session-v1"

// sessionEncoding is the base32 form of a session id: no padding.
var sessionEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// sessionID returns the session id of a refused event. The id is the first 16
// bytes of HMAC-SHA256 over the prefix, 0x00, the client key and the JA4 text.
// It is lower-case base32 with no padding. ip is the client address text. It
// returns nil when ip is empty or is not an address. It never returns the text
// of a parse error, because that text holds the input.
func (d *dayKey) sessionID(ip, ja4 string) *string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return nil
	}
	k, ok := event.CounterKey(a)
	if !ok {
		return nil
	}
	m := hmac.New(sha256.New, d.s().key[:])
	m.Write([]byte(sessionPrefix))
	m.Write([]byte{0})
	m.Write(k.AsSlice())
	m.Write([]byte(ja4))
	id := strings.ToLower(sessionEncoding.EncodeToString(m.Sum(nil)[:16]))
	return &id
}
