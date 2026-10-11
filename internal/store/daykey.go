package store

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
)

// dayLayout is the layout of the UTC date that keys ip_counter.day.
const dayLayout = "2006-01-02"

// overflowHMAC is the ip_hmac value of the overflow bucket of the counters.
const overflowHMAC = "overflow"

// dayKey holds the day key: 32 random bytes that live in memory only. The key
// is for one UTC date. The key never goes to a file, a log, an error or a
// metric. Only the writer goroutine uses a dayKey.
type dayKey struct {
	date string // the UTC date of key; empty before the first batch
	key  [32]byte
}

// use selects the key for date. When date is not the date of the current key,
// in either direction, it makes a new key and drops the old one. Thus a clock
// step back never brings an old key back.
func (d *dayKey) use(date string) {
	if d.date == date {
		return
	}
	d.date = date
	_, _ = rand.Read(d.key[:]) // since Go 1.24 Read does not return an error
}

// hmac returns the ip_hmac text of a client key: the lower-case hex of
// HMAC-SHA256 over the 4 bytes of an IPv4 key or the 16 bytes of an IPv6 key.
// The key is already unmapped and masked to /64 by the counters.
func (d *dayKey) hmac(a netip.Addr) string {
	m := hmac.New(sha256.New, d.key[:])
	if a.Is4() {
		b := a.As4()
		m.Write(b[:])
	} else {
		b := a.As16()
		m.Write(b[:])
	}
	return hex.EncodeToString(m.Sum(nil))
}
