package session

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"net/netip"
	"strings"

	"github.com/cybagard/cyba-phantom/internal/event"
)

// IPHMAC returns the ip_hmac text of a client key. It is the lower-case hex of
// HMAC-SHA256. The input is the 4 bytes of an IPv4 key or the 16 bytes of an
// IPv6 key. The key is already unmapped and masked to /64 by the counters. It
// returns an empty text for the zero Key.
func (k Key) IPHMAC(a netip.Addr) string {
	s := k.st()
	if s == nil {
		return ""
	}
	m := hmac.New(sha256.New, s.key[:])
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

// SessionID returns the session id of a client, for the writer and for the
// request path. The id is the first 16 bytes of HMAC-SHA256 over the prefix,
// 0x00, the client key and the JA4 text. It is lower-case base32 with no
// padding. ip is the client address text. It returns nil when ip is empty or is
// not an address, and for the zero Key. It never returns the text of a parse
// error, because that text holds the input.
func (k Key) SessionID(ip, ja4 string) *string {
	s := k.st()
	if s == nil {
		return nil
	}
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return nil
	}
	c, ok := event.CounterKey(a)
	if !ok {
		return nil
	}
	m := hmac.New(sha256.New, s.key[:])
	m.Write([]byte(sessionPrefix))
	m.Write([]byte{0})
	m.Write(c.AsSlice())
	m.Write([]byte(ja4))
	id := strings.ToLower(sessionEncoding.EncodeToString(m.Sum(nil)[:16]))
	return &id
}
