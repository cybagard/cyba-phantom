package session

import (
	"crypto/hmac"
	"crypto/sha256"
	"time"
)

const (
	// beaconPrefix makes the ticket tag differ from the other HMAC uses.
	beaconPrefix = "phantom-beacon-v1"
	sessionIDLen = 26
	// ticketBytes is the decoded size of a ticket: 6 bytes of time, 10 of tag.
	ticketBytes = 16
	msBytes     = 6
	ticketLen   = 26
	maxMS       = int64(1) << (8 * msBytes)
	// ticketMaxAgeMS is the longest age, in ms, that a ticket may have.
	ticketMaxAgeMS = 5000
	sha256Block    = 64
)

// beaconTag returns the first 10 bytes of HMAC-SHA256 over the prefix, 0x00,
// the session id and ms. It uses RFC 2104 with stack buffers, because
// crypto/hmac allocates. The key is shorter than one block.
func (s *state) beaconTag(sid string, ms []byte) (tag [tagLen]byte) {
	var in [sha256Block + len(beaconPrefix) + 1 + sessionIDLen + msBytes]byte
	var out [sha256Block + sha256.Size]byte
	for i := 0; i < sha256Block; i++ {
		var kb byte
		if i < len(s.key) {
			kb = s.key[i]
		}
		in[i] = kb ^ 0x36
		out[i] = kb ^ 0x5c
	}
	n := sha256Block
	n += copy(in[n:], beaconPrefix)
	in[n] = 0
	n++
	n += copy(in[n:], sid)
	copy(in[n:], ms)
	inner := sha256.Sum256(in[:])
	copy(out[sha256Block:], inner[:])
	sum := sha256.Sum256(out[:])
	copy(tag[:], sum[:tagLen])
	return tag
}

// BeaconTicket returns the beacon ticket of a session id at a time. The ticket
// is lower-case base32 with no padding, of 6 bytes of Unix time in ms and a
// 10-byte tag. It returns an empty text in three cases. The Key is the zero
// Key. The session id is not 26 bytes. The time is before 1970 or from 2^48 ms.
func (k Key) BeaconTicket(sid string, now time.Time) string {
	s := k.st()
	ms := now.UnixMilli()
	if s == nil || len(sid) != sessionIDLen || ms < 0 || ms >= maxMS {
		return ""
	}
	var b [ticketBytes]byte
	for i := 0; i < msBytes; i++ {
		b[i] = byte(ms >> (8 * (msBytes - 1 - i)))
	}
	tag := s.beaconTag(sid, b[:msBytes])
	copy(b[msBytes:], tag[:])
	var e [ticketLen]byte
	sessionEncoding.Encode(e[:], b[:])
	for i, c := range e {
		if c >= 'A' && c <= 'Z' {
			e[i] = c + 'a' - 'A'
		}
	}
	return string(e[:])
}

// CheckBeaconTicket reports whether a ticket is valid for a session id at a
// time. The ticket must have the form that BeaconTicket makes, a valid tag and
// an age from 0 to 5000 ms. It allocates nothing and keeps no state. The zero
// Key accepts no ticket.
func (k Key) CheckBeaconTicket(ticket, sid string, now time.Time) bool {
	s := k.st()
	nowMS := now.UnixMilli()
	if s == nil || len(sid) != sessionIDLen || len(ticket) != ticketLen {
		return false
	}
	if nowMS < 0 {
		return false
	}
	var up [ticketLen]byte
	for i := 0; i < ticketLen; i++ {
		if alphaIndex(ticket[i]) < 0 {
			return false
		}
		c := ticket[i]
		if c >= 'a' && c <= 'z' {
			c = c - 'a' + 'A'
		}
		up[i] = c
	}
	if alphaIndex(ticket[ticketLen-1])&3 != 0 {
		return false
	}
	var b [ticketBytes]byte
	if n, err := sessionEncoding.Decode(b[:], up[:]); err != nil || n != ticketBytes {
		return false
	}
	var ms int64
	for i := 0; i < msBytes; i++ {
		ms = ms<<8 | int64(b[i])
	}
	if age := nowMS - ms; age < 0 || age > ticketMaxAgeMS {
		return false
	}
	tag := s.beaconTag(sid, b[:msBytes])
	return hmac.Equal(b[msBytes:], tag[:])
}
