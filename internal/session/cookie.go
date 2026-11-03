package session

import (
	"crypto/hmac"
	"crypto/sha256"
	"net/http"
	"strings"
)

const (
	// cookieName is the fixed generic name of the session cookie.
	cookieName = "sid"
	// cookiePrefix makes the tag differ from the other HMAC uses of the key.
	cookiePrefix = "phantom-cookie-v1"
	idLen        = 16
	tagLen       = 10
	// cookieLen is the length of the base32 text of the id and the tag.
	cookieLen = 42
)

// tag returns the first 10 bytes of HMAC-SHA256 over the prefix, 0x00 and the
// id bytes. The caller must make sure that the Key is not the zero Key.
func (s *state) tag(id []byte) []byte {
	m := hmac.New(sha256.New, s.key[:])
	m.Write([]byte(cookiePrefix))
	m.Write([]byte{0})
	m.Write(id)
	return m.Sum(nil)[:tagLen]
}

// CookieValue returns the cookie value of a session id. The value is lower-case
// base32 with no padding, of the id bytes and the tag. It returns an empty text
// for the zero Key.
func (k Key) CookieValue(id [idLen]byte) string {
	s := k.st()
	if s == nil {
		return ""
	}
	b := append(id[:], s.tag(id[:])...)
	return strings.ToLower(sessionEncoding.EncodeToString(b))
}

// alphaIndex returns the base32 value of a lower-case alphabet byte, or -1.
func alphaIndex(c byte) int {
	switch {
	case c >= 'a' && c <= 'z':
		return int(c - 'a')
	case c >= '2' && c <= '7':
		return int(c-'2') + 26
	}
	return -1
}

// wellFormed reports whether v is 42 bytes of the alphabet a-z and 2-7. The
// decoder ignores the 2 low bits of the last character. Thus the last
// character must have the value of a multiple of 4.
func wellFormed(v string) bool {
	if len(v) != cookieLen {
		return false
	}
	for i := 0; i < len(v); i++ {
		if alphaIndex(v[i]) < 0 {
			return false
		}
	}
	return alphaIndex(v[cookieLen-1])&3 == 0
}

// CheckCookie checks a cookie value under the Key that made its tag. When the
// value is valid, it returns the session id text of the id bytes, in the form
// of SessionID. Else it returns false. The zero Key accepts no value.
func (k Key) CheckCookie(v string) (string, bool) {
	s := k.st()
	if s == nil || !wellFormed(v) {
		return "", false
	}
	b, err := sessionEncoding.DecodeString(strings.ToUpper(v))
	if err != nil || len(b) != idLen+tagLen {
		return "", false
	}
	if !hmac.Equal(b[idLen:], s.tag(b[:idLen])) {
		return "", false
	}
	return strings.ToLower(sessionEncoding.EncodeToString(b[:idLen])), true
}

// trimSPHTAB removes SP and HTAB, and no other byte, at the two ends of s.
func trimSPHTAB(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	return s
}

// CookieFromHeader returns the session cookie value of a request. It takes a
// value only when exactly one part, in all Cookie lines, has the name. A part
// with the name and a bad value counts. The value must have the form that
// CheckCookie needs. It does not call the net/http cookie functions and it
// allocates nothing. It does not check the tag.
func CookieFromHeader(h http.Header) (string, bool) {
	val, n := "", 0
	for _, line := range h.Values("Cookie") {
		for len(line) > 0 {
			part := line
			if i := strings.IndexByte(line, ';'); i >= 0 {
				part, line = line[:i], line[i+1:]
			} else {
				line = ""
			}
			part = trimSPHTAB(part)
			name, v, _ := strings.Cut(part, "=")
			if name != cookieName {
				continue
			}
			if n++; n > 1 {
				return "", false
			}
			val = v
		}
	}
	if n != 1 || !wellFormed(val) {
		return "", false
	}
	return val, true
}
