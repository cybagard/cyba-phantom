package bait

import (
	"io"
	"net/http"
	"sync"
	"unicode/utf8"
)

// bodyMax is the most body bytes that a callback route accepts (C8).
const bodyMax = 4096

// bodyPool holds the read buffers. A buffer has one byte more than bodyMax.
// So a read can tell a body of bodyMax bytes from a longer body.
var bodyPool = sync.Pool{New: func() any { return new([bodyMax + 1]byte) }}

// BodyCandidate gives the candidate in the member name of a JSON body (ADR-039
// decision 5). Only a POST has a body candidate. A Content-Length over
// bodyMax gives no read. Else it reads at most bodyMax+1 bytes, also for a
// chunked body. A body of bodyMax+1 bytes and a read error give none.
//
// The candidate is a copy in an array. The pooled buffer goes back to the pool
// before the call returns. So the caller has no release call, and no later
// request can overwrite the candidate. The caller turns the array into a
// string for token.Ring.Check, with string(c[:]).
func BodyCandidate(r *http.Request, name string) (c [candidateLen]byte, ok bool) {
	if r.Method != http.MethodPost || r.Body == nil || r.ContentLength > bodyMax {
		return c, false
	}
	buf := bodyPool.Get().(*[bodyMax + 1]byte)
	n, err := 0, error(nil)
	for n < len(buf) && err == nil {
		var m int
		m, err = r.Body.Read(buf[n:])
		n += m
	}
	if n < len(buf) && err == io.EOF {
		if v, found := bodyMember(buf[:n], name); found {
			ok = copy(c[:], v) == candidateLen
		}
	}
	clear(buf[:n])
	bodyPool.Put(buf)
	return c, ok
}

// bodyMember scans b as one JSON object of members with scalar values. It
// gives the raw content of the string value of the member name. It does this
// only when b is valid and no other member has the name. It decodes nothing,
// allocates nothing and does not recurse.
func bodyMember(b []byte, name string) (val []byte, found bool) {
	if !utf8.Valid(b) {
		return nil, false
	}
	i := skipSpace(b, 0)
	if i >= len(b) || b[i] != '{' {
		return nil, false
	}
	i = skipSpace(b, i+1)
	if i < len(b) && b[i] == '}' {
		return nil, false
	}
	var count int
	var str bool
	for {
		ns, ne, ok := scanString(b, i, true)
		if !ok {
			return nil, false
		}
		i = skipSpace(b, ne+1)
		if i >= len(b) || b[i] != ':' {
			return nil, false
		}
		i = skipSpace(b, i+1)
		vs, ve, isStr, ok := scanScalar(b, i)
		if !ok {
			return nil, false
		}
		if string(b[ns:ne]) == name {
			count++
			val, str = b[vs:ve], isStr
		}
		if isStr {
			ve++
		}
		i = skipSpace(b, ve)
		if i >= len(b) {
			return nil, false
		}
		if b[i] == '}' {
			break
		}
		if b[i] != ',' {
			return nil, false
		}
		i = skipSpace(b, i+1)
	}
	if skipSpace(b, i+1) != len(b) || count != 1 || !str || !isCandidate(val) {
		return nil, false
	}
	return val, true
}

// skipSpace gives the index of the first byte from i that is not JSON white
// space.
func skipSpace(b []byte, i int) int {
	for i < len(b) && (b[i] == ' ' || b[i] == '\t' || b[i] == '\n' || b[i] == '\r') {
		i++
	}
	return i
}

// scanString reads the string that starts with the quote at b[i]. It gives
// the content range [s, e), and b[e] is the closing quote. A control byte
// gives false. A backslash must start a valid escape, and in a name it gives
// false (noEscape).
func scanString(b []byte, i int, noEscape bool) (s, e int, ok bool) {
	if i >= len(b) || b[i] != '"' {
		return 0, 0, false
	}
	s = i + 1
	for j := s; j < len(b); j++ {
		switch c := b[j]; {
		case c == '"':
			return s, j, true
		case c < 0x20:
			return 0, 0, false
		case c == '\\':
			if noEscape || j+1 >= len(b) {
				return 0, 0, false
			}
			j++
			switch b[j] {
			case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
			case 'u':
				if j+4 >= len(b) {
					return 0, 0, false
				}
				for _, h := range b[j+1 : j+5] {
					if !isHex(h) {
						return 0, 0, false
					}
				}
				j += 4
			default:
				return 0, 0, false
			}
		}
	}
	return 0, 0, false
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// scanScalar reads a JSON string, number, true, false or null at b[i]. It
// gives the range [s, e) of the string content or of the literal. For a
// string, b[e] is the closing quote. An object or an array gives false.
func scanScalar(b []byte, i int) (s, e int, isStr, ok bool) {
	if i >= len(b) {
		return 0, 0, false, false
	}
	if b[i] == '"' {
		s, e, ok = scanString(b, i, false)
		return s, e, true, ok
	}
	for _, lit := range [...]string{"true", "false", "null"} {
		if len(b)-i >= len(lit) && string(b[i:i+len(lit)]) == lit {
			return i, i + len(lit), false, true
		}
	}
	e = scanNumber(b, i)
	return i, e, false, e > i
}

// scanNumber gives the end of the RFC 8259 number at b[i], or i for none.
func scanNumber(b []byte, i int) int {
	j := i
	digits := func() bool {
		k := j
		for j < len(b) && b[j] >= '0' && b[j] <= '9' {
			j++
		}
		return j > k
	}
	if j < len(b) && b[j] == '-' {
		j++
	}
	if j < len(b) && b[j] == '0' {
		j++
	} else if !digits() {
		return i
	}
	if j < len(b) && b[j] == '.' {
		j++
		if !digits() {
			return i
		}
	}
	if j < len(b) && (b[j] == 'e' || b[j] == 'E') {
		j++
		if j < len(b) && (b[j] == '+' || b[j] == '-') {
			j++
		}
		if !digits() {
			return i
		}
	}
	return j
}
