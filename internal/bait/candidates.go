package bait

import (
	"net/http"
	"strings"
)

// The candidate scans of a callback route (SEC-37, ADR-039 decision 4). Each
// scan takes request parts and gives the text of one position, or "" for no
// candidate. No scan decodes, parses a form or allocates.

// candidateLen is the length of a candidate. It is the length of a token text.
const candidateLen = 26

// candidateAlphabet is the set of bytes of a token text. It is a copy of the
// set in internal/token. A test ties the two sets.
const candidateAlphabet = "abcdefghijklmnopqrstuvwxyz234567"

// inAlphabet marks each byte value of candidateAlphabet.
var inAlphabet = func() (t [256]bool) {
	for i := 0; i < len(candidateAlphabet); i++ {
		t[candidateAlphabet[i]] = true
	}
	return t
}()

// isCandidate reports whether s has the length and the bytes of a candidate.
func isCandidate[T string | []byte](s T) bool {
	if len(s) != candidateLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !inAlphabet[s[i]] {
			return false
		}
	}
	return true
}

// candidate gives s when s is a candidate, else "".
func candidate(s string) string {
	if isCandidate(s) {
		return s
	}
	return ""
}

// PathCandidate gives the one segment after the route path in the escaped
// path (r.URL.EscapedPath()). The root path is "/". The route path itself, an
// empty segment and two segments give no candidate. An escaped byte stays
// escaped, so it gives no candidate.
func PathCandidate(escapedPath, routePath string) string {
	rest, ok := strings.CutPrefix(escapedPath, routePath)
	if !ok {
		return ""
	}
	if routePath != "/" {
		if rest, ok = strings.CutPrefix(rest, "/"); !ok {
			return ""
		}
	}
	if strings.IndexByte(rest, '/') >= 0 {
		return ""
	}
	return candidate(rest)
}

// QueryCandidate gives the raw value of the one part of the raw query whose
// name is name. The scan splits on "&" only. A part has the name before its
// first "=", and a part with no "=" has an empty value. Two parts with the
// name give no candidate.
func QueryCandidate(rawQuery, name string) string {
	val, found := "", false
	for rest := rawQuery; rest != ""; {
		part := rest
		if i := strings.IndexByte(rest, '&'); i >= 0 {
			part, rest = rest[:i], rest[i+1:]
		} else {
			rest = ""
		}
		key, v, _ := strings.Cut(part, "=")
		if key != name {
			continue
		}
		if found {
			return ""
		}
		val, found = v, true
	}
	return candidate(val)
}

// HeaderName gives the canonical form of a header name. It allocates. Call it
// one time at load, never on a request. It is
// textproto.CanonicalMIMEHeaderKey, called through net/http. The module import
// list of the egress test has no net/textproto.
func HeaderName(name string) string {
	return http.CanonicalHeaderKey(name)
}

// HeaderCandidate gives the value of the header under the canonical name
// (from HeaderName). It does this only when the name has exactly one value.
// net/http has removed the SP and HTAB at both ends of the value.
func HeaderCandidate(h http.Header, canonical string) string {
	if v := h[canonical]; len(v) == 1 {
		return candidate(v[0])
	}
	return ""
}
