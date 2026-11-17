package sensortime

import "strings"

// validUUID tells if s is 36 characters in the form 8-4-4-4-12 of hex digits.
// With upper false, a letter must be lower case.
func validUUID(s string, upper bool) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case i == 8 || i == 13 || i == 18 || i == 23:
			if c != '-' {
				return false
			}
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f':
		case upper && c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}

// parseLinuxBootID reads the file /proc/sys/kernel/random/boot_id. The text
// is exactly 36 characters in lower-case UUID form and one line feed. A read
// error or any other text gives ErrBootID. It never gives an empty boot id.
func parseLinuxBootID(b []byte, readErr error) (string, error) {
	if readErr != nil || len(b) != 37 || b[36] != '\n' {
		return "", ErrBootID
	}
	id := string(b[:36])
	if !validUUID(id, false) {
		return "", ErrBootID
	}
	return id, nil
}

// normalizeDarwinBootID reads the sysctl kern.bootsessionuuid. The system
// gives upper-case UUID form with no line feed. The sensor stores lower case,
// so one host boot has one spelling. Other text, or an error, gives
// ErrBootID. It never gives an empty boot id.
func normalizeDarwinBootID(s string, sysErr error) (string, error) {
	if sysErr != nil || !validUUID(s, true) {
		return "", ErrBootID
	}
	return strings.ToLower(s), nil
}
