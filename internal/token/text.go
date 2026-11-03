package token

import (
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
)

// The text of a token (ADR-036): base32 in lower case, no padding. A 16-byte
// block gives 26 bytes. The last character holds 2 pad bits that must be zero.
const (
	alphabet = "abcdefghijklmnopqrstuvwxyz234567"
	textLen  = 26
	idBytes  = 16
)

var enc = base32.NewEncoding(alphabet).WithPadding(base32.NoPadding)

// inAlphabet marks each byte value that can be in a token text.
var inAlphabet = func() (t [256]bool) {
	for i := 0; i < len(alphabet); i++ {
		t[alphabet[i]] = true
	}
	return t
}()

// Text gives the canonical text of a token: 26 bytes, lower case, no padding.
func Text(tok [Size]byte) string {
	var b [textLen]byte
	enc.Encode(b[:], tok[:])
	return string(b[:])
}

// Parse reads the canonical text of a token (SEC-33). The decoder alone is
// not strict: it accepts other pad bits and skips CR and LF. So Parse checks
// the length and each byte first. Then it decodes, and it encodes the block
// again and compares. On refusal it gives the zero block and false. It does
// not allocate.
func Parse(s string) ([Size]byte, bool) {
	var tok [Size]byte
	if len(s) != textLen {
		return tok, false
	}
	for i := 0; i < len(s); i++ {
		if !inAlphabet[s[i]] {
			return tok, false
		}
	}
	n, err := enc.Decode(tok[:], []byte(s))
	if err != nil || n != Size {
		return [Size]byte{}, false
	}
	var back [textLen]byte
	enc.Encode(back[:], tok[:])
	if string(back[:]) != s {
		return [Size]byte{}, false
	}
	return tok, true
}

// ID gives the token id. It is the first 16 bytes of the SHA-256 hash of the
// token text, in lower-case hex. It has 32 characters.
func ID(tok [Size]byte) string {
	sum := sha256.Sum256([]byte(Text(tok)))
	return hex.EncodeToString(sum[:idBytes])
}
