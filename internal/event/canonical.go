// Package event builds the canonical form of an event record and hashes it.
//
// The canonical form is the RFC 8785 (JCS) text of one JSON object. A third
// party who has the record can build the same bytes and the same hash. For
// this reason the package never repairs a value. It checks the input first and
// returns an error when a value is outside the strict domain. It uses only the
// standard library packages encoding/json/v2 and encoding/json/jsontext.
package event

import (
	"bytes"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

// maxInt is the largest integer that a JSON number holds exactly in an IEEE
// 754 double: 2^53 - 1.
const maxInt = 1<<53 - 1

// strict makes the decoder and the encoder reject invalid UTF-8 and duplicate
// member names. It sets no HTML or JavaScript escaping.
var strict = []jsontext.Options{
	jsontext.AllowDuplicateNames(false),
	jsontext.AllowInvalidUTF8(false),
}

// Canonical checks the input domain of raw, then returns its RFC 8785 bytes.
// The input must be one JSON object. It must hold only valid UTF-8, unique
// member names, and integers from -(2^53-1) to 2^53-1. It must hold no float
// and no -0. Canonical does not change raw. On a failed check it returns no
// bytes and an error that names the rule and the byte offset. The error text
// holds no input text.
func Canonical(raw []byte) ([]byte, error) {
	if err := check(raw); err != nil {
		return nil, err
	}
	// Canonicalize works in place. Copy first.
	v := jsontext.Value(bytes.Clone(raw))
	if err := v.Canonicalize(strict...); err != nil {
		return nil, errRule("canonicalize failed", 0)
	}
	return v, nil
}

// Encode marshals v with the strict options, then returns Canonical of the
// result. It returns an error if the marshaled text is outside the domain of
// Canonical.
func Encode(v any) ([]byte, error) {
	b, err := json.Marshal(v, strict...)
	if err != nil {
		return nil, errRule("marshal failed", 0)
	}
	return Canonical(b)
}

func errRule(rule string, off int64) error {
	return fmt.Errorf("event: %s at offset %d", rule, off)
}

// check walks the token stream of raw and rejects the first value that is
// outside the domain.
func check(raw []byte) error {
	if !utf8.Valid(raw) {
		off := 0
		for off < len(raw) {
			r, n := utf8.DecodeRune(raw[off:])
			if r == utf8.RuneError && n == 1 {
				break
			}
			off += n
		}
		return errRule("invalid UTF-8", int64(off))
	}
	dec := jsontext.NewDecoder(bytes.NewReader(raw), strict...)
	if dec.PeekKind() != '{' {
		return errRule("top level is not an object", 0)
	}
	for {
		tok, err := dec.ReadToken()
		switch {
		case errors.Is(err, jsontext.ErrDuplicateName):
			return errRule("duplicate member name", dec.InputOffset())
		case err != nil:
			return errRule("malformed JSON or lone surrogate", dec.InputOffset())
		case tok.Kind() == '0':
			if rule := numberRule(tok.String()); rule != "" {
				return errRule(rule, dec.InputOffset())
			}
		case tok.Kind() == '}' && dec.StackDepth() == 0:
			if _, err := dec.ReadToken(); err != io.EOF {
				return errRule("data after the object", dec.InputOffset())
			}
			return nil
		}
	}
}

// numberRule returns the rule that the number text n breaks, or "".
func numberRule(n string) string {
	switch {
	case n == "-0":
		return "negative zero"
	case strings.ContainsAny(n, ".eE"):
		return "number is not an integer"
	}
	if v, err := strconv.ParseInt(n, 10, 64); err != nil || v > maxInt || v < -maxInt {
		return "integer outside 2^53-1"
	}
	return ""
}
