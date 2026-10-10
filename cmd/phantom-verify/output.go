package main

import "strconv"

// escape makes input text safe to print. It uses the escape rule of
// strconv.Quote, without the outer quotes. The rule replaces each C0 control
// character, U+007F, each C1 control character, each bidirectional format
// character (U+061C, U+200E-U+200F, U+202A-U+202E, U+2066-U+2069), and each
// invalid UTF-8 byte with an escape sequence. The result has only printable
// characters. Every text from the input goes through this function before it
// goes to stdout or stderr.
func escape(s string) string {
	q := strconv.Quote(s)
	return q[1 : len(q)-1]
}
