package bundle

import "errors"

// Code is a rejection code of the bundle loader (FR-02). There are eight
// codes, and each failure gives exactly one of them.
type Code uint8

// The rejection codes. The zero value of Code is not a code.
const (
	CodeArchiveInvalid Code = iota + 1
	CodeBadSig
	CodeManifestInvalid
	CodeMinEngine
	CodeExpired
	CodeRollback
	CodeTemplateParse
	CodeSeedInvalid
)

var codeText = [...]string{
	CodeArchiveInvalid:  "archive_invalid",
	CodeBadSig:          "bad_sig",
	CodeManifestInvalid: "manifest_invalid",
	CodeMinEngine:       "min_engine",
	CodeExpired:         "expired",
	CodeRollback:        "rollback",
	CodeTemplateParse:   "template_parse",
	CodeSeedInvalid:     "seed_invalid",
}

// String returns the text of the code, for example "min_engine". A value that
// is not one of the eight codes gives "unknown".
func (c Code) String() string {
	if c < 1 || int(c) >= len(codeText) {
		return "unknown"
	}
	return codeText[c]
}

// The errors of the manifest steps. Each one is a fixed value with no input
// bytes.
var (
	ErrManifestInvalid = errors.New("bundle: manifest_invalid")
	ErrMinEngine       = errors.New("bundle: min_engine")
	ErrExpired         = errors.New("bundle: expired")
)

// CodeOf returns the rejection code of an error of this package. It gives false
// for an error that has no code here.
func CodeOf(err error) (Code, bool) {
	switch {
	case errors.Is(err, ErrArchiveInvalid):
		return CodeArchiveInvalid, true
	case errors.Is(err, ErrManifestInvalid):
		return CodeManifestInvalid, true
	case errors.Is(err, ErrMinEngine):
		return CodeMinEngine, true
	case errors.Is(err, ErrExpired):
		return CodeExpired, true
	}
	return 0, false
}
