package bundle

import (
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"strings"
	"time"
)

// MaxManifestBytes is the longest manifest that ParseManifest reads.
const MaxManifestBytes = 4096

// maxValidity is the longest time from created to expires.
const maxValidity = 366 * 24 * time.Hour

// stampLayout is the one form of created and expires: RFC 3339, UTC, "Z", and
// whole seconds.
const stampLayout = "2006-01-02T15:04:05Z"

// Manifest is a manifest that passed the format checks of ParseManifest.
type Manifest struct {
	Version   string
	MinEngine [3]int // major, minor, patch
	Created   time.Time
	Expires   time.Time
	KeyID     string
	// Rotation is set only in a transition bundle.
	Rotation *Rotation
}

// Rotation is the rotation member of a transition bundle.
type Rotation struct {
	From string   // key ID of the key that is trusted now
	Key  [32]byte // the new public key
}

// parseOpts make the decoder refuse invalid UTF-8, duplicate member names and
// unknown members. The decoder matches names with case (the default). These are
// the strict options of internal/event, plus the unknown-member rule.
var parseOpts = []json.Options{
	jsontext.AllowDuplicateNames(false),
	jsontext.AllowInvalidUTF8(false),
	json.RejectUnknownMembers(true),
}

// A pointer member is nil when the member is missing or null.
type rawManifest struct {
	Version   *string        `json:"version"`
	MinEngine *string        `json:"min_engine"`
	Created   *string        `json:"created"`
	Expires   *string        `json:"expires"`
	KeyID     *string        `json:"key_id"`
	Rotation  jsontext.Value `json:"rotation"`
}

type rawRotation struct {
	From *string `json:"from"`
	Key  *string `json:"key"`
}

// ParseManifest checks the format of a manifest. The manifest is one JSON
// object of at most MaxManifestBytes bytes, with all five members and, in a
// transition bundle, rotation. It has no duplicate, unknown or case-variant
// member, and no byte after the object except JSON white space. The forms:
//   - version: YYYY.MM.DD-N, a date of the calendar, N from 1 to 999;
//   - min_engine: MAJOR.MINOR.PATCH, each part from 0 to 9999;
//   - created and expires: RFC 3339, UTC, "Z", whole seconds, with created
//     before expires and at most 366 days between them;
//   - key_id: 1 to 16 bytes of a-z and 0-9;
//   - rotation: from (a key_id form) and key (canonical base64 of 32 bytes).
//
// A number in version or min_engine has no leading zero.
//
// Every failure gives ErrManifestInvalid and no manifest. The error holds no
// input bytes. ParseManifest does not check min_engine against the engine
// version and does not check the expiry; CheckEngine and CheckExpiry do.
func ParseManifest(b []byte) (*Manifest, error) {
	if len(b) > MaxManifestBytes {
		return nil, ErrManifestInvalid
	}
	var raw rawManifest
	if err := json.Unmarshal(b, &raw, parseOpts...); err != nil {
		return nil, ErrManifestInvalid
	}
	for _, p := range []*string{raw.Version, raw.MinEngine, raw.Created, raw.Expires, raw.KeyID} {
		if p == nil {
			return nil, ErrManifestInvalid
		}
	}
	m := &Manifest{Version: *raw.Version, KeyID: *raw.KeyID}
	var ok [4]bool
	m.MinEngine, ok[0] = parseEngine(*raw.MinEngine)
	m.Created, ok[1] = parseStamp(*raw.Created)
	m.Expires, ok[2] = parseStamp(*raw.Expires)
	ok[3] = validVersion(m.Version) && validKeyID(m.KeyID)
	for _, good := range ok {
		if !good {
			return nil, ErrManifestInvalid
		}
	}
	if !m.Created.Before(m.Expires) || m.Expires.Sub(m.Created) > maxValidity {
		return nil, ErrManifestInvalid
	}
	if raw.Rotation != nil {
		var rr rawRotation
		if err := json.Unmarshal(raw.Rotation, &rr, parseOpts...); err != nil || rr.From == nil || rr.Key == nil {
			return nil, ErrManifestInvalid
		}
		rot := &Rotation{From: *rr.From}
		var keyOK bool
		if rot.Key, keyOK = parseKey(*rr.Key); !keyOK || !validKeyID(rot.From) {
			return nil, ErrManifestInvalid
		}
		m.Rotation = rot
	}
	return m, nil
}

// CheckExpiry gives ErrExpired when the manifest expires at now or before. now
// is a parameter, so a later step can skip this check for a bundle that is
// already accepted. The check is not part of ParseManifest.
func (m *Manifest) CheckExpiry(now time.Time) error {
	if !now.Before(m.Expires) {
		return ErrExpired
	}
	return nil
}

// decimal reads 1 to maxDigits ASCII digits, with no leading zero except "0".
func decimal(s string, maxDigits int) (int, bool) {
	if len(s) == 0 || len(s) > maxDigits || (s[0] == '0' && len(s) > 1) {
		return 0, false
	}
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
		n = n*10 + int(s[i]-'0')
	}
	return n, true
}

// validVersion checks "YYYY.MM.DD-N": a date of the calendar, and N from 1 to
// 999 with no leading zero.
func validVersion(s string) bool {
	if len(s) < 12 || s[10] != '-' {
		return false
	}
	t, err := time.Parse("2006.01.02", s[:10])
	if err != nil || t.Format("2006.01.02") != s[:10] {
		return false
	}
	n, ok := decimal(s[11:], 3)
	return ok && n >= 1
}

// parseEngine reads "MAJOR.MINOR.PATCH", each part from 0 to 9999.
func parseEngine(s string) ([3]int, bool) {
	var v [3]int
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return v, false
	}
	for i, p := range parts {
		n, ok := decimal(p, 4)
		if !ok {
			return v, false
		}
		v[i] = n
	}
	return v, true
}

// parseStamp reads a time in stampLayout. The text must be the exact output of
// the layout, so an offset, a lower-case "z" and a fraction are refused.
func parseStamp(s string) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil || t.UTC().Format(stampLayout) != s {
		return time.Time{}, false
	}
	return t.UTC(), true
}

// validKeyID checks 1 to 16 bytes of a-z and 0-9.
func validKeyID(s string) bool {
	if len(s) < 1 || len(s) > 16 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

// parseKey reads canonical standard base64 of exactly 32 bytes. The text must
// be the re-encoding of the bytes that it decodes to.
func parseKey(s string) (k [32]byte, ok bool) {
	enc := base64.StdEncoding
	if len(s) != enc.EncodedLen(len(k)) {
		return k, false
	}
	b, err := enc.DecodeString(s)
	if err != nil || len(b) != len(k) || enc.EncodeToString(b) != s {
		return k, false
	}
	return [32]byte(b), true
}
