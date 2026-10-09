package event

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// The caps of the variable fields. Each cap is in bytes. With them the largest
// canonical record has a fixed size: MaxRecordBytes holds it, with room for
// the worst case, in which each byte of a string is a control character that
// the encoder writes as 6 bytes.
const (
	MaxRecordBytes = 24 << 10
	MaxDetailBytes = 2 << 10
	MaxBodyPrefix  = 4 << 10

	capVhost     = 253
	capMethod    = 16
	capPath      = 2048
	capID        = 64 // session, trap_id and token_id
	capFP        = 128
	capName      = 64
	maxIPText    = 39
	maxEventSize = MaxRecordBytes + MaxBodyPrefix + maxIPText
)

// Surface is the place of a request where a token was found.
type Surface string

const (
	SurfacePath   Surface = "path"
	SurfaceHeader Surface = "header"
	SurfaceQuery  Surface = "query"
	SurfaceBody   Surface = "body"
)

// FP holds the fingerprint members of a session. A nil member is absent.
type FP struct {
	JA4 *string `json:"ja4,omitzero"`
	H2  *string `json:"h2,omitzero"`
	Hdr *string `json:"hdr,omitzero"`
}

// Record is the hashed form of an event: the field set of the data model and
// no other field. It has no field for an IP, an ip_hmac, a body, a user agent,
// a header value or a cookie. A nil pointer and an empty Detail mean that the
// field is absent. The version member is not a field: it is always 1. A
// number is an int64, never a float.
type Record struct {
	TS      int64    `json:"ts"`
	Session *string  `json:"session,omitzero"`
	Kind    Kind     `json:"kind"`
	Vhost   *string  `json:"vhost,omitzero"`
	Method  *string  `json:"method,omitzero"`
	Path    *string  `json:"path,omitzero"`
	Status  *int64   `json:"status,omitzero"`
	TrapID  *string  `json:"trap_id,omitzero"`
	TokenID *string  `json:"token_id,omitzero"`
	Surface *Surface `json:"surface,omitzero"`
	FP      *FP      `json:"fp,omitzero"`
	Detail  Detail   `json:"detail,omitempty"`
}

type wire struct {
	V int64 `json:"v"`
	Record
}

// Value is one value of a Detail: an int64, a bool or a string.
type Value struct {
	kind byte
	i    int64
	s    string
}

func Int(v int64) Value  { return Value{kind: 'i', i: v} }
func Str(v string) Value { return Value{kind: 's', s: v} }
func Bool(v bool) Value {
	if v {
		return Value{kind: 'b', i: 1}
	}
	return Value{kind: 'b'}
}

// MarshalJSON writes the value. A Value that has no type is an error.
func (v Value) MarshalJSON() ([]byte, error) {
	switch v.kind {
	case 'i':
		return strconv.AppendInt(nil, v.i, 10), nil
	case 'b':
		return strconv.AppendBool(nil, v.i == 1), nil
	case 's':
		return json.Marshal(v.s, strict...)
	}
	return nil, errors.New("event: detail value has no type")
}

// Detail is the flat object of the detail member: unique ASCII names and
// values of the types int64, bool and string. It has no nesting. It is at most
// MaxDetailBytes in canonical form. Detail cannot know what a string means: a
// producer must not put request-derived text that can hold an address in it.
type Detail map[string]Value

func (d Detail) check() error {
	raw := 0
	for n, v := range d {
		if n == "" || len(n) > capName {
			return errors.New("event: detail name is empty or too long")
		}
		for i := 0; i < len(n); i++ {
			if n[i] < 0x20 || n[i] > 0x7e {
				return errors.New("event: detail name is not printable ASCII")
			}
		}
		// A canonical string is never shorter than its raw bytes, so a raw
		// sum past the cap is too large. This check runs before any encoding.
		if raw += len(n) + len(v.s); raw > MaxDetailBytes {
			return errors.New("event: detail is too large")
		}
	}
	return nil
}

// JSON returns the canonical text of d, which is the text of the detail
// column.
func (d Detail) JSON() ([]byte, error) {
	if err := d.check(); err != nil {
		return nil, err
	}
	b, err := Encode(d)
	if err != nil {
		return nil, err
	}
	if len(b) > MaxDetailBytes {
		return nil, errors.New("event: detail is too large")
	}
	return b, nil
}

// ParseDetail reads the text of a detail column. It accepts only the flat
// form: one object with int64, bool and string values.
func ParseDetail(text string) (Detail, error) {
	bad := errors.New("event: detail text is not a flat object")
	if len(text) > MaxDetailBytes {
		return nil, bad
	}
	dec := jsontext.NewDecoder(strings.NewReader(text), strict...)
	if tok, err := dec.ReadToken(); err != nil || tok.Kind() != '{' {
		return nil, bad
	}
	d := Detail{}
	for dec.PeekKind() != '}' {
		tok, err := dec.ReadToken()
		if err != nil || tok.Kind() != '"' {
			return nil, bad
		}
		name := tok.String() // a token is void after the next read
		if tok, err = dec.ReadToken(); err != nil {
			return nil, bad
		}
		switch tok.Kind() {
		case '"':
			d[name] = Str(tok.String())
		case 't', 'f':
			d[name] = Bool(tok.Bool())
		case '0':
			n, err := strconv.ParseInt(tok.String(), 10, 64)
			if err != nil || numberRule(tok.String()) != "" {
				return nil, bad
			}
			d[name] = Int(n)
		default:
			return nil, bad
		}
	}
	if _, err := dec.ReadToken(); err != nil {
		return nil, bad
	}
	if _, err := dec.ReadToken(); err != io.EOF {
		return nil, bad
	}
	if err := d.check(); err != nil {
		return nil, err
	}
	return d, nil
}

func checkText(name string, p *string, max int) error {
	if p == nil {
		return nil
	}
	if *p == "" || len(*p) > max || !utf8.ValidString(*p) {
		return fmt.Errorf("event: %s is empty, too long or not UTF-8", name)
	}
	return nil
}

// check tests the rules of the record before any encoding. Each cap is tested
// here, so the text that goes to the encoder is at most MaxRecordBytes.
func (r Record) check() error {
	if !r.Kind.valid() {
		return errUnknownKind
	}
	if r.Session != nil && r.Kind.isSystem() {
		return errors.New("event: a system kind has no session")
	}
	fp := FP{}
	if r.FP != nil {
		fp = *r.FP
		if fp == (FP{}) {
			return errors.New("event: fp has no member")
		}
	}
	for _, c := range []struct {
		name string
		p    *string
		max  int
	}{
		{"session", r.Session, capID}, {"vhost", r.Vhost, capVhost},
		{"method", r.Method, capMethod}, {"path", r.Path, capPath},
		{"trap_id", r.TrapID, capID}, {"token_id", r.TokenID, capID},
		{"fp.ja4", fp.JA4, capFP}, {"fp.h2", fp.H2, capFP}, {"fp.hdr", fp.Hdr, capFP},
	} {
		if err := checkText(c.name, c.p, c.max); err != nil {
			return err
		}
	}
	if r.Surface != nil {
		switch *r.Surface {
		case SurfacePath, SurfaceHeader, SurfaceQuery, SurfaceBody:
		default:
			return errors.New("event: unknown surface")
		}
	}
	if len(r.Detail) > 0 {
		if _, err := r.Detail.JSON(); err != nil {
			return err
		}
	}
	return nil
}

// canonical returns the canonical bytes of r for every kind. It is not
// exported: only EvidenceBytes and HashEvidence give these bytes out.
func (r Record) canonical() ([]byte, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	b, err := json.Marshal(wire{V: 1, Record: r}, strict...)
	if err != nil {
		return nil, errors.New("event: marshal failed")
	}
	if len(b) > MaxRecordBytes {
		return nil, errors.New("event: record is too large")
	}
	out, err := Canonical(b)
	if err != nil {
		return nil, err
	}
	if len(out) > MaxRecordBytes {
		return nil, errors.New("event: record is too large")
	}
	return out, nil
}

func (r Record) evidence() error {
	ok, err := r.Kind.IsEvidence()
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("event: kind is not an evidence kind")
	}
	return nil
}

// EvidenceBytes returns the canonical bytes of an evidence record. It returns
// an error for request and beacon records and for an unknown kind.
func EvidenceBytes(r Record) ([]byte, error) {
	if err := r.evidence(); err != nil {
		return nil, err
	}
	return r.canonical()
}

// HashEvidence returns the hash of an evidence record. It is the only function
// that hashes a record. It returns an error for request and beacon records
// and for an unknown kind.
func HashEvidence(r Record) ([32]byte, error) {
	b, err := EvidenceBytes(r)
	if err != nil {
		return [32]byte{}, err
	}
	return Hash(b), nil
}

// Row holds the values of a stored event row, with the fingerprint of its
// session row. RecordFromRow makes the record from them.
type Row struct {
	TS        int64    `json:"ts"`
	SessionID *string  `json:"session_id"`
	Kind      string   `json:"kind"`
	Vhost     *string  `json:"vhost"`
	Method    *string  `json:"method"`
	Path      *string  `json:"path"`
	Status    *int64   `json:"status"`
	TrapID    *string  `json:"trap_id"`
	TokenID   *string  `json:"token_id"`
	Surface   *Surface `json:"surface"`
	FP        *FP      `json:"fp"`
	Detail    *string  `json:"detail"`
}

// RecordFromRow makes the record of a stored row, so that a verifier can hash
// it again. It applies all rules of the record.
func RecordFromRow(row Row) (Record, error) {
	k, err := ParseKind(row.Kind)
	if err != nil {
		return Record{}, err
	}
	r := Record{
		TS: row.TS, Session: row.SessionID, Kind: k, Vhost: row.Vhost,
		Method: row.Method, Path: row.Path, Status: row.Status,
		TrapID: row.TrapID, TokenID: row.TokenID, Surface: row.Surface, FP: row.FP,
	}
	if row.Detail != nil {
		if r.Detail, err = ParseDetail(*row.Detail); err != nil {
			return Record{}, err
		}
	}
	if err := r.check(); err != nil {
		return Record{}, err
	}
	return r, nil
}

// Clock gives the time of the sensor.
type Clock func() time.Time

// Input holds the values for one event. The values from a request are
// untrusted. ClientIP and BodyPrefix go to the DB-only part. Forwarded is the
// value of an X-Forwarded-For or Forwarded header: NewEvent ignores it, as the
// record and the DB part never hold a forwarded address.
type Input struct {
	Kind                         Kind
	Session, Vhost, Method, Path string
	TrapID, TokenID              string
	Status                       *int64
	Surface                      Surface
	JA4, H2, Hdr                 string
	Detail                       Detail
	ClientIP, Forwarded          string
	BodyPrefix                   []byte
}

// DBOnly holds the values that only the local database keeps. They are never
// in the record.
type DBOnly struct {
	IP         string
	BodyPrefix []byte
}

// Event is a record with the DB-only values next to it. Record holds the
// value that the DB row and the hashed record both use.
type Event struct {
	Record Record
	DB     DBOnly
	size   int
}

// Size returns the size in bytes of the event: the canonical record, the IP
// text and the body prefix. It is at most MaxEventBytes.
func (e *Event) Size() int { return e.size }

// MaxEventBytes is the largest value of Size.
const MaxEventBytes = maxEventSize

// text makes a request-derived string valid: each byte of an invalid UTF-8
// sequence becomes %XX with upper-case hex. Then it cuts the result at a
// character boundary to max bytes. An empty result is absent (nil). It stops
// reading when the output is long enough, so the work is bounded by max.
func text(s string, max int) *string {
	var b strings.Builder
	for i := 0; i < len(s) && b.Len() < max; {
		r, n := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && n == 1 {
			fmt.Fprintf(&b, "%%%02X", s[i])
		} else {
			b.WriteString(s[i : i+n])
		}
		i += n
	}
	out := b.String()
	if len(out) > max {
		cut := max
		for !utf8.RuneStart(out[cut]) {
			cut--
		}
		out = out[:cut]
	}
	if out == "" {
		return nil
	}
	return &out
}

// NewEvent makes an event from in. ts comes from now (the sensor clock; nil
// means time.Now), never from the request. It returns an error if a rule of
// the record is broken.
func NewEvent(now Clock, in Input) (*Event, error) {
	if now == nil {
		now = time.Now
	}
	if in.Session != "" && in.Kind.isSystem() {
		return nil, errors.New("event: a system kind has no session")
	}
	r := Record{
		TS: now().UnixMilli(), Kind: in.Kind, Session: text(in.Session, capID),
		Vhost: text(in.Vhost, capVhost), Method: text(in.Method, capMethod),
		Path: text(in.Path, capPath), TrapID: text(in.TrapID, capID),
		TokenID: text(in.TokenID, capID), Detail: maps.Clone(in.Detail),
	}
	if in.Status != nil {
		st := *in.Status
		r.Status = &st
	}
	if in.Surface != "" {
		sf := in.Surface
		r.Surface = &sf
	}
	if fp := (FP{text(in.JA4, capFP), text(in.H2, capFP), text(in.Hdr, capFP)}); fp != (FP{}) {
		r.FP = &fp
	}
	db := DBOnly{BodyPrefix: append([]byte(nil), in.BodyPrefix[:min(len(in.BodyPrefix), MaxBodyPrefix)]...)}
	if in.ClientIP != "" {
		a, err := netip.ParseAddr(in.ClientIP)
		if err != nil || a.Zone() != "" {
			return nil, errors.New("event: client IP is not an address")
		}
		db.IP = a.String()
	}
	b, err := r.canonical()
	if err != nil {
		return nil, err
	}
	return &Event{Record: r, DB: db, size: len(b) + len(db.IP) + len(db.BodyPrefix)}, nil
}
