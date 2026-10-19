package event

import "errors"

// RefusedReason tells why the sensor refused a connection. A refused event
// holds one of five values. The zero value is not a reason.
type RefusedReason uint8

const (
	ReasonNoServerName RefusedReason = iota + 1
	ReasonUnknownName
	ReasonBadHello
	ReasonClientAbort
	ReasonRefusedRequest
)

var reasonNames = [...]string{
	ReasonNoServerName:   "no_server_name",
	ReasonUnknownName:    "unknown_name",
	ReasonBadHello:       "bad_hello",
	ReasonClientAbort:    "client_abort",
	ReasonRefusedRequest: "refused_request",
}

func (r RefusedReason) valid() bool {
	return r >= ReasonNoServerName && r <= ReasonRefusedRequest
}

// String returns the name of r, or "unknown" for a value that is not a reason.
func (r RefusedReason) String() string {
	if !r.valid() {
		return "unknown"
	}
	return reasonNames[r]
}

var (
	errRefusedReason = errors.New("event: refused reason is not one of the five values")
	errRefusedDetail = errors.New("event: the detail of a refused event has one member, reason, with a text value")
	errRefusedField  = errors.New("event: a refused record has no status, vhost, method, path, trap_id, token_id, surface, session, fp.h2 or fp.hdr")
	errRefusedInput  = errors.New("event: a refused event has no body prefix and no detail from the caller")
	errReasonKind    = errors.New("event: only a refused event has a reason")
)

// parseReason returns the reason with the name s. The match is exact and
// case-sensitive. An unknown name is an error.
func parseReason(s string) (RefusedReason, error) {
	for r := ReasonNoServerName; r <= ReasonRefusedRequest; r++ {
		if reasonNames[r] == s {
			return r, nil
		}
	}
	return 0, errRefusedReason
}

// refusedDetail checks the reason and the input that has no field in the record
// (the body prefix and the detail). It returns the detail of a refused event:
// one member, reason. checkRefused refuses the other inputs when NewEvent
// builds the record. ClientIP and JA4 are allowed. The writer uses them for the
// session id.
func (in Input) refusedDetail() (Detail, error) {
	if !in.Reason.valid() {
		return nil, errRefusedReason
	}
	if in.Detail != nil || len(in.BodyPrefix) > 0 {
		return nil, errRefusedInput
	}
	return Detail{"reason": Str(in.Reason.String())}, nil
}

// checkRefused tests the rule of a refused record. The record has no status,
// vhost, method, path, trap_id, token_id, surface, session, fp.h2 or fp.hdr.
// The detail has one member, reason, with one of the five values.
func (r Record) checkRefused() error {
	if r.Status != nil || r.Surface != nil || r.Session != nil || r.Vhost != nil ||
		r.Method != nil || r.Path != nil || r.TrapID != nil || r.TokenID != nil ||
		(r.FP != nil && (r.FP.H2 != nil || r.FP.Hdr != nil)) {
		return errRefusedField
	}
	v, ok := r.Detail["reason"]
	if len(r.Detail) != 1 || !ok || v.tag != 's' {
		return errRefusedDetail
	}
	_, err := parseReason(v.s)
	return err
}
