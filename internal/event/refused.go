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
	errRefusedField  = errors.New("event: a refused event has no status, vhost, method, path, trap_id, token_id, surface, session, body prefix or caller detail")
	errReasonKind    = errors.New("event: only a refused event has a reason")
)

// refusedDetail checks the input of a refused event and returns its detail: one
// member, reason. ClientIP and JA4 are allowed. The writer uses them for the
// session id.
func (in Input) refusedDetail() (Detail, error) {
	if !in.Reason.valid() {
		return nil, errRefusedReason
	}
	if in.Status != nil || in.Surface != "" || in.Session != "" || len(in.BodyPrefix) > 0 ||
		in.Vhost != "" || in.Method != "" || in.Path != "" || in.TrapID != "" || in.TokenID != "" ||
		in.Detail != nil {
		return nil, errRefusedField
	}
	return Detail{"reason": Str(in.Reason.String())}, nil
}

// checkRefused tests the rule of a refused record: one detail member, reason,
// with one of the five values, and none of the fields that the kind has no
// value for.
func (r Record) checkRefused() error {
	v, ok := r.Detail["reason"]
	if len(r.Detail) != 1 || !ok || v.tag != 's' {
		return errRefusedReason
	}
	for i := ReasonNoServerName; i <= ReasonRefusedRequest; i++ {
		if v.s == reasonNames[i] {
			if r.Status != nil || r.Surface != nil || r.Session != nil || r.Vhost != nil ||
				r.Method != nil || r.Path != nil || r.TrapID != nil || r.TokenID != nil {
				return errRefusedField
			}
			return nil
		}
	}
	return errRefusedReason
}
