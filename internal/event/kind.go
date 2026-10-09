package event

import "errors"

var errUnknownKind = errors.New("event: unknown kind")

// Kind is the kind of an event. The set is closed: it has the 8 kinds of the
// event table and no other value. The zero value is not a kind.
type Kind uint8

const (
	KindRequest Kind = iota + 1
	KindCallback
	KindBeacon
	KindScoreChange
	KindBundleLoad
	KindBundleRejected
	KindAlertSent
	KindRetention
)

var kindNames = [...]string{
	KindRequest:        "request",
	KindCallback:       "callback",
	KindBeacon:         "beacon",
	KindScoreChange:    "score_change",
	KindBundleLoad:     "bundle_load",
	KindBundleRejected: "bundle_rejected",
	KindAlertSent:      "alert_sent",
	KindRetention:      "retention",
}

// ParseKind returns the kind with the name s. The match is exact and
// case-sensitive. An unknown name is an error.
func ParseKind(s string) (Kind, error) {
	for k := KindRequest; k <= KindRetention; k++ {
		if kindNames[k] == s {
			return k, nil
		}
	}
	return 0, errUnknownKind
}

func (k Kind) valid() bool { return k >= KindRequest && k <= KindRetention }

// String returns the name of k, or "unknown" for a value that is not a kind.
func (k Kind) String() string {
	if !k.valid() {
		return "unknown"
	}
	return kindNames[k]
}

// MarshalText gives the name of k. A value that is not a kind is an error.
func (k Kind) MarshalText() ([]byte, error) {
	if !k.valid() {
		return nil, errUnknownKind
	}
	return []byte(kindNames[k]), nil
}

// IsEvidence tells if the hash of an event of kind k goes into the log. The
// switch names every kind and has no default result: a value that is not a
// kind is an error, never false.
func (k Kind) IsEvidence() (bool, error) {
	switch k {
	case KindCallback, KindScoreChange, KindAlertSent,
		KindBundleLoad, KindBundleRejected, KindRetention:
		return true, nil
	case KindRequest, KindBeacon:
		return false, nil
	}
	return false, errUnknownKind
}

// isSystem tells if k is a kind that has no session.
func (k Kind) isSystem() bool {
	switch k {
	case KindBundleLoad, KindBundleRejected, KindRetention:
		return true
	}
	return false
}
