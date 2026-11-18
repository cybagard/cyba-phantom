package event

import (
	"encoding/json/v2"
	"errors"
)

// Encode marshals v with the strict options, then returns Canonical of the
// result. It returns an error if the marshaled text is outside the domain of
// Canonical. It is a test helper: no production code calls it.
func Encode(v any) ([]byte, error) {
	b, err := json.Marshal(v, strict...)
	if err != nil {
		return nil, errors.New("event: marshal failed")
	}
	return Canonical(b)
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

// RecordFromRow is a test helper. It rebuilds the record of a stored row from
// the stored values. It applies all rules of the record. The record of a
// refused row has no session. The session column of that row is not part of
// the record.
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
	if k == KindRefused {
		r.Session = nil
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
