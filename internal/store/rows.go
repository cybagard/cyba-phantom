package store

import (
	"context"
	"database/sql"

	"github.com/cybagard/cyba-phantom/internal/event"
)

// The statements are constants. Every value is a bound parameter.
const (
	insertEvent = "INSERT INTO event (ts, session_id, kind, vhost, method, path, status, trap_id, token_id, surface, body_prefix, hash, leaf_index, detail, record) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"

	upsertCounter = "INSERT INTO ip_counter (day, ip_hmac, requests, dropped) VALUES (?, ?, 0, ?) ON CONFLICT(day, ip_hmac) DO UPDATE SET dropped = dropped + excluded.dropped"
)

// insertRow stores one event. It writes each column from the event as
// internal/event made it. A nil pointer is NULL. The client IP goes to no
// column. hash, leaf and record are nil for a bulk event. The body prefix is
// stored only when w.bodyPrefix is true. The caller gives r, the record of e.
func (w *Writer) insertRow(ctx context.Context, stmt *sql.Stmt, e *event.Event, r event.Record, hash, leaf, record any) error {
	var detail, prefix any // nil is NULL
	if len(r.Detail) > 0 {
		b, err := r.Detail.JSON()
		if err != nil {
			return fail(writerName, ruleRecord)
		}
		detail = string(b)
	}
	if w.bodyPrefix {
		if b := e.BodyPrefix(); len(b) > 0 {
			prefix = b
		}
	}
	if _, err := stmt.ExecContext(ctx, r.TS, r.Session, r.Kind.String(), r.Vhost, r.Method, r.Path,
		r.Status, r.TrapID, r.TokenID, r.Surface, prefix, hash, leaf, detail, record); err != nil {
		return fail(writerName, ruleDatabase)
	}
	return nil
}

// countDrops takes the drop counts of the queue and adds each count to the
// dropped column of the row (day, ip_hmac). A new row gets 0 requests. The
// overflow bucket has the fixed ip_hmac text.
func (w *Writer) countDrops(ctx context.Context, tx *sql.Tx, day string) error {
	counts, overflow := w.counters.Snapshot()
	for a, n := range counts {
		if n > 0 {
			if _, err := tx.ExecContext(ctx, upsertCounter, day, w.dk.hmac(a), n); err != nil {
				return fail(writerName, ruleDatabase)
			}
		}
	}
	if overflow > 0 {
		if _, err := tx.ExecContext(ctx, upsertCounter, day, overflowHMAC, overflow); err != nil {
			return fail(writerName, ruleDatabase)
		}
	}
	return nil
}
