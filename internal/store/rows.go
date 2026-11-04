package store

import (
	"context"
	"database/sql"

	"github.com/cybagard/cyba-phantom/internal/event"
	"github.com/cybagard/cyba-phantom/internal/session"
)

// The statements are constants. Every value is a bound parameter.
const (
	insertEvent = "INSERT INTO event (ts, session_id, kind, vhost, method, path, status, trap_id, token_id, surface, body_prefix, hash, leaf_index, detail, record) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"

	// insertMint stores one mint row. A row with the same key is not an error.
	// It changes nothing.
	insertMint = "INSERT INTO mint (set_id, unit, first, count, session_id, issued_at) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING"

	// clearMint marks a mint row whose key was written twice. Two renders took
	// the counters of the row, so its session is not known.
	clearMint = "UPDATE mint SET session_id = NULL WHERE set_id = ? AND unit = ? AND first = ?"

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

// mintWriter stores the mint rows of one transaction. It prepares the statement
// at the first range, and the mark statement at the first duplicate. dups
// counts the rows that the table already had.
type mintWriter struct {
	tx         *sql.Tx
	stmt, mark *sql.Stmt
	dups       uint64
}

// MintDuplicates returns the number of mint rows that the writer did not store.
// The table already had their key (set_id, unit, first). The row that the table
// kept gets a NULL session. A duplicate is not an error. The count holds only
// batches that committed. It is safe to call from any goroutine.
func (w *Writer) MintDuplicates() uint64 { return w.mintDups.Load() }

func (m *mintWriter) close() {
	for _, s := range []*sql.Stmt{m.stmt, m.mark} {
		if s != nil {
			s.Close()
		}
	}
}

// add stores the mint row of a request row that has a range, in the
// transaction of the event row. The row has the session of the stored row, or
// NULL. It holds no token text and no token id. A range that passes 2^42 gives
// two rows: the end of the counter space, and the rest from 0.
func (m *mintWriter) add(ctx context.Context, e *event.Event, r event.Record) error {
	rng, ok := e.Mint()
	if !ok || r.Kind != event.KindRequest {
		return nil
	}
	if m.stmt == nil {
		stmt, err := m.tx.PrepareContext(ctx, insertMint)
		if err != nil {
			return fail(writerName, ruleDatabase)
		}
		m.stmt = stmt
	}
	first, count := rng.First, uint64(rng.Count)
	if head := event.MintCounterLimit - first; count > head {
		if err := m.exec(ctx, rng, r, first, head); err != nil {
			return err
		}
		first, count = 0, count-head
	}
	return m.exec(ctx, rng, r, first, count)
}

func (m *mintWriter) exec(ctx context.Context, rng event.MintRange, r event.Record, first, count uint64) error {
	res, err := m.stmt.ExecContext(ctx, rng.SetID[:], int64(rng.Unit), int64(first), int64(count), r.Session, rng.IssuedAt)
	if err != nil {
		return fail(writerName, ruleDatabase)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fail(writerName, ruleDatabase)
	}
	if n > 0 {
		return nil
	}
	m.dups++
	if m.mark == nil {
		stmt, err := m.tx.PrepareContext(ctx, clearMint)
		if err != nil {
			return fail(writerName, ruleDatabase)
		}
		m.mark = stmt
	}
	if _, err := m.mark.ExecContext(ctx, rng.SetID[:], int64(rng.Unit), int64(first)); err != nil {
		return fail(writerName, ruleDatabase)
	}
	return nil
}

// countDrops takes the drop counts of the queue and adds each count to the
// dropped column of the row (day, ip_hmac). A new row gets 0 requests. The
// overflow bucket has the fixed ip_hmac text.
func (w *Writer) countDrops(ctx context.Context, tx *sql.Tx, day string, key session.Key) error {
	counts, overflow := w.counters.Snapshot()
	for a, n := range counts {
		if n > 0 {
			if _, err := tx.ExecContext(ctx, upsertCounter, day, key.IPHMAC(a), n); err != nil {
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
