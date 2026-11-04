package store

import (
	"context"
	"database/sql"

	"github.com/cybagard/cyba-phantom/internal/event"
)

// The statements are constants. Every value is a bound parameter. The lookup
// finds the mint rows that can hold a counter. A range has at most 68 tokens,
// so its first counter is in the 68 values up to the counter. The primary key
// (set_id, unit, first) serves the search. The lookup has no NULL filter. A row
// with a NULL session must still count. A NULL session has two sources: the
// mark of a duplicate key, and a render event with no session. Each gives
// "ambiguous". LIMIT 2 is enough to tell one row from many rows. The lookup
// runs for each linked callback, also when the token row exists.
const (
	bumpToken = "UPDATE token SET cb_count = cb_count + 1 WHERE token_id = ?"

	lookupMint = `SELECT session_id, issued_at FROM mint
WHERE set_id = ? AND unit = ? AND first BETWEEN ? - 67 AND ? AND first + count > ?
LIMIT 2`

	// insertToken stores the token row of the first callback. A row with the
	// same token id is not an error. It changes nothing.
	insertToken = "INSERT INTO token (token_id, session_id, trap_id, issued_at, first_cb_at, cb_count) VALUES (?, ?, ?, ?, ?, 1) ON CONFLICT(token_id) DO NOTHING"
)

// UnlinkedCallbacks returns the number of callbacks that the writer could not
// link to a mint row. These are the values of phantom_callback_unlinked_total.
// The reason "none" counts the callbacks with no mint row. It also counts the
// callbacks with one row that has a session and no issued_at. The reason
// "ambiguous" counts the callbacks with two or more mint rows. It also counts
// the callbacks with one row that has a NULL session. The counts hold only
// batches that committed. It is safe to call from any goroutine.
func (w *Writer) UnlinkedCallbacks() (none, ambiguous uint64) {
	return w.unlinkedNone.Load(), w.unlinkedAmbiguous.Load()
}

// tokenCall is a callback row that has a link. The token writer keeps the event
// and its record copy until the end of the batch.
type tokenCall struct {
	e   *event.Event
	rec event.Record
}

// tokenWriter stores the token rows of one transaction. It prepares each
// statement at its first use. none and ambiguous count the callbacks that the
// writer could not link.
type tokenWriter struct {
	tx                   *sql.Tx
	bump, lookup, insert *sql.Stmt
	calls                []tokenCall
	none, ambiguous      uint64
}

func (t *tokenWriter) close() {
	for _, s := range []*sql.Stmt{t.bump, t.lookup, t.insert} {
		if s != nil {
			s.Close()
		}
	}
}

// note keeps the row of a callback event that has a link. The writer calls it
// after the insert of the row. It does not keep a row with no trap id or no
// token id. Such a row cannot give a token row. NewEvent does not make such an
// event.
func (t *tokenWriter) note(e *event.Event, rec event.Record) {
	if _, ok := e.Link(); ok && rec.Kind == event.KindCallback && rec.TrapID != nil && rec.TokenID != nil {
		t.calls = append(t.calls, tokenCall{e, rec})
	}
}

// prepare returns *dst, and prepares the statement first when it is nil.
func (t *tokenWriter) prepare(ctx context.Context, dst **sql.Stmt, query string) (*sql.Stmt, error) {
	if *dst == nil {
		s, err := t.tx.PrepareContext(ctx, query)
		if err != nil {
			return nil, fail(writerName, ruleDatabase)
		}
		*dst = s
	}
	return *dst, nil
}

// run writes the token rows of the kept callbacks in batch order. Each callback
// first runs the lookup, also when its token row exists. When the lookup
// gives one row with a session and issued_at, a token with a row gets one more
// callback. A new token row has the session and issued_at of the one mint
// row. No row, no issued_at, two rows, or a NULL session change no token row.
func (t *tokenWriter) run(ctx context.Context) error {
	for _, c := range t.calls {
		if err := t.one(ctx, c); err != nil {
			return err
		}
	}
	return nil
}

func (t *tokenWriter) one(ctx context.Context, c tokenCall) error {
	link, _ := c.e.Link()
	session, issuedAt, rows, err := t.mintRow(ctx, link)
	if err != nil {
		return err
	}
	switch {
	case rows == 0:
		t.none++
		return nil
	case rows > 1:
		t.ambiguous++
		return nil
	}
	bump, err := t.prepare(ctx, &t.bump, bumpToken)
	if err != nil {
		return err
	}
	res, err := bump.ExecContext(ctx, *c.rec.TokenID)
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
	ins, err := t.prepare(ctx, &t.insert, insertToken)
	if err != nil {
		return err
	}
	if _, err := ins.ExecContext(ctx, *c.rec.TokenID, session, *c.rec.TrapID, issuedAt, c.rec.TS); err != nil {
		return fail(writerName, ruleDatabase)
	}
	return nil
}

// mintRow looks up the mint rows of a link. It returns 0 for none, 2 for
// ambiguous, and 1 with the session and issued_at of the one usable row.
func (t *tokenWriter) mintRow(ctx context.Context, l event.CallbackLink) (session string, issuedAt int64, rows int, err error) {
	stmt, err := t.prepare(ctx, &t.lookup, lookupMint)
	if err != nil {
		return "", 0, 0, err
	}
	c := int64(l.Counter)
	rs, err := stmt.QueryContext(ctx, l.SetID[:], int64(l.Unit), c, c, c)
	if err != nil {
		return "", 0, 0, fail(writerName, ruleDatabase)
	}
	defer rs.Close()
	var s sql.NullString
	var at sql.NullInt64
	for rs.Next() {
		if err := rs.Scan(&s, &at); err != nil {
			return "", 0, 0, fail(writerName, ruleDatabase)
		}
		rows++
	}
	if rs.Err() != nil {
		return "", 0, 0, fail(writerName, ruleDatabase)
	}
	// A NULL session gives ambiguous from each source. The sources are the mark
	// of a duplicate key and a render event with no session. A row with a
	// session and no issued_at gives no link. Only a changed database has such
	// a row.
	switch {
	case rows > 1:
		return "", 0, 2, nil
	case rows == 1 && !s.Valid:
		return "", 0, 2, nil
	case rows == 1 && !at.Valid:
		return "", 0, 0, nil
	}
	return s.String, at.Int64, rows, nil
}
