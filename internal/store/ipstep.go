package store

import (
	"context"
	"database/sql"
	"time"
)

// clearIPSQL sets the address of old session rows to NULL. The inner select
// uses the partial index session_ip_first, so it reads no row that has no
// address. It takes no row above a rowid. The cutoff, the rowid and the limit
// are bound values.
const clearIPSQL = "UPDATE session SET ip = NULL WHERE rowid IN " +
	"(SELECT rowid FROM session INDEXED BY session_ip_first WHERE ip IS NOT NULL AND first_seen < ? AND rowid <= ? LIMIT ?)"

// clearIPIDsSQL clears the address of the session rows of a JSON array of
// rowids. The cursor read ipRead gives the rowids. The read uses the index
// session_ip_first, and `ip IS NOT NULL` is the WHERE text of that index. The
// read has the bound of the rowid as its tail term.
const clearIPIDsSQL = "UPDATE session SET ip = NULL WHERE rowid IN (SELECT value FROM json_each(?))"

// topSessionSQL reads the largest session rowid.
const topSessionSQL = "SELECT coalesce(max(rowid), 0) FROM session"

var ipRead = cursorRead("session", "rowid", "first_seen", "session_ip_first", "ip IS NOT NULL AND ", " AND rowid <= ?")

// newIPStep returns the retention step for the raw address (SEC-39). It clears
// the address of each session with first_seen before S minus `days` x 24 h. The
// caller gives S as tPriv. The cutoff is in unix ms. The step reads no clock.
// The writer puts the session rows of refused events in the session table.
// Thus the step also clears the address of these rows.
//
// At its first call, the step reads the largest session rowid. It changes no
// row above that rowid. Thus a row that the writer stores during the run keeps
// its address until the next run. The step ends.
//
// With no clock_jump range, the step runs the plain statement. With a range, it
// reads session_ip_first after a cursor (see corrected). A session row in a
// session range of a clock_jump row has first_seen with the correction of that
// row (ADR-043). Each read keeps the bound. In that case, a call returns the
// entries that it read.
//
// The configuration keeps `days` in the range 1 to 7. Outside this range, or
// with a zero tPriv, the step runs no statement and returns an error. The
// runner then stops the writer, as for any other error of a chunk.
func newIPStep(tPriv time.Time, days int) retentionStep {
	if days < 1 || days > 7 || tPriv.IsZero() {
		return func(context.Context, *sql.Tx, int) (int, error) {
			return 0, fail(writerName, ruleDatabase)
		}
	}
	cutoff := tPriv.Add(-time.Duration(days) * 24 * time.Hour).UnixMilli()
	var begun bool
	var top int64
	read := newIndexRead(ipRead)
	step := (&corrected{
		kind: sessionRows, cutoff: cutoff, act: clearIPIDsSQL, mem: memIP, reads: []*indexRead{read},
		plain: func(ctx context.Context, tx *sql.Tx, limit int) (int, error) {
			return execCount(ctx, tx, memIP, clearIPSQL, cutoff, top, limit)
		},
	}).step()
	return func(ctx context.Context, tx *sql.Tx, limit int) (int, error) {
		if !begun {
			if err := tx.QueryRowContext(ctx, topSessionSQL).Scan(&top); err != nil {
				return 0, err
			}
			begun = true
			read.tail = []any{top}
		}
		return step(ctx, tx, limit)
	}
}
