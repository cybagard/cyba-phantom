package store

import (
	"context"
	"database/sql"
	"time"
)

// clearIPSQL sets the address of old session rows to NULL. The inner select
// uses the partial index session_ip_first, so it reads no row that has no
// address. The cutoff and the limit are bound values.
const clearIPSQL = "UPDATE session SET ip = NULL WHERE rowid IN (SELECT rowid FROM session WHERE ip IS NOT NULL AND first_seen < ? LIMIT ?)"

// clearIPSegSQL is clearIPSQL for the rows of one rowid segment. The index
// stays the same. Its entries hold the rowid, so the segment test reads no row.
const clearIPSegSQL = "UPDATE session SET ip = NULL WHERE rowid IN (SELECT rowid FROM session INDEXED BY session_ip_first " +
	"WHERE ip IS NOT NULL AND first_seen < ? AND rowid BETWEEN ? AND ? LIMIT ?)"

var ipCorrection = &correction{sessionRows, clearIPSegSQL}

// newIPStep returns the retention step for the raw address (SEC-39). It clears
// the address of each session with first_seen before S minus `days` x 24 h. The
// caller gives S as tPriv. The cutoff is in unix ms. The step reads no clock.
// The writer puts the session rows of refused events in the session table.
// Thus the step also clears the address of these rows.
//
// A session row in a session range of a clock_jump row has first_seen with the
// correction of that row (ADR-043). The step reads each rowid segment with its
// own cutoff. See rowKind.segments.
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
	return func(ctx context.Context, tx *sql.Tx, limit int) (int, error) {
		return ipCorrection.exec(ctx, tx, memIP, clearIPSQL, cutoff, limit)
	}
}
