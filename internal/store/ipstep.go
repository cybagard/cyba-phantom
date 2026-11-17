package store

import (
	"context"
	"database/sql"
	"time"
)

const (
	// The clear statements set the address of session rows to NULL. Each
	// inner select uses the partial index session_ip_first, so it reads no row
	// that has no address. It takes no row above a rowid. The bounds and the
	// limit are bound values. clearIPSQL takes the rows with first_seen before
	// a cutoff. clearIPFutureSQL takes the rows with first_seen after the
	// future line.
	clearIPSQL = "UPDATE session SET ip = NULL WHERE rowid IN " +
		"(SELECT rowid FROM session INDEXED BY session_ip_first WHERE ip IS NOT NULL AND first_seen < ? AND rowid <= ? LIMIT ?)"
	clearIPFutureSQL = "UPDATE session SET ip = NULL WHERE rowid IN " +
		"(SELECT rowid FROM session INDEXED BY session_ip_first WHERE ip IS NOT NULL AND first_seen > ? AND rowid <= ? LIMIT ?)"

	// topSessionSQL reads the largest rowid of session.
	topSessionSQL = "SELECT coalesce(max(rowid), 0) FROM session"
)

// newIPStep returns the retention step for the raw address (SEC-39). The
// writer puts the session rows of refused events in the session table. Thus the
// step also clears the address of these rows.
//
// Part 1 clears the address of each session with first_seen before the cutoff.
// The cutoff is tPriv minus `days` x 24 h, in unix ms. When part 1 has no row
// left, part 2 clears the address of each session after the future line. A
// first_seen after the line shows a wall clock that was ahead at the write.
//
// The future line is from futureLine: the later of two values, plus 1 h. One
// value is the wall time at the first call of the step, from the function
// `wall`. The other is the meta value retention_check. At its first call, the
// step also reads the largest rowid of session. Both parts change no row above
// that rowid. Thus a row that the writer stores during the run keeps its
// address until the next run. The step ends.
//
// A call changes at most `limit` rows. It takes the rest of `limit` for part 2
// when part 1 ends with fewer rows. It returns the rows that it changed. A
// count below `limit` means that no row is left in either part. The tally of
// the addresses counts the rows of both parts.
//
// Known limits. A run that takes a wall clock that is ahead takes a line that
// is ahead too. Then the rows of that clock keep their addresses. A start with
// the wall clock back and no stored value takes a line that is back. Then the
// rows of an earlier process after that line lose their addresses.
//
// With days outside 1 to 7, a zero tPriv, or no `wall`, the step runs no
// statement. It returns an error. The runner then stops the writer, as for any
// other error of a chunk.
func newIPStep(tPriv time.Time, wall func() time.Time, days int) retentionStep {
	if days < 1 || days > 7 || tPriv.IsZero() || wall == nil {
		return func(context.Context, *sql.Tx, int) (int, error) {
			return 0, fail(writerName, ruleDatabase)
		}
	}
	cutoff := tPriv.Add(-time.Duration(days) * 24 * time.Hour).UnixMilli()
	var begun, future bool
	var line, top int64
	return func(ctx context.Context, tx *sql.Tx, limit int) (int, error) {
		if !begun {
			if err := tx.QueryRowContext(ctx, topSessionSQL).Scan(&top); err != nil {
				return 0, err
			}
			line, begun = futureLine(ctx, tx, wall()), true
		}
		n := 0
		if !future {
			var err error
			if n, err = execCount(ctx, tx, memIP, clearIPSQL, cutoff, top, limit); err != nil || n == limit {
				return n, err
			}
			future = true
		}
		m, err := execCount(ctx, tx, memIP, clearIPFutureSQL, line, top, limit-n)
		return n + m, err
	}
}
