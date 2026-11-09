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

// newIPStep returns the retention step for the raw address (SEC-39). It clears
// the address of each session with first_seen before tPriv minus days days.
// The cutoff is in unix ms. The step reads no clock: tPriv is the only time.
// It covers the session rows of refused events too. They are in the same
// table.
func newIPStep(tPriv time.Time, days int) retentionStep {
	cutoff := tPriv.Add(-time.Duration(days) * 24 * time.Hour).UnixMilli()
	return func(ctx context.Context, tx *sql.Tx, limit int) (int, error) {
		res, err := tx.ExecContext(ctx, clearIPSQL, cutoff, limit)
		if err != nil {
			return 0, err
		}
		n, err := res.RowsAffected()
		return int(n), err
	}
}
