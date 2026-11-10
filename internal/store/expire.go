package store

import (
	"context"
	"database/sql"
	"time"
)

// These statements delete old rows (SEC-39). Each one picks the rowids in a
// subquery with LIMIT, through an index, so a chunk reads no other row.
// deleteEventSQL uses event_ts. deleteTokenSQL uses token_first_cb: a token
// with no callback has a NULL first_cb_at, and it is not deleted. The session
// statement names the four bands, so it uses session_band_last. The counter
// statement uses the primary key, and its cutoff is a UTC date text.
const (
	deleteEventSQL   = "DELETE FROM event WHERE id IN (SELECT id FROM event WHERE ts < ? LIMIT ?)"
	deleteTokenSQL   = "DELETE FROM token WHERE rowid IN (SELECT rowid FROM token WHERE first_cb_at < ? LIMIT ?)"
	deleteSessionSQL = "DELETE FROM session WHERE rowid IN (SELECT rowid FROM session WHERE " +
		"band IN ('human', 'crawler', 'agent-likely', 'agent-confirmed') AND last_seen < ? LIMIT ?)"
	deleteCounterSQL = "DELETE FROM ip_counter WHERE rowid IN (SELECT rowid FROM ip_counter WHERE day < ? LIMIT ?)"
)

// expireCutoff returns the cutoff in unix ms: tDel minus days x 24 h. The
// configuration keeps the days of the events in the range 1 to 90. Outside this
// range, or with a zero tDel, ok is false.
func expireCutoff(tDel time.Time, days int) (cutoff int64, ok bool) {
	if days < 1 || days > 90 || tDel.IsZero() {
		return 0, false
	}
	return tDel.Add(-time.Duration(days) * 24 * time.Hour).UnixMilli(), true
}

// newExpireStep returns the step that runs the delete statement q with the
// cutoff of expireCutoff. Each call deletes at most `limit` rows and returns
// their count. With bad parameters, the step runs no statement and returns an
// error.
func newExpireStep(q string, tDel time.Time, days int) retentionStep {
	cutoff, ok := expireCutoff(tDel, days)
	if !ok {
		return rollupRefused
	}
	return func(ctx context.Context, tx *sql.Tx, limit int) (int, error) {
		return execN(ctx, tx, q, cutoff, limit)
	}
}

// newEventExpireStep deletes the event rows of each kind with ts before the
// cutoff (SEC-39). days is store.retention_days.events.
func newEventExpireStep(tDel time.Time, days int) retentionStep {
	return newExpireStep(deleteEventSQL, tDel, days)
}

// newTokenExpireStep deletes the token rows with first_cb_at before the cutoff
// (SEC-39). days is store.retention_days.events.
func newTokenExpireStep(tDel time.Time, days int) retentionStep {
	return newExpireStep(deleteTokenSQL, tDel, days)
}

// newSessionExpireStep deletes the session rows with last_seen before the
// cutoff (SEC-39). The event rows of a session stay: they go by their own ts.
// days is store.retention_days.events.
func newSessionExpireStep(tDel time.Time, days int) retentionStep {
	return newExpireStep(deleteSessionSQL, tDel, days)
}

// newCounterDeleteStep returns the step that deletes the ip_counter rows with
// day before the UTC date of the cutoff (SEC-39). The cutoff is tDel minus
// `days` x 24 h, with days from store.retention_days.raw. A row of the date of
// the cutoff stays. Each call deletes at most `limit` rows and returns their
// count. With days outside 1 to 30, or a zero tDel, the step runs no statement
// and returns an error.
func newCounterDeleteStep(tDel time.Time, days int) retentionStep {
	cutoff, ok := rollupCutoff(tDel, days)
	if !ok {
		return rollupRefused
	}
	date := time.UnixMilli(cutoff).UTC().Format(dayLayout)
	return func(ctx context.Context, tx *sql.Tx, limit int) (int, error) {
		return execN(ctx, tx, deleteCounterSQL, date, limit)
	}
}
