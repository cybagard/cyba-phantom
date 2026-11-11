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

// The configuration keeps the days of the events in the range 1 to 90.
const expireMaxDays = 90

// This is the cost of one deleted session row. A row has a random ip_hmac and
// four fingerprint columns. Each delete touches a random page of the ip_hmac
// index. A chunk of 1 000 such rows took 195 ms at 4 million rows, over the
// 100 ms of SEC-39. Thus a chunk takes at most limit / cost rows.
const sessionExpireCost = 4

// newExpireStep returns the step that runs the delete statement q with the
// cutoff for days. A row costs `cost` of the limit, as in the roll-up step.
// Each call deletes at most limit / cost rows. It returns `limit` when it took
// the most rows, and cost x rows otherwise. With a limit below the cost, it
// runs no statement and returns `limit`. With bad parameters, the step runs no
// statement and returns an error.
func newExpireStep(q string, cost int, tDel time.Time, days int) retentionStep {
	cutoff, ok := retentionCutoff(tDel, days, expireMaxDays)
	if !ok {
		return rollupRefused
	}
	return func(ctx context.Context, tx *sql.Tx, limit int) (int, error) {
		most := limit / cost
		if most == 0 {
			return limit, nil
		}
		n, err := execN(ctx, tx, q, cutoff, most)
		if err != nil {
			return 0, err
		}
		if n == most {
			return limit, nil
		}
		return cost * n, nil
	}
}

// newEventExpireStep deletes the event rows of each kind with ts before the
// cutoff (SEC-39). days is store.retention_days.events.
func newEventExpireStep(tDel time.Time, days int) retentionStep {
	return newExpireStep(deleteEventSQL, 1, tDel, days)
}

// newTokenExpireStep deletes the token rows with first_cb_at before the cutoff
// (SEC-39). days is store.retention_days.events.
func newTokenExpireStep(tDel time.Time, days int) retentionStep {
	return newExpireStep(deleteTokenSQL, 1, tDel, days)
}

// newSessionExpireStep deletes the session rows with last_seen before the
// cutoff (SEC-39). The event rows of a session stay: they go by their own ts.
// days is store.retention_days.events.
func newSessionExpireStep(tDel time.Time, days int) retentionStep {
	return newExpireStep(deleteSessionSQL, sessionExpireCost, tDel, days)
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
