package store

import (
	"context"
	"database/sql"
	"math"
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

	// deleteEventIDsSQL deletes the event rows of a JSON array of rowids. The
	// cursor reads of the event delete and of the raw delete give the rowids.
	deleteEventIDsSQL = "DELETE FROM event WHERE id IN (SELECT value FROM json_each(?))"

	// deleteJumpSQL deletes each clock_jump row that holds no row. Its event
	// range has no event row, and its session range has no session row. A range
	// with its start after its end holds no row. Each probe is a rowid search.
	deleteJumpSQL = "DELETE FROM clock_jump WHERE id IN (SELECT id FROM clock_jump AS c WHERE " +
		"NOT EXISTS (SELECT 1 FROM event WHERE id BETWEEN c.event_from AND c.event_to) AND " +
		"NOT EXISTS (SELECT 1 FROM session WHERE rowid BETWEEN c.session_from AND c.session_to) LIMIT ?)"
)

// eventRead is the cursor read of the event delete. It uses event_ts.
var eventRead = cursorRead("event", "id", "ts", "event_ts", "", "")

// The configuration keeps the days of the events in the range 1 to 90.
const expireMaxDays = 90

// This is the cost of one deleted session row. A row has a random ip_hmac and
// four fingerprint columns. At 4 million such rows, a chunk of 1 000 rows took
// more than the 100 ms of SEC-39. Thus a chunk takes at most limit / cost rows.
const sessionExpireCost = 4

// newExpireStep returns the step that runs the delete statement q with the
// cutoff for days. A row costs `cost` of the limit, as in the roll-up step.
// Each call deletes at most limit / cost rows. It returns `limit` when it took
// the most rows, and cost x rows otherwise. With a limit below the cost, it
// runs no statement and returns `limit`. With bad parameters, the step runs no
// statement and returns an error.
func newExpireStep(q string, cost int, tDel time.Time, days int) retentionStep {
	return newGatedExpireStep(q, cost, tDel, days, nil)
}

// newGatedExpireStep is newExpireStep with a gate. The gate gets the cutoff
// of each chunk, in the transaction of the chunk. It returns the cutoff that
// the chunk uses. A nil gate keeps the cutoff.
func newGatedExpireStep(q string, cost int, tDel time.Time, days int,
	gate func(context.Context, *sql.Tx, int64) (int64, error)) retentionStep {
	cutoff, ok := retentionCutoff(tDel, days, expireMaxDays)
	if !ok {
		return rollupRefused
	}
	return func(ctx context.Context, tx *sql.Tx, limit int) (int, error) {
		most := limit / cost
		if most == 0 {
			return limit, nil
		}
		cut := cutoff
		if gate != nil {
			var err error
			if cut, err = gate(ctx, tx, cutoff); err != nil {
				return 0, err
			}
		}
		n, err := execCount(ctx, tx, memDeleted, q, cut, most)
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
// cutoff (SEC-39). days is store.retention_days.events. The day step has a day
// in progress or a next day (see rollupWorkDay). A chunk keeps each row with a
// stored ts at or after the start of that day. This holds for each sum of j.
// The day step can stop early with a request row left. When it has no such
// day, the chunk has no start to keep.
//
// With no clock_jump range, the step runs the plain statement with the cutoff
// capped at that start. The behavior is the same as before the correction.
// With a range, the step reads event_ts after a cursor (see corrected). A row
// in an event range of a clock_jump row has its ts with the correction of that
// row (ADR-043). The read ends at the cutoff minus the smallest sum, or at that
// start, whichever is earlier.
func newEventExpireStep(tDel time.Time, days int) retentionStep {
	plain := newGatedExpireStep(deleteEventSQL, 1, tDel, days, eventGate)
	cutoff, ok := retentionCutoff(tDel, days, expireMaxDays)
	if !ok {
		return plain
	}
	return (&corrected{
		kind: eventRows, cutoff: cutoff, plain: plain, act: deleteEventIDsSQL, mem: memDeleted,
		gate: func(ctx context.Context, tx *sql.Tx) (int64, error) {
			return eventGate(ctx, tx, math.MaxInt64)
		},
		reads: []*indexRead{newIndexRead(eventRead)},
	}).step()
}

// eventGate returns the earlier of the cutoff and the start of the day of
// rollupWorkDay.
func eventGate(ctx context.Context, tx *sql.Tx, cutoff int64) (int64, error) {
	start, ok, err := rollupWorkDay(ctx, tx)
	if err != nil || !ok {
		return cutoff, err
	}
	return min(cutoff, start), nil
}

// newTokenExpireStep deletes the token rows with first_cb_at before the cutoff
// (SEC-39). days is store.retention_days.events. A token row has no rowid
// range in clock_jump, so its cutoff is S minus the days, with no correction.
func newTokenExpireStep(tDel time.Time, days int) retentionStep {
	return newExpireStep(deleteTokenSQL, 1, tDel, days)
}

// newSessionExpireStep deletes the session rows with last_seen before the
// cutoff (SEC-39). The event rows of a session stay: they go by their own ts.
// days is store.retention_days.events. The step makes no clock_jump correction.
// A session seen again after a jump has a correct last_seen. The correction
// needs a test of last_seen against the time of the jump. No code makes it.
func newSessionExpireStep(tDel time.Time, days int) retentionStep {
	return newExpireStep(deleteSessionSQL, sessionExpireCost, tDel, days)
}

// newJumpExpireStep returns the step that deletes the clock_jump rows with no
// row in their two ranges (ADR-043). The schedule puts it after the event and
// session deletes. Each call deletes at most `limit` rows and returns their
// count. A count below `limit` means that no such row is left.
func newJumpExpireStep() retentionStep {
	return func(ctx context.Context, tx *sql.Tx, limit int) (int, error) {
		return execCount(ctx, tx, memDeleted, deleteJumpSQL, limit)
	}
}

// newCounterDeleteStep returns the step that deletes the ip_counter rows with
// day before the UTC date of the cutoff (SEC-39). The cutoff is S minus `days`
// x 24 h, with days from store.retention_days.raw. The caller gives S as tDel.
// A row of the date of the cutoff stays. An ip_counter row has no rowid range
// in clock_jump, so it has no correction. Each call deletes at most `limit`
// rows and returns their count. With days outside 1 to 30, or a zero tDel, the
// step runs no statement and returns an error.
func newCounterDeleteStep(tDel time.Time, days int) retentionStep {
	cutoff, ok := rollupCutoff(tDel, days)
	if !ok {
		return rollupRefused
	}
	date := time.UnixMilli(cutoff).UTC().Format(dayLayout)
	return func(ctx context.Context, tx *sql.Tx, limit int) (int, error) {
		return execCount(ctx, tx, memDeleted, deleteCounterSQL, date, limit)
	}
}
