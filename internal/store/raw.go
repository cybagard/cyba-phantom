package store

import (
	"context"
	"database/sql"
	"math"
	"strconv"
	"time"

	"github.com/cybagard/cyba-phantom/internal/event"
	"github.com/cybagard/cyba-phantom/internal/token"
)

const (
	// retentionCheckKey is the meta key of the wall time of the last hourly
	// check, in unix ms as decimal text. The field clear only reads it.
	retentionCheckKey = "retention_check"

	// rawIndexWhere is the WHERE text of event_raw_ts (migration 0005). The
	// clear statements repeat it in the same order. Then the index can serve.
	rawIndexWhere = "body_prefix IS NOT NULL OR detail IS NOT NULL OR record IS NOT NULL"

	// The clear statements set the three fields to NULL on at most a bound of
	// rows. The subquery picks the rows in ts order from event_raw_ts, and no
	// row above a rowid. Each picked row has a field. A cleared row leaves the
	// index. clearPastSQL takes the rows with ts before a cutoff.
	// clearFutureSQL takes the rows with ts after the future line.
	clearPastSQL = "UPDATE event SET body_prefix = NULL, detail = NULL, record = NULL WHERE id IN " +
		"(SELECT id FROM event INDEXED BY event_raw_ts WHERE ts < ? AND id <= ? AND (" + rawIndexWhere + ") " +
		"ORDER BY ts LIMIT ?)"
	clearFutureSQL = "UPDATE event SET body_prefix = NULL, detail = NULL, record = NULL WHERE id IN " +
		"(SELECT id FROM event INDEXED BY event_raw_ts WHERE ts > ? AND id <= ? AND (" + rawIndexWhere + ") " +
		"ORDER BY ts LIMIT ?)"

	// clearTopSQL reads the largest event id.
	clearTopSQL = "SELECT coalesce(max(id), 0) FROM event"

	// deleteRawSQL deletes old rows of the kinds that have no roll-up. It uses
	// event_kind_ts.
	deleteRawSQL = "DELETE FROM event WHERE id IN (SELECT id FROM event WHERE kind IN ('refused', 'beacon') AND ts < ? LIMIT ?)"

	// The mint statements use the primary key. mintNextSQL finds the next
	// set_id after a position. mintUnitSQL finds the oldest unit of a set_id
	// in a range. mintCountSQL counts the rows of a unit, at most a bound.
	// mintDropSQL deletes all rows of a unit. mintDeleteSQL deletes the first
	// rows of a unit, in the order of the primary key.
	mintNextSQL   = "SELECT set_id FROM mint WHERE set_id > ? ORDER BY set_id LIMIT 1"
	mintUnitSQL   = "SELECT unit FROM mint WHERE set_id = ? AND unit BETWEEN ? AND ? ORDER BY unit LIMIT 1"
	mintCountSQL  = "SELECT count(*) FROM (SELECT 1 FROM mint WHERE set_id = ? AND unit = ? LIMIT ?)"
	mintDropSQL   = "DELETE FROM mint WHERE set_id = ? AND unit = ?"
	mintDeleteSQL = "DELETE FROM mint WHERE (set_id, unit, first) IN " +
		"(SELECT set_id, unit, first FROM mint WHERE set_id = ? AND unit = ? ORDER BY first LIMIT ?)"
)

// futureLine returns the future line in unix ms. It is the later of the wall
// time and the meta value retention_check, plus 1 h. No value, a value that
// does not parse, or a failed read gives the wall time alone. A line past the
// largest ms is the largest ms, so that it never clears a row by overflow.
func futureLine(ctx context.Context, tx *sql.Tx, wall time.Time) int64 {
	at := wall.UnixMilli()
	if text, found, err := metaGet(ctx, tx, retentionCheckKey); err == nil && found {
		if v, err := strconv.ParseInt(text, 10, 64); err == nil {
			at = max(at, v)
		}
	}
	hour := time.Hour.Milliseconds()
	if at > math.MaxInt64-hour {
		return math.MaxInt64
	}
	return at + hour
}

// newFieldClearStep returns the step that sets body_prefix, detail and record
// to NULL (SEC-39). It reads the rows of the index event_raw_ts. It has no
// mark and no position, and it writes no meta key. A cleared row leaves the
// index, so the next call does not read it again.
//
// Part 1 clears the rows with ts before the cutoff, in ts order. The cutoff
// is tPriv minus `days` x 24 h, in unix ms. When part 1 has no row left, part 2
// clears the rows with ts after the future line. A ts after the line shows a
// wall clock that was ahead when the row was written.
//
// The future line is the later of two values, plus 1 h. One value is the wall
// time at the first call of the step, from the function `wall`. The other is
// the meta value retention_check. See futureLine. At its first call, the step
// also reads the largest event id. Both parts change no row above that id.
// Thus a row that a batch writes during the run keeps its fields until the
// next run. The step ends.
//
// Each statement names INDEXED BY event_raw_ts. It repeats the WHERE text of
// the index in the same order. A call changes at most `limit` rows. It takes
// the rest of `limit` for part 2 when part 1 ends with fewer rows. It returns
// the rows that it changed. A count below `limit` means that no row is left in
// either part. The tally of the fields counts the rows of both parts.
//
// Known limits. A run that takes a wall clock that is ahead takes a line that
// is ahead too. Then the rows of that clock keep their fields. A start with
// the wall clock back and no stored value takes a line that is back. Then the
// rows of an earlier process after that line lose their fields. The wall
// clock can step back by more than 1 h in a process. Then the next run also
// takes a line that is back. With no stored value, the next run clears the
// rows younger than the step minus 1 h. With a stored value, the rows up to
// that value plus 1 h keep their fields.
//
// With days outside 1 to 30, a zero tPriv, or no `wall`, the step runs no
// statement. It returns an error.
func newFieldClearStep(tPriv time.Time, wall func() time.Time, days int) retentionStep {
	cutoff, ok := rollupCutoff(tPriv, days)
	if !ok || wall == nil {
		return rollupRefused
	}
	var begun, future bool
	var line, top int64
	return func(ctx context.Context, tx *sql.Tx, limit int) (int, error) {
		if !begun {
			if err := tx.QueryRowContext(ctx, clearTopSQL).Scan(&top); err != nil {
				return 0, err
			}
			line, begun = futureLine(ctx, tx, wall()), true
		}
		n := 0
		if !future {
			var err error
			if n, err = execCount(ctx, tx, memFields, clearPastSQL, cutoff, top, limit); err != nil || n == limit {
				return n, err
			}
			future = true
		}
		m, err := execCount(ctx, tx, memFields, clearFutureSQL, line, top, limit-n)
		return n + m, err
	}
}

// newRawDeleteStep returns the step that deletes the refused and beacon rows
// with ts before the cutoff (SEC-39). The cutoff is tDel minus `days` x 24 h.
// It rolls up no row. It reads no clock. Each call deletes at most `limit`
// rows and returns their count. With days outside 1 to 30, or a zero tDel, the
// step runs no statement and returns an error.
func newRawDeleteStep(tDel time.Time, days int) retentionStep {
	cutoff, ok := rollupCutoff(tDel, days)
	if !ok {
		return rollupRefused
	}
	return func(ctx context.Context, tx *sql.Tx, limit int) (int, error) {
		return execCount(ctx, tx, memDeleted, deleteRawSQL, cutoff, limit)
	}
}

// mintRanges returns the unit ranges, both ends included, of the units before
// the unit cu. A unit is before cu when cu minus the unit is above 0. The
// difference is modulo 2^20, read as a signed 20-bit value (ADR-036 decision
// 2). These are the 2^19 - 1 units just before cu. The range can wrap, and it
// is then in two parts. The older part is first.
func mintRanges(cu uint32) [][2]int64 {
	const mask = event.MintUnitLimit - 1
	lo, hi := (int64(cu)-(event.MintUnitLimit/2-1))&mask, (int64(cu)-1)&mask
	if lo <= hi {
		return [][2]int64{{lo, hi}}
	}
	return [][2]int64{{lo, mask}, {0, hi}}
}

// mintNone is the mint step of a cutoff before the token epoch. It deletes no
// row.
func mintNone(context.Context, *sql.Tx, int) (int, error) { return 0, nil }

// newMintStep returns the step that deletes the mint rows of the units before
// the cutoff unit (SEC-39, ADR-038). The cutoff unit is the unit of tDel minus
// `days` x 24 h. A cutoff before the token epoch gives a step that deletes no
// row. Units are modulo 2^20, so such a cutoff can read as a cutoff ahead of
// the rows. Then young rows go.
//
// The step works for each set_id in turn. It keeps the position of the set_id
// in memory. For each set_id and each range of mintRanges, oldest unit first,
// it finds the next unit. It counts the rows of the unit, at most one more
// than the rows that the call can still delete. A unit that fits is deleted
// whole, in one statement. A unit that does not fit is not deleted. The call
// then returns `limit`. The next chunk starts the step again with a full
// limit. A call with a full limit deletes the first rows of a unit that does
// not fit. It uses the order of the primary key. All statements use the
// primary key (set_id, unit, first).
//
// The rows of one unit go in one statement. Thus two rows that cover one
// counter go together, or stay together. The exception is a unit with more
// rows than one chunk (1 000). Its rows go in two or more chunks. Between two
// commits, a callback can find one of the rows. This is the known limit.
//
// One call can read each set_id that has no row to delete. The bound is the
// count of set_ids, one for each bundle (event.MintRange).
//
// A call returns `limit` when it can have rows left, and the rows that it
// deleted otherwise. With days outside 1 to 30, or a zero tDel, the step runs
// no statement and returns an error.
func newMintStep(tDel time.Time, days int) retentionStep {
	cutoff, ok := rollupCutoff(tDel, days)
	if !ok {
		return rollupRefused
	}
	if time.UnixMilli(cutoff).Before(token.Epoch()) {
		return mintNone
	}
	ranges := mintRanges(token.Unit(time.UnixMilli(cutoff)))
	// A text is below each blob, so it is before the first set_id.
	var set any = ""
	return func(ctx context.Context, tx *sql.Tx, limit int) (int, error) {
		left := limit
		for {
			var next []byte
			found, err := scanOne(tx.QueryRowContext(ctx, mintNextSQL, set), &next)
			if err != nil || !found {
				return limit - left, err
			}
			for _, r := range ranges {
				for {
					var unit int64
					found, err := scanOne(tx.QueryRowContext(ctx, mintUnitSQL, next, r[0], r[1]), &unit)
					if err != nil || !found {
						if err != nil {
							return 0, err
						}
						break
					}
					var rows int
					if err := tx.QueryRowContext(ctx, mintCountSQL, next, unit, left+1).Scan(&rows); err != nil {
						return 0, err
					}
					if rows <= left {
						if _, err := execCount(ctx, tx, memDeleted, mintDropSQL, next, unit); err != nil {
							return 0, err
						}
						if left -= rows; left == 0 {
							return limit, nil
						}
						continue
					}
					if left < chunkRows {
						return limit, nil
					}
					if _, err := execCount(ctx, tx, memDeleted, mintDeleteSQL, next, unit, left); err != nil {
						return 0, err
					}
					return limit, nil
				}
			}
			set = next
		}
	}
}
