package store

import (
	"context"
	"database/sql"
	"time"

	"github.com/cybagard/cyba-phantom/internal/event"
	"github.com/cybagard/cyba-phantom/internal/token"
)

const (
	// rawIndexWhere is the WHERE text of event_raw_ts (migration 0005). The
	// clear statements repeat it in the same order. Then the index can serve.
	rawIndexWhere = "body_prefix IS NOT NULL OR detail IS NOT NULL OR record IS NOT NULL"

	// The plain clear statements set the three fields to NULL on at most a
	// bound of rows. The subquery picks the rows in ts order from
	// event_raw_ts, and no row above a rowid. Each picked row has a field. A
	// cleared row leaves the index. clearPastSQL takes the rows with ts before
	// a cutoff. The corrected path reads the index in the cursor read
	// clearRead, and clearIDsSQL clears the rows that it picks.
	clearPastSQL = "UPDATE event SET body_prefix = NULL, detail = NULL, record = NULL WHERE id IN " +
		"(SELECT id FROM event INDEXED BY event_raw_ts WHERE ts < ? AND id <= ? AND (" + rawIndexWhere + ") " +
		"ORDER BY ts LIMIT ?)"

	// clearIDsSQL clears the three fields of the rows of a JSON array of
	// rowids. The cursor read gives the rowids.
	clearIDsSQL = "UPDATE event SET body_prefix = NULL, detail = NULL, record = NULL WHERE id IN " +
		"(SELECT value FROM json_each(?))"

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

// The cursor reads of the field clear and of the raw delete. The clear read
// has two terms after the time terms. They are the bound `top` and the WHERE
// text of event_raw_ts. The raw read has the kind as its lead term. A kind is
// one of rawKinds, which are the kinds of deleteRawSQL.
var (
	clearRead = cursorRead("event", "id", "ts", "event_raw_ts", "", " AND id <= ? AND ("+rawIndexWhere+")")
	rawRead   = cursorRead("event", "id", "ts", "event_kind_ts", "kind = ? AND ", "")
	rawKinds  = []string{"refused", "beacon"}
)

// newFieldClearStep returns the step that sets body_prefix, detail and record
// to NULL (SEC-39). It reads the rows of the index event_raw_ts. It has no
// mark and no position, and it writes no meta key. A cleared row leaves the
// index, so the next call does not read it again.
//
// The step clears the rows with ts before the cutoff, in ts order. The cutoff
// is tPriv minus `days` x 24 h, in unix ms. At its first call, the step reads
// the largest event id. It changes no row above that id. Thus a row that a
// batch writes during the run keeps its fields until the next run. The step
// ends.
//
// The plain statement names INDEXED BY event_raw_ts. It repeats the WHERE text
// of the index in the same order. A call changes at most `limit` rows. With
// the plain statement, it returns the rows that it changed. A count below
// `limit` means that no row is left.
//
// With no clock_jump range, the step runs the plain statement. With a range, it
// reads event_raw_ts after a cursor (see corrected). A row in an event range of
// a clock_jump row has its ts with the correction of that row (ADR-043). Each
// read keeps the bound `top`. In that case, a call returns the entries that it
// read, not the rows that it changed.
//
// With days outside 1 to 30, or a zero tPriv, the step runs no statement. It
// returns an error.
func newFieldClearStep(tPriv time.Time, days int) retentionStep {
	cutoff, ok := rollupCutoff(tPriv, days)
	if !ok {
		return rollupRefused
	}
	var begun bool
	var top int64
	read := newIndexRead(clearRead)
	past := (&corrected{
		kind: eventRows, cutoff: cutoff, act: clearIDsSQL, mem: memFields, reads: []*indexRead{read},
		plain: func(ctx context.Context, tx *sql.Tx, limit int) (int, error) {
			return execCount(ctx, tx, memFields, clearPastSQL, cutoff, top, limit)
		},
	}).step()
	return func(ctx context.Context, tx *sql.Tx, limit int) (int, error) {
		if !begun {
			if err := tx.QueryRowContext(ctx, clearTopSQL).Scan(&top); err != nil {
				return 0, err
			}
			begun = true
			read.tail = []any{top}
		}
		return past(ctx, tx, limit)
	}
}

// newRawDeleteStep returns the step that deletes the refused and beacon rows
// with ts before the cutoff (SEC-39). The cutoff is tDel minus `days` x 24 h.
// With days = 1, the DB cap sets the cutoff to the end of a UTC day (see
// dayCut). It rolls up no row. It reads no clock. Each call deletes at most
// `limit` rows and returns their count. With days outside 1 to 30, or a zero
// tDel, the step runs no statement and returns an error.
//
// The step has no clock_jump correction. The DB cap uses it. The cap evicts by
// the oldest UTC day in stored time. A correction would keep a row that a
// range moves after that day, and the cap would evict no row.
func newRawDeleteStep(tDel time.Time, days int) retentionStep {
	cutoff, ok := rollupCutoff(tDel, days)
	if !ok {
		return rollupRefused
	}
	return func(ctx context.Context, tx *sql.Tx, limit int) (int, error) {
		return execCount(ctx, tx, memDeleted, deleteRawSQL, cutoff, limit)
	}
}

// newJumpRawDeleteStep is newRawDeleteStep with the clock_jump correction. The
// retention run uses it. With no clock_jump range, it runs the plain statement.
// With a range, it reads event_kind_ts after a cursor for each kind (see
// corrected). A row in an event range of a clock_jump row has its ts with the
// correction of that row (ADR-043). In that case, a call returns the entries
// that it read.
func newJumpRawDeleteStep(tDel time.Time, days int) retentionStep {
	cutoff, ok := rollupCutoff(tDel, days)
	if !ok {
		return rollupRefused
	}
	c := &corrected{
		kind: eventRows, cutoff: cutoff, act: deleteEventIDsSQL, mem: memDeleted,
		plain: newRawDeleteStep(tDel, days),
	}
	for _, kind := range rawKinds {
		c.reads = append(c.reads, newIndexRead(rawRead, kind))
	}
	return c.step()
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
