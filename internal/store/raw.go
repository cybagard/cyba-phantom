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
	// rawDoneKey is the meta key of the mark. The mark is the delete cutoff
	// of the last field clear that ended its window. It is in unix ms, as
	// decimal text. It can be before the old mark. The next window starts
	// there.
	rawDoneKey = "retention_raw_done"

	// clearReadSQL reads the ts and the id of the next rows of the window
	// after a position. It reads at most a bound of rows, in the order of
	// event_ts: ts, then the rowid. It reads also a row with no field.
	clearReadSQL = "SELECT ts, id FROM event WHERE ts >= ? AND ts < ? AND (ts, id) > (?, ?) " +
		"ORDER BY ts, id LIMIT ?"

	// clearRawSQL sets the three fields to NULL on the rows that hold a value.
	// It takes the rows after a position, up to a last row included. The
	// caller takes the last row from clearReadSQL. So a call touches at most
	// the bound.
	clearRawSQL = "UPDATE event SET body_prefix = NULL, detail = NULL, record = NULL " +
		"WHERE ts >= ? AND ts <= ? AND (ts, id) > (?, ?) AND (ts, id) <= (?, ?) " +
		"AND (body_prefix IS NOT NULL OR detail IS NOT NULL OR record IS NOT NULL)"

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

// newFieldClearStep returns the step that sets body_prefix, detail and record
// to NULL (SEC-39). It takes the event rows with ts in [mark, cutoff). The
// cutoff is tPriv minus `days` x 24 h, in unix ms. The mark is the meta key
// rawDoneKey. With no mark, or a mark that does not parse, the window starts at
// the oldest row. The step reads no clock.
//
// At the end of the window, the step writes the mark. The mark is tDel minus
// `days` x 24 h, not the cutoff. It can be before the old mark, so a wall clock
// that was ahead leaves no row behind the mark. A cutoff at or before the mark
// reads and clears no row. The step then writes that mark at once.
//
// Each call reads at most `limit` rows of the window, in the order of event_ts.
// It reads also the rows that have no field. It sets the fields of the rows
// that hold a value to NULL. The step keeps the ts and the id of the last row
// that it read. The next call starts after that row. Thus a ts that many rows
// share is not read two times. Two statements do this: one reads the rows, and
// one clears them. One statement cannot return a row that it did not change.
// The step writes the mark in the transaction of its last chunk. A run that
// ends early writes no mark. The next run starts at the old mark. A row that is
// written later with a ts before the mark keeps its fields. A row that is
// written during a run, behind the position of the step, also keeps its fields.
//
// A call returns `limit` when it read that many rows, and the rows read plus 1
// for the mark otherwise. The tally of the fields counts the rows that changed.
// With days outside 1 to 30, or a zero tPriv or tDel, the step runs no
// statement. It returns an error.
func newFieldClearStep(tPriv, tDel time.Time, days int) retentionStep {
	cutoff, ok := rollupCutoff(tPriv, days)
	markAt, markOK := rollupCutoff(tDel, days)
	if !ok || !markOK {
		return rollupRefused
	}
	var begun, done bool
	pos := rollupPos{ts: math.MinInt64, id: math.MinInt64}
	end := func(ctx context.Context, tx *sql.Tx, read int) (int, error) {
		done = true
		if _, err := execN(ctx, tx, metaSetSQL, rawDoneKey, strconv.FormatInt(markAt, 10)); err != nil {
			return 0, err
		}
		return read + 1, nil
	}
	return func(ctx context.Context, tx *sql.Tx, limit int) (int, error) {
		if done {
			return 0, nil
		}
		if !begun {
			begun = true
			text, found, merr := metaGet(ctx, tx, rawDoneKey)
			if merr != nil {
				return 0, merr
			}
			if mark, perr := strconv.ParseInt(text, 10, 64); found && perr == nil {
				if cutoff <= mark {
					return end(ctx, tx, 0)
				}
				pos.ts = mark
			}
		}
		rows, err := tx.QueryContext(ctx, clearReadSQL, pos.ts, cutoff, pos.ts, pos.id, limit)
		if err != nil {
			return 0, err
		}
		n, last := 0, pos
		err = eachRow(rows, func() error {
			n++
			return rows.Scan(&last.ts, &last.id)
		})
		if err != nil {
			return 0, err
		}
		if n > 0 {
			if _, err := execCount(ctx, tx, memFields, clearRawSQL, pos.ts, last.ts, pos.ts, pos.id, last.ts, last.id); err != nil {
				return 0, err
			}
		}
		pos = last
		if n == limit {
			return limit, nil
		}
		return end(ctx, tx, n)
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
