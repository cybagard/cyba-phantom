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
	// rawDoneKey is the meta key of the mark. The mark is the cutoff of the
	// last field clear that ended its window, in unix ms as decimal text. The
	// next window starts there.
	rawDoneKey = "retention_raw_done"

	// clearRawSQL clears the fields of the next rows after a position. It
	// picks them in the order of event_ts: ts, then the rowid. It returns the
	// ts and the id of each row that it changed.
	clearRawSQL = "UPDATE event SET body_prefix = NULL, detail = NULL, record = NULL WHERE id IN " +
		"(SELECT id FROM event WHERE ts >= ? AND ts < ? AND (ts, id) > (?, ?) ORDER BY ts, id LIMIT ?) RETURNING ts, id"

	// deleteRawSQL deletes old rows of the kinds that have no roll-up. It uses
	// event_kind_ts.
	deleteRawSQL = "DELETE FROM event WHERE id IN (SELECT id FROM event WHERE kind IN ('refused', 'beacon') AND ts < ? LIMIT ?)"

	// mintNextSQL finds the next set_id after a position. mintDeleteSQL deletes
	// the rows of one set_id in a range of units, in the order of the primary
	// key. Both use the primary key.
	mintNextSQL   = "SELECT set_id FROM mint WHERE set_id > ? ORDER BY set_id LIMIT 1"
	mintDeleteSQL = "DELETE FROM mint WHERE (set_id, unit, first) IN " +
		"(SELECT set_id, unit, first FROM mint WHERE set_id = ? AND unit BETWEEN ? AND ? ORDER BY unit, first LIMIT ?)"
)

// newFieldClearStep returns the step that sets body_prefix, detail and record
// to NULL (SEC-39). It takes the event rows with ts in [mark, cutoff). The
// cutoff is tPriv minus `days` x 24 h, in unix ms. The mark is the meta key
// rawDoneKey.
// With no mark, the window starts at the oldest row. The step reads no clock.
//
// A cutoff at or before the mark gives no read and no write, so the mark never
// moves back. In one run, the step keeps the ts and the id of the last row that
// it changed. The next call starts after that row. Thus a ts that many rows
// share is not read two times. The step writes the mark, with the cutoff, in
// the transaction of its last chunk. A run that ends early writes no mark. The
// next run starts at the old mark. A row that is written later with a ts
// before the mark keeps its fields.
//
// A call returns `limit` when it changed that many rows, and the rows plus 1
// for the mark otherwise. With days outside 1 to 30, or a zero tPriv, the step
// runs no statement and returns an error.
func newFieldClearStep(tPriv time.Time, days int) retentionStep {
	cutoff, ok := rollupCutoff(tPriv, days)
	if !ok {
		return rollupRefused
	}
	var begun, done bool
	pos := rollupPos{ts: math.MinInt64, id: math.MinInt64}
	return func(ctx context.Context, tx *sql.Tx, limit int) (int, error) {
		if done {
			return 0, nil
		}
		if !begun {
			begun = true
			if v, ok, err := metaGet(ctx, tx, rawDoneKey); err != nil {
				return 0, err
			} else if mark, err := strconv.ParseInt(v, 10, 64); ok && err == nil {
				if cutoff <= mark {
					done = true
					return 0, nil
				}
				pos.ts = mark
			}
		}
		rows, err := tx.QueryContext(ctx, clearRawSQL, pos.ts, cutoff, pos.ts, pos.id, limit)
		if err != nil {
			return 0, err
		}
		n, last := 0, pos
		err = eachRow(rows, func() error {
			var p rollupPos
			if err := rows.Scan(&p.ts, &p.id); err != nil {
				return err
			}
			if n++; p.ts > last.ts || p.ts == last.ts && p.id > last.id {
				last = p
			}
			return nil
		})
		if err != nil {
			return 0, err
		}
		pos = last
		if n == limit {
			return limit, nil
		}
		done = true
		if _, err := execN(ctx, tx, metaSetSQL, rawDoneKey, strconv.FormatInt(cutoff, 10)); err != nil {
			return 0, err
		}
		return n + 1, nil
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
		return execN(ctx, tx, deleteRawSQL, cutoff, limit)
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

// newMintStep returns the step that deletes the mint rows of the units before
// the cutoff unit (SEC-39, ADR-038). The cutoff unit is the unit of tDel minus
// `days` x 24 h. The step works for each set_id in turn. It keeps the position
// of the set_id in memory. For each set_id it deletes the rows of the unit
// ranges of mintRanges, oldest unit first. It uses the primary key (set_id,
// unit, first). A cutoff on the unit, not on issued_at, deletes the rows of
// one unit together. Thus two rows that cover one counter go together, or stay
// together.
//
// Known limit: a unit of one set_id can have more rows than one chunk. Its
// rows can then go in two chunks of one run. Between the two commits, a
// callback can find one of the two rows and link to its session. The step does
// not prevent this.
//
// A call returns `limit` when it deleted that many rows, and their count
// otherwise. With days outside 1 to 30, or a zero tDel, the step runs no
// statement and returns an error.
func newMintStep(tDel time.Time, days int) retentionStep {
	cutoff, ok := rollupCutoff(tDel, days)
	if !ok {
		return rollupRefused
	}
	ranges := mintRanges(token.Unit(time.UnixMilli(cutoff)))
	// A text is below each blob, so it is before the first set_id.
	var set any = ""
	return func(ctx context.Context, tx *sql.Tx, limit int) (int, error) {
		left := limit
		for {
			var next []byte
			if found, err := scanOne(tx.QueryRowContext(ctx, mintNextSQL, set), &next); err != nil || !found {
				return limit - left, err
			}
			for _, r := range ranges {
				if left == 0 {
					break
				}
				n, err := execN(ctx, tx, mintDeleteSQL, next, r[0], r[1], left)
				if err != nil {
					return 0, err
				}
				left -= n
			}
			if left == 0 {
				return limit, nil // this set_id can have rows left
			}
			set = next
		}
	}
}
