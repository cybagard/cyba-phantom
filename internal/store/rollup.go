package store

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"strings"
	"time"
)

const (
	// rollupDoneKey is the meta key of the last day that is done: its callbacks
	// are counted and its rollup_seen rows are gone. rollupPosKey is the meta key
	// of the last callback counted in the day that is in progress. It holds the
	// ts and the id, as ts:id. The day step removes it when the day is done.
	rollupDoneKey = "retention_rollup_done"
	rollupPosKey  = "retention_rollup_pos"
	rollupDayFmt  = "2006-01-02"

	// rollupPickSQL gives the oldest request rows before the cutoff, in the order
	// of event_kind_ts. Each key part is never NULL: a missing vhost or family is
	// '' and a missing session row has the band 'human'.
	rollupPickSQL = "SELECT e.id, e.ts, coalesce(e.vhost, ''), e.session_id, coalesce(s.band, 'human'), coalesce(s.family, '') " +
		"FROM event e LEFT JOIN session s ON s.id = e.session_id " +
		"WHERE e.id IN (SELECT id FROM event WHERE kind = 'request' AND ts < ? ORDER BY ts LIMIT ?)"
	rollupSeenSQL = "INSERT INTO rollup_seen (day, vhost, band, family, session_id) VALUES (?, ?, ?, ?, ?) ON CONFLICT DO NOTHING"
	rollupDropSQL = "DELETE FROM event WHERE id = ?"

	// rollupAddSQL adds to the row of a key. It never sets a count.
	rollupAddSQL = "INSERT INTO aggregate_day (day, vhost, band, family, sessions, requests, callbacks) VALUES (?, ?, ?, ?, ?, ?, ?) " +
		"ON CONFLICT (day, vhost, band, family) DO UPDATE SET sessions = sessions + excluded.sessions, " +
		"requests = requests + excluded.requests, callbacks = callbacks + excluded.callbacks"

	// The day step uses these. rollupLeftSQL finds a request row that the
	// roll-up step has not done. rollupCallbackSQL gives the callbacks of one day
	// after a position, at most the limit. The next two find the first day with
	// data.
	rollupLeftSQL     = "SELECT 1 FROM event WHERE kind = 'request' AND ts < ? LIMIT 1"
	rollupCallbackSQL = "WITH pick AS (SELECT id, ts, vhost, session_id FROM event WHERE kind = 'callback' AND ts >= ? AND ts < ? " +
		"AND (ts > ? OR id > ?) ORDER BY ts, id LIMIT ?) " +
		"SELECT p.id, p.ts, coalesce(p.vhost, ''), coalesce(s.band, 'human'), coalesce(s.family, '') FROM pick p LEFT JOIN session s ON s.id = p.session_id"
	rollupFirstCallbackSQL = "SELECT ts FROM event WHERE kind = 'callback' AND ts >= ? ORDER BY ts LIMIT 1"
	rollupFirstSeenSQL     = "SELECT day FROM rollup_seen WHERE day > ? ORDER BY day LIMIT 1"
	rollupDropSeenSQL      = "DELETE FROM rollup_seen WHERE (day, vhost, band, family, session_id) IN " +
		"(SELECT day, vhost, band, family, session_id FROM rollup_seen WHERE day = ? LIMIT ?)"
	metaGetSQL = "SELECT value FROM meta WHERE key = ?"
	metaSetSQL = "INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value"
	metaDelSQL = "DELETE FROM meta WHERE key = ?"
)

// rollupKey is the key of a row of aggregate_day. No part is NULL (SEC-39).
type rollupKey struct{ day, vhost, band, family string }

// rollupCount is what one call adds to the row of a key.
type rollupCount struct{ sessions, requests, callbacks int }

// rollupCutoff returns the cutoff in unix ms: tDel minus days x 24 h. The
// configuration keeps days in the range 1 to 30. Outside this range, or with a
// zero tDel, ok is false.
func rollupCutoff(tDel time.Time, days int) (cutoff int64, ok bool) {
	if days < 1 || days > 30 || tDel.IsZero() {
		return 0, false
	}
	return tDel.Add(-time.Duration(days) * 24 * time.Hour).UnixMilli(), true
}

// rollupRefused is the step for bad parameters. It runs no statement. The error
// stops the writer, as for newIPStep.
func rollupRefused(context.Context, *sql.Tx, int) (int, error) {
	return 0, fail(writerName, ruleDatabase)
}

// rollupDay returns the UTC date of a time in unix ms.
func rollupDay(ts int64) string { return time.UnixMilli(ts).UTC().Format(rollupDayFmt) }

// newRollupStep returns the roll-up step for the request rows (SEC-39). It
// takes the rows with ts before tDel minus `days` x 24 h. The step reads no
// clock. Each call takes at most `limit` rows, oldest first. It adds the rows
// and the new sessions of each key to aggregate_day. Then it deletes the rows.
// All this is in the transaction of the caller, so a failed chunk keeps the
// rows and changes no count.
//
// "Exact for each key" means this: a session counts one time for each key
// (day, vhost, band, family) in which it has a row. A session whose band
// changes between two chunks counts one time under each band.
//
// The pairs of a key and a session stay in rollup_seen. A session can have
// rows in two chunks or two runs of one day, and the pair stops a second count.
// The day step removes the pairs of a day when the day is done.
//
// Outside the days range 1 to 30, or with a zero tDel, the step runs no
// statement and returns an error. The runner then stops the writer.
func newRollupStep(tDel time.Time, days int) retentionStep {
	cutoff, ok := rollupCutoff(tDel, days)
	if !ok {
		return rollupRefused
	}
	return func(ctx context.Context, tx *sql.Tx, limit int) (int, error) {
		type picked struct {
			id  int64
			key rollupKey
			sid sql.NullString
		}
		rows, err := tx.QueryContext(ctx, rollupPickSQL, cutoff, limit)
		if err != nil {
			return 0, err
		}
		var batch []picked
		err = eachRow(rows, func() error {
			var p picked
			var ts int64
			err := rows.Scan(&p.id, &ts, &p.key.vhost, &p.sid, &p.key.band, &p.key.family)
			p.key.day = rollupDay(ts)
			batch = append(batch, p)
			return err
		})
		if err != nil {
			return 0, err
		}
		counts := rollupCounts{}
		for _, p := range batch {
			c := counts.of(p.key)
			c.requests++
			if p.sid.Valid {
				n, err := execN(ctx, tx, rollupSeenSQL, p.key.day, p.key.vhost, p.key.band, p.key.family, p.sid.String)
				if err != nil {
					return 0, err
				}
				c.sessions += n
			}
			if _, err := execN(ctx, tx, rollupDropSQL, p.id); err != nil {
				return 0, err
			}
		}
		if err := rollupAdd(ctx, tx, counts); err != nil {
			return 0, err
		}
		return len(batch), nil
	}
}

// rollupCounts holds what one call adds to each key.
type rollupCounts map[rollupKey]*rollupCount

// of returns the count of a key. It makes the count when it is new.
func (m rollupCounts) of(k rollupKey) *rollupCount {
	if m[k] == nil {
		m[k] = &rollupCount{}
	}
	return m[k]
}

// eachRow calls f for each row, then closes rows. It returns the first error.
func eachRow(rows *sql.Rows, f func() error) (err error) {
	defer func() {
		if cerr := rows.Close(); err == nil {
			err = cerr
		}
	}()
	for rows.Next() {
		if err = f(); err != nil {
			return err
		}
	}
	return rows.Err()
}

// rollupAdd adds the counts to the rows of aggregate_day.
func rollupAdd(ctx context.Context, tx *sql.Tx, counts rollupCounts) error {
	for k, c := range counts {
		if _, err := tx.ExecContext(ctx, rollupAddSQL, k.day, k.vhost, k.band, k.family, c.sessions, c.requests, c.callbacks); err != nil {
			return err
		}
	}
	return nil
}

// metaGet reads a meta value. ok is false when the key is not there.
func metaGet(ctx context.Context, tx *sql.Tx, key string) (v string, ok bool, err error) {
	ok, err = scanOne(tx.QueryRowContext(ctx, metaGetSQL, key), &v)
	return v, ok, err
}

// scanOne scans a row into dst. ok is false when there is no row.
func scanOne(row *sql.Row, dst ...any) (ok bool, err error) {
	switch err = row.Scan(dst...); {
	case err == nil:
		return true, nil
	case errors.Is(err, sql.ErrNoRows):
		return false, nil
	}
	return false, err
}

// newRollupDayStep returns the day step. It runs after the roll-up step in a
// step list (SEC-39). A day is done when its end is not after the cutoff, and
// no request row with ts before the cutoff is left. The step takes the done
// days in order, from the day after the meta mark rollupDoneKey. For each day it
// adds the callback events to aggregate_day, with the key rules of the roll-up
// step. Then it deletes the rollup_seen rows of the day. At the end of a day it
// sets the mark. Each call reads or changes at most `limit` rows. A day with
// many callbacks takes several calls. The position in the day is in the meta
// key rollupPosKey, and it is saved in the transaction of the counts. Thus no
// callback counts two times, and none is missed. A day with no callback and no
// seen row is not visited: the step looks for the next day with data.
//
// The step returns less than `limit` only when no done day is left. Outside the
// days range 1 to 30, or with a zero tDel, the step runs no statement and
// returns an error.
func newRollupDayStep(tDel time.Time, days int) retentionStep {
	cutoff, ok := rollupCutoff(tDel, days)
	if !ok {
		return rollupRefused
	}
	return func(ctx context.Context, tx *sql.Tx, limit int) (int, error) {
		budget := limit
		for budget > 0 {
			day, ok, err := rollupNextDay(ctx, tx, cutoff)
			if err != nil {
				return 0, err
			}
			if !ok {
				break
			}
			used, finished, err := rollupCountDay(ctx, tx, day, budget)
			if err != nil {
				return 0, err
			}
			budget -= used
			if !finished {
				break
			}
		}
		return limit - budget, nil
	}
}

// rollupNextDay returns the next day to work on: the day in progress, or the
// first day with a callback or a seen row after the mark. ok is false when
// there is no such day, when a request row before the cutoff is left, or when
// the day is not over at the cutoff.
func rollupNextDay(ctx context.Context, tx *sql.Tx, cutoff int64) (day string, ok bool, err error) {
	var one int
	if left, err := scanOne(tx.QueryRowContext(ctx, rollupLeftSQL, cutoff), &one); left || err != nil {
		return "", false, err
	}
	pos, inProgress, err := metaGet(ctx, tx, rollupPosKey)
	if err != nil {
		return "", false, err
	}
	if inProgress {
		ts, _, err := rollupPos(pos)
		if err != nil {
			return "", false, err
		}
		day = rollupDay(ts)
	} else if day, err = rollupFirstDay(ctx, tx); err != nil || day == "" {
		return "", false, err
	}
	t, err := time.Parse(rollupDayFmt, day)
	if err != nil {
		return "", false, err
	}
	return day, t.AddDate(0, 0, 1).UnixMilli() <= cutoff, nil
}

// rollupFirstDay returns the first day after the mark with a callback event or
// a seen row. It returns "" when there is none. It uses two index seeks.
func rollupFirstDay(ctx context.Context, tx *sql.Tx) (string, error) {
	mark, hasMark, err := metaGet(ctx, tx, rollupDoneKey)
	if err != nil {
		return "", err
	}
	from := int64(0)
	if hasMark {
		t, err := time.Parse(rollupDayFmt, mark)
		if err != nil {
			return "", err
		}
		from = t.AddDate(0, 0, 1).UnixMilli()
	}
	day := ""
	var ts int64
	if ok, err := scanOne(tx.QueryRowContext(ctx, rollupFirstCallbackSQL, from), &ts); err != nil {
		return "", err
	} else if ok {
		day = rollupDay(ts)
	}
	var seen string
	if ok, err := scanOne(tx.QueryRowContext(ctx, rollupFirstSeenSQL, mark), &seen); err != nil {
		return "", err
	} else if ok && (day == "" || seen < day) {
		day = seen
	}
	return day, nil
}

// rollupPos reads the value of rollupPosKey: the ts and the id, as ts:id.
func rollupPos(v string) (ts, id int64, err error) {
	a, b, _ := strings.Cut(v, ":")
	if ts, err = strconv.ParseInt(a, 10, 64); err != nil {
		return 0, 0, err
	}
	id, err = strconv.ParseInt(b, 10, 64)
	return ts, id, err
}

// rollupCountDay does at most budget rows of work for the day. First it counts
// the callbacks after the saved position. When they are all counted, it deletes
// the seen rows of the day. When it deletes the last of them, it sets the mark
// and removes the position. It returns the rows that it read or deleted.
// finished is false only when it used the whole budget.
func rollupCountDay(ctx context.Context, tx *sql.Tx, day string, budget int) (used int, finished bool, err error) {
	start, err := time.Parse(rollupDayFmt, day)
	if err != nil {
		return 0, false, err
	}
	from, afterID := start.UnixMilli(), int64(0)
	afterTS := from - 1
	if pos, ok, err := metaGet(ctx, tx, rollupPosKey); err != nil {
		return 0, false, err
	} else if ok {
		if afterTS, afterID, err = rollupPos(pos); err != nil {
			return 0, false, err
		}
		from = afterTS
	}
	end := start.AddDate(0, 0, 1).UnixMilli()
	rows, err := tx.QueryContext(ctx, rollupCallbackSQL, from, end, afterTS, afterID, budget)
	if err != nil {
		return 0, false, err
	}
	counts := rollupCounts{}
	var lastTS, lastID int64
	err = eachRow(rows, func() error {
		var id, ts int64
		k := rollupKey{day: day}
		err := rows.Scan(&id, &ts, &k.vhost, &k.band, &k.family)
		counts.of(k).callbacks++
		if ts > lastTS || ts == lastTS && id > lastID {
			lastTS, lastID = ts, id
		}
		used++
		return err
	})
	if err != nil {
		return 0, false, err
	}
	if err = rollupAdd(ctx, tx, counts); err != nil {
		return 0, false, err
	}
	if used > 0 {
		pos := strconv.FormatInt(lastTS, 10) + ":" + strconv.FormatInt(lastID, 10)
		if _, err = execN(ctx, tx, metaSetSQL, rollupPosKey, pos); err != nil {
			return 0, false, err
		}
	}
	if used == budget {
		return used, false, nil
	}
	n, err := execN(ctx, tx, rollupDropSeenSQL, day, budget-used)
	if used += n; err != nil || used == budget {
		return used, false, err
	}
	if _, err = execN(ctx, tx, metaSetSQL, rollupDoneKey, day); err != nil {
		return 0, false, err
	}
	_, err = execN(ctx, tx, metaDelSQL, rollupPosKey)
	return used, true, err
}

// execN runs a statement and returns the rows that it changed.
func execN(ctx context.Context, tx *sql.Tx, q string, args ...any) (int, error) {
	res, err := tx.ExecContext(ctx, q, args...)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}
