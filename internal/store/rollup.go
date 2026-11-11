package store

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"strconv"
	"strings"
	"time"
)

const (
	// rollupDoneKey is the meta key of the last day that is done. The day
	// step counts the callbacks of that day and removes its rollup_seen rows.
	// rollupPosKey is the meta key of the position in the day in progress.
	// It holds the ts and the id of the last callback counted, as ts:id. It
	// holds start:-1 when the day has no callback. The day step removes it
	// when the day is done.
	rollupDoneKey = "retention_rollup_done"
	rollupPosKey  = "retention_rollup_pos"
	rollupDayFmt  = "2006-01-02"

	// rollupPickSQL gives the oldest request rows before the cutoff, in the
	// order of event_kind_ts. No key part is NULL. A missing vhost or family
	// is ''. A missing session row gives the band 'human'.
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
	// roll-up step has not done. rollupCallbackSQL gives the callbacks
	// before a time and after a position. It gives at most the limit, in
	// the order of the position. The row value seeks in event_kind_ts. The
	// next two find the first day with data.
	rollupLeftSQL     = "SELECT 1 FROM event WHERE kind = 'request' AND ts < ? LIMIT 1"
	rollupCallbackSQL = "WITH pick AS (SELECT id, ts, vhost, session_id FROM event WHERE kind = 'callback' AND ts < ? " +
		"AND (ts, id) > (?, ?) ORDER BY ts, id LIMIT ?) " +
		"SELECT p.id, p.ts, coalesce(p.vhost, ''), coalesce(s.band, 'human'), coalesce(s.family, '') FROM pick p " +
		"LEFT JOIN session s ON s.id = p.session_id ORDER BY p.ts, p.id"
	rollupFirstCallbackSQL = "SELECT ts FROM event WHERE kind = 'callback' AND ts >= ? ORDER BY ts LIMIT 1"
	rollupFirstSeenSQL     = "SELECT day FROM rollup_seen WHERE day > ? ORDER BY day LIMIT 1"
	rollupDropSeenSQL      = "DELETE FROM rollup_seen WHERE (day, vhost, band, family, session_id) IN " +
		"(SELECT day, vhost, band, family, session_id FROM rollup_seen WHERE day <= ? LIMIT ?)"
	metaGetSQL = "SELECT value FROM meta WHERE key = ?"
	metaSetSQL = "INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value"
	metaDelSQL = "DELETE FROM meta WHERE key = ?"
)

// rollupKey is the key of a row of aggregate_day. No part is NULL (SEC-39).
type rollupKey struct{ day, vhost, band, family string }

// rollupCount is what one call adds to the row of a key.
type rollupCount struct{ sessions, requests, callbacks int }

// retentionCutoff returns the cutoff in unix ms: tDel minus days x 24 h. Days
// must be in the range 1 to maxDays. Outside this range, or with a zero tDel,
// ok is false.
func retentionCutoff(tDel time.Time, days, maxDays int) (cutoff int64, ok bool) {
	if days < 1 || days > maxDays || tDel.IsZero() {
		return 0, false
	}
	return tDel.Add(-time.Duration(days) * 24 * time.Hour).UnixMilli(), true
}

// rollupCutoff is retentionCutoff for the raw days. The configuration keeps
// them in the range 1 to 30.
func rollupCutoff(tDel time.Time, days int) (cutoff int64, ok bool) {
	return retentionCutoff(tDel, days, 30)
}

// rollupRefused is the step for bad parameters. It runs no statement. The error
// stops the writer, as for newIPStep.
func rollupRefused(context.Context, *sql.Tx, int) (int, error) {
	return 0, fail(writerName, ruleDatabase)
}

// These costs bound the rows that a piece of work changes. A step returns the
// sum of them, so the count is at least the rows changed (see retentionStep).
const (
	// rollupRowCost is for a request row. The step deletes the event and
	// adds a seen row. It also does its share of the upserts.
	rollupRowCost = 3
	// rollupReadCost is for a callback: the read and its share of the upserts
	// and of the position write.
	rollupReadCost = 2
	// rollupEndCost is for the two meta writes that end a day.
	rollupEndCost = 2
)

// rollupDayMs is the length of a UTC day in unix ms.
const rollupDayMs = int64(24 * time.Hour / time.Millisecond)

// rollupDayStart returns the start of the UTC day of a time, in unix ms.
func rollupDayStart(ts int64) int64 { return ts - (ts%rollupDayMs+rollupDayMs)%rollupDayMs }

// rollupDay returns the UTC date of a time in unix ms.
func rollupDay(ts int64) string { return time.UnixMilli(ts).UTC().Format(rollupDayFmt) }

// rollupFarMs is the start of UTC year 10000 in unix ms. The date text of a
// later day has 5 digits for the year. The day step never finishes such a day.
var rollupFarMs = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC).UnixMilli()

// rollupFloor returns the last date text that gets no new seen pair in the
// roll-up step. It is the mark, or the date of the saved position when that is
// later.
func rollupFloor(ctx context.Context, tx *sql.Tx) (string, error) {
	floor, _, err := metaGet(ctx, tx, rollupDoneKey)
	if err != nil {
		return "", err
	}
	v, ok, err := metaGet(ctx, tx, rollupPosKey)
	if err != nil || !ok {
		return floor, err
	}
	pos, err := parseRollupPos(v)
	if err != nil {
		return "", err
	}
	return max(floor, rollupDay(pos.ts)), nil
}

// newRollupStep returns the roll-up step for the request rows (SEC-39). It
// takes the rows with ts before tDel minus `days` x 24 h. The step reads no
// clock. Each request row costs 3 changed rows. Thus each call takes at most
// `limit`/3 rows, oldest first. It adds the rows and the new sessions of each
// key to aggregate_day. Then it deletes the rows. All this is in the
// transaction of the caller. A failed chunk keeps the rows and changes no
// count.
//
// The call returns `limit` when it took the most rows, and 3 times the rows
// otherwise. With `limit` below 3, it runs no statement and returns `limit`.
// The next chunk gives the step a full limit.
//
// "Exact for each key" means this. A session counts one time for each key
// (day, vhost, band, family) in which it has a row. A session whose band
// changes between two chunks counts one time under each band.
//
// The pairs of a key and a session stay in rollup_seen. A session can have
// rows in two chunks or two runs of one day. The pair stops a second count.
// The day step removes the pairs of a day when the day is done. A row of a
// day at or before the mark rollupDoneKey still rolls up, after a wall clock
// moves back. It counts as a request. It adds no pair and no session, as no
// step would remove the pair. The same holds for a day at or before the day
// of the saved position rollupPosKey. The day step has begun to count the
// callbacks of that day, or to remove its pairs. Thus a late row of a new
// session in that day adds no session.
// A row after year 9999 rolls up with no pair and no session. Its day is
// never done.
//
// With days outside 1 to 30, or a zero tDel, the step runs no statement and
// returns an error. The runner then stops the writer.
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
			far bool
		}
		most := limit / rollupRowCost
		if most == 0 {
			return limit, nil
		}
		floor, err := rollupFloor(ctx, tx)
		if err != nil {
			return 0, err
		}
		rows, err := tx.QueryContext(ctx, rollupPickSQL, cutoff, most)
		if err != nil {
			return 0, err
		}
		var batch []picked
		err = eachRow(rows, func() error {
			var p picked
			var ts int64
			err := rows.Scan(&p.id, &ts, &p.key.vhost, &p.sid, &p.key.band, &p.key.family)
			p.key.day, p.far = rollupDay(ts), ts >= rollupFarMs
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
			if p.sid.Valid && p.key.day > floor && !p.far {
				n, err := execN(ctx, tx, rollupSeenSQL, p.key.day, p.key.vhost, p.key.band, p.key.family, p.sid.String)
				if err != nil {
					return 0, err
				}
				c.sessions += n
			}
			if _, err := execCount(ctx, tx, memRolled, rollupDropSQL, p.id); err != nil {
				return 0, err
			}
		}
		if err := rollupAdd(ctx, tx, counts); err != nil {
			return 0, err
		}
		if len(batch) == most {
			return limit, nil
		}
		return rollupRowCost * len(batch), nil
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
// step list (SEC-39). A day is done when its end is not after the cutoff.
// Also, no request row with ts before the cutoff is left. The step takes the
// done days in order, from the day after the meta mark rollupDoneKey. For
// each day it adds the callback events to aggregate_day. It uses the key
// rules of the roll-up step. Then it deletes the rollup_seen rows of the
// day and of older days. Older days have rows of an older binary or a broken
// run. At the end of a day it sets the mark.
//
// Each call has a row limit. A callback costs 2, a seen row costs 1, and the
// end of a day costs 2. Thus the cost is at least the rows that the call
// changes. A day with many callbacks takes several calls. The step saves the
// position in the day in the meta key rollupPosKey, in the transaction of the
// counts. Thus no callback counts two times, and the step misses none. The step
// does not visit a day with no callback and no seen row. It looks for the next
// day with data.
//
// The step returns less than `limit` only when no done day is left. With
// days outside 1 to 30, or a zero tDel, it runs no statement and returns an
// error.
func newRollupDayStep(tDel time.Time, days int) retentionStep {
	cutoff, ok := rollupCutoff(tDel, days)
	if !ok {
		return rollupRefused
	}
	return func(ctx context.Context, tx *sql.Tx, limit int) (int, error) {
		left, last := limit, int64(math.MinInt64)
		for left > 0 {
			start, ok, err := rollupPickDay(ctx, tx, cutoff)
			if err != nil {
				return 0, err
			}
			if !ok {
				break
			}
			if start <= last {
				// No input can cause this: the code broke an invariant.
				return 0, fail(writerName, ruleDatabase)
			}
			used, err := rollupCountDay(ctx, tx, start, left)
			if err != nil {
				return 0, err
			}
			if used < left {
				last = start
			}
			left -= used
		}
		return limit - left, nil
	}
}

// rollupPickDay is rollupNextDay. A test replaces it to break the invariant
// that a done day is not picked again.
var rollupPickDay = rollupNextDay

// rollupNextDay returns the start of the next day to work on, in unix ms. This
// is the day in progress, or the first day with a callback or a seen row after
// the mark. ok is false in three cases. There is no such day. Or a request row
// before the cutoff is left. Or the day is not over at the cutoff. A day after
// year 9999 is never over. The step parses no day text of a day that is not
// done.
func rollupNextDay(ctx context.Context, tx *sql.Tx, cutoff int64) (start int64, ok bool, err error) {
	var one int
	if left, err := scanOne(tx.QueryRowContext(ctx, rollupLeftSQL, cutoff), &one); left || err != nil {
		return 0, false, err
	}
	v, inProgress, err := metaGet(ctx, tx, rollupPosKey)
	if err != nil {
		return 0, false, err
	}
	if inProgress {
		pos, err := parseRollupPos(v)
		if err != nil {
			return 0, false, err
		}
		start = rollupDayStart(pos.ts)
	} else if start, ok, err = rollupFirstDay(ctx, tx); err != nil || !ok {
		return 0, false, err
	}
	return start, start+rollupDayMs <= cutoff && start < rollupFarMs, nil
}

// rollupFirstDay returns the start of the first day after the mark that has a
// callback or a seen row. The start is in unix ms. ok is false when there is
// none. It uses two index seeks.
func rollupFirstDay(ctx context.Context, tx *sql.Tx) (start int64, ok bool, err error) {
	mark, hasMark, err := metaGet(ctx, tx, rollupDoneKey)
	if err != nil {
		return 0, false, err
	}
	from := int64(0)
	if hasMark {
		t, err := time.Parse(rollupDayFmt, mark)
		if err != nil {
			return 0, false, err
		}
		from = t.UnixMilli() + rollupDayMs
	}
	var ts int64
	if found, err := scanOne(tx.QueryRowContext(ctx, rollupFirstCallbackSQL, from), &ts); err != nil {
		return 0, false, err
	} else if found {
		start, ok = rollupDayStart(ts), true
	}
	var seen string
	if found, err := scanOne(tx.QueryRowContext(ctx, rollupFirstSeenSQL, mark), &seen); err != nil || !found {
		return start, ok, err
	}
	t, err := time.Parse(rollupDayFmt, seen)
	if err != nil {
		return 0, false, err
	}
	if s := t.UnixMilli(); !ok || s < start {
		start, ok = s, true
	}
	return start, ok, nil
}

// rollupPos is the position in a day: the ts and the id of the last callback
// counted. The meta key rollupPosKey holds it as ts:id.
type rollupPos struct{ ts, id int64 }

func (p rollupPos) String() string {
	return strconv.FormatInt(p.ts, 10) + ":" + strconv.FormatInt(p.id, 10)
}

// parseRollupPos reads the text of a position.
func parseRollupPos(v string) (p rollupPos, err error) {
	a, b, _ := strings.Cut(v, ":")
	if p.ts, err = strconv.ParseInt(a, 10, 64); err != nil {
		return rollupPos{}, err
	}
	p.id, err = strconv.ParseInt(b, 10, 64)
	return p, err
}

// rollupCountDay does work for the day that starts at `start`, at a cost of at
// most `limit`. First it counts the callbacks after the saved position. When
// it has counted them all, it saves the position if it has saved no position.
// The saved position tells the roll-up step that the day is closing. Then it
// removes the seen rows of the day. When it removes the last of them, it sets
// the mark and removes the position. It returns the cost. The cost is less
// than `limit` only when the day is done.
func rollupCountDay(ctx context.Context, tx *sql.Tx, start int64, limit int) (cost int, err error) {
	day := rollupDay(start)
	after, saved := rollupPos{ts: start, id: -1}, false
	if v, ok, err := metaGet(ctx, tx, rollupPosKey); err != nil {
		return 0, err
	} else if ok {
		saved = true
		if after, err = parseRollupPos(v); err != nil {
			return 0, err
		}
	}
	most := limit / rollupReadCost
	if most == 0 {
		return limit, nil
	}
	rows, err := tx.QueryContext(ctx, rollupCallbackSQL, start+rollupDayMs, after.ts, after.id, most)
	if err != nil {
		return 0, err
	}
	counts := rollupCounts{}
	var last rollupPos
	read := 0
	err = eachRow(rows, func() error {
		k := rollupKey{day: day}
		err := rows.Scan(&last.id, &last.ts, &k.vhost, &k.band, &k.family)
		counts.of(k).callbacks++
		read++
		return err
	})
	if err != nil {
		return 0, err
	}
	if err = rollupAdd(ctx, tx, counts); err != nil {
		return 0, err
	}
	if read > 0 {
		if _, err = execN(ctx, tx, metaSetSQL, rollupPosKey, last.String()); err != nil {
			return 0, err
		}
	}
	if read == most {
		return limit, nil
	}
	cost = read * rollupReadCost
	if read == 0 && !saved {
		if _, err = execN(ctx, tx, metaSetSQL, rollupPosKey, after.String()); err != nil {
			return 0, err
		}
		cost++
	}
	n, err := execN(ctx, tx, rollupDropSeenSQL, day, limit-cost)
	if err != nil {
		return 0, err
	}
	if cost += n; cost+rollupEndCost > limit {
		return limit, nil
	}
	if _, err = execN(ctx, tx, metaSetSQL, rollupDoneKey, day); err != nil {
		return 0, err
	}
	_, err = execN(ctx, tx, metaDelSQL, rollupPosKey)
	return cost + rollupEndCost, err
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
