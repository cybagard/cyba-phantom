package store

import (
	"context"
	"database/sql"
	"math"
	"slices"
)

// A rowKind names the two clock_jump columns that hold the rowid range of the
// rows of one table.
type rowKind struct{ from, to string }

var (
	eventRows   = rowKind{"event_from", "event_to"}
	sessionRows = rowKind{"session_from", "session_to"}
)

// A segment is a range of rowids, both ends included. Each row in it takes the
// same correction. The field sum is the sum of j of each clock_jump row that
// holds the segment. The segments of a table do not overlap. They cover all
// rowids.
type segment struct{ lo, hi, sum int64 }

// segments cuts the ranges of the clock_jump rows into segments, in rowid
// order. A range with no row (from after to) is not used. It returns nil when
// no range is used. The ranges of one host boot overlap. Thus each rowid takes
// the sum of j of the ranges that hold it. A rowid in no range takes 0. Two
// segments next to each other with the same sum are one segment.
func (k rowKind) segments(ctx context.Context, tx *sql.Tx) ([]segment, error) {
	rows, err := tx.QueryContext(ctx, "SELECT "+k.from+", "+k.to+", j FROM clock_jump WHERE "+k.from+" <= "+k.to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	step := map[int64]int64{} // the change of the sum at a rowid
	for rows.Next() {
		var from, to, j int64
		if err := rows.Scan(&from, &to, &j); err != nil {
			return nil, err
		}
		step[from] += j
		if to < math.MaxInt64 {
			step[to+1] -= j
		}
	}
	if err := rows.Err(); err != nil || len(step) == 0 {
		return nil, err
	}
	edges := make([]int64, 0, len(step))
	for e := range step {
		edges = append(edges, e)
	}
	slices.Sort(edges)
	var segs []segment
	lo, sum := int64(math.MinInt64), int64(0)
	cut := func(hi int64) {
		if n := len(segs); n > 0 && segs[n-1].sum == sum {
			segs[n-1].hi = hi
		} else {
			segs = append(segs, segment{lo, hi, sum})
		}
	}
	for _, e := range edges {
		if e > lo {
			cut(e - 1)
		}
		lo, sum = e, sum+step[e]
	}
	cut(math.MaxInt64)
	return segs, nil
}

// shift returns the cutoff of a segment: cutoff minus sum. A row acts when its
// time plus the sum is before the cutoff. Thus its time must be before this
// value. The result stays in the range of int64.
func shift(cutoff, sum int64) int64 {
	switch {
	case sum > 0 && cutoff < math.MinInt64+sum:
		return math.MinInt64
	case sum < 0 && cutoff > math.MaxInt64+sum:
		return math.MaxInt64
	}
	return cutoff - sum
}

// each calls run for the segments of k in rowid order, until the calls changed
// limit rows. run gets the cutoff of the segment, the segment, and the rows
// that it can still change. It returns the rows that it changed, at most that
// limit. A segment that gives fewer rows has no row left. Thus each returns
// fewer than limit rows only when no segment has a row left. With no clock_jump
// range, each calls run one time, with the cutoff and a nil segment.
func (k rowKind) each(ctx context.Context, tx *sql.Tx, cutoff int64, limit int,
	run func(cut int64, s *segment, limit int) (int, error)) (int, error) {
	segs, err := k.segments(ctx, tx)
	if err != nil {
		return 0, err
	}
	if segs == nil {
		return run(cutoff, nil, limit)
	}
	n := 0
	for i := range segs {
		m, err := run(shift(cutoff, segs[i].sum), &segs[i], limit-n)
		if n += m; err != nil || n >= limit {
			return n, err
		}
	}
	return n, nil
}

// A correction is a statement that reads the rows of one segment. Its text
// takes the cutoff, the two ends of the segment and the limit, in this order.
type correction struct {
	kind rowKind
	sql  string
}

// exec runs a step statement on the rows that act at the cutoff. A nil
// correction, or no clock_jump range, runs plain with the cutoff and the limit.
// Else it runs the statement of c for each segment, with the cutoff of the
// segment. It counts the rows that the statements changed in member m.
func (c *correction) exec(ctx context.Context, tx *sql.Tx, m member, plain string, cutoff int64, limit int) (int, error) {
	if c == nil {
		return execCount(ctx, tx, m, plain, cutoff, limit)
	}
	return c.kind.each(ctx, tx, cutoff, limit, func(cut int64, s *segment, lim int) (int, error) {
		if s == nil {
			return execCount(ctx, tx, m, plain, cut, lim)
		}
		return execCount(ctx, tx, m, c.sql, cut, s.lo, s.hi, lim)
	})
}
