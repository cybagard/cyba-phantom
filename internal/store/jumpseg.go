package store

import (
	"cmp"
	"context"
	"database/sql"
	"math"
	"slices"
	"strconv"
)

// A rowKind names the two clock_jump columns that hold the rowid range of the
// rows of one table.
type rowKind struct{ from, to string }

var (
	eventRows   = rowKind{"event_from", "event_to"}
	sessionRows = rowKind{"session_from", "session_to"}
)

// A segment is a range of rowids, both ends included. Each row in it has the
// same sum of j.
type segment struct{ lo, hi, sum int64 }

// resetAt is the `at` of a reset row. A reset row has no test of the row time:
// each row of its ranges takes its j. Any other `at` is the S of a grace jump.
// A row of its ranges takes the j only when the row time is before that `at`.
const resetAt = math.MaxInt64

// A graceRow is a clock_jump row with an `at` test.
type graceRow struct{ from, to, j, at int64 }

// jumpSums gives the sum of j of the clock_jump rows for each rowid of one
// table.
type jumpSums struct {
	// segs holds the sums of the reset rows. They are in rowid order, with no
	// overlap, and they cover all rowids.
	segs []segment
	// grace holds the rows with an `at` test. An entry takes the j of one when
	// its rowid is in the range and its time is before `at`.
	grace []graceRow
	// low is the smallest sum that any row can get, at most 0. It takes each
	// negative j of a grace row as if its test were true.
	low int64
}

// sums reads the ranges of the clock_jump rows of kind k. It returns nil when
// no range is used. A range with its start after its end is not used. The
// ranges of one host boot overlap. Thus a rowid has the sum of j of each range
// that holds it. A grace row gives its j only when the time of the row is
// before its `at` (see sum). A rowid in no range has the sum 0. Two segments
// next to each other with the same sum are one segment. A sum stays in the
// range of int64: it is the true sum, or the nearest end of that range.
//
// A step calls sums one time for each step call, not one time for each run.
// The writer can move the end of a range between two chunks. A call then sees
// the ranges that its own transaction sees. The memory of a call is about 160
// bytes for each clock_jump row. This is two changes of 40 bytes, two segments
// of 24 bytes and one grace row of 32 bytes.
func (k rowKind) sums(ctx context.Context, tx *sql.Tx) (*jumpSums, error) {
	rows, err := tx.QueryContext(ctx, "SELECT "+k.from+", "+k.to+", j, at FROM clock_jump WHERE "+k.from+" <= "+k.to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	// A change of the sums at a rowid. A wide number holds the sum of any count
	// of changes. The result is clamped when a segment is made. fixed is for
	// the segments. low is for the smallest sum.
	type change struct {
		at         int64
		fixed, low int128
	}
	var changes []change
	js := &jumpSums{}
	found := false
	for rows.Next() {
		var g graceRow
		if err := rows.Scan(&g.from, &g.to, &g.j, &g.at); err != nil {
			return nil, err
		}
		found = true
		var fixed, low int128
		if g.at == resetAt {
			fixed, low = wide(g.j), wide(g.j)
		} else {
			js.grace = append(js.grace, g)
			low = wide(min(g.j, 0))
		}
		changes = append(changes, change{g.from, fixed, low})
		if g.to < math.MaxInt64 {
			changes = append(changes, change{g.to + 1, fixed.neg(), low.neg()})
		}
	}
	if err := rows.Err(); err != nil || !found {
		return nil, err
	}
	slices.SortFunc(changes, func(a, b change) int { return cmp.Compare(a.at, b.at) })
	lo, fixed, low := int64(math.MinInt64), int128{}, int128{}
	cut := func(hi int64) {
		s := fixed.clamp()
		js.low = min(js.low, low.clamp())
		if n := len(js.segs); n > 0 && js.segs[n-1].sum == s {
			js.segs[n-1].hi = hi
		} else {
			js.segs = append(js.segs, segment{lo, hi, s})
		}
	}
	for i := 0; i < len(changes); {
		e := changes[i].at
		if e > lo {
			cut(e - 1)
		}
		for ; i < len(changes) && changes[i].at == e; i++ {
			fixed, low = fixed.add(changes[i].fixed), low.add(changes[i].low)
		}
		lo = e
	}
	cut(math.MaxInt64)
	return js, nil
}

// An int128 is a number of 128 bits in two's complement form. It holds the sum
// of fewer than 2^64 values of j, with no wrap.
type int128 struct {
	hi int64
	lo uint64
}

// wide returns j as a number of 128 bits.
func wide(j int64) int128 { return int128{j >> 63, uint64(j)} }

// add returns the sum of a and b. It wraps at 2^128, which no sum of int64
// values reaches.
func (a int128) add(b int128) int128 {
	sum := int128{a.hi + b.hi, a.lo + b.lo}
	if sum.lo < a.lo { // the low words wrapped: carry 1 to the high word
		sum.hi++
	}
	return sum
}

// neg returns the number with the other sign.
func (a int128) neg() int128 {
	return int128{^a.hi, ^a.lo}.add(int128{0, 1})
}

// clamp returns the number, or the nearest end of the range of int64.
func (a int128) clamp() int64 {
	switch {
	case a.hi == 0 && a.lo <= math.MaxInt64, a.hi == -1 && a.lo > math.MaxInt64:
		return int64(a.lo)
	case a.hi < 0:
		return math.MinInt64
	}
	return math.MaxInt64
}

// sum returns the sum of j of the entry with the rowid id and the row time t.
// The entry takes the j of a reset row that holds id. It takes the j of a grace
// row that holds id only if t is before its `at`. This is one compare for each
// grace row. The step reads no index range for each `at`.
func (s *jumpSums) sum(id, t int64) int64 {
	base := s.at(id)
	if len(s.grace) == 0 {
		return base
	}
	total := wide(base)
	for _, g := range s.grace {
		if g.from <= id && id <= g.to && t < g.at {
			total = total.add(wide(g.j))
		}
	}
	return total.clamp()
}

// at returns the sum of j of the reset rows that hold the rowid id.
func (s *jumpSums) at(id int64) int64 {
	i, _ := slices.BinarySearchFunc(s.segs, id, func(g segment, id int64) int {
		switch {
		case g.hi < id:
			return -1
		case g.lo > id:
			return 1
		}
		return 0
	})
	return s.segs[i].sum
}

// shift returns the time before which a row with the sum acts. The row acts
// when its time plus the sum is before the cutoff. Thus its time must be before
// cutoff minus sum. The result stays in the range of int64.
func shift(cutoff, sum int64) int64 {
	switch {
	case sum > 0 && cutoff < math.MinInt64+sum:
		return math.MinInt64
	case sum < 0 && cutoff > math.MaxInt64+sum:
		return math.MaxInt64
	}
	return cutoff - sum
}

// An entry is one entry of an index: the rowid and the row time.
type entry struct{ id, ts int64 }

// A readSQL holds the two statements of a cursor read. Each selects the rowid
// and the time of at most `limit` entries of one index. The order is time, then
// rowid. The eq statement has the entries with the time of the cursor and a
// larger rowid. The gt statement has the entries with a later time and a time
// before the end. Together they read at most `limit` entries. This holds also
// when more than `limit` entries have one time.
//
// Each statement takes these bound values, in this order. They are the lead
// values, two values of the time terms, the tail values and the limit. The eq
// values are a time and a rowid. The gt values are a time and the end.
type readSQL struct{ eq, gt string }

// cursorRead makes the statements of the index `index` of `table`. lead and
// tail are the terms of the WHERE text before and after the time terms. They
// are the only filters. Each of them is a term of the index.
func cursorRead(table, idCol, timeCol, index, lead, tail string) readSQL {
	from := "SELECT " + idCol + ", " + timeCol + " FROM " + table + " INDEXED BY " + index + " WHERE " + lead
	return readSQL{
		eq: from + timeCol + " = ? AND " + idCol + " > ?" + tail + " ORDER BY " + idCol + " LIMIT ?",
		gt: from + timeCol + " > ? AND " + timeCol + " < ?" + tail + " ORDER BY " + timeCol + ", " + idCol + " LIMIT ?",
	}
}

// An indexRead is the cursor read of one step on one index. cur is the last
// entry that a call read. The step keeps it for the run. newIndexRead sets
// lead. A caller that has tail values sets tail before the first read.
type indexRead struct {
	sql        readSQL
	lead, tail []any
	cur        entry
}

// newIndexRead returns a read of q with the lead values. Its cursor is before
// each entry.
func newIndexRead(q readSQL, lead ...any) *indexRead {
	return &indexRead{sql: q, lead: lead, cur: entry{math.MinInt64, math.MinInt64}}
}

// read returns at most limit entries after the cursor, with a time before end.
// It moves the cursor to the last entry that it returns. An answer with fewer
// than limit entries means that no entry before end is left.
func (r *indexRead) read(ctx context.Context, tx *sql.Tx, end int64, limit int) ([]entry, error) {
	if r.cur.ts >= end {
		return nil, nil
	}
	es, err := r.query(ctx, tx, r.sql.eq, r.cur.id, limit)
	if err != nil || len(es) == limit {
		return es, r.move(es, err)
	}
	more, err := r.query(ctx, tx, r.sql.gt, end, limit-len(es))
	es = append(es, more...)
	return es, r.move(es, err)
}

// move puts the cursor on the last of the entries es.
func (r *indexRead) move(es []entry, err error) error {
	if n := len(es); err == nil && n > 0 {
		r.cur = es[n-1]
	}
	return err
}

// query runs q with the cursor time and the value b.
func (r *indexRead) query(ctx context.Context, tx *sql.Tx, q string, b int64, limit int) ([]entry, error) {
	args := slices.Concat(r.lead, []any{r.cur.ts, b}, r.tail, []any{limit})
	rows, err := tx.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var es []entry
	for rows.Next() {
		var e entry
		if err := rows.Scan(&e.id, &e.ts); err != nil {
			return nil, err
		}
		es = append(es, e)
	}
	return es, rows.Err()
}

// A corrected is a retention step with the clock_jump correction. This is the
// one place of the correction code.
//
// A call reads at most `limit` index entries, with no other filter than the
// index terms. It adds to each entry the sum of j of its rowid. A grace row
// gives its j only when the time of the entry is before its `at` (see
// jumpSums.sum). It acts, by rowid, on the entries with a corrected time before
// the cutoff. The read ends at the time "cutoff minus low". Here low is the
// smallest sum that any entry can get, at most 0. Thus no entry that can act
// lies after the end.
//
// With no clock_jump range, a call runs `plain`. It is the statement that the
// step had before the correction. The behavior of the step does not change.
type corrected struct {
	kind   rowKind
	cutoff int64
	// gate gives an end in stored time. No row with a stored time at or after
	// it acts, whatever its sum. A nil gate has no such end.
	gate  func(context.Context, *sql.Tx) (int64, error)
	plain retentionStep
	// reads has one read for each statement form. A call reads them in order.
	reads []*indexRead
	act   string // the statement that takes a JSON array of rowids
	mem   member
}

// step returns the retention step. It returns the count of the entries that it
// read, at most `limit`. A count below `limit` means that no entry before the
// end is left.
func (c *corrected) step() retentionStep {
	return func(ctx context.Context, tx *sql.Tx, limit int) (int, error) {
		js, err := c.kind.sums(ctx, tx)
		if err != nil {
			return 0, err
		}
		if js == nil {
			return c.plain(ctx, tx, limit)
		}
		stored := int64(math.MaxInt64)
		if c.gate != nil {
			if stored, err = c.gate(ctx, tx); err != nil {
				return 0, err
			}
		}
		n := 0
		for _, r := range c.reads {
			m, err := c.run(ctx, tx, r, js, stored, limit-n)
			if n += m; err != nil || n >= limit {
				return n, err
			}
		}
		return n, nil
	}
}

// run reads the entries of r. The read ends before `stored`, so that each
// entry has a stored time before it. The test of each entry repeats that term
// as a second guard. run acts on the entries with a corrected time before the
// cutoff. It returns the count of the entries that it read.
func (c *corrected) run(ctx context.Context, tx *sql.Tx, r *indexRead, js *jumpSums, stored int64, limit int) (int, error) {
	es, err := r.read(ctx, tx, min(shift(c.cutoff, js.low), stored), limit)
	if err != nil {
		return 0, err
	}
	ids := []byte{'['}
	for _, e := range es {
		if e.ts < min(shift(c.cutoff, js.sum(e.id, e.ts)), stored) {
			if len(ids) > 1 {
				ids = append(ids, ',')
			}
			ids = strconv.AppendInt(ids, e.id, 10)
		}
	}
	if len(ids) > 1 {
		_, err = execCount(ctx, tx, c.mem, c.act, string(append(ids, ']')))
	}
	return len(es), err
}
