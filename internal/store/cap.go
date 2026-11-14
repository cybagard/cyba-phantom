package store

import (
	"context"
	"database/sql"
	"errors"
	"io/fs"
	"strconv"
	"time"

	"github.com/cybagard/cyba-phantom/internal/event"
	"github.com/cybagard/cyba-phantom/internal/token"
)

const (
	// A run evicts down to capPercent of the cap.
	capPercent = 90

	// mintUnitMs is the length of a mint time unit (ADR-036), in ms.
	mintUnitMs = 600_000

	// The shrink step frees pages with one statement for each chunk. The first
	// statement frees at most shrinkFirst pages. After a fast statement, the
	// next one has at most twice the pages, and at most shrinkMax. After one
	// over shrinkBudget, it has half (ADR-040). A statement can still stall on
	// the file write. The pages of a statement are from 1 to 16.
	shrinkFirst  = 16
	shrinkMax    = 16
	shrinkBudget = 50 * time.Millisecond

	// Each seek reads the oldest row of one kind, band or table through an
	// index. The evidence delete picks its rowids through event_kind_ts.
	oldestEventSQL   = "SELECT ts FROM event WHERE kind = ? ORDER BY ts LIMIT 1"
	oldestSessionSQL = "SELECT last_seen FROM session WHERE band = ? ORDER BY last_seen LIMIT 1"
	oldestCounterSQL = "SELECT min(day) FROM ip_counter"
	oldestTokenSQL   = "SELECT first_cb_at FROM token WHERE first_cb_at IS NOT NULL ORDER BY first_cb_at LIMIT 1"
	evictEvidenceSQL = "DELETE FROM event WHERE id IN (SELECT id FROM event WHERE kind = ? AND ts < ? LIMIT ?)"

	// evictSeenSQL deletes the seen rows of one day, at most the limit. keptSQL
	// gives the bytes of the tables that no tier removes, with their indexes.
	evictSeenSQL = "DELETE FROM rollup_seen WHERE (day, vhost, band, family, session_id) IN " +
		"(SELECT day, vhost, band, family, session_id FROM rollup_seen WHERE day = ? LIMIT ?)"
	keptSQL = "SELECT coalesce(sum(pgsize), 0) FROM dbstat WHERE aggregate = TRUE AND name IN " +
		"(SELECT name FROM sqlite_schema WHERE tbl_name IN ('aggregate_day', 'checkpoint'))"

	// The reasons of a cap that a run does not meet.
	reasonKept, reasonStuck, reasonFault = "kept", "stuck", "fault"
)

// CapUnmet counts the runs that did not meet the cap, for each reason. These
// are the values of the reason label of phantom_retention_cap_unmet_total.
//   - Kept: the tables that no tier removes hold 90 % of the cap or more.
//     Tier 3 did not run (SEC-41).
//   - Stuck: the live pages stay above 90 % of the cap. No tier can remove a
//     row.
//   - Fault: the files of the cap could not be measured.
type CapUnmet struct {
	Kept, Stuck, Fault uint64
}

// evidenceKinds are the event kinds that have a hash. Tier 3 evicts them.
var evidenceKinds = []string{"callback", "score_change", "alert_sent", "bundle_load", "bundle_rejected", "retention"}

// A capSource is one kind of row of a tier. oldest gives the ts of its oldest
// row. evict removes at most limit rows with ts before end, and returns the
// rows that it removed.
type capSource struct {
	oldest func(ctx context.Context, tx *sql.Tx) (int64, bool, error)
	evict  func(ctx context.Context, tx *sql.Tx, end int64, limit int) (int, error)
}

// capRun is the state of the cap steps in one run (ADR-040). The schedule
// makes one for each run, so no state stays between runs.
//
// The trigger measure is the bytes of the database file and the WAL on disk.
// The loop measure is the live pages: pages in use, with no free page. A delete
// moves pages to the freelist, and the file does not shrink until the shrink
// step frees them.
// The WAL grows during the run. The last checkpoint empties it when no reader
// holds it. So the WAL is not in the loop measure.
type capRun struct {
	w      *Writer
	rel    string // the database name that SetMaxBytes checked
	limit  int64  // the cap, in bytes
	target int64
	tiers  [][]*capSource

	begun, over, done bool

	// unmet is called with a reason when the run does not meet the cap. It is
	// called one time at most in a run. It can be nil.
	unmet   func(reason string)
	counted bool

	// seenDay is the UTC date of a day whose last request row tier 1 evicted.
	// Its seen rows go in the next calls. keptKnown and kept hold the one read
	// of the kept bytes in a run.
	seenDay   string
	keptKnown bool
	kept      bool

	// keptBytes replaces the dbstat read. A test sets it; nil in production.
	keptBytes func(ctx context.Context, tx *sql.Tx) (int64, error)

	// The pages of the next shrink statement, and the least and the most
	// that the run used.
	stmtPages, minPages, maxPages int

	// measure replaces the live pages. A test sets it; nil in production.
	measure func(ctx context.Context, tx *sql.Tx) (int64, error)
}

// newCapRun makes the cap state for a cap of limit bytes. rel is the name that
// SetMaxBytes checked, relative to the state root. now is the time of the run.
func newCapRun(w *Writer, limit int64, rel string, now time.Time) *capRun {
	c := &capRun{w: w, rel: rel, limit: limit, target: limit / 100 * capPercent}
	order := newMintOrder(now)
	request := &capSource{
		oldest: func(ctx context.Context, tx *sql.Tx) (int64, bool, error) {
			return oldestOf(ctx, tx, oldestEventSQL, "request")
		},
		evict: func(ctx context.Context, tx *sql.Tx, end int64, limit int) (int, error) {
			n, err := viaTally(ctx, tx, newRollupStep(dayCut(end), 1), limit)
			if err != nil || n == 0 {
				return n, err
			}
			// With no request row left in the day, its seen rows go next.
			var left int
			if err := tx.QueryRowContext(ctx, rollupLeftSQL, end).Scan(&left); errors.Is(err, sql.ErrNoRows) {
				c.seenDay = rollupDay(end - 1)
			} else if err != nil {
				return 0, err
			}
			return n, nil
		},
	}
	refused := &capSource{
		oldest: func(ctx context.Context, tx *sql.Tx) (int64, bool, error) {
			return oldestOf(ctx, tx, oldestEventSQL, "refused", "beacon")
		},
		evict: func(ctx context.Context, tx *sql.Tx, end int64, limit int) (int, error) {
			return viaTally(ctx, tx, newRawDeleteStep(dayCut(end), 1), limit)
		},
	}
	counter := &capSource{
		oldest: func(ctx context.Context, tx *sql.Tx) (int64, bool, error) {
			var day sql.NullString
			if err := tx.QueryRowContext(ctx, oldestCounterSQL).Scan(&day); err != nil || !day.Valid {
				return 0, false, err
			}
			t, err := time.Parse(dayLayout, day.String)
			return t.UnixMilli(), err == nil, err
		},
		evict: func(ctx context.Context, tx *sql.Tx, end int64, limit int) (int, error) {
			return viaTally(ctx, tx, newCounterDeleteStep(dayCut(end), 1), limit)
		},
	}
	mint := &capSource{
		oldest: func(ctx context.Context, tx *sql.Tx) (int64, bool, error) { return order.oldest(ctx, tx) },
		evict: func(ctx context.Context, tx *sql.Tx, end int64, limit int) (int, error) {
			return order.evict(ctx, tx, end, limit)
		},
	}
	sess := &capSource{
		oldest: func(ctx context.Context, tx *sql.Tx) (int64, bool, error) {
			return oldestOf(ctx, tx, oldestSessionSQL, "human", "crawler", "agent-likely", "agent-confirmed")
		},
		evict: func(ctx context.Context, tx *sql.Tx, end int64, limit int) (int, error) {
			return viaTally(ctx, tx, newSessionExpireStep(dayCut(end), 1), limit)
		},
	}
	tok := &capSource{
		oldest: func(ctx context.Context, tx *sql.Tx) (int64, bool, error) {
			return seek(ctx, tx, oldestTokenSQL)
		},
		evict: func(ctx context.Context, tx *sql.Tx, end int64, limit int) (int, error) {
			return viaTally(ctx, tx, newTokenExpireStep(dayCut(end), 1), limit)
		},
	}
	evidence := &capSource{
		oldest: func(ctx context.Context, tx *sql.Tx) (int64, bool, error) {
			return oldestOf(ctx, tx, oldestEventSQL, evidenceKinds...)
		},
		evict: evictEvidence,
	}
	c.tiers = [][]*capSource{{request, refused, counter}, {mint, sess, tok}, {evidence}}
	return c
}

// withCap puts the cap steps before the last step of a run. That step is the
// mark step, which stays last. A cap of 0 or less adds no step. The run record
// tells the runner where the cap steps start. unmet is called with the reason,
// one time at most, when the run does not meet the cap. It can be nil.
func withCap(steps []retentionStep, run *retentionRun, w *Writer, capBytes int64, rel string, now time.Time, unmet func(string)) []retentionStep {
	if capBytes <= 0 || len(steps) == 0 {
		return steps
	}
	c, last := newCapRun(w, capBytes, rel, now), len(steps)-1
	c.unmet = unmet
	if run != nil {
		run.capAt = last + 1
	}
	return append(steps[:last:last], c.evict, c.shrink, steps[last])
}

// dayCut returns the tDel of a step for days = 1, so its cutoff is end.
func dayCut(end int64) time.Time { return time.UnixMilli(end).Add(24 * time.Hour) }

// viaTally runs a delete step and returns the rows that it changed. The roll-up
// and the delete steps count rows as rolled or deleted. The cap counts them as
// evicted.
func viaTally(ctx context.Context, tx *sql.Tx, step retentionStep, limit int) (int, error) {
	var sub tally
	_, err := step(context.WithValue(ctx, tallyKey{}, &sub), tx, limit)
	n := int(sub[memRolled] + sub[memDeleted])
	tallyRows(ctx, memEvicted, n)
	return n, err
}

// seek returns the integer that a query with one row gives.
func seek(ctx context.Context, tx *sql.Tx, q string, args ...any) (v int64, ok bool, err error) {
	ok, err = scanOne(tx.QueryRowContext(ctx, q, args...), &v)
	return v, ok, err
}

// oldestOf returns the least ts of the oldest rows of the keys. Each key is one
// seek through an index.
func oldestOf(ctx context.Context, tx *sql.Tx, q string, keys ...string) (ts int64, ok bool, err error) {
	for _, k := range keys {
		v, found, err := seek(ctx, tx, q, k)
		if err != nil {
			return 0, false, err
		}
		if found && (!ok || v < ts) {
			ts, ok = v, true
		}
	}
	return ts, ok, nil
}

// mintOrder is the order of the mint units for a run (ADR-036 decision 2). The
// units make a circle of 2^20. The unit of the run has the rank 2^19-1. A unit
// with a lower rank is older. A unit with a higher rank is later: the wall
// clock stepped back. Each unit has a rank, so the order sees every mint row.
type mintOrder struct {
	lo    int64 // the unit of rank 0
	start int64 // the start of the unit of the run, in unix ms
}

// newMintOrder makes the order for the time of a run. A time before the token
// epoch gives units near the top of the range, and the order still holds.
func newMintOrder(now time.Time) mintOrder {
	const mask = event.MintUnitLimit - 1
	epoch := token.Epoch().UnixMilli()
	n, units := now.UnixMilli()-epoch, int64(0)
	if units = n / mintUnitMs; n%mintUnitMs < 0 {
		units--
	}
	cu := int64(token.Unit(now))
	return mintOrder{lo: (cu - (event.MintUnitLimit/2 - 1)) & mask, start: epoch + units*mintUnitMs}
}

// ranges returns the unit ranges in the order of the ranks.
func (o mintOrder) ranges() [][2]int64 {
	if o.lo == 0 {
		return [][2]int64{{0, event.MintUnitLimit - 1}}
	}
	return [][2]int64{{o.lo, event.MintUnitLimit - 1}, {0, o.lo - 1}}
}

// rank returns the rank of a unit.
func (o mintOrder) rank(unit int64) int64 { return (unit - o.lo) & (event.MintUnitLimit - 1) }

// at returns the start time of a unit, in unix ms.
func (o mintOrder) at(unit int64) int64 {
	return o.start + (o.rank(unit)-(event.MintUnitLimit/2-1))*mintUnitMs
}

// oldest returns the start time of the oldest mint unit. For each set_id it
// seeks once for each range, through the primary key.
func (o mintOrder) oldest(ctx context.Context, tx *sql.Tx) (int64, bool, error) {
	best, ok := int64(0), false
	var set any = ""
	for {
		var next []byte
		if found, err := scanOne(tx.QueryRowContext(ctx, mintNextSQL, set), &next); err != nil || !found {
			return best, ok, err
		}
		set = next
		for _, r := range o.ranges() {
			unit, found, err := seek(ctx, tx, mintUnitSQL, next, r[0], r[1])
			if err != nil {
				return 0, false, err
			}
			if found {
				if t := o.at(unit); !ok || t < best {
					best, ok = t, true
				}
				break
			}
		}
	}
}

// evict deletes the mint units that start before end, oldest first in each
// set_id. A unit goes whole, with one statement. It deletes at most limit rows.
// A unit with more rows than the limit goes in parts. This is the known limit
// of the mint step (ADR-040). It returns the rows that it deleted.
func (o mintOrder) evict(ctx context.Context, tx *sql.Tx, end int64, limit int) (int, error) {
	left := limit
	var set any = ""
	for {
		var next []byte
		if found, err := scanOne(tx.QueryRowContext(ctx, mintNextSQL, set), &next); err != nil || !found {
			return limit - left, err
		}
		set = next
		for _, r := range o.ranges() {
			for {
				unit, found, err := seek(ctx, tx, mintUnitSQL, next, r[0], r[1])
				if err != nil {
					return 0, err
				}
				if !found || o.at(unit) >= end {
					break
				}
				var rows int
				if err := tx.QueryRowContext(ctx, mintCountSQL, next, unit, left+1).Scan(&rows); err != nil {
					return 0, err
				}
				if rows > left {
					if left == limit {
						_, err = execCount(ctx, tx, memEvicted, mintDeleteSQL, next, unit, left)
						return limit, err
					}
					return limit - left, nil
				}
				if _, err := execCount(ctx, tx, memEvicted, mintDropSQL, next, unit); err != nil {
					return 0, err
				}
				if left -= rows; left == 0 {
					return limit, nil
				}
			}
		}
	}
}

// evictEvidence deletes at most limit evidence rows with ts before end, one
// kind for each statement.
func evictEvidence(ctx context.Context, tx *sql.Tx, end int64, limit int) (int, error) {
	left := limit
	for _, k := range evidenceKinds {
		n, err := execCount(ctx, tx, memEvicted, evictEvidenceSQL, k, end, left)
		if err != nil {
			return 0, err
		}
		if left -= n; left == 0 {
			break
		}
	}
	return limit - left, nil
}

// pragmaInt reads a PRAGMA with one integer result.
func pragmaInt(ctx context.Context, tx *sql.Tx, name string) (v int64, err error) {
	err = tx.QueryRowContext(ctx, "PRAGMA "+name).Scan(&v)
	return v, err
}

// pages returns the page count, the free page count and the page size.
func pages(ctx context.Context, tx *sql.Tx) (count, free, size int64, err error) {
	for _, p := range []struct {
		name string
		to   *int64
	}{{"page_count", &count}, {"freelist_count", &free}, {"page_size", &size}} {
		if *p.to, err = pragmaInt(ctx, tx, p.name); err != nil {
			return 0, 0, 0, err
		}
	}
	return count, free, size, nil
}

// diskBytes returns the bytes of the database file and its WAL on disk. It
// reads them with Lstat through the state root, on the name that SetMaxBytes
// checked. It opens no file. With a bare name, it resolves no path. A missing
// WAL has 0 bytes. Any other Lstat error gives ok false. So does a result that
// is not a regular file. This is the cap fault.
func (c *capRun) diskBytes() (n int64, ok bool) {
	for i, name := range []string{c.rel, c.rel + "-wal"} {
		fi, err := c.w.rec.State.Lstat(name)
		if i == 1 && errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil || !fi.Mode().IsRegular() {
			return 0, false
		}
		n += fi.Size()
	}
	return n, true
}

// live returns the bytes of the pages in use.
func (c *capRun) live(ctx context.Context, tx *sql.Tx) (int64, error) {
	if c.measure != nil {
		return c.measure(ctx, tx)
	}
	count, free, size, err := pages(ctx, tx)
	return (count - free) * size, err
}

// evict is the eviction step. On its first call it tests if the disk bytes are
// above the cap. If so, each call evicts rows of one source and one UTC day.
// This goes on until the live bytes are at most 90 % of the cap. A call starts
// at tier 1. Thus a row stored between two chunks goes before any row of a
// later tier. A call returns the limit while it can have work left.
func (c *capRun) evict(ctx context.Context, tx *sql.Tx, limit int) (int, error) {
	if !c.begun {
		c.begun = true
		n, ok := c.diskBytes()
		if !ok {
			c.note(reasonFault)
			c.done = true
			return 0, nil
		}
		c.over = n > c.limit
	}
	if !c.over || c.done {
		return 0, nil
	}
	if c.seenDay != "" {
		// The seen rows of an evicted day go before the live check. Thus a run
		// that meets the target leaves none. They are not in the evicted count.
		n, err := execN(ctx, tx, evictSeenSQL, c.seenDay, limit)
		if err != nil {
			return 0, err
		}
		if n > 0 {
			return limit, nil
		}
		c.seenDay = ""
	}
	live, err := c.live(ctx, tx)
	if err != nil {
		return 0, err
	}
	if live <= c.target {
		c.done = true
		return 0, nil
	}
	for i, tier := range c.tiers {
		if i == len(c.tiers)-1 {
			if kept, err := c.keptOver(ctx, tx); err != nil {
				return 0, err
			} else if kept {
				c.note(reasonKept)
				c.done = true
				return 0, nil
			}
		}
		moved, stuck, err := c.work(ctx, tx, tier, limit)
		if err != nil {
			return 0, err
		}
		if stuck {
			break
		}
		if moved {
			return limit, nil
		}
	}
	c.note(reasonStuck)
	c.done = true
	return 0, nil
}

// note counts a cap that the run does not meet. A run counts one reason.
func (c *capRun) note(reason string) {
	if c.unmet != nil && !c.counted {
		c.unmet(reason)
	}
	c.counted = true
}

// keptOver tells if aggregate_day and checkpoint, with their indexes, hold 90 %
// of the cap or more. No tier removes these tables. The run reads dbstat one
// time, when tier 3 is the next tier to run (SEC-41).
func (c *capRun) keptOver(ctx context.Context, tx *sql.Tx) (bool, error) {
	if c.keptKnown {
		return c.kept, nil
	}
	var n int64
	var err error
	if c.keptBytes != nil {
		n, err = c.keptBytes(ctx, tx)
	} else {
		err = tx.QueryRowContext(ctx, keptSQL).Scan(&n)
	}
	if err != nil {
		return false, err
	}
	c.keptKnown, c.kept = true, n >= c.target
	return c.kept, nil
}

// work evicts rows of the source of the tier with the oldest UTC day. A tie
// goes to the first source. It returns moved false when the tier has no row
// left. It returns stuck true when that source has a row but removes none. The
// eviction then ends: no later tier runs, and the step cannot spin.
func (c *capRun) work(ctx context.Context, tx *sql.Tx, tier []*capSource, limit int) (moved, stuck bool, err error) {
	var pick *capSource
	var day int64
	for _, s := range tier {
		ts, ok, err := s.oldest(ctx, tx)
		if err != nil {
			return false, false, err
		}
		if d := rollupDayStart(ts); ok && (pick == nil || d < day) {
			pick, day = s, d
		}
	}
	if pick == nil {
		return false, false, nil
	}
	n, err := pick.evict(ctx, tx, day+rollupDayMs, limit)
	return n > 0, n == 0 && err == nil, err
}

// nextShrink returns the pages of the next shrink statement. n pages took
// `took`. After a statement of at most shrinkBudget, the result is n scaled to
// that budget, but at most 2n. A time of 0 or less counts as fast. After a
// longer statement, the result is n/2. It is in the range 1 to 16. A statement
// can still stall on the file write (ADR-040).
func nextShrink(n int, took time.Duration) int {
	if took > shrinkBudget {
		return max(n/2, 1)
	}
	next := int64(2 * n)
	if took > 0 {
		next = min(next, int64(float64(n)*float64(shrinkBudget)/float64(took)))
	}
	return int(min(max(next, 1), shrinkMax))
}

// shrink frees pages with one statement for each chunk, after the eviction. It
// stops when the file is at most 90 % of the cap or no free page is left. It
// does nothing when the disk bytes were not above the cap. It counts the freed
// pages. The pages of a statement come from the last one: see nextShrink.
func (c *capRun) shrink(ctx context.Context, tx *sql.Tx, limit int) (int, error) {
	if !c.over {
		return 0, nil
	}
	count, free, size, err := pages(ctx, tx)
	if err != nil || free == 0 || count*size <= c.target {
		return 0, err
	}
	if c.stmtPages == 0 {
		c.stmtPages = shrinkFirst
	}
	if c.minPages == 0 || c.stmtPages < c.minPages {
		c.minPages = c.stmtPages
	}
	c.maxPages = max(c.maxPages, c.stmtPages)
	start := c.w.now()
	if _, err := tx.ExecContext(ctx, "PRAGMA incremental_vacuum("+strconv.Itoa(c.stmtPages)+")"); err != nil {
		return 0, err
	}
	c.stmtPages = nextShrink(c.stmtPages, c.w.now().Sub(start))
	_, after, _, err := pages(ctx, tx)
	if err != nil || after >= free {
		return 0, err // no page freed: stop, not loop
	}
	tallyRows(ctx, memVacuumed, int(free-after))
	return limit, nil
}
