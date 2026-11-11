package store

import (
	"context"
	"database/sql"
	"errors"
	"io/fs"
	"strings"
	"time"

	"github.com/cybagard/cyba-phantom/internal/event"
	"github.com/cybagard/cyba-phantom/internal/token"
)

const (
	// A run evicts down to capPercent of the cap.
	capPercent = 90

	// mintUnitMs is the length of a mint time unit (ADR-036), in ms.
	mintUnitMs = 600_000

	// Each seek reads the oldest row of one kind or band through an index. The
	// evidence delete picks its rowids through event_kind_ts.
	oldestEventSQL   = "SELECT ts FROM event WHERE kind = ? ORDER BY ts LIMIT 1"
	oldestSessionSQL = "SELECT last_seen FROM session WHERE band = ? ORDER BY last_seen LIMIT 1"
	evictEvidenceSQL = "DELETE FROM event WHERE id IN (SELECT id FROM event WHERE kind = ? AND ts < ? LIMIT ?)"
	mainFileSQL      = "SELECT file FROM pragma_database_list WHERE name = 'main'"
)

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
// The WAL grows during the run and the last checkpoint empties it, so it is not
// in the loop measure.
type capRun struct {
	w           *Writer
	max, target int64
	tiers       [][]*capSource
	skip        map[*capSource]bool // sources that removed no row

	begun, over, done bool

	// measure replaces the live pages. A test sets it; nil in production.
	measure func(ctx context.Context, tx *sql.Tx) (int64, error)
}

// newCapRun makes the cap state for a cap of max bytes. now is the time of the
// run. The mint rows are old by their unit, counted from now.
func newCapRun(w *Writer, max int64, now time.Time) *capRun {
	c := &capRun{w: w, max: max, target: max / 100 * capPercent, skip: map[*capSource]bool{}}
	request := &capSource{
		oldest: func(ctx context.Context, tx *sql.Tx) (int64, bool, error) {
			return oldestOf(ctx, tx, oldestEventSQL, "request")
		},
		evict: func(ctx context.Context, tx *sql.Tx, end int64, limit int) (int, error) {
			return viaTally(ctx, tx, newRollupStep(dayCut(end), 1), limit)
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
	mint := &capSource{
		oldest: func(ctx context.Context, tx *sql.Tx) (int64, bool, error) { return mintOldest(ctx, tx, now) },
		evict: func(ctx context.Context, tx *sql.Tx, end int64, limit int) (int, error) {
			return viaTally(ctx, tx, newMintStep(dayCut(end), 1), limit)
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
	evidence := &capSource{
		oldest: func(ctx context.Context, tx *sql.Tx) (int64, bool, error) {
			return oldestOf(ctx, tx, oldestEventSQL, evidenceKinds...)
		},
		evict: evictEvidence,
	}
	c.tiers = [][]*capSource{{request, refused}, {mint, sess}, {evidence}}
	return c
}

// withCap puts the cap steps before the last step of a run. That step is the
// mark step, which stays last. A cap of 0 or less adds no step. The run record
// tells the runner where the cap steps start.
func withCap(steps []retentionStep, run *retentionRun, w *Writer, max int64, now time.Time) []retentionStep {
	if max <= 0 || len(steps) == 0 {
		return steps
	}
	c, last := newCapRun(w, max, now), len(steps)-1
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

// oldestOf returns the least ts of the oldest rows of the keys. Each key is one
// seek through an index.
func oldestOf(ctx context.Context, tx *sql.Tx, q string, keys ...string) (ts int64, ok bool, err error) {
	for _, k := range keys {
		var v int64
		found, err := scanOne(tx.QueryRowContext(ctx, q, k), &v)
		if err != nil {
			return 0, false, err
		}
		if found && (!ok || v < ts) {
			ts, ok = v, true
		}
	}
	return ts, ok, nil
}

// mintOldest returns the start time of the oldest mint unit, in unix ms. For
// each set_id and each range of mintRanges, it seeks once through the primary
// key. The age of a unit is the unit of now minus the unit, modulo 2^20.
func mintOldest(ctx context.Context, tx *sql.Tx, now time.Time) (int64, bool, error) {
	if now.Before(token.Epoch()) {
		return 0, false, nil
	}
	cu, age := token.Unit(now), int64(-1)
	var set any = ""
	for {
		var next []byte
		if found, err := scanOne(tx.QueryRowContext(ctx, mintNextSQL, set), &next); err != nil || !found {
			if err != nil {
				return 0, false, err
			}
			break
		}
		for _, r := range mintRanges(cu) {
			var unit int64
			found, err := scanOne(tx.QueryRowContext(ctx, mintUnitSQL, next, r[0], r[1]), &unit)
			if err != nil {
				return 0, false, err
			}
			if found {
				age = max(age, (int64(cu)-unit)&(event.MintUnitLimit-1))
				break
			}
		}
		set = next
	}
	if age < 0 {
		return 0, false, nil
	}
	epoch := token.Epoch().UnixMilli()
	start := epoch + (now.UnixMilli()-epoch)/mintUnitMs*mintUnitMs
	return start - age*mintUnitMs, true, nil
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
// reads them through the state directory root with Lstat: it opens no file. The
// name comes from database_list. A missing WAL has 0 bytes.
func (c *capRun) diskBytes(ctx context.Context, tx *sql.Tx) (n int64, err error) {
	var file string
	if err = tx.QueryRowContext(ctx, mainFileSQL).Scan(&file); err != nil {
		return 0, err
	}
	base, err := stateBase(c.w.rec.State)
	if err != nil {
		return 0, err
	}
	rel, ok := strings.CutPrefix(file, base+"/")
	if !ok {
		return 0, fail(writerName, ruleDatabase)
	}
	for _, name := range []string{rel, rel + "-wal"} {
		fi, err := c.w.rec.State.Lstat(name)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return 0, err
		}
		n += fi.Size()
	}
	return n, nil
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
		n, err := c.diskBytes(ctx, tx)
		if err != nil {
			return 0, err
		}
		c.over = n > c.max
	}
	if !c.over || c.done {
		return 0, nil
	}
	live, err := c.live(ctx, tx)
	if err != nil {
		return 0, err
	}
	if live <= c.target {
		c.done = true
		return 0, nil
	}
	for _, tier := range c.tiers {
		if moved, err := c.work(ctx, tx, tier, limit); err != nil {
			return 0, err
		} else if moved {
			return limit, nil
		}
	}
	c.done = true
	return 0, nil
}

// work evicts rows of the source of the tier with the oldest UTC day. A tie
// goes to the first source. It returns false when the tier has no row left. A
// source that has a row but removes none is not asked again in this run.
func (c *capRun) work(ctx context.Context, tx *sql.Tx, tier []*capSource, limit int) (bool, error) {
	for {
		var pick *capSource
		var day int64
		for _, s := range tier {
			if c.skip[s] {
				continue
			}
			ts, ok, err := s.oldest(ctx, tx)
			if err != nil {
				return false, err
			}
			if d := rollupDayStart(ts); ok && (pick == nil || d < day) {
				pick, day = s, d
			}
		}
		if pick == nil {
			return false, nil
		}
		n, err := pick.evict(ctx, tx, day+rollupDayMs, limit)
		if err != nil {
			return false, err
		}
		if n > 0 {
			return true, nil
		}
		c.skip[pick] = true
	}
}

// shrink frees pages in steps of 1 000 after the eviction. It stops when the
// file is at most 90 % of the cap or no free page is left. It does nothing when
// the disk bytes were not above the cap. It counts the freed pages.
func (c *capRun) shrink(ctx context.Context, tx *sql.Tx, limit int) (int, error) {
	if !c.over {
		return 0, nil
	}
	count, free, size, err := pages(ctx, tx)
	if err != nil || free == 0 || count*size <= c.target {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, "PRAGMA incremental_vacuum(1000)"); err != nil {
		return 0, err
	}
	_, after, _, err := pages(ctx, tx)
	if err != nil || after >= free {
		return 0, err // no page freed: stop, not loop
	}
	tallyRows(ctx, memVacuumed, int(free-after))
	return limit, nil
}
