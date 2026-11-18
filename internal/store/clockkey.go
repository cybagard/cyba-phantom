package store

import (
	"context"
	"database/sql"
	"time"

	"github.com/cybagard/cyba-phantom/internal/sensortime"
)

const (
	clockName       = "sensor time"
	ruleClock       = "clock check failed"
	ruleStoredClock = "stored value is not valid"

	// sensorTimeKey is the meta key of the stored sensor time state.
	sensorTimeKey = "sensor_time"

	// checkEvery is the least boot clock time between two clock checks.
	// keyEvery is the most boot clock time between two key writes.
	checkEvery = time.Minute
	keyEvery   = time.Hour

	maxEventSQL    = "SELECT coalesce(max(id), 0) FROM event"
	maxSessionSQL  = "SELECT coalesce(max(rowid), 0) FROM session"
	maxJumpSQL     = "SELECT coalesce(max(id), 0) FROM clock_jump"
	insertJumpSQL  = "INSERT INTO clock_jump (id, event_from, event_to, session_from, session_to, j, at) VALUES (?, ?, ?, ?, ?, ?, ?)"
	readSensorTime = "SELECT value FROM meta WHERE key = '" + sensorTimeKey + "'"
)

// StartClock starts the sensor time (ADR-043). The caller calls it one time,
// before Run, and refuses the start on an error. It reads the stored state,
// the next rowids of event and session, and the largest clock_jump id. It
// calls sensortime.Start with them, and writes the key of the result before it
// returns. A start jump has no clock_jump row: only the key holds it.
//
// A stored value that does not decode gives an *Error with a fixed rule. A
// Start error is returned as it is. A failed write is an *Error. In each case
// the database keeps its old rows, and the writer has no clock and does not
// stop. Without a StartClock call, the writer has no clock and writes no key.
func (w *Writer) StartClock(src sensortime.Source) error {
	ctx := context.Background()
	in := sensortime.StartInput{Log: w.log}
	var v string
	switch ok, err := scanOne(w.db.QueryRowContext(ctx, readSensorTime), &v); {
	case err != nil:
		return fail(writerName, ruleDatabase)
	case ok:
		st, err := sensortime.Decode(v)
		if err != nil {
			return fail(clockName, ruleStoredClock)
		}
		in.Stored = &st
	}
	for _, q := range []struct {
		sql string
		to  *int64
	}{{maxEventSQL, &in.NextEvent}, {maxSessionSQL, &in.NextSession}, {maxJumpSQL, &in.KnownJumpID}} {
		if err := w.db.QueryRowContext(ctx, q.sql).Scan(q.to); err != nil {
			return fail(writerName, ruleDatabase)
		}
	}
	in.NextEvent++
	in.NextSession++
	clk, res, err := sensortime.Start(src, in)
	if err != nil {
		return err
	}
	w.clk, w.src = clk, src
	if err := w.writeKey(res.State, res.Jump); err != nil {
		w.clk = nil
		return err
	}
	w.lastCheck = res.State.BootClock
	return nil
}

// writeKey writes the key of st in one transaction. A grace jump adds its
// clock_jump row in the same transaction. The rowid floor of the key is the
// largest of three values. These are the floor that the writer wrote last, the
// floor of st, and the largest rowid plus 1. After the COMMIT it calls
// Committed. A failed write changes nothing and does not call Committed. The
// caller decides on a stop.
func (w *Writer) writeKey(st sensortime.State, jump *sensortime.JumpResult) error {
	ctx := context.Background()
	conn, err := w.db.Conn(ctx)
	if err != nil {
		return fail(writerName, ruleDatabase)
	}
	defer conn.Close()
	var tx *sql.Tx
	if w.beforeBegin != nil {
		err = w.beforeBegin()
	}
	if err == nil {
		tx, err = conn.BeginTx(ctx, nil)
	}
	if err != nil {
		return fail(writerName, ruleDatabase)
	}
	defer tx.Rollback() // no effect after COMMIT
	var ev, ses int64
	if tx.QueryRowContext(ctx, maxEventSQL).Scan(&ev) != nil ||
		tx.QueryRowContext(ctx, maxSessionSQL).Scan(&ses) != nil {
		return fail(writerName, ruleDatabase)
	}
	st.NextEvent = max(w.floorEvent, st.NextEvent, ev+1)
	st.NextSession = max(w.floorSession, st.NextSession, ses+1)
	if jump != nil && jump.Kind == sensortime.KindGrace {
		j := st.Jump
		if _, err := tx.ExecContext(ctx, insertJumpSQL, j.ID, j.FirstEvent,
			st.NextEvent-1, j.FirstSession, st.NextSession-1, j.Size, j.At); err != nil {
			return fail(writerName, ruleDatabase)
		}
	}
	v, err := st.Encode()
	if err != nil {
		return fail(clockName, ruleClock)
	}
	if _, err := tx.ExecContext(ctx, metaSetSQL, sensorTimeKey, v); err != nil {
		return fail(writerName, ruleDatabase)
	}
	err = nil
	if w.beforeCommit != nil {
		err = w.beforeCommit(tx)
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		return fail(writerName, ruleDatabase)
	}
	w.floorEvent, w.floorSession = st.NextEvent, st.NextSession
	w.lastKey = st.BootClock
	w.clk.Committed()
	return nil
}

// writeSnapshot writes the key of the state that Snapshot gives. A writer with
// no clock writes nothing. An error stops the writer and is returned.
func (w *Writer) writeSnapshot() error {
	if w.clk == nil {
		return nil
	}
	st, err := w.clk.Snapshot()
	if err == nil {
		err = w.writeKey(st, nil)
	} else {
		err = fail(clockName, ruleClock)
	}
	if err != nil {
		w.stop(err)
	}
	return err
}

// serveClock is for a tick of the flush. It runs in a pause too. It calls
// Check at most one time for each minute of boot clock. It writes the key when
// Check says so. Else it writes the key when 1 h of boot clock has passed
// since the last key write. A stopped writer does nothing. An error stops the
// writer.
func (w *Writer) serveClock() {
	if w.clk == nil || !w.Healthy() {
		return
	}
	bc, err := w.src.BootClock()
	if err != nil {
		w.stop(fail(clockName, ruleClock))
		return
	}
	if bc-w.lastCheck >= checkEvery {
		w.lastCheck = bc
		res, err := w.clk.Check()
		if err != nil {
			w.stop(fail(clockName, ruleClock))
			return
		}
		if res.Write {
			if err := w.writeKey(res.State, res.Jump); err != nil {
				w.stop(err)
			}
			return
		}
	}
	if bc-w.lastKey >= keyEvery {
		w.writeSnapshot()
	}
}
