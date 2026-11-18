package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cybagard/cyba-phantom/internal/event"
	"github.com/cybagard/cyba-phantom/internal/sensortime"
)

const (
	testBootID = "11111111-1111-4111-8111-111111111111"
	insertEv   = "INSERT INTO event (ts, kind) VALUES (1, 'request')"
	insertSes  = "INSERT INTO session (id, first_seen, last_seen, ip_hmac, band) VALUES (?, 1, 1, 'h', 'human')"
)

// wall0 is the wall clock of a fake source at boot clock 0, in unix ms.
var wall0 = time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC).UnixMilli()

// fakeSrc is a source that a test drives. The wall clock follows the boot clock
// and adds skew ms. walls counts the reads of the wall clock.
type fakeSrc struct {
	boot, skew, walls atomic.Int64
}

func (f *fakeSrc) source() sensortime.Source {
	return sensortime.Source{
		Wall: func() time.Time {
			f.walls.Add(1)
			return time.UnixMilli(wall0 + f.boot.Load()/int64(time.Millisecond) + f.skew.Load())
		},
		BootClock: func() (time.Duration, error) { return time.Duration(f.boot.Load()), nil },
		BootID:    func() (string, error) { return testBootID, nil },
	}
}

// at sets the boot clock.
func (f *fakeSrc) at(d time.Duration) { f.boot.Store(int64(d)) }

// clockRig is a rig with a started clock.
func clockRig(t *testing.T) (*rig, *fakeSrc) {
	t.Helper()
	r, f := newRig(t, 8), &fakeSrc{}
	if err := r.w.StartClock(f.source()); err != nil {
		t.Fatal(err)
	}
	return r, f
}

func (r *rig) key() sensortime.State {
	r.t.Helper()
	st, err := sensortime.Decode(metaValue(r.t, r.db, sensorTimeKey))
	if err != nil {
		r.t.Fatal(err)
	}
	return st
}

// twoTicks sends two ticks. The writer reads the second only after it has
// served the first.
func (r *rig) twoTicks() {
	r.t.Helper()
	r.fire()
	r.fire()
}

// jumpRows returns each clock_jump row as text.
func jumpRows(t *testing.T, db *sql.DB) string {
	t.Helper()
	return rawText(t, db, "SELECT coalesce(group_concat(id||','||event_from||','||event_to||','||session_from||','||session_to||','||j||','||at, ' '), '') FROM clock_jump")
}

// dbText gives the meta rows and the clock_jump rows as one text.
func dbText(t *testing.T, db *sql.DB) string {
	t.Helper()
	return rawText(t, db, "SELECT group_concat(key||'='||value, '|') FROM (SELECT * FROM meta ORDER BY key)") + "#" + jumpRows(t, db)
}

// T-U-18: a database of schema 5 gets schema 6. clock_jump is empty. The two
// old keys are gone. The other meta rows stay. A second Migrate passes the
// event table check.
func TestTU18MigrationFromSchema5AddsClockJump(t *testing.T) {
	db, _ := opened(t)
	if err := migrate(db, schema5Set(t), "origin"); err != nil {
		t.Fatal(err)
	}
	mustExec(t, db, "INSERT INTO meta (key, value) VALUES ('retention_check', '1'), ('retention_mint_done', '2')")
	if err := Migrate(db, "origin"); err != nil {
		t.Fatal(err)
	}
	if v := metaValue(t, db, "schema_version"); v != "6" {
		t.Fatalf("schema_version %s", v)
	}
	if n := count(t, db, "SELECT count(*) FROM clock_jump"); n != 0 {
		t.Fatalf("%d clock_jump rows", n)
	}
	if n := count(t, db, "SELECT count(*) FROM meta WHERE key IN ('retention_check', 'retention_mint_done')"); n != 0 {
		t.Fatalf("%d old keys", n)
	}
	if o := metaValue(t, db, "tlog_origin"); o != "origin" {
		t.Fatalf("origin %s", o)
	}
	if err := Migrate(db, "origin"); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
}

// T-U-30: StartClock writes the key before it returns. The first rowids of the
// host boot are the next rowids. A start jump has no clock_jump row.
func TestTU30StartClockWritesTheKey(t *testing.T) {
	r, f := newRig(t, 8), &fakeSrc{}
	mustExec(t, r.db, insertEv)
	mustExec(t, r.db, insertEv)
	if err := r.w.StartClock(f.source()); err != nil || r.w.Err() != nil {
		t.Fatalf("StartClock %v, writer %v", err, r.w.Err())
	}
	st := r.key()
	if st.S != wall0 || st.BootID != testBootID || st.FirstEvent != 3 || st.NextEvent != 3 || st.FirstSession != 1 {
		t.Fatalf("key %+v", st)
	}
	if n := count(t, r.db, "SELECT count(*) FROM clock_jump"); n != 0 {
		t.Fatalf("%d clock_jump rows", n)
	}
}

// T-U-30: a crash in the first process of a host boot. The next start on the
// host boot takes the stored S plus the boot clock time. This holds with the
// wall clock 40 d ahead. It keeps the first rowids.
func TestTU30StartAfterACrashKeepsTheFirstRowids(t *testing.T) {
	r, f := newRig(t, 8), &fakeSrc{}
	for range 3 {
		mustExec(t, r.db, insertEv)
	}
	f.at(10 * time.Second)
	if err := r.w.StartClock(f.source()); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		mustExec(t, r.db, insertEv)
	}
	f.at(70 * time.Second)
	f.skew.Store((40 * 24 * time.Hour).Milliseconds())
	w2 := NewWriter(r.db, r.q, false, nil, r.w.rec)
	if err := w2.StartClock(f.source()); err != nil {
		t.Fatal(err)
	}
	if st := r.key(); st.S != wall0+70000 || st.FirstEvent != 4 || st.NextEvent != 6 {
		t.Fatalf("key %+v, want S %d, first 4, next 6", st, wall0+70000)
	}
}

// T-U-30: a stored value that does not decode gives the fixed error and changes
// no row. A Start error and a failed write also change no row.
func TestTU30BadStoredValueRefusesTheStart(t *testing.T) {
	r, f := clockRig(t)
	good := metaValue(t, r.db, sensorTimeKey)
	field := func(i int, v string) string {
		p := strings.Split(good, ";")
		p[i] = v
		return strings.Join(p, ";")
	}
	mustExec(t, r.db, "INSERT INTO clock_jump VALUES (7, 1, 1, 1, 1, 5, 5)")
	for name, bad := range map[string]string{"truncated": good[:len(good)-3], "not a number": field(1, "12a"),
		"out of range": field(1, "9223372036855"), "empty": ""} {
		mustExec(t, r.db, metaSetSQL, sensorTimeKey, bad)
		before := dbText(t, r.db)
		w := NewWriter(r.db, r.q, false, nil, r.w.rec)
		err := w.StartClock(f.source())
		var e *Error
		if !errors.As(err, &e) || e.Rule != ruleStoredClock || strings.Contains(err.Error(), bad) && bad != "" {
			t.Errorf("%s: error %v", name, err)
		}
		if after := dbText(t, r.db); after != before || w.clk != nil {
			t.Errorf("%s: rows changed:\n%s\n%s", name, before, after)
		}
	}
	mustExec(t, r.db, metaSetSQL, sensorTimeKey, good)
	before := dbText(t, r.db)
	w := NewWriter(r.db, r.q, false, nil, r.w.rec)
	src := f.source()
	src.BootID = func() (string, error) { return "", sensortime.ErrBootID }
	if err := w.StartClock(src); !errors.Is(err, sensortime.ErrBootID) {
		t.Errorf("boot id error: %v", err)
	}
	w.beforeCommit = func(*sql.Tx) error { return errors.New("no commit") }
	var e *Error
	if err := w.StartClock(f.source()); !errors.As(err, &e) || e.Rule != ruleDatabase || w.Err() != nil || w.clk != nil {
		t.Errorf("failed write: %v, stop %v", err, w.Err())
	}
	if after := dbText(t, r.db); after != before {
		t.Errorf("rows changed:\n%s\n%s", before, after)
	}
}

// T-U-30: the key is written when 1 h of boot clock has passed since the last
// write, not before.
func TestTU30KeyIsWrittenEachHour(t *testing.T) {
	r, f := clockRig(t)
	var n atomic.Int64
	r.w.beforeCommit = func(*sql.Tx) error { n.Add(1); return nil }
	stop := r.start()
	f.at(time.Hour - time.Millisecond)
	r.twoTicks()
	if n.Load() != 0 {
		t.Fatalf("%d writes before the hour", n.Load())
	}
	f.at(time.Hour)
	r.twoTicks()
	f.at(time.Hour + 30*time.Second)
	r.twoTicks()
	stop()
	if st := r.key(); n.Load() != 1 || st.BootClock != time.Hour {
		t.Fatalf("%d writes, boot clock of the key %v", n.Load(), st.BootClock)
	}
}

// T-U-30: the writer calls Check at most once for each minute of boot
// clock.
func TestTU30CheckRunsOnceForEachMinute(t *testing.T) {
	r, f := clockRig(t)
	stop := r.start()
	defer stop()
	base := f.walls.Load()
	for _, c := range []struct {
		at   time.Duration
		want int64
	}{{30 * time.Second, 0}, {61 * time.Second, 1}, {100 * time.Second, 1}, {121 * time.Second, 2}} {
		f.at(c.at)
		r.twoTicks()
		if got := f.walls.Load() - base; got != c.want {
			t.Fatalf("at %v: %d checks, want %d", c.at, got, c.want)
		}
	}
}

// T-U-30: a retention run writes the key before its first chunk. The write is
// not a run: the run makes one retention event.
func TestTU30RetentionRunWritesTheKeyFirst(t *testing.T) {
	r, f := clockRig(t)
	stop := r.start()
	defer stop()
	f.at(30 * time.Minute)
	var seen time.Duration
	step := func(ctx context.Context, tx *sql.Tx, limit int) (int, error) {
		v, _, err := metaGet(ctx, tx, sensorTimeKey)
		st, derr := sensortime.Decode(v)
		seen = st.BootClock
		return 0, errors.Join(err, derr)
	}
	ctx := withRun(context.Background(), &retentionRun{})
	if err := r.w.runSteps(ctx, []retentionStep{step}); err != nil {
		t.Fatal(err)
	}
	if n := count(t, r.db, "SELECT count(*) FROM event WHERE kind = 'retention'"); seen != 30*time.Minute || n != 1 {
		t.Fatalf("key boot clock %v at the first chunk, %d retention events", seen, n)
	}
}

// T-U-30: a clean stop writes the key after the last batch.
func TestTU30CleanStopWritesTheKey(t *testing.T) {
	r, f := clockRig(t)
	f.at(7 * time.Minute)
	r.q.Close()
	if err := r.run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if st := r.key(); st.BootClock != 7*time.Minute {
		t.Fatalf("boot clock of the key %v", st.BootClock)
	}
}

// graceJump makes a grace jump of 3 h at the boot clock of 2 min, with rows in
// the tables. The rows 4 to 6 of event and the row 1 of session are in the
// range. It returns when the writer has served the tick.
func graceJump(t *testing.T, r *rig, f *fakeSrc) {
	t.Helper()
	f.at(2 * time.Minute)
	f.skew.Store((3 * time.Hour).Milliseconds())
	r.twoTicks()
}

func rangeRig(t *testing.T) (*rig, *fakeSrc) {
	t.Helper()
	r, f := newRig(t, 8), &fakeSrc{}
	for range 3 {
		mustExec(t, r.db, insertEv)
	}
	if err := r.w.StartClock(f.source()); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		mustExec(t, r.db, insertEv)
	}
	mustExec(t, r.db, insertSes, "s1")
	return r, f
}

// T-U-30: a grace jump gives its row and the key in one commit. The row has
// the ranges of the host boot and J. Its at is the S of the jump. Readers get
// the new S.
func TestTU30GraceJumpWritesRowAndKey(t *testing.T) {
	r, f := rangeRig(t)
	stop := r.start()
	graceJump(t, r, f)
	stop()
	at := wall0 + 2*60000 + (3 * time.Hour).Milliseconds()
	st := r.key()
	want := fmt.Sprintf("1,4,6,1,1,10800000,%d", at)
	if got := jumpRows(t, r.db); got != want {
		t.Fatalf("rows %q, want %q", got, want)
	}
	if st.Jump.ID != 1 || st.Jump.Size != 10800000 || st.Jump.At != at || st.NextEvent != 7 {
		t.Fatalf("key %+v", st)
	}
	if s, err := r.w.clk.Now(); err != nil || s != at {
		t.Fatalf("Now %d %v, want %d", s, err, at)
	}
}

// failJumpKey makes each commit that holds the key of the first jump fail.
func failJumpKey(w *Writer) {
	w.beforeCommit = func(tx *sql.Tx) error {
		var v string
		if tx.QueryRow(readSensorTime).Scan(&v) == nil {
			if st, err := sensortime.Decode(v); err == nil && st.Jump.ID == 1 {
				return errors.New("no commit")
			}
		}
		return nil
	}
}

// T-U-30: a failed write of a jump leaves no row and no new key. It stops the
// writer. Now keeps the old S.
func TestTU30FailedJumpWriteStopsTheWriter(t *testing.T) {
	r, f := rangeRig(t)
	failJumpKey(r.w)
	stop := r.start()
	graceJump(t, r, f)
	stop()
	if st := r.key(); r.w.Err() == nil || st.Jump.ID != 0 || st.S != wall0 || jumpRows(t, r.db) != "" {
		t.Fatalf("stop %v, key %+v, rows %q", r.w.Err(), st, jumpRows(t, r.db))
	}
	if s, err := r.w.clk.Now(); err != nil || s != wall0+2*60000 {
		t.Fatalf("Now %d %v, want the old S", s, err)
	}
}

// T-U-30, SEC-40: in a disk pause, a grace jump writes its row and the key.
// After a crash (no shutdown, the database opens again) the jump record is
// there.
func TestTU30GraceJumpInADiskPauseSurvivesACrash(t *testing.T) {
	r, f := rangeRig(t)
	r.w.disk = func() (float64, error) { return 0.95, nil }
	stop := r.start()
	graceJump(t, r, f)
	stop()
	if !r.w.paused.Load() {
		t.Fatal("the writer did not pause")
	}
	if err := r.db.Close(); err != nil {
		t.Fatal(err)
	}
	db := mustOpen(t, r.root, "events.db")
	t.Cleanup(func() { db.Close() })
	st, err := sensortime.Decode(metaValue(t, db, sensorTimeKey))
	if err != nil || st.Jump.ID != 1 || st.Jump.Size != 10800000 {
		t.Fatalf("key %+v %v", st, err)
	}
	if want := fmt.Sprintf("1,4,6,1,1,10800000,%d", st.Jump.At); jumpRows(t, db) != want {
		t.Fatalf("rows %q, want %q", jumpRows(t, db), want)
	}
}

// graceMove moves the wall clock ahead of the boot clock by skew. The writer
// then moves S at its next check.
func graceMove(r *rig, f *fakeSrc, at, skew time.Duration) {
	f.at(at)
	f.skew.Store(skew.Milliseconds())
	r.twoTicks()
}

// T-U-30: grace moves of 7 min each. The key waits until the moves pass 10 min.
func TestTU30GraceMovesAreWrittenAfterTenMinutes(t *testing.T) {
	r, f := clockRig(t)
	stop := r.start()
	graceMove(r, f, time.Minute, 7*time.Minute)
	if st := r.key(); st.S != wall0 {
		t.Fatalf("key S %d after 7 min of moves, want %d", st.S, wall0)
	}
	graceMove(r, f, 2*time.Minute, 14*time.Minute)
	stop()
	if st := r.key(); st.S != wall0+2*60000+14*60000 {
		t.Fatalf("key S %d after 14 min of moves", st.S)
	}
}

// T-U-30: a crash before the write of 7 min of moves gives S back by less than
// 10 min. This is at the next start on the host boot.
func TestTU30CrashBeforeTheWriteOfGraceMovesLosesLessThanTenMinutes(t *testing.T) {
	r, f := clockRig(t)
	stop := r.start()
	graceMove(r, f, time.Minute, 7*time.Minute)
	stop()
	// The next start is on the same host boot, 30 s later.
	f.at(90 * time.Second)
	before, err := r.w.clk.Now()
	if err != nil {
		t.Fatal(err)
	}
	w2 := NewWriter(r.db, r.q, false, nil, r.w.rec)
	if err := w2.StartClock(f.source()); err != nil {
		t.Fatal(err)
	}
	if back := time.Duration(before-r.key().S) * time.Millisecond; back != 7*time.Minute {
		t.Fatalf("S went back %v, want 7 min", back)
	}
}

// T-U-30: the floor of the key never goes down. A delete of every row between
// two writes keeps the floor.
func TestTU30FloorSurvivesADelete(t *testing.T) {
	r, f := rangeRig(t)
	stop := r.start()
	f.at(time.Hour)
	r.twoTicks()
	if st := r.key(); st.NextEvent != 7 || st.NextSession != 2 {
		t.Fatalf("floors %d, %d", st.NextEvent, st.NextSession)
	}
	mustExec(t, r.db, "DELETE FROM event")
	mustExec(t, r.db, "DELETE FROM session")
	f.at(2 * time.Hour)
	r.twoTicks()
	stop()
	if st := r.key(); st.NextEvent != 7 || st.NextSession != 2 {
		t.Fatalf("floors %d, %d after the delete", st.NextEvent, st.NextSession)
	}
}

// T-U-30: the next grace row has an id above the largest stored id.
func TestTU30GraceRowIdIsAboveTheStoredId(t *testing.T) {
	r, f := newRig(t, 8), &fakeSrc{}
	mustExec(t, r.db, "INSERT INTO clock_jump VALUES (1, 1, 1, 1, 1, 5, 5)")
	if err := r.w.StartClock(f.source()); err != nil {
		t.Fatal(err)
	}
	stop := r.start()
	graceJump(t, r, f)
	stop()
	if n := count(t, r.db, "SELECT count(*) FROM clock_jump WHERE id = 2"); r.w.Err() != nil || n != 1 {
		t.Fatalf("stop %v, %d rows with id 2", r.w.Err(), n)
	}
}

// T-U-30: a stopped writer calls no Check and writes no key. A batch error
// stops it at a tick with a key write due. A batch error in the shutdown does
// the same.
func TestTU30StoppedWriterWritesNoKey(t *testing.T) {
	for _, closed := range []bool{false, true} {
		r, f := clockRig(t)
		var begins, commits atomic.Int64
		r.w.beforeBegin = func() error {
			if begins.Add(1) == 1 {
				return errors.New("no begin")
			}
			return nil
		}
		r.w.beforeCommit = func(*sql.Tx) error { commits.Add(1); return nil }
		f.at(time.Hour)
		r.add(event.KindRequest, 1)
		if closed {
			r.q.Close()
			r.run(context.Background())
		} else {
			stop := r.start()
			r.drained()
			r.twoTicks()
			stop()
		}
		if r.w.Err() == nil || commits.Load() != 0 {
			t.Errorf("closed %v: stop %v, %d commits", closed, r.w.Err(), commits.Load())
		}
	}
}
