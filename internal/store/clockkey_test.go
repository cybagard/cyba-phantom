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

	// storedText is the whole text of the error of a stored value that is not
	// valid.
	storedText = "store: sensor time stored value is not valid"
	maxRowid   = "9223372036854775807"
)

// wall0 is the wall clock of a fake source at boot clock 0, in unix ms.
var wall0 = time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC).UnixMilli()

// fakeSrc is a source that a test drives. The wall clock follows the boot clock
// and adds skew ms. walls counts the reads of the wall clock. A test can set
// onWall. It gets the count after each read, and the read does not see its
// changes.
type fakeSrc struct {
	boot, skew, walls atomic.Int64
	onWall            func(n int64)
}

func (f *fakeSrc) source() sensortime.Source {
	return sensortime.Source{
		Wall: func() time.Time {
			n := f.walls.Add(1)
			t := time.UnixMilli(wall0 + f.boot.Load()/int64(time.Millisecond) + f.skew.Load())
			if f.onWall != nil {
				f.onWall(n)
			}
			return t
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
		if !errors.As(err, &e) || e.Rule != ruleStoredClock || err.Error() != storedText {
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
// clock. The first Check is one minute after the start, not one minute after
// the boot clock 0.
func TestTU30CheckRunsOnceForEachMinute(t *testing.T) {
	r, f := newRig(t, 8), &fakeSrc{}
	f.at(10 * time.Minute)
	if err := r.w.StartClock(f.source()); err != nil {
		t.Fatal(err)
	}
	stop := r.start()
	defer stop()
	base := f.walls.Load()
	for _, c := range []struct {
		at   time.Duration
		want int64
	}{{10*time.Minute + 30*time.Second, 0}, {11 * time.Minute, 1}, {11*time.Minute + 40*time.Second, 1}, {12 * time.Minute, 2}} {
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
	return rangeRigOf(t, 8)
}

// rangeRigOf is rangeRig with a queue of the given depth.
func rangeRigOf(t *testing.T, depth int) (*rig, *fakeSrc) {
	t.Helper()
	r, f := newRig(t, depth), &fakeSrc{}
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

	// A delete of the top rows, then a new writer. The largest rowid plus 1
	// is still at or above the first rowid. So only the stored floor keeps 7
	// and 2.
	r, f = rangeRig(t)
	stop = r.start()
	f.at(time.Hour)
	r.twoTicks()
	stop()
	mustExec(t, r.db, "DELETE FROM event WHERE id > 4")
	mustExec(t, r.db, "DELETE FROM session")
	f.at(time.Hour + time.Minute)
	if err := NewWriter(r.db, r.q, false, nil, r.w.rec).StartClock(f.source()); err != nil {
		t.Fatal(err)
	}
	if st := r.key(); st.NextEvent != 7 || st.NextSession != 2 {
		t.Fatalf("floors %d, %d after the restart", st.NextEvent, st.NextSession)
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

// ruleOf gives the rule of err when err is an *Error.
func ruleOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Rule
	}
	return ""
}

// T-U-30: StartClock gives an error and writes no key. Five cases do this. One
// is a stop marker. One is a writer with no recovery. One is a read error. One
// is a largest rowid with no next rowid. One is a largest clock_jump id with no
// next id. The writer has no clock. It does not stop.
func TestTU30StartClockRefusals(t *testing.T) {
	for _, c := range []struct{ name, rule, sql string }{
		{"no recovery", ruleNoRecover, "-"},
		{"marker", ruleMarkerExists, ""},
		{"first read", ruleDBRead, "DROP TABLE meta"},
		{"jump read", ruleDBRead, "DROP TABLE clock_jump"},
		{"event rowid", ruleStoredClock, "INSERT INTO event (id, ts, kind) VALUES (" + maxRowid + ", 1, 'request')"},
		{"session rowid", ruleStoredClock, "INSERT INTO session (rowid, id, first_seen, last_seen, ip_hmac, band) VALUES (" + maxRowid + ", 's', 1, 1, 'h', 'human')"},
		{"jump id", ruleStoredClock, "INSERT INTO clock_jump VALUES (9223372036854, 1, 1, 1, 1, 5, 5)"},
	} {
		r := newRig(t, 8)
		switch c.sql {
		case "-":
			r.w.rec = Recovery{}
		case "":
			if err := makeMarker(r.root); err != nil {
				t.Fatal(err)
			}
		default:
			mustExec(t, r.db, c.sql)
		}
		if err := r.w.StartClock((&fakeSrc{}).source()); ruleOf(err) != c.rule || r.w.clk != nil || r.w.Err() != nil {
			t.Errorf("%s: error %v, stop %v", c.name, err, r.w.Err())
		}
		if c.sql != "DROP TABLE meta" && count(t, r.db, "SELECT count(*) FROM meta WHERE key = 'sensor_time'") != 0 {
			t.Errorf("%s: the key was written", c.name)
		}
	}
}

// T-U-30: a stored key with the last jump id has no next jump id, also with no
// clock_jump row. StartClock gives the fixed error and writes nothing.
func TestTU30StoredLastJumpIdRefusesTheStart(t *testing.T) {
	r, f := clockRig(t)
	st := r.key()
	st.Jump = sensortime.Jump{ID: lastJumpID, Size: 5, At: 5}
	v, err := st.Encode()
	if err != nil {
		t.Fatal(err)
	}
	mustExec(t, r.db, metaSetSQL, sensorTimeKey, v)
	before := dbText(t, r.db)
	w := NewWriter(r.db, r.q, false, nil, r.w.rec)
	if err := w.StartClock(f.source()); ruleOf(err) != ruleStoredClock || w.clk != nil || dbText(t, r.db) != before {
		t.Errorf("error %v", err)
	}
}

// T-U-30: the COMMIT of the start write works and the NORMAL pragma fails. The
// key is stored, StartClock gives the database error, and the writer has no
// clock and does not stop. A start with no hook takes the stored key on the
// same boot.
func TestTU30StartClockFailedNormalKeepsTheKey(t *testing.T) {
	r, f := newRig(t, 8), &fakeSrc{}
	r.w.beforePragma = func(s string) error {
		if s == "PRAGMA synchronous=NORMAL" {
			return errors.New("no pragma")
		}
		return nil
	}
	f.at(10 * time.Second)
	if err := r.w.StartClock(f.source()); ruleOf(err) != ruleDatabase || r.w.clk != nil || r.w.Err() != nil {
		t.Fatalf("error %v, stop %v", err, r.w.Err())
	}
	if st := r.key(); st.S != wall0+10000 || st.BootClock != 10*time.Second {
		t.Fatalf("key %+v", st)
	}
	r.w.beforePragma = nil
	f.at(20 * time.Second)
	f.skew.Store((40 * 24 * time.Hour).Milliseconds())
	if err := r.w.StartClock(f.source()); err != nil {
		t.Fatal(err)
	}
	if st := r.key(); st.S != wall0+20000 || st.BootClock != 20*time.Second {
		t.Fatalf("key %+v after the second start", st)
	}
}

// T-U-30: a running writer has a largest rowid of math.MaxInt64. Its key write
// stops the writer and changes no row.
func TestTU30KeyWriteRefusesAMaxRowid(t *testing.T) {
	for _, q := range []string{
		"INSERT INTO event (id, ts, kind) VALUES (" + maxRowid + ", 1, 'request')",
		"INSERT INTO session (rowid, id, first_seen, last_seen, ip_hmac, band) VALUES (" + maxRowid + ", 's', 1, 1, 'h', 'human')",
	} {
		r, f := clockRig(t)
		stop := r.start()
		mustExec(t, r.db, q)
		before := dbText(t, r.db)
		f.at(time.Hour)
		r.twoTicks()
		stop()
		if ruleOf(r.w.Err()) != ruleStoredClock || dbText(t, r.db) != before {
			t.Errorf("%s: stop %v", q, r.w.Err())
		}
	}
}

// T-U-30: a start jump is in the key and has no clock_jump row. The stored key
// has another boot id, and its S is more than 1 h before the wall.
func TestTU30StartJumpIsInTheKeyOnly(t *testing.T) {
	r, f := clockRig(t)
	src := f.source()
	src.BootID = func() (string, error) { return "22222222-2222-4222-8222-222222222222", nil }
	f.skew.Store((3 * time.Hour).Milliseconds())
	if err := NewWriter(r.db, r.q, false, nil, r.w.rec).StartClock(src); err != nil {
		t.Fatal(err)
	}
	j := r.key().Jump
	if j.ID != 1 || j.Size != (3*time.Hour).Milliseconds() || j.At != wall0+(3*time.Hour).Milliseconds() {
		t.Fatalf("jump %+v", j)
	}
	if n := count(t, r.db, "SELECT count(*) FROM clock_jump"); n != 0 {
		t.Fatalf("%d clock_jump rows", n)
	}
}

// floodRig is a rig with a started clock and 503 request events in the lanes.
// Its tick channel has room for one tick. on gets the number of each flush of
// the writer goroutine. So it can put a tick in the channel at that point.
func floodRig(t *testing.T, on func(n int, tick chan time.Time)) (*rig, *fakeSrc) {
	t.Helper()
	r, f := rangeRigOf(t, 600)
	tick, n := make(chan time.Time, 1), 0
	r.tick, r.w.tick = tick, tick
	r.w.disk = func() (float64, error) { n++; on(n, tick); return 0, nil }
	for i := range maxBatch + 3 {
		r.add(event.KindRequest, int64(i))
	}
	return r, f
}

// T-U-30: serveWaiting serves the clock. A tick waits at the flush of 500
// events, and the lanes are not empty. The jump row comes from that tick. The
// queue closes before the run, so no other tick serves the clock.
func TestTU30ServeWaitingServesTheClock(t *testing.T) {
	r, f := floodRig(t, func(n int, tick chan time.Time) {
		if n == 1 {
			tick <- time.Now()
		}
	})
	f.at(2 * time.Minute)
	f.skew.Store((3 * time.Hour).Milliseconds())
	r.q.Close()
	if err := r.run(context.Background()); err != nil || r.w.Err() != nil {
		t.Fatalf("run %v, stop %v", err, r.w.Err())
	}
	if n := count(t, r.db, "SELECT count(*) FROM clock_jump"); n != 1 {
		t.Fatalf("%d clock_jump rows", n)
	}
}

// T-U-30: a tick flushes the batch before it serves the clock. Tick A is for
// serveWaiting and tick B is for Run, with 3 events in the batch. The first
// Check is at A, and it makes no jump. It then moves the clock, so that the
// Check at B gives a jump. The range of that jump ends at the last row.
func TestTU30TickFlushesBeforeTheClock(t *testing.T) {
	deposited := make(chan struct{})
	r, f := floodRig(t, func(n int, tick chan time.Time) {
		if n < 3 {
			tick <- time.Now()
		}
		if n == 2 {
			close(deposited)
		}
	})
	f.at(2 * time.Minute)
	f.onWall = func(n int64) {
		if n == 2 {
			f.at(3 * time.Minute)
			f.skew.Store((3 * time.Hour).Milliseconds())
		}
	}
	stop := r.start()
	select {
	case <-deposited:
	case <-time.After(waitFor):
		t.Fatal("the writer did not flush twice")
	}
	r.twoTicks()
	stop()
	last := count(t, r.db, "SELECT max(id) FROM event")
	if to := count(t, r.db, "SELECT event_to FROM clock_jump"); last != 509 || to != last {
		t.Fatalf("event_to %d, last row %d", to, last)
	}
}

// T-U-30: betweenChunks serves the clock. A tick waits after chunk 1 of a run.
func TestTU30BetweenChunksServesTheClock(t *testing.T) {
	r, f := clockRig(t)
	tick, calls := make(chan time.Time, 1), 0
	r.tick, r.w.tick = tick, tick
	step := func(_ context.Context, _ *sql.Tx, limit int) (int, error) {
		if calls++; calls == 1 {
			f.at(2 * time.Minute)
			f.skew.Store((3 * time.Hour).Milliseconds())
			tick <- time.Now()
			return limit, nil // a full step: a second chunk follows
		}
		return 0, nil
	}
	stop := r.start()
	defer stop()
	if err := r.w.runSteps(context.Background(), []retentionStep{step}); err != nil {
		t.Fatal(err)
	}
	if n := count(t, r.db, "SELECT count(*) FROM clock_jump"); calls != 2 || n != 1 {
		t.Fatalf("%d step calls, %d clock_jump rows", calls, n)
	}
}

// T-U-30: a key write fails at the start of a retention run. The run gives the
// error, runs no chunk and makes no retention event. The writer stops.
func TestTU30FailedKeyWriteAtARunStopsTheRun(t *testing.T) {
	r, _ := clockRig(t)
	r.w.beforeCommit = func(*sql.Tx) error { return errors.New("no commit") }
	stop := r.start()
	defer stop()
	calls := 0
	step := func(context.Context, *sql.Tx, int) (int, error) { calls++; return 0, nil }
	err := r.w.runSteps(withRun(context.Background(), &retentionRun{}), []retentionStep{step})
	n := count(t, r.db, "SELECT count(*) FROM event WHERE kind = 'retention'")
	if ruleOf(err) != ruleDatabase || calls != 0 || n != 0 || r.w.Err() == nil {
		t.Fatalf("error %v, %d chunks, %d retention events, stop %v", err, calls, n, r.w.Err())
	}
}

// T-U-30: the key write sets synchronous=FULL before BEGIN, and NORMAL after
// the COMMIT.
func TestTU30KeyWriteUsesFullSync(t *testing.T) {
	r, level, seq := newRig(t, 8), -1, []string{}
	r.w.beforePragma = func(s string) error { seq = append(seq, s); return nil }
	r.w.beforeBegin = func() error { seq = append(seq, "BEGIN"); return nil }
	r.w.beforeCommit = func(tx *sql.Tx) error {
		seq = append(seq, "COMMIT")
		return tx.QueryRow("PRAGMA synchronous").Scan(&level)
	}
	if err := r.w.StartClock((&fakeSrc{}).source()); err != nil {
		t.Fatal(err)
	}
	const want = "PRAGMA synchronous=FULL BEGIN COMMIT PRAGMA synchronous=NORMAL"
	if got := strings.Join(seq, " "); got != want || level != 2 || count(t, r.db, "PRAGMA synchronous") != 1 {
		t.Fatalf("calls %q, level in the transaction %d", got, level)
	}
}

// T-U-30: a failed synchronous pragma of the key write is a database error. It
// stops the writer. A failed FULL leaves no row, the old key and the old S. A
// failed NORMAL comes after the COMMIT. The row and the key are there, and
// Committed has run, so Now gives the new S.
func TestTU30KeyWritePragmaFailureStopsTheWriter(t *testing.T) {
	for _, c := range []struct {
		stmt   string
		stored bool
	}{{"PRAGMA synchronous=FULL", false}, {"PRAGMA synchronous=NORMAL", true}} {
		r, f := rangeRig(t)
		r.w.beforePragma = func(s string) error {
			if s == c.stmt {
				return errors.New("no pragma")
			}
			return nil
		}
		stop := r.start()
		graceJump(t, r, f)
		stop()
		now, err := r.w.clk.Now()
		want := wall0 + 2*60000
		if c.stored {
			want += (3 * time.Hour).Milliseconds()
		}
		if got := r.key().Jump.ID != 0 && jumpRows(t, r.db) != ""; got != c.stored || now != want || err != nil || ruleOf(r.w.Err()) != ruleDatabase {
			t.Errorf("%s: stored %v, Now %d (want %d), stop %v", c.stmt, got, now, want, r.w.Err())
		}
	}
}
