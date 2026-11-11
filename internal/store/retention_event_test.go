package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/cybagard/cyba-phantom/internal/event"
)

// serveWithRun is the run function of a schedule that has no running writer.
// Like runSteps, it takes the run record from the context.
func serveWithRun(r *rig) func(context.Context, []retentionStep) error {
	return func(ctx context.Context, steps []retentionStep) error {
		run, _ := ctx.Value(runKey{}).(*retentionRun)
		rq := retentionRequest{reply: make(chan error, 1), gone: ctx.Done(), steps: steps, run: run}
		r.w.serveRetention(ctx, r.tick, nil, rq)
		return <-rq.reply
	}
}

// scheduleRun makes one run of the schedule at rollTDel, with the days 7, 30
// and 90.
func scheduleRun(t *testing.T, r *rig, ctx context.Context) error {
	t.Helper()
	s, _ := fakeSchedule(t, r, time.UTC, rollTDel, nil)
	var err error
	s.run = func(ctx context.Context, steps []retentionStep) error {
		err = serveWithRun(r)(ctx, steps)
		return err
	}
	s.runOnce(ctx)
	return err
}

// retentionRows returns the number of retention rows.
func retentionRows(t *testing.T, r *rig) int {
	t.Helper()
	return count(t, r.db, "SELECT count(*) FROM event WHERE kind = 'retention'")
}

// seededDetail is the detail that a run over seedRetention gives. The members
// ip, fields and deleted have more than 1 000 rows. So each has rows in two
// chunks or more. The request rows cost 1 200, so rolled is in two chunks too.
func seededDetail() event.Detail {
	return event.Detail{
		"ip": event.Int(1200), "fields": event.Int(1200), "rolled": event.Int(400), "deleted": event.Int(1224),
		"evicted": event.Int(0), "vacuumed": event.Int(0),
		"cutoff_ip": event.Int(rollTDel.UnixMilli() - 7*24*3600*1000), "cutoff_raw": event.Int(rollCutoff(30)),
	}
}

// seedRetention seeds a known number of rows for each member. These are 1 200
// addresses, 1 200 field rows, 400 request rows, and 1 224 rows to delete.
func seedRetention(t *testing.T, db *sql.DB) {
	t.Helper()
	day := int64(24 * time.Hour / time.Millisecond)
	now := rollTDel.UnixMilli()
	// ip: 1200
	mustExec(t, db, `WITH RECURSIVE c(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM c WHERE i < 1199)
		INSERT INTO session (id, first_seen, last_seen, ip, ip_hmac, band)
		SELECT 'ip' || i, ?, ?, '192.0.2.1', 'h', 'human' FROM c`, now-8*day, now-8*day)
	for i := range 3 {
		mustExec(t, db, "INSERT INTO session (id, first_seen, last_seen, ip_hmac, band) VALUES (?, ?, ?, 'h', 'human')",
			fmt.Sprint("old", i), now-100*day, now-100*day)
	}
	addFull(t, db, "callback", 1200, now-50*day, 1)           // fields: 1200
	addEvents(t, db, "request", 400, now-40*day, 1, nil, nil) // rolled: 400
	addFull(t, db, "refused", 5, now-35*day, 1)               // deleted: 5
	addFull(t, db, "beacon", 4, now-35*day, 1)                // deleted: 4
	addFull(t, db, "callback", 7, now-100*day, 1)             // deleted: 7
	for i := range 2 {
		mustExec(t, db, "INSERT INTO token (token_id, session_id, trap_id, issued_at, first_cb_at) VALUES (?, 's', 't', 1, ?)",
			fmt.Sprint("t", i), now-100*day) // deleted: 2
	}
	// deleted: 1200
	mustExec(t, db, `WITH RECURSIVE c(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM c WHERE i < 1199)
		INSERT INTO ip_counter (day, ip_hmac, requests, dropped) SELECT '2000-01-01', 'h' || i, 1, 0 FROM c`)
	for _, first := range []int64{1, 11, 21} {
		addMintRow(t, db, 1, 1, first, 1) // deleted: 3
	}
	// The session delete removes the three old session rows: 3 more.
}

// T-U-11: a run of the schedule makes one retention event. It has a leaf
// index, its hash is the sha256 of its record, and it has no session. Each
// member is the number of rows that the statements changed. The request rows
// cost 1 200, so a sum of step costs would not give 400.
func TestTU11RetentionEventCountsRows(t *testing.T) {
	r := newRig(t, 8)
	seedRetention(t, r.db)
	r.app.next = 10_000 // above the leaf indexes of the seed
	var chunks int
	r.w.beforeCommit = func(*sql.Tx) error { chunks++; return nil }
	if err := scheduleRun(t, r, context.Background()); err != nil {
		t.Fatal(err)
	}
	if chunks < 2 {
		t.Fatalf("the run had %d chunks, want more than 1", chunks)
	}
	if n := retentionRows(t, r); n != 1 {
		t.Fatalf("%d retention rows, want 1", n)
	}
	var leaf sql.NullInt64
	var hash, rec []byte
	var sid sql.NullString
	var detail string
	check(t, r.db.QueryRow("SELECT leaf_index, hash, record, session_id, detail FROM event WHERE kind = 'retention'").
		Scan(&leaf, &hash, &rec, &sid, &detail))
	if sum := sha256.Sum256(rec); !leaf.Valid || sid.Valid || string(hash) != string(sum[:]) {
		t.Fatalf("leaf %v, session %v, hash is the sha256 of the record: %v", leaf, sid, string(hash) == string(sum[:]))
	}
	sameDetail(t, detail, seededDetail())
}

// sameDetail fails the test if the detail text has other members than want.
func sameDetail(t *testing.T, text string, want event.Detail) {
	t.Helper()
	got, err := event.ParseDetail(text)
	check(t, err)
	if len(got) != len(want) {
		t.Errorf("detail %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("member %s = %v, want %v", k, got[k], v)
		}
	}
}

// T-U-11: a full evidence lane does not drop the retention event. The event
// goes to flush, not to the lane.
func TestTU11RetentionEventSurvivesFullEvidenceLane(t *testing.T) {
	r := newRig(t, 8)
	addEvents(t, r.db, "request", 3, rollCutoff(30)-1000, 1, nil, nil)
	filled := 0
	for ; ; filled++ {
		e, err := event.NewEvent(nil, event.Input{Kind: event.KindCallback})
		check(t, err)
		if !r.q.Enqueue(e) {
			break
		}
	}
	if filled == 0 {
		t.Fatal("the lane took no event")
	}
	before := r.w.Stats().Dropped
	if err := scheduleRun(t, r, context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := retentionRows(t, r); n != 1 || r.w.Stats().Dropped != before {
		t.Fatalf("%d retention rows, drops %v before and %v after", n, before, r.w.Stats().Dropped)
	}
}

// T-U-11: in a disk pause the writer writes no retention row. It counts one
// evidence drop, and the run replies with no error.
func TestTU11RetentionEventDroppedInDiskPause(t *testing.T) {
	r := newRig(t, 8)
	r.w.disk = func() (float64, error) { return 0.95, nil }
	addEvents(t, r.db, "request", 3, rollCutoff(30)-1000, 1, nil, nil)
	if err := scheduleRun(t, r, context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := retentionRows(t, r); n != 0 || r.w.Stats().Dropped != (Drops{Evidence: 1}) || !r.w.Healthy() {
		t.Fatalf("%d retention rows, drops %v, healthy %v", n, r.w.Stats().Dropped, r.w.Healthy())
	}
}

// T-U-11: a run that the writer refuses at its start makes no event. A run with
// no run record makes none.
func TestTU11NoRetentionEventWithoutRun(t *testing.T) {
	r := newRig(t, 8)
	addEvents(t, r.db, "request", 3, rollCutoff(30)-1000, 1, nil, nil)
	gone, cancel := context.WithCancel(context.Background())
	cancel()
	if err := scheduleRun(t, r, gone); err == nil {
		t.Fatal("a run with an ended context did not fail")
	}
	if n := retentionRows(t, r); n != 0 || r.events() != 3 {
		t.Fatalf("%d retention rows, %d rows, want 0 and 3", n, r.events())
	}
	ctx := context.Background()
	rq := retentionRequest{reply: make(chan error, 1), gone: ctx.Done(), steps: runSteps(rollTDel, rollTDel, rollTDel, 7, 30, 90)}
	r.w.serveRetention(ctx, r.tick, nil, rq)
	if err := <-rq.reply; err != nil || r.events() != 0 || retentionRows(t, r) != 0 {
		t.Fatalf("no run record: error %v, %d rows", err, r.events())
	}
}

// T-U-11: a run that ends early after a committed chunk makes its event. The
// event counts the rows of the committed chunks.
func TestTU11RetentionEventAfterEarlyEnd(t *testing.T) {
	r := newRig(t, 8)
	addEvents(t, r.db, "request", 1500, rollCutoff(30)-2000, 1, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s, _ := fakeSchedule(t, r, time.UTC, rollTDel, nil)
	s.run = func(ctx context.Context, steps []retentionStep) error {
		steps[0] = onCall(steps[0], func(i int, _ *sql.Tx) {
			if i == 1 {
				cancel() // the first chunk commits, and the run then ends
			}
		})
		return serveWithRun(r)(ctx, steps)
	}
	s.runOnce(ctx)
	var detail string
	check(t, r.db.QueryRow("SELECT detail FROM event WHERE kind = 'retention'").Scan(&detail))
	got, err := event.ParseDetail(detail)
	check(t, err)
	left := int64(count(t, r.db, "SELECT count(*) FROM event WHERE kind = 'request'"))
	if got["rolled"] != event.Int(1500-left) || left == 0 || left == 1500 {
		t.Fatalf("rolled %v with %d request rows left of 1500", got["rolled"], left)
	}
}

// T-U-11: a chunk that does not commit adds nothing to the run record.
func TestTU11RolledBackChunkIsNotCounted(t *testing.T) {
	r := newRig(t, 8)
	addEvents(t, r.db, "request", 5, rollCutoff(30)-1000, 1, nil, nil)
	r.w.beforeCommit = func(*sql.Tx) error { return fmt.Errorf("no commit") }
	run, cur := &retentionRun{}, 0
	if _, err := r.w.chunkRun([]retentionStep{newRollupStep(rollTDel, 30)}, &cur, run); err == nil {
		t.Fatal("the chunk committed")
	}
	if run.counts != (event.RetentionCounts{}) {
		t.Fatalf("run record %+v after a rolled back chunk", run)
	}
}

// T-U-11: a run of the schedule through the running writer makes the event.
// The run function is the real Writer.runSteps. It takes the run record from
// the context.
func TestTU11RetentionEventThroughRunningWriter(t *testing.T) {
	r := newRig(t, 8)
	r.launchCancelable(context.Background())
	// The writer reads the tick only after its start check. The seed has
	// callback rows with no leaf in the log, so it comes after that check.
	r.fire()
	r.app.next = 10_000 // above the leaf indexes of the seed
	seedRetention(t, r.db)
	ctx, cancel := context.WithTimeout(context.Background(), waitFor)
	defer cancel()
	s, _ := fakeSchedule(t, r, time.UTC, rollTDel, nil)
	s.runOnce(ctx)
	if n := retentionRows(t, r); n != 1 {
		t.Fatalf("%d retention rows, want 1", n)
	}
	var detail string
	check(t, r.db.QueryRow("SELECT detail FROM event WHERE kind = 'retention'").Scan(&detail))
	sameDetail(t, detail, seededDetail())
}

// T-U-11: the address cutoff uses tPriv and the raw cutoff uses tDel. The wall
// clock is 30 min behind the monotonic clock, so tDel is before tPriv.
func TestTU11RetentionEventCutoffsUseTheirTimes(t *testing.T) {
	r := newRig(t, 8)
	addEvents(t, r.db, "request", 3, rollCutoff(30)-2*3600*1000, 1, nil, nil)
	s, f := fakeSchedule(t, r, time.UTC, rollTDel, nil)
	f.jump(-30 * time.Minute)
	s.run = serveWithRun(r)
	s.runOnce(context.Background())
	var detail string
	check(t, r.db.QueryRow("SELECT detail FROM event WHERE kind = 'retention'").Scan(&detail))
	sameDetail(t, detail, event.Detail{
		"ip": event.Int(0), "fields": event.Int(0), "rolled": event.Int(3), "deleted": event.Int(0),
		"evicted": event.Int(0), "vacuumed": event.Int(0),
		"cutoff_ip":  event.Int(rollTDel.UnixMilli() - 7*24*3600*1000),
		"cutoff_raw": event.Int(rollCutoff(30) - 30*60*1000),
	})
}

// T-U-11: when the write of the event stops the writer, the run replies with
// the error of the stop. The row is not stored.
func TestTU11RetentionEventWriteStopsTheWriter(t *testing.T) {
	r := newRig(t, 8)
	r.app.err = errors.New("append failed")
	addEvents(t, r.db, "request", 3, rollCutoff(30)-1000, 1, nil, nil)
	err := scheduleRun(t, r, context.Background())
	if err == nil || r.w.Healthy() || err != r.w.Err() {
		t.Fatalf("reply %v, writer error %v, healthy %v", err, r.w.Err(), r.w.Healthy())
	}
	if n := retentionRows(t, r); n != 0 {
		t.Fatalf("%d retention rows after a failed append", n)
	}
}

// T-U-11: a writer that stops after a committed chunk makes no event and counts
// no drop. The run ends early.
func TestTU11StoppedWriterMakesNoRetentionEvent(t *testing.T) {
	r := newRig(t, 8)
	addEvents(t, r.db, "request", 1500, rollCutoff(30)-2000, 1, nil, nil)
	s, _ := fakeSchedule(t, r, time.UTC, rollTDel, nil)
	s.run = func(ctx context.Context, steps []retentionStep) error {
		steps[0] = onCall(steps[0], func(i int, _ *sql.Tx) {
			if i == 1 {
				// The chunk commits after this call.
				r.w.stop(fail(writerName, ruleDatabase))
			}
		})
		return serveWithRun(r)(ctx, steps)
	}
	s.runOnce(context.Background())
	if r.events() == 1500 {
		t.Fatal("no chunk committed")
	}
	if n := retentionRows(t, r); n != 0 || r.w.Stats().Dropped != (Drops{}) {
		t.Fatalf("%d retention rows, drops %v", n, r.w.Stats().Dropped)
	}
}
