package store

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/note"

	"github.com/cybagard/cyba-phantom/internal/event"
	"github.com/cybagard/cyba-phantom/internal/tlog"
)

// fakeSpool keeps the notes that the sink gives it. check runs inside Add.
type fakeSpool struct {
	mu    sync.Mutex
	sizes []uint64
	check func()
	fails int // the next Add calls that return an error and keep nothing
}

func (s *fakeSpool) Add(size uint64, _ []byte) error {
	if s.check != nil {
		s.check()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fails > 0 {
		s.fails--
		return errors.New("spool failed")
	}
	s.sizes = append(s.sizes, size)
	return nil
}

func (s *fakeSpool) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sizes)
}

type sinkRig struct {
	*rig
	signer note.Signer
	v      note.Verifier
	spool  *fakeSpool
	sink   *Sink
}

func newSinkRig(t *testing.T) *sinkRig { return newSinkRigDepth(t, 10) }

func newSinkRigDepth(t *testing.T, depth int) *sinkRig {
	t.Helper()
	skey, vkey, err := note.GenerateKey(rand.Reader, "origin")
	if err != nil {
		t.Fatal(err)
	}
	s, err := note.NewSigner(skey)
	if err != nil {
		t.Fatal(err)
	}
	v, err := note.NewVerifier(vkey)
	if err != nil {
		t.Fatal(err)
	}
	r := &sinkRig{rig: newRig(t, depth), signer: s, v: v, spool: &fakeSpool{}}
	r.sink = NewSink(r.w, r.spool, "origin", v)
	return r
}

func (r *sinkRig) note(size uint64, root byte) []byte {
	r.t.Helper()
	msg, err := tlog.SignCheckpoint(r.signer, size, [32]byte{root})
	if err != nil {
		r.t.Fatal(err)
	}
	return msg
}

func (r *sinkRig) rowCount() (n int) {
	r.t.Helper()
	if err := r.db.QueryRow("SELECT count(*) FROM checkpoint").Scan(&n); err != nil {
		r.t.Fatal(err)
	}
	return n
}

// T-U-18: the sink checks the note, stores the row in a FULL transaction with the
// store time, and only then gives the note to the spool.
func TestTU18SinkStoresTheRowBeforeTheSpool(t *testing.T) {
	r := newSinkRig(t)
	r.w.clock = func() time.Time { return time.UnixMilli(1234) }
	var mode atomic.Int64
	r.w.beforeRowCommit = func(tx *sql.Tx) error {
		var m int64
		err := tx.QueryRow("PRAGMA synchronous").Scan(&m)
		mode.Store(m)
		return err
	}
	var rowsAtSpool atomic.Int64
	r.spool.check = func() { rowsAtSpool.Store(int64(r.rowCount())) }
	r.start()

	msg := r.note(7, 3)
	if err := r.sink.Add(7, msg); err != nil {
		t.Fatal(err)
	}
	if mode.Load() != 2 || rowsAtSpool.Load() != 1 || r.spool.count() != 1 {
		t.Errorf("synchronous %d (want 2), rows at spool %d (want 1), spool %d (want 1)", mode.Load(), rowsAtSpool.Load(), r.spool.count())
	}
	var size, at int64
	var root []byte
	var got string
	if err := r.db.QueryRow("SELECT tree_size, root_hash, signed_note, created_at FROM checkpoint").Scan(&size, &root, &got, &at); err != nil {
		t.Fatal(err)
	}
	if size != 7 || !bytes.Equal(root, append([]byte{3}, make([]byte, 31)...)) || got != string(msg) || at != 1234 {
		t.Errorf("row %d %x %q %d", size, root, got, at)
	}
	var m int
	if err := r.db.QueryRow("PRAGMA synchronous").Scan(&m); err != nil || m != 1 {
		t.Errorf("synchronous after the row: %d, %v", m, err)
	}

	other, _ := tlog.SignCheckpoint(r.signer, 8, [32]byte{})
	for name, c := range map[string]struct {
		size uint64
		msg  []byte
	}{"size 0": {0, r.note(0, 0)}, "size differs": {8, msg}, "bad note": {8, other[:len(other)-3]}} {
		if err := r.sink.Add(c.size, c.msg); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	if r.rowCount() != 1 || r.spool.count() != 1 {
		t.Errorf("a refused note changed rows (%d) or spool (%d)", r.rowCount(), r.spool.count())
	}
}

// T-U-18: the same note a second time is a success and changes nothing. Another
// note for the size stops the writer, and no later note goes to the spool.
func TestTU18SinkSecondAddAndForkSignal(t *testing.T) {
	r := newSinkRig(t)
	r.start()
	msg := r.note(5, 1)
	for range 2 {
		if err := r.sink.Add(5, msg); err != nil {
			t.Fatal(err)
		}
	}
	if r.rowCount() != 1 || r.spool.count() != 2 {
		t.Fatalf("rows %d (want 1), spool %d (want 2)", r.rowCount(), r.spool.count())
	}

	if err := r.sink.Add(5, r.note(5, 2)); err == nil {
		t.Fatal("a fork signal gave no error")
	}
	eventually(t, func() bool { return !r.w.Healthy() })
	if _, err := r.marker(); err != nil {
		t.Errorf("no stop marker: %v", err)
	}
	var got string
	if err := r.db.QueryRow("SELECT signed_note FROM checkpoint WHERE tree_size = 5").Scan(&got); err != nil || got != string(msg) {
		t.Errorf("the row changed: %v", err)
	}
	if err := r.sink.Add(5, msg); err == nil {
		t.Error("the sink took a note after the fork signal")
	}
	if err := r.sink.Add(9, r.note(9, 1)); err == nil {
		t.Error("the sink took a later note after the fork signal")
	}
	if r.spool.count() != 2 || r.sink.RowMissing() != 0 {
		t.Errorf("spool %d (want 2), missing %d (want 0)", r.spool.count(), r.sink.RowMissing())
	}
}

// T-U-18: a failed commit of the row gives an error and no note to the spool, and
// it stops the writer with the database rule, not the fork rule. The next note
// goes to the spool with no row, and the sink counts the missing row. With a
// healthy writer, no reply in 5 s gives an error and no note to the spool.
func TestTU18SinkHealthyWriterFailureGivesNoSpool(t *testing.T) {
	r := newSinkRig(t)
	r.w.beforeRowCommit = func(*sql.Tx) error { return errors.New("commit failed") }
	stop := r.start()
	msg := r.note(4, 1)
	err := r.sink.Add(4, msg)
	wantRule(t, err, writerName, ruleDatabase)
	if r.spool.count() != 0 || r.rowCount() != 0 {
		t.Fatalf("failed commit: error %v, spool %d, rows %d", err, r.spool.count(), r.rowCount())
	}
	eventually(t, func() bool { return !r.w.Healthy() })
	wantRule(t, r.w.Err(), writerName, ruleDatabase)
	if _, err := r.marker(); err != nil {
		t.Errorf("no stop marker: %v", err)
	}
	if err := r.sink.Add(4, msg); err != nil || r.spool.count() != 1 || r.rowCount() != 0 || r.sink.RowMissing() != 1 {
		t.Fatalf("after the stop: error %v, spool %d, rows %d, missing %d (want nil, 1, 0, 1)", err, r.spool.count(), r.rowCount(), r.sink.RowMissing())
	}
	if err := stop(); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}

	// No Run goroutine: the first request waits in the channel, the second finds
	// the channel full. Both end at the timeout.
	idle := newSinkRig(t)
	idle.sink.timeout = 20 * time.Millisecond
	for range 2 {
		begin := time.Now()
		if err := idle.sink.Add(4, idle.note(4, 1)); err == nil || time.Since(begin) > waitFor || idle.spool.count() != 0 {
			t.Fatalf("no reply: error %v, spool %d", err, idle.spool.count())
		}
	}
}

// T-U-18: when a row request stops the writer, the events that the writer took
// from the lanes and did not write are dropped and counted for their lane.
func TestTU18SinkRowStopCountsTheEventsTheWriterTook(t *testing.T) {
	r := newSinkRig(t)
	r.w.beforeRowCommit = func(*sql.Tx) error { return errors.New("commit failed") }
	r.start()
	for i := range 3 {
		r.add(event.KindRequest, int64(i))
	}
	r.add(event.KindAlertSent, 9)
	r.drained()
	err := r.sink.Add(4, r.note(4, 1))
	wantRule(t, err, writerName, ruleDatabase)
	eventually(t, func() bool { return !r.w.Healthy() })
	// The writer flushes the batch before the discard loop reads a tick, so the
	// counts are final when fire returns.
	r.fire()
	if got := r.w.Stats().Dropped; got != (Drops{Bulk: 3, Evidence: 1}) || r.rows() != 0 {
		t.Errorf("dropped %+v (want bulk 3, evidence 1), event rows %d (want 0)", got, r.rows())
	}
}

// T-U-18: a failed INSERT of the row gives the same result as a failed commit.
// The sink gets an error with the database rule, and the spool gets no note.
// No row exists. The writer stops with the database rule and leaves its marker.
func TestTU18SinkFailedRowInsertStopsTheWriter(t *testing.T) {
	r := newSinkRig(t)
	if _, err := r.db.Exec("CREATE TRIGGER refuse_row BEFORE INSERT ON checkpoint BEGIN SELECT RAISE(ABORT, 'refused'); END"); err != nil {
		t.Fatal(err)
	}
	stop := r.start()
	err := r.sink.Add(4, r.note(4, 1))
	wantRule(t, err, writerName, ruleDatabase)
	if r.spool.count() != 0 || r.rowCount() != 0 {
		t.Fatalf("failed insert: error %v, spool %d, rows %d", err, r.spool.count(), r.rowCount())
	}
	eventually(t, func() bool { return !r.w.Healthy() })
	wantRule(t, r.w.Err(), writerName, ruleDatabase)
	if _, err := r.marker(); err != nil {
		t.Errorf("no stop marker: %v", err)
	}
	if err := stop(); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

// T-U-18: a database error before the commit of the row also stops the writer.
// Here the database is closed, so the connection for the row fails.
func TestTU18SinkDatabaseErrorBeforeTheCommitStopsTheWriter(t *testing.T) {
	r := newSinkRig(t)
	stop := r.start()
	// A good row first: the writer has passed its start check before the close.
	if err := r.sink.Add(3, r.note(3, 1)); err != nil || r.spool.count() != 1 {
		t.Fatalf("good row: error %v, spool %d", err, r.spool.count())
	}
	if err := r.db.Close(); err != nil {
		t.Fatal(err)
	}
	err := r.sink.Add(4, r.note(4, 1))
	wantRule(t, err, writerName, ruleDatabase)
	if r.spool.count() != 1 {
		t.Fatalf("closed database: error %v, spool %d (want an error, 1)", err, r.spool.count())
	}
	eventually(t, func() bool { return !r.w.Healthy() })
	wantRule(t, r.w.Err(), writerName, ruleDatabase)
	if _, err := r.marker(); err != nil {
		t.Errorf("no stop marker: %v", err)
	}
	if err := stop(); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

// T-U-18: a writer that is not healthy, and no writer, give the verified note to
// the spool with no row, and the sink counts it.
func TestTU18SinkStoppedOrMissingWriterGivesTheSpoolTheNote(t *testing.T) {
	r := newSinkRig(t)
	r.w.stop(fail(writerName, ruleDatabase))
	none := NewSink(nil, r.spool, "origin", r.v)
	for i, s := range []*Sink{r.sink, none} {
		if err := s.Add(3, r.note(3, 1)); err != nil {
			t.Fatal(err)
		}
		if s.RowMissing() != 1 || r.spool.count() != i+1 || r.rowCount() != 0 {
			t.Errorf("sink %d: missing %d, spool %d, rows %d", i, s.RowMissing(), r.spool.count(), r.rowCount())
		}
	}
	if err := none.Add(3, []byte("junk")); err == nil || none.RowMissing() != 1 {
		t.Errorf("a note that does not verify: error %v, missing %d", err, none.RowMissing())
	}
}

// T-U-18: a writer that stopped for a fork signal gives an error, also when the
// sink did not see the reply. The spool gets no note and nothing is counted.
func TestTU18SinkTakesTheForkStateFromTheWriter(t *testing.T) {
	r := newSinkRig(t)
	r.w.stop(fail(writerName, ruleFork))
	for range 2 {
		if err := r.sink.Add(3, r.note(3, 1)); err == nil {
			t.Fatal("a stopped writer with the fork rule gave no error")
		}
	}
	if r.spool.count() != 0 || r.sink.RowMissing() != 0 {
		t.Errorf("spool %d (want 0), missing %d (want 0)", r.spool.count(), r.sink.RowMissing())
	}
}

// T-U-18: a request that ends with an error also gives the fork state of the
// writer. Here the writer stops for a fork signal, and the reply is another
// error, as when the timer ends first. The sink gives the fork rule. It takes
// no later note.
func TestTU18SinkRequestErrorTakesTheForkStateFromTheWriter(t *testing.T) {
	r := newSinkRig(t)
	go func() {
		rq := <-r.w.rows
		r.w.stop(fail(writerName, ruleFork))
		rq.reply <- fail(sinkName, ruleRowReply)
	}()
	wantRule(t, r.sink.Add(3, r.note(3, 1)), sinkName, ruleRowFork)
	if err := r.sink.Add(4, r.note(4, 1)); err == nil {
		t.Error("the sink took a note after the fork signal")
	}
	if r.spool.count() != 0 || r.sink.RowMissing() != 0 {
		t.Errorf("spool %d (want 0), missing %d (want 0)", r.spool.count(), r.sink.RowMissing())
	}
}

// T-U-18: the missing row is counted after the spool took the note. A failed
// spool call counts nothing, and the retry counts once.
func TestTU18SinkCountsTheMissingRowAfterTheSpool(t *testing.T) {
	r := newSinkRig(t)
	r.spool.fails = 1
	r.w.stop(fail(writerName, ruleDatabase))
	msg := r.note(3, 1)
	if err := r.sink.Add(3, msg); err == nil || r.sink.RowMissing() != 0 {
		t.Fatalf("failed spool: error %v, missing %d (want 0)", err, r.sink.RowMissing())
	}
	if err := r.sink.Add(3, msg); err != nil || r.sink.RowMissing() != 1 || r.spool.count() != 1 {
		t.Errorf("retry: error %v, missing %d, spool %d (want nil, 1, 1)", err, r.sink.RowMissing(), r.spool.count())
	}
}
