package store

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/cybagard/cyba-phantom/internal/event"
	"github.com/cybagard/cyba-phantom/internal/tlog"
)

// realLog opens a log below a temporary state directory, as the tlog tests do.
func realLog(t *testing.T) *tlog.Log {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "state") // mode 0700, as the log needs
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	l, err := tlog.OpenLog(root, "tlog")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l
}

// T-I-07: with the real log, each stored evidence row verifies against the root
// of the log size after the writes, with the proof from the log. The leaf index
// of the row is its place in the log.
func TestTI07StoredEvidenceRowsVerifyAgainstTheRealLog(t *testing.T) {
	r := newRig(t, 2000)
	l := realLog(t)
	r.w.app = l
	want := 0
	for i := int64(0); i < 1100; i++ {
		kind := event.KindRequest
		if i%11 == 0 {
			kind = event.KindCallback
			want++
		}
		r.add(kind, i)
	}
	r.q.Close()
	if err := r.run(context.Background()); err != nil || !r.w.Healthy() {
		t.Fatalf("Run returned %v, writer error %v", err, r.w.Err())
	}
	size, _ := l.Head()
	root, err := l.RootAt(size)
	if err != nil || size != int64(want) {
		t.Fatalf("log size %d, want %d: %v", size, want, err)
	}
	rows, err := r.db.Query("SELECT hash, leaf_index FROM event WHERE leaf_index IS NOT NULL ORDER BY leaf_index")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	n := int64(0)
	for ; rows.Next(); n++ {
		var hash []byte
		var leaf int64
		var h tlog.EventHash
		if err := rows.Scan(&hash, &leaf); err != nil || copy(h[:], hash) != len(h) || leaf != n {
			t.Fatalf("row %d: leaf %d, %d hash bytes, %v", n, leaf, len(hash), err)
		}
		proof, err := l.ProveInclusion(leaf, size)
		if err != nil {
			t.Fatal(err)
		}
		if err := tlog.VerifyInclusion(h, leaf, size, root, proof); err != nil {
			t.Fatalf("leaf %d does not verify: %v", leaf, err)
		}
	}
	if n != size {
		t.Fatalf("%d evidence rows for %d leaves", n, size)
	}
}

// T-U-18: a failed COMMIT after a good AppendBatch call leaves the leaves in the
// real log and no row in the database. The writer counts each leaf as an orphan
// leaf and stops.
func TestTU18FailedCommitCountsOrphanLeavesAndStops(t *testing.T) {
	r := newRig(t, 100)
	l := realLog(t)
	r.w.app = l
	r.w.beforeCommit = func(*sql.Tx) error { return errors.New("commit refused") }
	r.add(event.KindRequest, 1)
	for i := int64(2); i < 6; i++ {
		r.add(event.KindCallback, i)
	}
	r.q.Close()
	if err := r.run(context.Background()); err != nil {
		t.Fatal(err)
	}
	wantRule(t, r.w.Err(), writerName, ruleDatabase)
	size, _ := l.Head()
	if s := r.w.Stats(); r.w.Healthy() || s.OrphanLeaves != 4 || s.WriteFailed != 0 || size != 4 {
		t.Fatalf("healthy %v, stats %+v, log size %d", r.w.Healthy(), s, size)
	}
	if r.rows() != 0 || len(r.commits) != 0 {
		t.Fatalf("%d rows, %d commits after the failed COMMIT", r.rows(), len(r.commits))
	}
}

// T-U-18: a transaction with an evidence row runs with synchronous=FULL. A batch
// with bulk rows only stays on NORMAL. NORMAL is set again after each batch,
// after a rollback too. The value is read inside the transaction.
func TestTU18EvidenceTransactionUsesSynchronousFull(t *testing.T) {
	const normal, full = 1, 2
	r := newRig(t, 100)
	var inTx int
	r.w.beforeCommit = func(tx *sql.Tx) error {
		return tx.QueryRow("PRAGMA synchronous").Scan(&inTx)
	}
	for _, c := range []struct {
		name   string
		kinds  []event.Kind
		inTx   int
		failed bool
	}{
		{"bulk only", []event.Kind{event.KindRequest, event.KindBeacon}, normal, false},
		{"with evidence", []event.Kind{event.KindRequest, event.KindCallback}, full, false},
		{"rolled back", []event.Kind{event.KindCallback}, full, true},
	} {
		var batch []*event.Event
		for i, k := range c.kinds {
			batch = append(batch, rowEvent(t, k, false, int64(i)))
		}
		if c.failed {
			r.app.next = -1 // the insert is refused, the transaction rolls back
		}
		err := r.w.write(batch)
		var after int
		if e := r.db.QueryRow("PRAGMA synchronous").Scan(&after); e != nil {
			t.Fatal(e)
		}
		if (err != nil) != c.failed || after != normal || (!c.failed && inTx != c.inTx) {
			t.Fatalf("%s: error %v, %d inside the transaction, %d after", c.name, err, inTx, after)
		}
	}
}
