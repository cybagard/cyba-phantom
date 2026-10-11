package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cybagard/cyba-phantom/internal/event"
	"github.com/cybagard/cyba-phantom/internal/tlog"
)

const (
	evidenceBatch = 500
	batchLimit    = 250 * time.Millisecond
)

// BenchmarkEvidenceBatch writes batches of 500 evidence events through the real
// log and the real database. Each op is one batch, so ns/op is the batch time.
// The pass line is a batch time of at most 250 ms. Run it only with -bench, in a
// 1 CPU / 512 MB container:
//
//	go test -run '^$' -bench BenchmarkEvidenceBatch ./internal/store
func BenchmarkEvidenceBatch(b *testing.B) {
	dir := filepath.Join(b.TempDir(), "state") // mode 0700, as the log needs
	if err := os.Mkdir(dir, 0o700); err != nil {
		b.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		b.Fatal(err)
	}
	defer root.Close()
	db, err := Open(root, "events.db", Options{})
	if err != nil {
		b.Fatal(err)
	}
	defer db.Close()
	if err := Migrate(db, "origin"); err != nil {
		b.Fatal(err)
	}
	l, err := tlog.OpenLog(root, "tlog")
	if err != nil {
		b.Fatal(err)
	}
	defer l.Close()
	c := event.NewCounters()
	q, err := event.NewQueue(loadDepth, c)
	if err != nil {
		b.Fatal(err)
	}
	w := NewWriter(db, q, l, c, false, nil, Recovery{State: root, Origin: "origin", Log: l})
	n := 0
	for range b.N {
		b.StopTimer()
		batch := make([]*event.Event, evidenceBatch)
		for i := range batch {
			batch[i] = loadEvent(b, n*loadEvery) // a multiple of loadEvery is an evidence event
			n++
		}
		b.StartTimer()
		if err := w.write(batch); err != nil {
			b.Fatal(err)
		}
	}
	perBatch := b.Elapsed() / time.Duration(b.N)
	b.ReportMetric(ms(perBatch), "ms/batch")
	b.ReportMetric(float64(evidenceBatch)/perBatch.Seconds(), "leaves/s")
	if size, _ := l.Head(); size != int64(n) {
		b.Fatalf("log size %d for %d evidence events", size, n)
	}
	if perBatch > batchLimit {
		b.Errorf("a batch of %d evidence events took %v, above %v", evidenceBatch, perBatch, batchLimit)
	}
}
