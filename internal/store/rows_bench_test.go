package store

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cybagard/cyba-phantom/internal/event"
)

const (
	loadRate     = 3000 // events per second
	loadDuration = 60 * time.Second
	loadIdle     = 30 * time.Second
	loadDepth    = 4096 // the default of limits.queue_depth
	loadEvery    = 50   // one evidence event in 50
	rssLimit     = 60 * 1000 * 1000
)

// procStatus returns a field of /proc/self/status in bytes (the file gives KiB).
func procStatus(b *testing.B, field string) int64 {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		b.Fatal(err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if rest, ok := strings.CutPrefix(line, field+":"); ok {
			kib, err := strconv.ParseInt(strings.Fields(rest)[0], 10, 64)
			if err != nil {
				b.Fatal(err)
			}
			return kib * 1024
		}
	}
	b.Fatalf("no %s in /proc/self/status", field)
	return 0
}

// p99 returns the 99th percentile of d. It sorts a copy.
func p99(d []time.Duration) time.Duration {
	if len(d) == 0 {
		return 0
	}
	s := slices.Sorted(slices.Values(d))
	return s[min(len(s)-1, len(s)*99/100)]
}

func ms(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }

func loadEvent(b *testing.B, n int) *event.Event {
	in := event.Input{
		Kind: event.KindRequest, Session: fmt.Sprintf("sess-%016x", n%5000), Vhost: "www.example.test",
		Method: "GET", Path: fmt.Sprintf("/wp-content/plugins/example/readme-%07d.txt", n),
		ClientIP: fmt.Sprintf("198.51.%d.%d", n%250, n/250%250),
	}
	st := int64(200)
	in.Status = &st
	if n%loadEvery == 0 {
		in.Kind = event.KindCallback
		in.TrapID, in.TokenID, in.Surface = "trap-config-backup", fmt.Sprintf("tok-%016x", n), event.SurfacePath
		in.Detail = event.Detail{"hits": event.Int(int64(n % 7)), "first": event.Bool(n%3 == 0), "route": event.Str("/api/v2/internal/export")}
	}
	e, err := event.NewEvent(nil, in)
	if err != nil {
		b.Fatal(err)
	}
	return e
}

// BenchmarkWriterLoad feeds 3 000 events/s for 60 s through the real queue to
// the writer, waits 30 s with the writer idle, and reads the memory. The pass
// line is: RSS 30 s after the feed stops is at most 60 MB (60 * 1000 * 1000
// bytes). Run it only with -bench, in a 1 CPU / 512 MB container:
//
//	go test -run '^$' -bench BenchmarkWriterLoad -benchtime=1x ./internal/store
func BenchmarkWriterLoad(b *testing.B) {
	if _, err := os.Stat("/proc/self/status"); err != nil {
		b.Skip("no /proc/self/status: the benchmark reads RSS from it")
	}
	for range b.N {
		runLoad(b, false)
	}
}

// BenchmarkWriterFlood feeds a burst of 2 * loadDepth events every 10 ms for
// 3 s. A burst is more than the queue holds. So the queue drops events, and the
// writer adds the drop counts to ip_counter. It fails when no event is dropped
// or no counter row is written. The pass line for RSS is the same as for
// BenchmarkWriterLoad. Run it only with -bench, in a 1 CPU / 512 MB container:
//
//	go test -run '^$' -bench BenchmarkWriterFlood -benchtime=1x ./internal/store
func BenchmarkWriterFlood(b *testing.B) {
	if _, err := os.Stat("/proc/self/status"); err != nil {
		b.Skip("no /proc/self/status: the benchmark reads RSS from it")
	}
	for range b.N {
		runLoad(b, true)
	}
}

const (
	floodBurst = 2 * loadDepth
	floodTicks = 300
)

// loadLog is a test appender that is also an empty log for the start check.
type loadLog struct {
	*testAppender
	fakeLog
}

// runLoad feeds the writer at loadRate, or in bursts above the queue size when
// flood is true.
func runLoad(b *testing.B, flood bool) {
	dir := b.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
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
	c := event.NewCounters()
	q, err := event.NewQueue(loadDepth, c)
	if err != nil {
		b.Fatal(err)
	}
	// The appender and the log are one object.
	lg := &loadLog{testAppender: &testAppender{}}
	w := NewWriter(db, q, lg, c, false, nil, Recovery{State: root, Origin: "origin", Log: lg})
	// The writer goroutine appends. Read after Run returns.
	var batches, commits []time.Duration
	w.timing = func(batch, commit time.Duration) {
		batches, commits = append(batches, batch), append(commits, commit)
	}
	done := make(chan error, 1)
	go func() { done <- w.Run(context.Background()) }()

	total := loadRate * int(loadDuration/time.Second)
	if flood {
		total = floodBurst * floodTicks
	}
	start := time.Now()
	tick := time.NewTicker(10 * time.Millisecond)
	for fed := 0; fed < total; {
		<-tick.C
		due := min(total, int(time.Since(start).Seconds()*loadRate))
		if flood {
			due = fed + floodBurst
		}
		for ; fed < due; fed++ {
			q.Enqueue(loadEvent(b, fed))
		}
	}
	tick.Stop()
	var wal int64
	if fi, err := os.Stat(filepath.Join(dir, "events.db-wal")); err == nil {
		wal = fi.Size()
	}
	rssEnd := procStatus(b, "VmRSS")

	time.Sleep(loadIdle) // the writer runs idle; no GC call
	rss, hwm := procStatus(b, "VmRSS"), procStatus(b, "VmHWM")
	var ms0 runtime.MemStats
	runtime.ReadMemStats(&ms0)

	q.Close()
	if err := <-done; err != nil {
		b.Fatal(err)
	}
	var rows, pages, pageSize int64
	for _, s := range []struct {
		sql string
		to  *int64
	}{{"SELECT count(*) FROM event", &rows}, {"PRAGMA page_count", &pages}, {"PRAGMA page_size", &pageSize}} {
		if err := db.QueryRow(s.sql).Scan(s.to); err != nil {
			b.Fatal(err)
		}
	}
	var counterRows int64
	if err := db.QueryRow("SELECT count(*) FROM ip_counter").Scan(&counterRows); err != nil {
		b.Fatal(err)
	}
	dropped := q.Dropped()
	if flood && (dropped.Bulk+dropped.Evidence == 0 || counterRows == 0) {
		b.Errorf("the flood dropped %d events and wrote %d ip_counter rows, want both above 0", dropped.Bulk+dropped.Evidence, counterRows)
	}
	b.ReportMetric(float64(counterRows), "ip_counter_rows")
	lost := int64(total) - rows
	perRow := float64(pages*pageSize) / float64(max(rows, 1))

	b.ReportMetric(float64(lost), "rows_lost")
	b.ReportMetric(ms(p99(batches)), "p99_batch_ms")
	b.ReportMetric(ms(slices.Max(batches)), "max_batch_ms")
	b.ReportMetric(ms(p99(commits)), "p99_commit_ms")
	b.ReportMetric(ms(slices.Max(commits)), "max_commit_ms")
	b.ReportMetric(float64(hwm)/1e6, "max_rss_MB")
	b.ReportMetric(float64(rss)/1e6, "rss_after_idle_MB")
	b.ReportMetric(float64(ms0.HeapInuse)/1e6, "heap_inuse_MB")
	b.ReportMetric(perRow, "db_bytes/row")
	b.ReportMetric(float64(wal)/1e6, "wal_end_of_feed_MB")
	b.Logf("units: MB = 1 000 000 bytes; the pass line is RSS 30 s after the feed <= %d bytes", rssLimit)
	b.Logf("events fed %d, rows stored %d, rows lost %d (queue drops: bulk %d, evidence %d, invalid %d)",
		total, rows, lost, dropped.Bulk, dropped.Evidence, dropped.Invalid)
	b.Logf("batches %d: p99 batch %.2f ms, max batch %.2f ms, p99 commit %.2f ms, max commit %.2f ms",
		len(batches), ms(p99(batches)), ms(slices.Max(batches)), ms(p99(commits)), ms(slices.Max(commits)))
	b.Logf("RSS at end of feed %d bytes; RSS 30 s after the feed (VmRSS) %d bytes; max RSS (VmHWM) %d bytes", rssEnd, rss, hwm)
	b.Logf("Go heap HeapInuse %d bytes (HeapAlloc %d bytes)", ms0.HeapInuse, ms0.HeapAlloc)
	b.Logf("DB %.1f bytes/row (page_count %d * page_size %d / %d rows); WAL at end of feed %d bytes", perRow, pages, pageSize, rows, wal)
	if rss > rssLimit {
		b.Errorf("RSS 30 s after the feed stops is %d bytes, above %d bytes (60 MB)", rss, rssLimit)
	}
}
