package store

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/cybagard/cyba-phantom/internal/event"
	"github.com/cybagard/cyba-phantom/internal/tlog"
)

const (
	// loadChildDir is the state directory of the child. loadChildCap is its
	// cap in bytes.
	loadChildDir = "STORE_RET_CHILD_DIR"
	loadChildCap = "STORE_RET_CHILD_CAP"

	// startedOfferRate is the events for each second that the child offers
	// to the writer during the run.
	startedOfferRate = 500
	// loadQueueDepth is the default of limits.queue_depth.
	loadQueueDepth = 4096
)

// loadSteps are the names of the steps of one run with a cap, in the order
// of runSteps and withCap. loadGroups gives the group of each step.
var (
	loadSteps = []string{"rollup", "rollup-day", "ip-7d", "raw-delete",
		"counter-delete", "event-expire", "token-expire", "session-expire",
		"field-clear", "mint", "cap", "shrink", "mark"}
	loadGroups = []string{"30d", "30d", "7d-ip", "30d", "30d", "90d", "90d",
		"90d", "7d-ip", "30d", "cap", "shrink", "mark"}
)

// BenchmarkRetention measures one retention run of the schedule with a cap.
// The writer gets 500 events a second (T-P-13, SEC-39, SEC-41). It is not
// part of make all. The parent makes the database. The child process runs
// the schedule, so it has its own peak. The child prints two times for each
// step and each group. The chunk body goes from the start of the chunk to
// its COMMIT. The writer hold goes from one chunk start to the next. It has
// the COMMIT and the batches between the chunks. The child prints the count
// of each over 100 ms and over 250 ms. It prints the queue bytes in the
// longest chunk and the largest queue bytes of the run. It prints the peak
// RSS (VmHWM) and the dropped events. It prints the extra disk against the
// 90 % line of the file system. It ends with one PASS or FAIL line for each
// rule. Run it with -benchtime=1x:
//
//	PHANTOM_RETENTION_ROWS=30000000 go test -run '^$' \
//	  -bench '^BenchmarkRetention$' -benchtime=1x ./internal/store
//
// PHANTOM_RETENTION_ROWS gives the rows of the event table (default 20 000).
// The rows cover 120 days that end now. 1 row in 20 is a refused or beacon
// row. There is a session row for each 8 rows. There is a token and a mint
// row for each 16. Each step of the run finds rows. The cap is a tenth of the
// database size at the start. So the cap step evicts and the shrink step
// frees pages. The rule on the longest chunk uses the writer hold, as the
// writer serves no event during it. A chunk that runs several steps counts
// for the last of them. So a step with 0 chunks ran inside the chunk of a
// later step. The database is below TMPDIR.
func BenchmarkRetention(b *testing.B) {
	if _, err := os.Stat("/proc/self/status"); err != nil {
		b.Skip("no /proc/self/status: the benchmark reads RSS from it")
	}
	n := 20_000
	if s := os.Getenv("PHANTOM_RETENTION_ROWS"); s != "" {
		v, err := strconv.Atoi(s)
		if err != nil || v < chunkRows {
			b.Fatalf("PHANTOM_RETENTION_ROWS %q: want a number of at least %d", s, chunkRows)
		}
		n = v
	}
	state := retentionState(b, n)
	size := fileSize(filepath.Join(state, "events.db")) + fileSize(filepath.Join(state, "events.db-wal"))
	cmd := exec.Command(os.Args[0], "-test.run=^$", "-test.bench=^BenchmarkRetentionChild$", "-test.benchtime=1x")
	cmd.Env = append(os.Environ(), loadChildDir+"="+state, loadChildCap+"="+strconv.FormatInt(max(size/10, mib), 10))
	out, err := cmd.CombinedOutput()
	m := map[string]float64{}
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.HasPrefix(line, "ret-") || err != nil {
			continue
		}
		fmt.Println(line)
		if fields, ok := strings.CutPrefix(line, "ret-summary "); ok {
			for _, kv := range strings.Fields(fields) {
				k, v, _ := strings.Cut(kv, "=")
				m[k], _ = strconv.ParseFloat(v, 64)
			}
		}
	}
	if m["rss"] == 0 {
		b.Fatalf("child: %v\n%s", err, out)
	}
	b.ReportMetric(m["rss"]/mib, "peak-rss-MiB")
	b.ReportMetric(m["extra"]/mib, "extra-disk-MiB")
	b.ReportMetric(m["hold"], "hold-max-ms")
	b.ReportMetric(m["body"], "chunk-max-ms")
	b.ReportMetric(m["dropped"], "dropped")
}

// retentionState makes the database of n event rows for BenchmarkRetention. It
// returns the state directory. The WAL has no bytes at the end.
func retentionState(b *testing.B, n int) string {
	top, err := filepath.EvalSymlinks(b.TempDir())
	check(b, err)
	state := filepath.Join(top, "state")
	check(b, os.Mkdir(state, 0o700))
	db := openState(b, state)
	defer db.Close()
	check(b, Migrate(db, "origin"))
	span := int64(120 * 24 * time.Hour / time.Millisecond)
	base := time.Now().UnixMilli() - span
	epoch := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).Unix()
	const rec = "WITH RECURSIVE c(i) AS (SELECT ? UNION ALL SELECT i+1 FROM c WHERE i < ?) "
	// fill runs insert for the rows 0 to total-1 in batches of 100 000. The
	// rows are spread over the span. The query gets the batch and inc.
	fill := func(total int, insert string, extra func(inc int64) []any) {
		inc := max(1, span/int64(total))
		for off := 0; off < total; off += 100_000 {
			args := []any{off, off + min(100_000, total-off) - 1}
			mustExec(b, db, rec+insert, append(args, extra(inc)...)...)
		}
	}
	fill(n, "INSERT INTO event (ts, kind, session_id, vhost, path, body_prefix, detail) SELECT ? + i*?, "+
		"CASE WHEN i % 20 = 0 THEN 'refused' WHEN i % 20 = 10 THEN 'beacon' ELSE 'request' END, "+
		"CASE WHEN i % 10 = 0 THEN NULL ELSE "+rollSID("i/8")+" END, 'www.example.com', '/a/' || hex(randomblob(12)), "+
		"CASE WHEN i % 10 = 0 THEN NULL ELSE zeroblob(100) END, CASE WHEN i % 10 = 0 THEN NULL ELSE '{}' END FROM c",
		func(inc int64) []any { return []any{base, inc} })
	fill(n/8+1, "INSERT INTO session (id, first_seen, last_seen, ip_hmac, ja4, h2_fp, ua, hdr_order_hash, family, band) SELECT "+rollSID("i")+
		", ? + i*?, ? + i*?, hex(randomblob(32)), hex(randomblob(18)), hex(randomblob(20)), hex(randomblob(60)), hex(randomblob(8)), 'fam', "+
		"CASE i % 4 WHEN 0 THEN 'human' WHEN 1 THEN 'crawler' WHEN 2 THEN 'agent-likely' ELSE 'agent-confirmed' END FROM c",
		func(inc int64) []any { return []any{base, inc, base, inc} })
	fill(n/16+1, "INSERT INTO token (token_id, session_id, trap_id, issued_at, first_cb_at) SELECT "+rollSID("i")+", "+rollSID("i+1")+", 't', ?, ? + i*? FROM c",
		func(inc int64) []any { return []any{base, base, inc} })
	fill(n/16+1, `INSERT INTO mint SELECT substr(x'000102', 1 + i % 3, 1), ((? + i*?) / 1000 - ?) / 600 % ?, i, 10, 's', ? + i*? FROM c`,
		func(inc int64) []any { return []any{base, inc, epoch, event.MintUnitLimit, base, inc} })
	mustExec(b, db, checkpointSQL)
	return state
}

// loadStats holds what the hooks of the writer note during the run. The
// writer goroutine sets the step fields. The load goroutine sets the atomic
// ones.
type loadStats struct {
	body, hold         [13]time.Duration
	bodyFill           [13]event.Bytes // the queue at the longest body
	over100b, over250b [13]int
	over100h, over250h [13]int
	chunks             [13]int
	maxFill            atomic.Int64 // the most queue bytes, both lanes
	maxDisk            atomic.Int64 // the most database and WAL bytes
}

// childDisk returns the bytes of the database file and of its WAL.
func childDisk(dir string) int64 {
	return fileSize(filepath.Join(dir, "events.db")) + fileSize(filepath.Join(dir, "events.db-wal"))
}

// raise raises a maximum.
func raise(a *atomic.Int64, v int64) {
	for old := a.Load(); v > old && !a.CompareAndSwap(old, v); old = a.Load() {
	}
}

// BenchmarkRetentionChild is the child process of BenchmarkRetention. Without
// its environment variables, it skips.
func BenchmarkRetentionChild(b *testing.B) {
	dir := os.Getenv(loadChildDir)
	if dir == "" {
		b.Skip("child process of BenchmarkRetention")
	}
	capBytes, err := strconv.ParseInt(os.Getenv(loadChildCap), 10, 64)
	check(b, err)
	root, err := os.OpenRoot(dir)
	check(b, err)
	defer root.Close()
	db, err := Open(root, "events.db", Options{})
	check(b, err)
	defer db.Close()
	q, err := event.NewQueue(loadQueueDepth, event.NewCounters())
	check(b, err)
	lg, err := tlog.OpenLog(root, "tlog")
	check(b, err)
	defer lg.Close()
	w := NewWriter(db, q, false, nil, Recovery{State: root, Origin: "origin", Log: lg})
	s := NewSchedule(w, 7, 30, 90, nil)
	check(b, s.SetMaxBytes(capBytes, "events.db"))

	var st loadStats
	var cur atomic.Int32
	startDisk := childDisk(dir)
	inner := s.run
	s.run = func(ctx context.Context, steps []retentionStep) error {
		if len(steps) != len(loadSteps) {
			b.Fatalf("%d steps, want %d", len(steps), len(loadSteps))
		}
		wrapped := make([]retentionStep, len(steps))
		for i, step := range steps {
			wrapped[i] = func(ctx context.Context, tx *sql.Tx, limit int) (int, error) {
				cur.Store(int32(i))
				return step(ctx, tx, limit)
			}
		}
		return inner(ctx, wrapped)
	}
	var begin, prevBegin time.Time
	prevStep := 0
	w.beforeBegin = func() error {
		begin = time.Now()
		if !prevBegin.IsZero() {
			st.addHold(prevStep, begin.Sub(prevBegin))
		}
		prevBegin = begin
		raise(&st.maxDisk, childDisk(dir))
		return nil
	}
	w.beforeCommit = func(*sql.Tx) error {
		step, took, fill := int(cur.Load()), time.Since(begin), q.Bytes()
		st.addBody(step, took, fill)
		prevStep = step
		raise(&st.maxFill, fill.Bulk+fill.Evidence)
		raise(&st.maxDisk, childDisk(dir))
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan struct{})
	go func() { w.Run(ctx); close(runDone) }()
	stopLoad := make(chan struct{})
	loadDone := make(chan int64)
	go func() {
		// The load offers startedOfferRate events each second. A tick can
		// be late, so each tick offers all that are due.
		tick, start, sent := time.NewTicker(2*time.Millisecond), time.Now(), int64(0)
		defer tick.Stop()
		for {
			select {
			case <-stopLoad:
				loadDone <- sent
				return
			case <-tick.C:
				for ; sent < int64(time.Since(start).Seconds()*startedOfferRate); sent++ {
					if e, err := event.NewEvent(time.Now, event.Input{Kind: event.KindRequest, Vhost: "www.example.com", Method: "GET", Path: "/p"}); err == nil {
						q.Enqueue(e)
					}
				}
				f := q.Bytes()
				raise(&st.maxFill, f.Bulk+f.Evidence)
				raise(&st.maxDisk, childDisk(dir))
			}
		}
	}()

	runStart := time.Now()
	s.runOnce(context.Background())
	if !prevBegin.IsZero() {
		// The last hold has the checkpoint and the event.
		st.addHold(prevStep, time.Since(prevBegin))
	}
	total := time.Since(runStart)
	raise(&st.maxDisk, childDisk(dir))
	close(stopLoad)
	offered := <-loadDone
	q.Close()
	cancel()
	<-runDone

	extra := max(0, st.maxDisk.Load()-startDisk)
	var fs syscall.Statfs_t
	check(b, syscall.Statfs(dir, &fs))
	bs := uint64(fs.Bsize)
	// line is the bytes that the file system can still fill up to 90 %.
	line := int64(float64(fs.Blocks*bs)*0.9) - int64((fs.Blocks-fs.Bfree)*bs)
	dropped := q.Dropped()
	wdrop := w.Stats().Dropped
	droppedTotal := dropped.Bulk + dropped.Evidence + dropped.Invalid + wdrop.Bulk + wdrop.Evidence
	rss := procStatus(b, "VmHWM")

	groups := map[string]*[2]time.Duration{}
	var order []string
	for i, name := range loadSteps {
		fmt.Printf("ret-step %-15s chunks=%d body-max=%.1fms body>100ms=%d body>250ms=%d hold-max=%.1fms hold>100ms=%d hold>250ms=%d queue-at-longest-body=%d+%d bytes\n",
			name, st.chunks[i], ms(st.body[i]), st.over100b[i], st.over250b[i], ms(st.hold[i]), st.over100h[i], st.over250h[i],
			st.bodyFill[i].Bulk, st.bodyFill[i].Evidence)
		g := groups[loadGroups[i]]
		if g == nil {
			g = new([2]time.Duration)
			groups[loadGroups[i]], order = g, append(order, loadGroups[i])
		}
		g[0], g[1] = max(g[0], st.body[i]), max(g[1], st.hold[i])
	}
	var body, hold time.Duration
	var o100b, o250b, o100h, o250h, chunks int
	for i := range loadSteps {
		body, hold = max(body, st.body[i]), max(hold, st.hold[i])
		o100b, o250b, o100h, o250h, chunks = o100b+st.over100b[i], o250b+st.over250b[i], o100h+st.over100h[i], o250h+st.over250h[i], chunks+st.chunks[i]
	}
	for _, g := range order {
		fmt.Printf("ret-group %-6s body-max=%.1fms hold-max=%.1fms\n", g, ms(groups[g][0]), ms(groups[g][1]))
	}
	fmt.Printf("ret-run chunks=%d body>100ms=%d body>250ms=%d hold>100ms=%d hold>250ms=%d total=%.1fs offered=%d (%d a second) cap=%d MiB\n",
		chunks, o100b, o250b, o100h, o250h, total.Seconds(), offered, startedOfferRate, capBytes/mib)
	fmt.Printf("ret-queue largest=%d bytes (both lanes)\n", st.maxFill.Load())
	fmt.Printf("ret-disk start=%.1fMiB largest=%.1fMiB extra=%.1fMiB line90=%.1fMiB\n", float64(startDisk)/mib, float64(st.maxDisk.Load())/mib, float64(extra)/mib, float64(line)/mib)
	fmt.Printf("ret-dropped queue(bulk=%d evidence=%d invalid=%d) writer(bulk=%d evidence=%d)\n",
		dropped.Bulk, dropped.Evidence, dropped.Invalid, wdrop.Bulk, wdrop.Evidence)
	verdict := func(rule string, ok bool) {
		r := "FAIL"
		if ok {
			r = "PASS"
		}
		fmt.Printf("ret-rule %s: %s\n", r, rule)
	}
	verdict(fmt.Sprintf("peak RSS %.1f MiB + 60 MiB < 300 MiB", float64(rss)/mib), rss+60*mib < 300*mib)
	verdict(fmt.Sprintf("extra disk %.1f MiB below the 90 %% line %.1f MiB", float64(extra)/mib, float64(line)/mib), extra < line)
	verdict(fmt.Sprintf("longest writer hold %.1f ms <= 250 ms", ms(hold)), hold <= 250*time.Millisecond)
	verdict(fmt.Sprintf("dropped events %d == 0", droppedTotal), droppedTotal == 0)
	fmt.Printf("ret-summary rss=%d extra=%d hold=%.3f body=%.3f dropped=%d\n", rss, extra, ms(hold), ms(body), droppedTotal)
}

// addBody notes the chunk body of the step.
func (s *loadStats) addBody(step int, took time.Duration, fill event.Bytes) {
	s.chunks[step]++
	if took > s.body[step] {
		s.body[step], s.bodyFill[step] = took, fill
	}
	if took > 100*time.Millisecond {
		s.over100b[step]++
	}
	if took > 250*time.Millisecond {
		s.over250b[step]++
	}
}

// addHold notes the hold of the writer that began with a chunk of the step.
func (s *loadStats) addHold(step int, took time.Duration) {
	s.hold[step] = max(s.hold[step], took)
	if took > 100*time.Millisecond {
		s.over100h[step]++
	}
	if took > 250*time.Millisecond {
		s.over250h[step]++
	}
}
