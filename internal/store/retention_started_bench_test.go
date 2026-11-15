package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/metrics"
	"strconv"
	"strings"
	"sync"
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
	loadGroups = []string{"30d", "30d", "7d", "30d", "30d", "90d", "90d",
		"90d", "30d", "30d", "cap", "shrink", "mark"}
)

// BenchmarkRetention measures one retention run of the schedule with a cap.
// The writer gets 500 events a second (T-P-13, SEC-39, SEC-41). It is not
// part of make all. The parent makes the database. The child process runs
// the schedule, so it has its own peak. The child prints two times for each
// step and each group, for chunk transactions only. A batch transaction of
// events is not a chunk: the step wrapper tells them apart. The chunk body
// goes from the start of the chunk to its COMMIT. The writer hold goes from
// one chunk start to the next. It has four fields. The body is the chunk
// body. The commit goes from the COMMIT call of the chunk to the next BEGIN
// of any transaction. It holds the COMMIT, the WAL settle and the work of the
// writer before that BEGIN. The batch is the sum of the batch transactions
// in the hold. Each goes from its BEGIN to the next BEGIN. The rest is the
// hold minus the three. The child prints
// the count of each over 100 ms and over 250 ms. For each hold over 100 ms
// it prints one ret-long line. It has the fields and the COMMIT time of the
// batches. It has the WAL bytes, checkpoint sequence and nBackfill at the
// chunk's COMMIT call and at the next BEGIN. It has the change of the GC
// cycles. It has the change of the CPU throttling (-1 when
// /sys/fs/cgroup/cpu.stat is missing). The ret-batch line counts the batch
// transactions. The child prints the queue bytes in the longest chunk
// and the largest queue bytes of the run. It prints the peak RSS (VmHWM) and
// the dropped events. It prints the extra disk against the 90 % line of the
// file system. It ends with one PASS or FAIL line for each rule. Run it with
// -benchtime=1x:
//
//	PHANTOM_RETENTION_ROWS=30000000 go test -run '^$' \
//	  -bench '^BenchmarkRetention$' -benchtime=1x ./internal/store
//
// PHANTOM_RETENTION_ROWS gives the rows of the event table (default 20 000).
// The rows cover 120 days that end now. 1 row in 20 is a refused row. 1 row
// in 20 is a beacon row. 1 in 50 is a callback row with a detail and a body
// prefix.
// The rest, 88 %, are request rows. For 30 M request rows, set the variable
// to 34 100 000. There is a session row, with an address, for each 8 rows.
// There is a token, a mint and an ip_counter row for each 16. So each step
// of the run finds rows. The roll-up and the raw delete take the request,
// refused and beacon rows older than 30 d. The address step takes the
// sessions older than 7 d. The counter delete takes the ip_counter rows
// older than 30 d. The event expire takes the callback rows older than
// 90 d. The field clear takes the callback rows between 30 d and 90 d. The
// child prints rows= for each step. It is the sum of the values that the
// chunks of the step returned. A step can count a row more than one time.
// The cap and shrink steps count their own units. A rule fails for a step
// with 0. The cap is a tenth of the database size at the start. So the cap
// step evicts and the shrink step frees pages. The rule on the longest chunk
// uses the writer hold, as the writer serves no event during it. A chunk that
// runs several steps counts for the last of them. So a step with 0 chunks ran
// inside the chunk of a later step. The database is below TMPDIR.
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
	fill(n, "INSERT INTO event (ts, kind, session_id, vhost, path, body_prefix, detail, hash, leaf_index) SELECT ? + i*?, "+
		"CASE WHEN i % 20 = 0 THEN 'refused' WHEN i % 20 = 10 THEN 'beacon' WHEN i % 50 = 7 THEN 'callback' ELSE 'request' END, "+
		"CASE WHEN i % 10 = 0 THEN NULL ELSE "+rollSID("i/8")+" END, 'www.example.com', '/a/' || hex(randomblob(12)), "+
		"CASE WHEN i % 10 = 0 THEN NULL ELSE zeroblob(100) END, CASE WHEN i % 10 = 0 THEN NULL ELSE '{}' END, "+
		// A callback row has a zero hash and the leaf index i/50. The log
		// gets one zero leaf for each. So the start check of the writer
		// finds the largest leaf index in the log.
		"CASE WHEN i % 50 = 7 THEN zeroblob(32) END, CASE WHEN i % 50 = 7 THEN i / 50 END FROM c",
		func(inc int64) []any { return []any{base, inc} })
	fill(n/8+1, "INSERT INTO session (id, first_seen, last_seen, ip, ip_hmac, ja4, h2_fp, ua, hdr_order_hash, family, band) SELECT "+rollSID("i")+
		", ? + i*?, ? + i*?, printf('10.%d.%d.%d', i/65536 % 256, i/256 % 256, i % 256), hex(randomblob(32)), hex(randomblob(18)), hex(randomblob(20)), hex(randomblob(60)), hex(randomblob(8)), 'fam', "+
		"CASE i % 4 WHEN 0 THEN 'human' WHEN 1 THEN 'crawler' WHEN 2 THEN 'agent-likely' ELSE 'agent-confirmed' END FROM c",
		func(inc int64) []any { return []any{base, inc, base, inc} })
	fill(n/16+1, "INSERT INTO token (token_id, session_id, trap_id, issued_at, first_cb_at) SELECT "+rollSID("i")+", "+rollSID("i+1")+", 't', ?, ? + i*? FROM c",
		func(inc int64) []any { return []any{base, base, inc} })
	fill(n/16+1, `INSERT INTO mint SELECT substr(x'000102', 1 + i % 3, 1), ((? + i*?) / 1000 - ?) / 600 % ?, i, 10, 's', ? + i*? FROM c`,
		func(inc int64) []any { return []any{base, inc, epoch, event.MintUnitLimit, base, inc} })
	fill(n/16+1, "INSERT INTO ip_counter SELECT strftime('%Y-%m-%d', (? + i*?) / 1000, 'unixepoch'), hex(randomblob(16)), 1, 0 FROM c",
		func(inc int64) []any { return []any{base, inc} })
	mustExec(b, db, checkpointSQL)
	root, err := os.OpenRoot(state)
	check(b, err)
	defer root.Close()
	lg, err := tlog.OpenLog(root, "tlog")
	check(b, err)
	defer lg.Close()
	for left := (n + 42) / 50; left > 0; left -= 4096 {
		_, err := lg.AppendBatch(make([]tlog.EventHash, min(left, 4096)))
		check(b, err)
	}
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
	rows               [13]int      // the sum of the step returns
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
	startDisk := childDisk(dir)
	tr := newHoldTrace(&st, q, dir)
	defer tr.close()
	inner := s.run
	s.run = func(ctx context.Context, steps []retentionStep) error {
		if len(steps) != len(loadSteps) {
			b.Fatalf("%d steps, want %d", len(steps), len(loadSteps))
		}
		wrapped := make([]retentionStep, len(steps))
		for i, step := range steps {
			wrapped[i] = func(ctx context.Context, tx *sql.Tx, limit int) (int, error) {
				tr.step, tr.chunk = i, true // only a chunk runs a step
				n, err := step(ctx, tx, limit)
				st.rows[i] += n
				return n, err
			}
		}
		return inner(ctx, wrapped)
	}
	w.beforeBegin, w.beforeCommit = tr.beforeBegin, tr.beforeCommit
	w.timing = tr.timing

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
	// The last hold has the checkpoint and the event.
	tr.finish()
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
		fmt.Printf("ret-step %-15s chunks=%d rows=%d body-max=%.1fms body>100ms=%d body>250ms=%d hold-max=%.1fms hold>100ms=%d hold>250ms=%d queue-at-longest-body=%d+%d bytes\n",
			name, st.chunks[i], st.rows[i], ms(st.body[i]), st.over100b[i], st.over250b[i], ms(st.hold[i]), st.over100h[i], st.over250h[i],
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
	fmt.Printf("ret-batch transactions=%d longest=%.1fms longest-commit=%.1fms\n", tr.batches, ms(tr.longBatch), ms(tr.longBatchCommit))
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
	var idle []string
	for i, name := range loadSteps {
		if st.rows[i] == 0 {
			idle = append(idle, name)
		}
	}
	rule := "every step changed rows"
	if len(idle) > 0 {
		rule += ", 0 rows in " + strings.Join(idle, ", ")
	}
	verdict(rule, len(idle) == 0)
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

// walMark is the state of the WAL at one point. It has the bytes of the WAL.
// It has the checkpoint sequence number of its header (bytes 12-15,
// big-endian). It has nBackfill of the -shm file (offset 96, native byte
// order).
type walMark struct {
	bytes         int64
	seq, backfill uint32
}

// readWAL reads the WAL mark through the files that newHoldTrace opened. A
// close of a second descriptor would drop the locks of SQLite on that file.
func (t *holdTrace) readWAL() (m walMark) {
	var b [16]byte
	m.bytes = fileSize(filepath.Join(t.dir, "events.db-wal"))
	if t.wal != nil {
		if n, _ := t.wal.ReadAt(b[:], 0); n == len(b) {
			m.seq = binary.BigEndian.Uint32(b[12:])
		}
	}
	if t.shm != nil {
		if n, _ := t.shm.ReadAt(b[:4], 96); n == 4 {
			m.backfill = binary.NativeEndian.Uint32(b[:4])
		}
	}
	return m
}

// loadMark is the GC cycle count and the CPU throttling counters (-1: no
// cpu.stat) at one point.
type loadMark struct {
	gc                     uint64
	throttled, throttledUS int64
}

var statKeys = [2][]byte{[]byte("nr_throttled "), []byte("throttled_usec ")}

// holdTrace splits the writer hold of each chunk. All hooks run on the writer
// goroutine. finish ends the trace, and the mutex orders it with the hooks.
type holdTrace struct {
	mu   sync.Mutex
	done bool
	st   *loadStats
	q    *event.Queue
	dir  string
	cpu  *os.File // cpu.stat of the cgroup; nil when missing
	wal  *os.File // the WAL file; nil when missing
	shm  *os.File // the shared-memory file of the WAL; nil when missing
	buf  [512]byte
	gcs  []metrics.Sample

	step  int  // set by the step wrapper
	chunk bool // the open transaction ran a step, so it is a chunk
	begin time.Time
	at    loadMark // marks at the BEGIN of the open transaction

	open            bool // a chunk hold is open
	start           time.Time
	startMark       loadMark
	hstep           int
	body, commit    time.Duration
	batch, batchCom time.Duration
	commitAt        time.Time
	commitDue       bool // the commit field waits for the next BEGIN
	commitWAL, next walMark
	batchAt         time.Time
	batchOpen       bool

	batches                    int
	longBatch, longBatchCommit time.Duration
}

func newHoldTrace(st *loadStats, q *event.Queue, dir string) *holdTrace {
	f, _ := os.Open("/sys/fs/cgroup/cpu.stat")
	t := &holdTrace{st: st, q: q, dir: dir, cpu: f, gcs: []metrics.Sample{{Name: "/gc/cycles/total:gc-cycles"}}}
	// The database is open, so both files exist.
	t.wal, _ = os.Open(filepath.Join(dir, "events.db-wal"))
	t.shm, _ = os.Open(filepath.Join(dir, "events.db-shm"))
	return t
}

func (t *holdTrace) close() {
	for _, f := range []*os.File{t.cpu, t.wal, t.shm} {
		if f != nil {
			f.Close()
		}
	}
}

func (t *holdTrace) mark() loadMark {
	metrics.Read(t.gcs)
	m := loadMark{gc: t.gcs[0].Value.Uint64(), throttled: -1, throttledUS: -1}
	if t.cpu != nil {
		n, _ := t.cpu.ReadAt(t.buf[:], 0)
		for rest := t.buf[:n]; len(rest) > 0; {
			var line []byte
			line, rest, _ = bytes.Cut(rest, []byte("\n"))
			for i, p := range [2]*int64{&m.throttled, &m.throttledUS} {
				if v, ok := bytes.CutPrefix(line, statKeys[i]); ok {
					*p, _ = strconv.ParseInt(string(v), 10, 64)
				}
			}
		}
	}
	return m
}

// endBatch ends the open batch transaction at now.
func (t *holdTrace) endBatch(now time.Time) {
	if t.batchOpen {
		d := now.Sub(t.batchAt)
		t.batch, t.batchOpen = t.batch+d, false
		t.longBatch = max(t.longBatch, d)
	}
}

func (t *holdTrace) beforeBegin() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.done {
		return nil
	}
	now := time.Now()
	if t.commitDue {
		t.commit, t.commitDue, t.next = now.Sub(t.commitAt), false, t.readWAL()
	}
	t.endBatch(now)
	t.begin, t.chunk, t.at = now, false, t.mark()
	raise(&t.st.maxDisk, childDisk(t.dir))
	return nil
}

// beforeCommit tells a chunk from a batch by the flag of the step wrapper.
func (t *holdTrace) beforeCommit(*sql.Tx) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.done {
		return nil
	}
	now, fill := time.Now(), t.q.Bytes()
	raise(&t.st.maxFill, fill.Bulk+fill.Evidence)
	raise(&t.st.maxDisk, childDisk(t.dir))
	if !t.chunk {
		t.batches, t.batchAt, t.batchOpen = t.batches+1, t.begin, true
		return nil
	}
	body := now.Sub(t.begin)
	t.st.addBody(t.step, body, fill)
	if t.open {
		t.closeHold(t.begin, t.at)
	}
	t.open, t.start, t.startMark, t.hstep, t.body = true, t.begin, t.at, t.step, body
	t.commit, t.batch, t.batchCom, t.commitAt, t.commitDue = 0, 0, 0, now, true
	t.commitWAL = t.readWAL()
	return nil
}

// timing gets the COMMIT time of each batch transaction that has an event.
func (t *holdTrace) timing(_, commit time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.done {
		t.batchCom += commit
		t.longBatchCommit = max(t.longBatchCommit, commit)
	}
}

// finish ends the open hold after the run.
func (t *holdTrace) finish() {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	if t.commitDue {
		t.commit, t.next = now.Sub(t.commitAt), t.readWAL()
	}
	t.endBatch(now)
	if t.open {
		t.closeHold(now, t.mark())
	}
	t.done = true
}

// closeHold ends the hold at end, with the marks of that point. A hold over
// 100 ms gets a ret-long line.
func (t *holdTrace) closeHold(end time.Time, em loadMark) {
	hold := end.Sub(t.start)
	t.st.addHold(t.hstep, hold)
	if hold <= 100*time.Millisecond {
		return
	}
	delta := func(a, b int64) int64 {
		if a < 0 || b < 0 {
			return -1
		}
		return b - a
	}
	fmt.Printf("ret-long step=%s body=%.1fms commit=%.1fms batch=%.1fms batch-commit=%.1fms rest=%.1fms hold=%.1fms "+
		"wal-bytes=%d>%d wal-seq=%d>%d backfill=%d>%d gc-cycles=%d throttled=%d throttled-usec=%d\n",
		loadSteps[t.hstep], ms(t.body), ms(t.commit), ms(t.batch), ms(t.batchCom), ms(hold-t.body-t.commit-t.batch), ms(hold),
		t.commitWAL.bytes, t.next.bytes, t.commitWAL.seq, t.next.seq, t.commitWAL.backfill, t.next.backfill,
		em.gc-t.startMark.gc, delta(t.startMark.throttled, em.throttled), delta(t.startMark.throttledUS, em.throttledUS))
}
