package store

import (
	"database/sql"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cybagard/cyba-phantom/internal/event"
)

const (
	// rawChildDir is the state directory of the child. rawChildStep is its
	// step: "clear", "delete", "mint", "session", "token" or "event".
	// rawChildTime is the time of the step, in unix ms.
	rawChildDir  = "STORE_RAW_CHILD_DIR"
	rawChildStep = "STORE_RAW_CHILD_STEP"
	rawChildTime = "STORE_RAW_CHILD_TIME"
)

// BenchmarkRaw measures the field clear, the delete of the refused and beacon
// rows, and the mint delete through the runner. Each step has its own
// sub-benchmark. The child process runs w.chunk until no row is left. It prints
// VmHWM, the total time and the longest chunk. It prints the rows changed, and
// the WAL and database bytes after. Run it with -benchtime=1x:
//
//	PHANTOM_RAW_ROWS=4000000 go test -run '^$' -bench '^BenchmarkRaw$' \
//	  -benchtime=1x ./internal/store
//
// PHANTOM_RAW_ROWS gives the rows of the table (default 20 000). The rows cover
// 40 days that end at the time of the step. The steps use 30 days. The clear
// has request rows with a body of 256 bytes and a detail. The delete has
// refused and beacon rows. The mint rows are in 3 sets. The session, token and
// event deletes use 30 days, as the others. Their rows have a last_seen, a
// first_cb_at or a ts in the 40 days. The session rows have the 4 bands. For
// the session step, rows-changed counts 4 for each deleted row: its cost.
func BenchmarkRaw(b *testing.B) {
	if _, err := os.Stat("/proc/self/status"); err != nil {
		b.Skip("no /proc/self/status: the benchmark reads RSS from it")
	}
	n := 20_000
	if s := os.Getenv("PHANTOM_RAW_ROWS"); s != "" {
		v, err := strconv.Atoi(s)
		if err != nil || v < chunkRows {
			b.Fatalf("PHANTOM_RAW_ROWS %q: want a number of at least %d", s, chunkRows)
		}
		n = v
	}
	for _, step := range []string{"clear", "delete", "mint", "session", "token", "event"} {
		b.Run(step, func(b *testing.B) {
			at := time.Now()
			state := rawBenchState(b, step, n, at)
			cmd := exec.Command(os.Args[0], "-test.run=^$", "-test.bench=^BenchmarkRawChild$", "-test.benchtime=1x")
			cmd.Env = append(os.Environ(), rawChildDir+"="+state, rawChildStep+"="+step, rawChildTime+"="+strconv.FormatInt(at.UnixMilli(), 10))
			out, err := cmd.CombinedOutput()
			m := map[string]float64{}
			for _, line := range strings.Split(string(out), "\n") {
				if fields, ok := strings.CutPrefix(line, "raw-child "); ok && err == nil {
					for _, kv := range strings.Fields(fields) {
						k, v, _ := strings.Cut(kv, "=")
						m[k], _ = strconv.ParseFloat(v, 64)
					}
				}
			}
			if m["rss"] == 0 || m["rows"] == 0 {
				b.Fatalf("child: %v\n%s", err, out)
			}
			b.ReportMetric(m["rss"]/mib, "peak-rss-MiB")
			b.ReportMetric(m["ms"], "total-ms")
			b.ReportMetric(m["longest"], "chunk-max-ms")
			b.ReportMetric(m["rows"], "rows-changed")
			b.ReportMetric(m["wal"]/mib, "wal-MiB")
			b.ReportMetric(m["db"]/mib, "db-MiB")
		})
	}
}

// rawBenchState makes a database of n rows for the step. The setup runs in the
// parent, so the child has its own peak. It returns the state directory.
func rawBenchState(b *testing.B, step string, n int, at time.Time) string {
	top, err := filepath.EvalSymlinks(b.TempDir())
	check(b, err)
	state := filepath.Join(top, "state")
	check(b, os.Mkdir(state, 0o700))
	db := openState(b, state)
	defer db.Close()
	check(b, Migrate(db, "origin"))
	span := int64(40 * 24 * time.Hour / time.Millisecond)
	base, inc := at.UnixMilli()-span, max(1, span/int64(n))
	epoch := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).Unix()
	const rec = "WITH RECURSIVE c(i) AS (SELECT ? UNION ALL SELECT i+1 FROM c WHERE i < ?) "
	for off := 0; off < n; off += 100_000 {
		last := off + min(100_000, n-off) - 1
		switch step {
		case "clear":
			mustExec(b, db, rec+"INSERT INTO event (ts, kind, body_prefix, detail) SELECT ? + i*?, 'request', zeroblob(256), '{}' FROM c", off, last, base, inc)
		case "delete":
			mustExec(b, db, rec+"INSERT INTO event (ts, kind) SELECT ? + i*?, CASE i % 2 WHEN 0 THEN 'refused' ELSE 'beacon' END FROM c", off, last, base, inc)
		case "event":
			mustExec(b, db, rec+"INSERT INTO event (ts, kind, session_id, vhost, path) SELECT ? + i*?, 'request', "+rollSID("i+1")+", 'www.example.com', '/a/' || hex(randomblob(12)) FROM c",
				off, last, base, inc)
		case "session":
			mustExec(b, db, rec+"INSERT INTO session (id, first_seen, last_seen, ip_hmac, ja4, h2_fp, ua, hdr_order_hash, family, band) SELECT "+rollSID("i")+", ? + i*?, ? + i*?, "+
				"hex(randomblob(32)), hex(randomblob(18)), hex(randomblob(20)), hex(randomblob(60)), hex(randomblob(8)), 'fam', "+
				"CASE i % 4 WHEN 0 THEN 'human' WHEN 1 THEN 'crawler' WHEN 2 THEN 'agent-likely' ELSE 'agent-confirmed' END FROM c", off, last, base, inc, base, inc)
		case "token":
			mustExec(b, db, rec+"INSERT INTO token (token_id, session_id, trap_id, issued_at, first_cb_at) SELECT "+rollSID("i")+", "+rollSID("i+1")+", 't', ?, ? + i*? FROM c",
				off, last, base, base, inc)
		default:
			mustExec(b, db, rec+`INSERT INTO mint SELECT substr(x'000102', 1 + i % 3, 1), ((? + i*?) / 1000 - ?) / 600 % ?, i, 10, 's', ? + i*? FROM c`,
				off, last, base, inc, epoch, event.MintUnitLimit, base, inc)
		}
	}
	return state
}

// BenchmarkRawChild is the child process of BenchmarkRaw. Without its
// environment variables, it skips.
func BenchmarkRawChild(b *testing.B) {
	dir := os.Getenv(rawChildDir)
	if dir == "" {
		b.Skip("child process of BenchmarkRaw")
	}
	tms, err := strconv.ParseInt(os.Getenv(rawChildTime), 10, 64)
	check(b, err)
	db := openState(b, dir)
	q, err := event.NewQueue(1, event.NewCounters())
	check(b, err)
	at := time.UnixMilli(tms)
	steps := map[string]retentionStep{"clear": newFieldClearStep(at, 30), "delete": newRawDeleteStep(at, 30), "mint": newMintStep(at, 30),
		"session": newSessionExpireStep(at, 30), "token": newTokenExpireStep(at, 30), "event": newEventExpireStep(at, 30)}
	run := []retentionStep{steps[os.Getenv(rawChildStep)]}
	w := NewWriter(db, q, false, nil, Recovery{})
	var total, longest time.Duration
	rows := 0
	for cur := 0; cur < len(run); {
		begin := time.Now()
		n, err := w.chunk(run, &cur)
		check(b, err)
		took := time.Since(begin)
		total, longest, rows = total+took, max(longest, took), rows+n
	}
	fmt.Printf("raw-child rss=%d ms=%.3f longest=%.3f rows=%d wal=%d db=%d\n", procStatus(b, "VmHWM"),
		ms(total), ms(longest), rows, fileSize(filepath.Join(dir, "events.db-wal")), fileSize(filepath.Join(dir, "events.db")))
}

const (
	vacuumChildDir = "STORE_VACUUM_CHILD_DIR"
	vacuumFixedN   = "PHANTOM_VACUUM_N"
)

// vacuumDelete deletes all rows of event, n rows with the ids 1 to n. In file
// order, it is one statement. Scattered, it deletes blocks of 100 ids in a
// permuted order, 1 000 blocks for each transaction. Then the freelist is not
// in file order.
func vacuumDelete(b *testing.B, db *sql.DB, n int, scattered bool) {
	if !scattered {
		mustExec(b, db, "DELETE FROM event")
		return
	}
	const block = 100
	blocks := (n + block - 1) / block
	step := 7919
	if blocks%step == 0 {
		step = 7907
	}
	tx, err := db.Begin()
	check(b, err)
	for i := range blocks {
		lo := i*step%blocks*block + 1
		_, err := tx.Exec("DELETE FROM event WHERE id BETWEEN ? AND ?", lo, lo+block-1)
		check(b, err)
		if i%1000 == 999 {
			check(b, tx.Commit())
			tx, err = db.Begin()
			check(b, err)
		}
	}
	check(b, tx.Commit())
}

// BenchmarkVacuum measures PRAGMA incremental_vacuum through the cap shrink
// step. The parent makes a database of request rows. A body of 3 000 bytes
// gives a row about one page. The parent deletes all rows, so their pages stay
// on the freelist. The child process runs the shrink step until no free
// page is left. It prints VmHWM, the total time and the longest chunk. It
// prints the smallest and the largest pages of a statement. It prints the time
// of the first 3 chunks and the pages freed. It prints the largest WAL during
// the run. It prints the database bytes before the delete and after the end
// TRUNCATE checkpoint. It prints over100 and over250. These are the chunks over
// 100 ms and over 250 ms. With a fixed N, they are statements. Run it with
// -benchtime=1x:
//
//	PHANTOM_VACUUM_ROWS=4000000 PHANTOM_VACUUM_ORDER=scattered \
//	  go test -run '^$' -bench '^BenchmarkVacuum$' -benchtime=1x \
//	  ./internal/store
//
// PHANTOM_VACUUM_ROWS gives the rows (default 20 000). PHANTOM_VACUUM_ORDER is
// file (default) or scattered: the order of the delete. PHANTOM_VACUUM_N gives
// a fixed number of pages for each statement. Then the child runs statements
// with that number, and it prints the longest statement and the first 3.
func BenchmarkVacuum(b *testing.B) {
	if _, err := os.Stat("/proc/self/status"); err != nil {
		b.Skip("no /proc/self/status: the benchmark reads RSS from it")
	}
	n := 20_000
	if s := os.Getenv("PHANTOM_VACUUM_ROWS"); s != "" {
		v, err := strconv.Atoi(s)
		if err != nil || v < chunkRows {
			b.Fatalf("PHANTOM_VACUUM_ROWS %q: want a number of at least %d", s, chunkRows)
		}
		n = v
	}
	top, err := filepath.EvalSymlinks(b.TempDir())
	check(b, err)
	state := filepath.Join(top, "state")
	check(b, os.Mkdir(state, 0o700))
	db := openState(b, state)
	check(b, Migrate(db, "origin"))
	const rec = "WITH RECURSIVE c(i) AS (SELECT ? UNION ALL SELECT i+1 FROM c WHERE i < ?) "
	for off := 0; off < n; off += 100_000 {
		mustExec(b, db, rec+"INSERT INTO event (ts, kind, session_id, vhost, path, body_prefix) SELECT i, 'request', "+rollSID("i")+
			", 'www.example.com', '/a/' || hex(randomblob(12)), zeroblob(3000) FROM c", off+1, off+min(100_000, n-off))
	}
	mustExec(b, db, "PRAGMA wal_checkpoint(TRUNCATE)")
	before := fileSize(filepath.Join(state, "events.db"))
	vacuumDelete(b, db, n, os.Getenv("PHANTOM_VACUUM_ORDER") == "scattered")
	mustExec(b, db, "PRAGMA wal_checkpoint(TRUNCATE)")
	check(b, db.Close())
	cmd := exec.Command(os.Args[0], "-test.run=^$", "-test.bench=^BenchmarkVacuumChild$", "-test.benchtime=1x")
	cmd.Env = append(os.Environ(), vacuumChildDir+"="+state)
	out, err := cmd.CombinedOutput()
	m := map[string]float64{}
	for _, line := range strings.Split(string(out), "\n") {
		if fields, ok := strings.CutPrefix(line, "vacuum-child "); ok && err == nil {
			for _, kv := range strings.Fields(fields) {
				k, v, _ := strings.Cut(kv, "=")
				m[k], _ = strconv.ParseFloat(v, 64)
			}
		}
	}
	if m["rss"] == 0 || m["pages"] == 0 {
		b.Fatalf("child: %v\n%s", err, out)
	}
	b.ReportMetric(m["rss"]/mib, "peak-rss-MiB")
	b.ReportMetric(m["ms"], "total-ms")
	b.ReportMetric(m["longest"], "chunk-max-ms")
	b.ReportMetric(m["pages"], "pages-freed")
	b.ReportMetric(m["over100"], "chunks-over-100ms")
	b.ReportMetric(m["over250"], "chunks-over-250ms")
	b.ReportMetric(m["first1"], "first-ms")
	b.ReportMetric(m["first2"], "second-ms")
	b.ReportMetric(m["first3"], "third-ms")
	b.ReportMetric(m["nmin"], "pages-min")
	b.ReportMetric(m["nmax"], "pages-max")
	b.ReportMetric(m["walmax"]/mib, "wal-max-MiB")
	b.ReportMetric(float64(before)/mib, "db-before-MiB")
	b.ReportMetric(m["db"]/mib, "db-after-MiB")
}

// BenchmarkVacuumChild is the child process of BenchmarkVacuum. Without its
// environment variable, it skips.
func BenchmarkVacuumChild(b *testing.B) {
	dir := os.Getenv(vacuumChildDir)
	if dir == "" {
		b.Skip("child process of BenchmarkVacuum")
	}
	db := openState(b, dir)
	q, err := event.NewQueue(1, event.NewCounters())
	check(b, err)
	w := NewWriter(db, q, false, nil, Recovery{})
	fixed, _ := strconv.Atoi(os.Getenv(vacuumFixedN))
	wal := filepath.Join(dir, "events.db-wal")
	var total, longest time.Duration
	var walMax int64
	var first []float64
	var over100, over250 int
	note := func(took time.Duration) {
		total, longest = total+took, max(longest, took)
		if took > 100*time.Millisecond {
			over100++
		}
		if took > 250*time.Millisecond {
			over250++
		}
		walMax = max(walMax, fileSize(wal))
		if len(first) < 3 {
			first = append(first, ms(took))
		}
	}
	freed, nmin, nmax := int64(0), fixed, fixed
	if fixed > 0 {
		var free0, free int64
		check(b, db.QueryRow("PRAGMA freelist_count").Scan(&free0))
		for free = free0; free > 0; {
			begin := time.Now()
			mustExec(b, db, "PRAGMA incremental_vacuum("+strconv.Itoa(fixed)+")")
			note(time.Since(begin))
			var after int64
			check(b, db.QueryRow("PRAGMA freelist_count").Scan(&after))
			if after >= free {
				break
			}
			free = after
		}
		freed = free0 - free
	} else {
		c := &capRun{w: w, over: true} // a target of 0: free all pages
		steps, run := []retentionStep{c.shrink}, &retentionRun{}
		for cur := 0; cur < len(steps); {
			begin := time.Now()
			_, err := w.chunkRun(steps, &cur, run)
			check(b, err)
			note(time.Since(begin))
		}
		freed, nmin, nmax = run.counts.Vacuumed, c.minPages, c.maxPages
	}
	mustExec(b, db, "PRAGMA wal_checkpoint(TRUNCATE)")
	for len(first) < 3 {
		first = append(first, 0)
	}
	fmt.Printf("vacuum-child rss=%d ms=%.3f longest=%.3f first1=%.3f first2=%.3f first3=%.3f nmin=%d nmax=%d pages=%d walmax=%d over100=%d over250=%d db=%d\n",
		procStatus(b, "VmHWM"), ms(total), ms(longest), first[0], first[1], first[2], nmin, nmax, freed, walMax,
		over100, over250, fileSize(filepath.Join(dir, "events.db")))
}
