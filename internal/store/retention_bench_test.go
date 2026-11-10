package store

import (
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
	// step: "clear", "delete" or "mint". rawChildTime is the time of the step,
	// in unix ms.
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
// refused and beacon rows. The mint rows are in 3 sets.
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
	for _, step := range []string{"clear", "delete", "mint"} {
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
	steps := map[string]retentionStep{"clear": newFieldClearStep(at, 30), "delete": newRawDeleteStep(at, 30), "mint": newMintStep(at, 30)}
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
