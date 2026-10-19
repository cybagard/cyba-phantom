package store

import (
	"crypto/sha256"
	"database/sql"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"testing"
	"time"
)

const (
	migrateRows  = 1_000_000
	migrateEvery = 50    // one evidence row in 50, as in the load benchmark
	migrateBatch = 10000 // rows in one setup transaction
)

// fillV1 writes migrateRows rows to the event table of a version 1 database:
// request rows with a path and, in one row of ten, a body prefix of 256 bytes;
// evidence rows with a 32-byte hash, a leaf index, a detail and a record of 600
// bytes.
func fillV1(b *testing.B, db *sql.DB) {
	const ins = "INSERT INTO event (ts, session_id, kind, vhost, method, path, status, trap_id, token_id, surface, body_prefix, hash, leaf_index, detail, record) " +
		"VALUES (?, ?, ?, 'www.example.test', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
	body, rec := make([]byte, 256), make([]byte, 600)
	leaf := 0
	for start := 0; start < migrateRows; start += migrateBatch {
		tx, err := db.Begin()
		if err != nil {
			b.Fatal(err)
		}
		st, err := tx.Prepare(ins)
		if err != nil {
			b.Fatal(err)
		}
		for i := start; i < start+migrateBatch; i++ {
			sess := fmt.Sprintf("sess-%021d", i%50000)
			path := fmt.Sprintf("/wp-content/plugins/example/readme-%07d.txt", i)
			if i%migrateEvery == 0 {
				copy(rec, fmt.Sprintf(`{"v":1,"ts":%d,"kind":"callback","n":%d}`, 1758300000000+i, i))
				h := sha256.Sum256(rec)
				_, err = st.Exec(1758300000000+i, sess, "callback", "GET", path, 200, "trap-config-backup", fmt.Sprintf("tok-%016x", i),
					"path", nil, h[:], leaf, `{"hits":3,"route":"/api/v2/internal/export"}`, rec)
				leaf++
			} else {
				var prefix []byte
				if i%10 == 0 {
					prefix = body
				}
				_, err = st.Exec(1758300000000+i, sess, "request", "POST", path, 404, nil, nil, nil, prefix, nil, nil, nil, nil)
			}
			if err != nil {
				b.Fatal(err)
			}
		}
		st.Close()
		if err := tx.Commit(); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkMigrationRefusedKind runs the migration 0002 on a version 1 database
// with 1 000 000 event rows and reports its time and the peak RSS (VmHWM) of
// the migration alone. The setup writes the rows through one connection. After
// it, the benchmark closes that connection and opens the file again, frees the
// heap, and sets VmHWM to the current RSS through /proc/self/clear_refs. So the
// peak is the peak of the migration and not of the setup. The migration is the
// real Migrate with the real free-space check. The benchmark fails if the
// migration is refused or the version after it is not 2. Run it only with
// -bench, in a 1 CPU / 512 MB container:
//
//	go test -run '^$' -bench BenchmarkMigrationRefusedKind -benchtime 1x ./internal/store
func BenchmarkMigrationRefusedKind(b *testing.B) {
	if _, err := os.Stat("/proc/self/status"); err != nil {
		b.Skip("no /proc/self/status: the benchmark reads the peak RSS from it")
	}
	for range b.N {
		b.StopTimer()
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
		if err := migrate(db, testSet(nil), "origin", nil); err != nil {
			b.Fatal(err)
		}
		fillV1(b, db)
		if _, err := db.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
			b.Fatal(err)
		}
		if err := db.Close(); err != nil {
			b.Fatal(err)
		}
		if db, err = Open(root, "events.db", Options{}); err != nil {
			b.Fatal(err)
		}
		defer db.Close()
		fi, err := root.Stat("events.db")
		if err != nil {
			b.Fatal(err)
		}
		runtime.GC()
		debug.FreeOSMemory()
		if err := os.WriteFile("/proc/self/clear_refs", []byte("5"), 0); err != nil {
			b.Fatalf("the peak RSS cannot be reset: %v", err)
		}
		rssBefore := procStatus(b, "VmHWM")

		b.StartTimer()
		start := time.Now()
		err = Migrate(db, root, "events.db", "origin")
		took := time.Since(start)
		b.StopTimer()

		if err != nil {
			b.Fatalf("the migration did not run: %v", err)
		}
		var version string
		var rows int
		if err := db.QueryRow("SELECT value FROM meta WHERE key = 'schema_version'").Scan(&version); err != nil || version != "2" {
			b.Fatalf("schema_version %q after the migration: %v", version, err)
		}
		if err := db.QueryRow("SELECT count(*) FROM event").Scan(&rows); err != nil || rows != migrateRows {
			b.Fatalf("%d rows after the migration: %v", rows, err)
		}
		hwm := procStatus(b, "VmHWM")
		b.ReportMetric(took.Seconds(), "migrate_s")
		b.ReportMetric(float64(hwm)/1e6, "peak_rss_MB")
		b.ReportMetric(float64(rssBefore)/1e6, "rss_before_MB")
		b.ReportMetric(float64(fi.Size())/1e6, "db_MB")
		b.Logf("units: MB = 1 000 000 bytes; %d rows, database file %d bytes before the migration", migrateRows, fi.Size())
		b.Logf("migration %.2f s; peak RSS of the migration (VmHWM after reset) %d bytes; RSS right after the reset %d bytes", took.Seconds(), hwm, rssBefore)
	}
}
