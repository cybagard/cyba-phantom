package store

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

const rawIndexText = "CREATE INDEX event_raw_ts ON event(ts) WHERE body_prefix IS NOT NULL OR detail IS NOT NULL OR record IS NOT NULL"

// schema4Set is the embedded first four migrations: the schema of version 4.
func schema4Set(tb testing.TB) fstest.MapFS {
	tb.Helper()
	set := schema2Set(tb)
	for _, name := range []string{"0003_retention.sql", "0004_rollup.sql"} {
		b, err := migrationFiles.ReadFile("migrations/" + name)
		if err != nil {
			tb.Fatal(err)
		}
		set[name] = &fstest.MapFile{Data: b}
	}
	return set
}

// schema4DB returns a database of schema 4 in the state directory root.
func schema4DB(t *testing.T) *sql.DB {
	t.Helper()
	root, _, _ := newState(t)
	db := mustOpen(t, root, "events.db")
	t.Cleanup(func() { db.Close() })
	if err := migrate(db, schema4Set(t), "origin"); err != nil || metaValue(t, db, "schema_version") != "4" {
		t.Fatalf("no schema 4 database: %v", err)
	}
	return db
}

// rawIDs returns the ids that a read of event with the filter of rawFull gives.
// mode is "INDEXED BY event_raw_ts" or "NOT INDEXED".
func rawIDs(t *testing.T, db *sql.DB, mode string) string {
	t.Helper()
	return rawText(t, db, "SELECT coalesce(group_concat(id, ' '), '') FROM (SELECT id FROM event "+mode+" WHERE "+rawFull+" ORDER BY id)")
}

// T-U-18: a new database has schema_version 5. It has the index event_raw_ts
// with its fixed text. The event table text is the text of schema 4.
func TestTU18NewDatabaseHasRawIndex(t *testing.T) {
	db := migrated(t)
	if v := metaValue(t, db, "schema_version"); v != "5" {
		t.Fatalf("schema_version %s", v)
	}
	if got := rawText(t, db, "SELECT sql FROM sqlite_master WHERE name = 'event_raw_ts'"); got != rawIndexText {
		t.Fatalf("index text %q, want %q", got, rawIndexText)
	}
	if got, want := rawText(t, db, eventSQL), rawText(t, schema4DB(t), eventSQL); got != want {
		t.Fatalf("event table text changed:\n%s\n%s", got, want)
	}
}

// T-U-18: a database of schema 4 gets schema 5. The mark of the field clear is
// gone. Each other meta row stays. The index holds the ids of the rows with a
// field. A row has only a body prefix, only a detail, or only a record.
func TestTU18MigrationFromSchema4DropsMarkAndIndexesRows(t *testing.T) {
	db := schema4DB(t)
	for _, s := range []string{
		"INSERT INTO meta (key, value) VALUES ('retention_raw_done', '123')",
		"INSERT INTO meta (key, value) VALUES ('retention_mint_done', '456')",
		"INSERT INTO event (ts, kind) VALUES (1, 'request')",
		"INSERT INTO event (ts, kind, body_prefix) VALUES (2, 'request', x'62')",
		"INSERT INTO event (ts, kind, detail) VALUES (3, 'request', '{}')",
		"INSERT INTO event (ts, kind, hash, leaf_index, record) VALUES (4, 'callback', zeroblob(32), 0, x'7b7d')",
		"INSERT INTO event (ts, kind) VALUES (5, 'beacon')",
	} {
		mustExec(t, db, s)
	}
	if err := Migrate(db, "origin"); err != nil {
		t.Fatal(err)
	}
	if v := metaValue(t, db, "schema_version"); v != "5" {
		t.Fatalf("schema_version %s", v)
	}
	if n := count(t, db, "SELECT count(*) FROM meta WHERE key = 'retention_raw_done'"); n != 0 {
		t.Fatalf("%d mark rows after the migration", n)
	}
	if v, o := metaValue(t, db, "retention_mint_done"), metaValue(t, db, "tlog_origin"); v != "456" || o != "origin" {
		t.Fatalf("meta rows: mint %s, origin %s", v, o)
	}
	if in, all := rawIDs(t, db, "INDEXED BY event_raw_ts"), rawIDs(t, db, "NOT INDEXED"); in != "2 3 4" || all != in {
		t.Fatalf("ids in the index %q, ids with a field %q, want 2 3 4", in, all)
	}
}

// T-U-18: the read of the field clear uses the index for a bound of ts in each
// direction. The plan has no scan and no sort. A row with its fields set to
// NULL leaves the index.
func TestTU18RawIndexPlanAndExit(t *testing.T) {
	db := migrated(t)
	for _, op := range []string{"<", ">"} {
		q := "SELECT id FROM event INDEXED BY event_raw_ts WHERE " + rawFull + " AND ts " + op + " ? ORDER BY ts LIMIT ?"
		want := "SEARCH event USING INDEX event_raw_ts (ts" + op + "?)"
		if p := strings.Join(queryPlan(t, db, q, 1000, 10), "\n"); p != want {
			t.Errorf("plan of the read with ts %s:\n%s\nwant:\n%s", op, p, want)
		}
	}
	addFull(t, db, "request", 3, 100, 1)
	addFull(t, db, "callback", 1, 200, 1)
	if got := rawIDs(t, db, "INDEXED BY event_raw_ts"); got != "1 2 3 4" {
		t.Fatalf("ids in the index %q, want 1 2 3 4", got)
	}
	mustExec(t, db, "UPDATE event SET body_prefix = NULL, detail = NULL, record = NULL WHERE id IN (2, 4)")
	if in, all := rawIDs(t, db, "INDEXED BY event_raw_ts"), rawIDs(t, db, "NOT INDEXED"); in != "1 3" || all != in {
		t.Fatalf("ids in the index %q, ids with a field %q, want 1 3", in, all)
	}
}

const (
	// rawIdxChildDir is the state directory of the child process.
	rawIdxChildDir = "STORE_RAWINDEX_CHILD_DIR"
	rawIdxChildKey = "rawindex-child "
)

// rawBenchRows reads PHANTOM_RAWINDEX_ROWS (default 20 000) for the benchmark.
func rawBenchRows(b *testing.B) int {
	n := 20_000
	if s := os.Getenv("PHANTOM_RAWINDEX_ROWS"); s != "" {
		v, err := strconv.Atoi(s)
		if err != nil || v < 1 {
			b.Fatalf("PHANTOM_RAWINDEX_ROWS %q: want a positive number", s)
		}
		n = v
	}
	return n
}

// BenchmarkRawIndexBuild measures migration 0005 on a database of schema 4.
// PHANTOM_RAWINDEX_ROWS gives the event rows (default 20 000). Each row has
// kind request and a ts that covers 30 days. It has a body prefix of 1 byte
// and a detail of 2 bytes. The child process runs Migrate. It prints VmHWM and
// the time. It prints the file and WAL bytes before and after. It prints the
// file bytes after a checkpoint and the bytes of the index. Run it with
// -benchtime=1x.
func BenchmarkRawIndexBuild(b *testing.B) {
	if _, err := os.Stat("/proc/self/status"); err != nil {
		b.Skip("no /proc/self/status: the benchmark reads RSS from it")
	}
	n := rawBenchRows(b)
	top, err := filepath.EvalSymlinks(b.TempDir())
	if err != nil {
		b.Fatal(err)
	}
	state := filepath.Join(top, "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		b.Fatal(err)
	}
	root, err := os.OpenRoot(state)
	if err != nil {
		b.Fatal(err)
	}
	defer root.Close()
	db, err := Open(root, "events.db", Options{})
	if err != nil {
		b.Fatal(err)
	}
	if err := migrate(db, schema4Set(b), "origin"); err != nil {
		b.Fatal(err)
	}
	span := int64(30 * 24 * time.Hour / time.Millisecond)
	base, step := time.Now().UnixMilli()-span, max(1, span/int64(n))
	for off := 0; off < n; off += 100_000 {
		k := min(100_000, n-off)
		mustExec(b, db, `WITH RECURSIVE c(i) AS (SELECT ? UNION ALL SELECT i+1 FROM c WHERE i < ?)
			INSERT INTO event (ts, kind, body_prefix, detail) SELECT ? + i*?, 'request', x'62', '{}' FROM c`,
			off, off+k-1, base, step)
	}
	if err := db.Close(); err != nil {
		b.Fatal(err)
	}
	keys := []string{"rss", "ms", "db0", "wal0", "db1", "wal1", "file", "index"}
	m := runChild(b, "BenchmarkRawIndexChild", rawIdxChildKey, keys, rawIdxChildDir+"="+state)
	if db, err = Open(root, "events.db", Options{}); err != nil {
		b.Fatal(err)
	}
	defer db.Close()
	if got := count(b, db, "SELECT count(*) FROM event INDEXED BY event_raw_ts WHERE "+rawFull); got != n {
		b.Fatalf("the index has %d entries, want %d", got, n)
	}
	b.ReportMetric(m["rss"]/mib, "peak-rss-MiB")
	b.ReportMetric(m["ms"], "build-ms")
	b.ReportMetric(m["db0"]/mib, "db-MiB")
	b.ReportMetric((m["db1"]+m["wal1"]-m["db0"]-m["wal0"])/mib, "extra-disk-MiB")
	b.ReportMetric(m["file"]/mib, "file-MiB")
	b.ReportMetric(m["index"]/mib, "index-MiB")
}

// BenchmarkRawIndexChild is the child process of BenchmarkRawIndexBuild.
// Without its environment variable, it skips.
func BenchmarkRawIndexChild(b *testing.B) {
	dir := os.Getenv(rawIdxChildDir)
	if dir == "" {
		b.Skip("child process of the raw index build benchmark")
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		b.Fatal(err)
	}
	db, err := Open(root, "events.db", Options{})
	if err != nil {
		b.Fatal(err)
	}
	file, wal := filepath.Join(dir, "events.db"), filepath.Join(dir, "events.db-wal")
	db0, wal0 := fileSize(file), fileSize(wal)
	begin := time.Now()
	if err := Migrate(db, "origin"); err != nil {
		b.Fatal(err)
	}
	took, rss := time.Since(begin), procStatus(b, "VmHWM")
	db1, wal1 := fileSize(file), fileSize(wal)
	mustExec(b, db, "PRAGMA wal_checkpoint(TRUNCATE)")
	var index int64
	if err := db.QueryRow("SELECT coalesce(sum(pgsize),0) FROM dbstat WHERE name = 'event_raw_ts'").Scan(&index); err != nil {
		b.Fatal(err)
	}
	fmt.Printf(rawIdxChildKey+"rss=%d ms=%.3f db0=%d wal0=%d db1=%d wal1=%d file=%d index=%d\n", rss, ms(took), db0, wal0, db1, wal1,
		fileSize(file), index)
}
