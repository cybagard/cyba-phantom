package store

import (
	"bytes"
	"context"
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

// ipTPriv is the time of the run in the tests: the tPriv that the caller gives
// to the step.
var ipTPriv = time.Unix(1_800_000_000, 0)

// ipCutoff is the cutoff of the step for days days, in unix ms. The tests make
// it again from the definition, not from the code under test.
func ipCutoff(days int) int64 { return ipTPriv.UnixMilli() - int64(days)*24*3600*1000 }

// addSessions inserts n session rows with the ids prefix+i for i from from. The
// first_seen of row i is base + i*step. An ip of nil is NULL.
func addSessions(tb testing.TB, db *sql.DB, prefix string, from, n int, base, step int64, ip any) {
	tb.Helper()
	if _, err := db.Exec(`WITH RECURSIVE c(i) AS (SELECT ? UNION ALL SELECT i+1 FROM c WHERE i < ?)
		INSERT INTO session (id, first_seen, last_seen, ip, ip_hmac, band)
		SELECT ? || i, ? + i*?, ? + i*?, ?, 'h' || (i % 1000), 'human' FROM c`,
		from, from+n-1, prefix, base, step, base, step, ip); err != nil {
		tb.Fatal(err)
	}
}

// ipRig makes a rig with the IP step for days days. See ipRigFor.
func ipRig(t *testing.T, days int) (r *rig, chunks *[]int) {
	t.Helper()
	return ipRigFor(t, newIPStep(ipTPriv, days))
}

// ipRigFor makes a rig with step. The step gets only its tPriv, not the clock
// of the writer. The writer clock is fixed, so the chunk budget does not end a
// chunk. It is one year after tPriv. A step that reads time.Now gets another
// cutoff, and the tests of the IP step fail. chunks gets the rows that each
// chunk changed.
func ipRigFor(t *testing.T, step retentionStep) (r *rig, chunks *[]int) {
	t.Helper()
	r, _, chunks = chunkLog(t, 0, step)
	r.w.clock = func() time.Time { return ipTPriv.Add(365 * 24 * time.Hour) }
	return r, chunks
}

func rowsChanged(v []int) (s int) {
	for _, n := range v {
		s += n
	}
	return s
}

// nullIPs returns, for each session id, whether its ip is NULL.
func nullIPs(t *testing.T, db *sql.DB) map[string]bool {
	t.Helper()
	rows, err := db.Query("SELECT id, ip IS NULL FROM session")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var id string
		var null bool
		if err := rows.Scan(&id, &null); err != nil {
			t.Fatal(err)
		}
		out[id] = null
	}
	return out
}

// T-U-11: a run over more than one chunk sets the ip of each old row to NULL,
// and no other. The chunks change 1 000, 1 000 and 500 rows.
func TestTU11IPStepClearsOldRowsInChunks(t *testing.T) {
	r, chunks := ipRig(t, 7)
	cut := ipCutoff(7)
	addSessions(t, r.db, "old", 0, 2500, cut-1_000_000, 1, "192.0.2.1")
	addSessions(t, r.db, "young", 0, 100, cut+1_000_000, 1, "192.0.2.2")
	if err := r.retain(waitFor); err != nil {
		t.Fatal(err)
	}
	var old, young int
	q := "SELECT count(*) FROM session WHERE ip IS NULL AND first_seen < ?"
	if err := r.db.QueryRow(q, cut).Scan(&old); err != nil {
		t.Fatal(err)
	}
	if err := r.db.QueryRow("SELECT count(*) FROM session WHERE ip IS NOT NULL").Scan(&young); err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(*chunks); got != "[1000 1000 500]" || old != 2500 || young != 100 {
		t.Fatalf("rows changed by chunk %s, %d old rows cleared, %d rows keep an ip", got, old, young)
	}
}

// T-U-11: a row with first_seen one ms before the cutoff loses its ip. A row at
// the cutoff and a younger row keep it. A row with no ip stays NULL and is not
// counted. A row of a returning visitor has an old first_seen and a young
// last_seen. It loses its ip too. The step uses days and its own tPriv, not the
// clock of the writer.
func TestTU11IPStepBoundary(t *testing.T) {
	for _, days := range []int{1, 7} {
		t.Run(fmt.Sprint(days, " days"), func(t *testing.T) {
			r, chunks := ipRig(t, days)
			cut := ipCutoff(days)
			for _, s := range []struct {
				id string
				ts int64
				ip any
			}{
				{"before", cut - 1, "192.0.2.1"}, {"at", cut, "192.0.2.2"}, {"after", cut + 1, "192.0.2.3"},
				{"none", cut - 5, nil}, {"oldest", 1, "192.0.2.4"},
			} {
				addSessions(t, r.db, s.id, 0, 1, s.ts, 0, s.ip)
			}
			q := "INSERT INTO session (id, first_seen, last_seen, ip, ip_hmac, band) VALUES ('returning', ?, ?, '192.0.2.5', 'h', 'human')"
			if _, err := r.db.Exec(q, cut-1, ipTPriv.UnixMilli()); err != nil {
				t.Fatal(err)
			}
			if err := r.retain(waitFor); err != nil {
				t.Fatal(err)
			}
			want := map[string]bool{"before0": true, "at0": false, "after0": false, "none0": true, "oldest0": true, "returning": true}
			got := nullIPs(t, r.db)
			if fmt.Sprint(got) != fmt.Sprint(want) || rowsChanged(*chunks) != 3 {
				t.Fatalf("NULL ip by session %v, want %v; %d rows changed, want 3", got, want, rowsChanged(*chunks))
			}
		})
	}
}

// T-U-11: the sessions of request events and of refused events lose the ip
// when old, and keep it when young. The writer makes all four rows.
func TestTU11IPStepCoversRequestAndRefusedSessions(t *testing.T) {
	r, chunks := ipRig(t, 7)
	cut := ipCutoff(7)
	young, err := event.NewEvent(func() time.Time { return time.UnixMilli(cut + 10) },
		event.Input{Kind: event.KindRefused, Reason: event.ReasonBadHello, ClientIP: "192.0.2.4"})
	if err != nil {
		t.Fatal(err)
	}
	r.writeOK(sessEvent(t, event.KindRequest, "old-request", "192.0.2.1", "", cut-10),
		refusedEvent(t, "192.0.2.2", ""),
		sessEvent(t, event.KindRequest, "young-request", "192.0.2.3", "", cut+10), young)
	var before int
	if err := r.db.QueryRow("SELECT count(*) FROM session WHERE ip IS NOT NULL").Scan(&before); err != nil || before != 4 {
		t.Fatalf("%d sessions with an ip before the run (want 4): %v", before, err)
	}
	if err := r.retain(waitFor); err != nil {
		t.Fatal(err)
	}
	var left string
	q := "SELECT group_concat(ip) FROM (SELECT ip FROM session WHERE ip IS NOT NULL ORDER BY ip)"
	if err := r.db.QueryRow(q).Scan(&left); err != nil || left != "192.0.2.3,192.0.2.4" || rowsChanged(*chunks) != 2 {
		t.Fatalf("addresses left %q (%v), %d rows changed; want the two young ones and 2", left, err, rowsChanged(*chunks))
	}
}

// wantIPRunStops checks that a run of the rig ends with an error and that the
// writer is not healthy.
func wantIPRunStops(t *testing.T, r *rig) {
	t.Helper()
	if err := r.retain(waitFor); err == nil || r.w.Healthy() {
		t.Fatalf("run error %v, healthy %v; want an error and a stopped writer", err, r.w.Healthy())
	}
}

// T-U-11: an error of the statement reaches the runner. The run returns it,
// the writer stops, and the address stays. A trigger makes the statement fail.
func TestTU11IPStepErrorStopsTheWriter(t *testing.T) {
	r, _ := ipRig(t, 7)
	addSessions(t, r.db, "old", 0, 1, ipCutoff(7)-1_000, 0, "192.0.2.1")
	if _, err := r.db.Exec("CREATE TRIGGER no_ip BEFORE UPDATE OF ip ON session BEGIN SELECT RAISE(ABORT,'x'); END"); err != nil {
		t.Fatal(err)
	}
	wantIPRunStops(t, r)
	if got := nullIPs(t, r.db); fmt.Sprint(got) != "map[old0:false]" {
		t.Fatalf("NULL ip by session %v, want the ip of old0 set", got)
	}
}

// T-U-11: a days value below 1 or above 7, or a zero tPriv, gives a step that
// runs no statement and returns an error. The run stops the writer, and no row
// changes. A session of 9 days and a young session show the rows.
func TestTU11IPStepRefusesBadParameters(t *testing.T) {
	for _, c := range []struct {
		name  string
		tPriv time.Time
		days  int
	}{
		{"0 days", ipTPriv, 0}, {"8 days", ipTPriv, 8}, {"zero tPriv", time.Time{}, 7},
	} {
		t.Run(c.name, func(t *testing.T) {
			r, chunks := ipRigFor(t, newIPStep(c.tPriv, c.days))
			addSessions(t, r.db, "old", 0, 1, ipCutoff(7)-2*24*3600*1000, 0, "192.0.2.1")
			addSessions(t, r.db, "young", 0, 1, ipCutoff(7)+1_000_000, 0, "192.0.2.2")
			wantIPRunStops(t, r)
			if got := nullIPs(t, r.db); fmt.Sprint(got) != "map[old0:false young0:false]" || rowsChanged(*chunks) != 0 {
				t.Fatalf("NULL ip by session %v, %d rows changed; want no change", got, rowsChanged(*chunks))
			}
		})
	}
}

// T-U-11: the statement uses the limit that the runner gives it. In one
// transaction, a limit of 7 over 20 old rows changes 7 rows and leaves 13.
func TestTU11IPStepUsesTheLimitOfTheRunner(t *testing.T) {
	r := newRig(t, 100)
	addSessions(t, r.db, "old", 0, 20, ipCutoff(7)-1_000_000, 1, "192.0.2.1")
	tx, err := r.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	n, err := newIPStep(ipTPriv, 7)(context.Background(), tx, 7)
	if err != nil {
		t.Fatal(err)
	}
	var left int
	if err := tx.QueryRow("SELECT count(*) FROM session WHERE ip IS NOT NULL").Scan(&left); err != nil || n != 7 || left != 13 {
		t.Fatalf("%d rows changed (want 7), %d rows keep an ip (want 13): %v", n, left, err)
	}
}

// schemaEntry is one row of sqlite_schema, and the row count of a table.
type schemaEntry struct {
	typ, sql string
	page     int64
	rows     int64
}

func schemaEntries(t *testing.T, db *sql.DB) map[string]schemaEntry {
	t.Helper()
	rows, err := db.Query("SELECT type, name, sql, rootpage FROM sqlite_schema")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]schemaEntry{}
	for rows.Next() {
		var typ, name string
		var text sql.NullString
		var page int64
		if err := rows.Scan(&typ, &name, &text, &page); err != nil {
			t.Fatal(err)
		}
		out[name] = schemaEntry{typ: typ, sql: text.String, page: page}
	}
	for name, e := range out {
		if e.typ == "table" {
			if err := db.QueryRow(fmt.Sprintf("SELECT count(*) FROM %q", name)).Scan(&e.rows); err != nil {
				t.Fatal(err)
			}
			out[name] = e
		}
	}
	return out
}

// T-U-11: a database of schema 2 with a row in each table gets schema 3. Each
// old entry keeps its SQL text and its root page, so no table is rebuilt. The
// row counts stay. The only new entries are the two indexes.
func TestTU11MigrationAddsTwoIndexesWithoutRebuild(t *testing.T) {
	root, _, _ := newState(t)
	db := mustOpen(t, root, "events.db")
	t.Cleanup(func() { db.Close() })
	if err := migrate(db, schema2Set(t), "origin"); err != nil || metaValue(t, db, "schema_version") != "2" {
		t.Fatalf("no schema 2 database: %v", err)
	}
	for _, s := range []string{
		"INSERT INTO session (id, first_seen, last_seen, ip, ip_hmac, band) VALUES ('s1', 1, 2, '192.0.2.1', 'h', 'human')",
		"INSERT INTO event (ts, session_id, kind, path) VALUES (1, 's1', 'request', '/a')",
		"INSERT INTO token (token_id, session_id, trap_id, issued_at, first_cb_at) VALUES ('t1', 's1', 'trap', 3, 4)",
		"INSERT INTO aggregate_day (day, vhost, band, sessions, requests, callbacks) VALUES ('2026-01-01', 'v', 'human', 1, 1, 0)",
		"INSERT INTO ip_counter (day, ip_hmac, requests, dropped) VALUES ('2026-01-01', 'h', 1, 0)",
		"INSERT INTO checkpoint (tree_size, root_hash, signed_note, created_at) VALUES (1, zeroblob(32), 'note', 4)",
		"INSERT INTO mint (set_id, unit, first, count, session_id, issued_at) VALUES (x'01', 1, 1, 1, 's1', 1)",
	} {
		if _, err := db.Exec(s); err != nil {
			t.Fatal(err)
		}
	}
	before := schemaEntries(t, db)
	if err := Migrate(db, "origin"); err != nil {
		t.Fatal(err)
	}
	after := schemaEntries(t, db)
	if v := metaValue(t, db, "schema_version"); v != "3" {
		t.Fatalf("schema_version %s", v)
	}
	for name, was := range before {
		if after[name] != was {
			t.Errorf("%s changed: %+v, was %+v", name, after[name], was)
		}
	}
	if len(after) != len(before)+2 || after["session_ip_first"].typ != "index" || after["token_first_cb"].typ != "index" {
		t.Errorf("new entries: %+v", after)
	}
}

// queryPlan returns the lines of EXPLAIN QUERY PLAN for q.
func queryPlan(tb testing.TB, db *sql.DB, q string, args ...any) []string {
	tb.Helper()
	rows, err := db.Query("EXPLAIN QUERY PLAN "+q, args...)
	if err != nil {
		tb.Fatal(err)
	}
	defer rows.Close()
	var lines []string
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
			tb.Fatal(err)
		}
		lines = append(lines, detail)
	}
	return lines
}

// T-U-11: the IP step statement uses session_ip_first, and the token delete
// statement uses token_first_cb. Each test compares the whole plan, so a plan
// of another shape fails it. The token delete is a plan check only: no
// production code runs it.
func TestTU11StatementsUseTheirIndexes(t *testing.T) {
	db := migrated(t)
	const tokenDelete = "DELETE FROM token WHERE rowid IN (SELECT rowid FROM token WHERE first_cb_at < ? LIMIT ?)"
	for _, c := range []struct{ q, plan string }{
		{clearIPSQL, "SEARCH session USING INTEGER PRIMARY KEY (rowid=?)\n" +
			"LIST SUBQUERY 1\n" +
			"SEARCH session USING INDEX session_ip_first (first_seen<?)"},
		{tokenDelete, "SEARCH token USING INTEGER PRIMARY KEY (rowid=?)\n" +
			"LIST SUBQUERY 1\n" +
			"SEARCH token USING COVERING INDEX token_first_cb (first_cb_at<?)"},
	} {
		if p := strings.Join(queryPlan(t, db, c.q, 1, 1000), "\n"); p != c.plan {
			t.Errorf("plan of %q:\n%s\nwant:\n%s", c.q, p, c.plan)
		}
	}
}

// fileBytes returns the content of a file. A missing file is an error.
func fileBytes(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// T-S-33: a run of the IP step and its checkpoint leaves no marker address.
// No byte of it stays in the database file or in its WAL. The writer stores
// 1 000 session rows with an IPv4 and an IPv6 marker. Before the run, the file
// or the WAL holds both markers. The WAL is read also when it has 0 bytes.
func TestTS33NoAddressResidueAfterTheIPStep(t *testing.T) {
	r, _ := ipRig(t, 7)
	markers := [][]byte{[]byte("198.51.100.77"), []byte("2001:db8::bad:cafe")}
	for off := 0; off < 1000; off += 200 {
		var batch []*event.Event
		for i := off; i < off+200; i++ {
			batch = append(batch, sessEvent(t, event.KindRequest, fmt.Sprintf("residue-%04d", i), string(markers[i%2]), "", 5000))
		}
		r.writeOK(batch...)
	}
	files := []string{filepath.Join(r.state, "events.db"), filepath.Join(r.state, "events.db-wal")}
	found := func() (n [2]int) {
		for _, f := range files {
			for i, m := range markers {
				n[i] += bytes.Count(fileBytes(t, f), m)
			}
		}
		return n
	}
	if n := found(); n[0] == 0 || n[1] == 0 {
		t.Fatalf("copies of the markers before the run: %v", n)
	}
	if err := r.retain(waitFor); err != nil {
		t.Fatal(err)
	}
	var left int
	if err := r.db.QueryRow("SELECT count(*) FROM session WHERE ip IS NOT NULL").Scan(&left); err != nil || left != 0 {
		t.Fatalf("%d sessions keep an ip: %v", left, err)
	}
	if n := found(); n != [2]int{} {
		t.Fatalf("copies of the markers after the run: %v", n)
	}
}

const (
	// ipChildDir is the state directory of the child. ipChildMode is "build" or
	// "step". ipChildTPriv is the tPriv of the step, in unix ms.
	ipChildDir   = "STORE_IPSTEP_CHILD_DIR"
	ipChildMode  = "STORE_IPSTEP_CHILD_MODE"
	ipChildTPriv = "STORE_IPSTEP_CHILD_TPRIV"
)

// ipBenchRows reads PHANTOM_IPSTEP_ROWS (default 20 000) for the benchmarks.
func ipBenchRows(b *testing.B) int {
	n := 20_000
	if s := os.Getenv("PHANTOM_IPSTEP_ROWS"); s != "" {
		v, err := strconv.Atoi(s)
		if err != nil || v < chunkRows {
			b.Fatalf("PHANTOM_IPSTEP_ROWS %q: want a number of at least %d", s, chunkRows)
		}
		n = v
	}
	return n
}

// ipBenchState makes a database of n session rows, all with an ip. The
// first_seen values cover 40 days that end at tPriv. With build, the schema is
// 2 and there are n/4 token rows with first_cb_at. Otherwise the schema is 3.
// It returns the state directory. A child process opens it, so the setup is
// not in its peak.
func ipBenchState(b *testing.B, n int, build bool, tPriv time.Time) string {
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
	defer db.Close()
	if build {
		err = migrate(db, schema2Set(b), "origin")
	} else {
		err = Migrate(db, "origin")
	}
	if err != nil {
		b.Fatal(err)
	}
	span := int64(40 * 24 * time.Hour / time.Millisecond)
	base, step := tPriv.UnixMilli()-span, max(1, span/int64(n))
	for off := 0; off < n; off += 100_000 {
		k := min(100_000, n-off)
		addSessions(b, db, "s", off, k, base, step, "198.51.100.7")
		if !build {
			continue
		}
		if _, err := db.Exec(`WITH RECURSIVE c(i) AS (SELECT ? UNION ALL SELECT i+1 FROM c WHERE i < ?)
			INSERT INTO token (token_id, session_id, trap_id, issued_at, first_cb_at)
			SELECT 't' || i, 's' || i, 'trap', ? + i*?, ? + i*? + 1 FROM c`,
			off/4, (off+k)/4-1, base, step*4, base, step*4); err != nil {
			b.Fatal(err)
		}
	}
	return state
}

// runIPChild runs the child benchmark in mode on state. It returns the numbers
// that the child printed on its line, for example rss=1234 ms=5.6. It fails
// when a value is not a number, when a key of keys is missing, or when rss is 0.
func runIPChild(b *testing.B, state, mode string, keys []string, env ...string) map[string]float64 {
	cmd := exec.Command(os.Args[0], "-test.run=^$", "-test.bench=^BenchmarkIPStepChild$", "-test.benchtime=1x")
	cmd.Env = append(append(os.Environ(), ipChildDir+"="+state, ipChildMode+"="+mode), env...)
	out, err := cmd.CombinedOutput()
	for _, line := range strings.Split(string(out), "\n") {
		if fields, ok := strings.CutPrefix(line, "ipstep-child "); ok && err == nil {
			m := map[string]float64{}
			for _, kv := range strings.Fields(fields) {
				k, v, _ := strings.Cut(kv, "=")
				f, perr := strconv.ParseFloat(v, 64)
				if perr != nil {
					b.Fatalf("child value %q: %v\n%s", kv, perr, out)
				}
				m[k] = f
			}
			for _, k := range keys {
				if _, ok := m[k]; !ok {
					b.Fatalf("child line has no %s\n%s", k, out)
				}
			}
			if m["rss"] == 0 {
				b.Fatalf("child reports rss 0\n%s", out)
			}
			return m
		}
	}
	b.Fatalf("child: %v\n%s", err, out)
	return nil
}

const mib = 1 << 20 // a MiB is 2^20 bytes

// BenchmarkIPStepIndexBuild measures migration 0003 on a database of schema 2.
// PHANTOM_IPSTEP_ROWS gives the session rows (default 20 000). The database has
// a quarter as many token rows. The child process runs Migrate. It prints
// VmHWM, the time, and the file and WAL bytes before and after. Run it with
// -benchtime=1x.
func BenchmarkIPStepIndexBuild(b *testing.B) {
	n := ipBenchRows(b)
	keys := []string{"rss", "ms", "db0", "wal0", "db1", "wal1"}
	m := runIPChild(b, ipBenchState(b, n, true, time.Now()), "build", keys)
	b.ReportMetric(m["rss"]/mib, "peak-rss-MiB")
	b.ReportMetric(m["ms"], "build-ms")
	b.ReportMetric(m["db0"]/mib, "db-MiB")
	b.ReportMetric((m["db1"]+m["wal1"]-m["db0"]-m["wal0"])/mib, "extra-disk-MiB")
}

// BenchmarkIPStepChunks measures the IP step of the real runner on a database
// of schema 3. PHANTOM_IPSTEP_ROWS gives the session rows (default 20 000). The
// child process runs w.chunk until no row is left. It prints the file bytes
// before the run, VmHWM, the longest chunk, the total time, the rows changed
// and the WAL bytes at the end. Run it with -benchtime=1x.
func BenchmarkIPStepChunks(b *testing.B) {
	n, tPriv := ipBenchRows(b), time.Now()
	state := ipBenchState(b, n, false, tPriv)
	keys := []string{"rss", "ms", "longest", "rows", "wal", "db0"}
	m := runIPChild(b, state, "step", keys, ipChildTPriv+"="+strconv.FormatInt(tPriv.UnixMilli(), 10))
	want := 0
	root, err := os.OpenRoot(state)
	if err != nil {
		b.Fatal(err)
	}
	defer root.Close()
	db, err := Open(root, "events.db", Options{})
	if err != nil {
		b.Fatal(err)
	}
	defer db.Close()
	if err := db.QueryRow("SELECT count(*) FROM session WHERE ip IS NULL").Scan(&want); err != nil || int(m["rows"]) != want || want == 0 {
		b.Fatalf("child changed %v rows, the database has %d rows with no ip: %v", m["rows"], want, err)
	}
	b.ReportMetric(m["rss"]/mib, "peak-rss-MiB")
	b.ReportMetric(m["db0"]/mib, "db-MiB")
	b.ReportMetric(m["longest"], "chunk-max-ms")
	b.ReportMetric(m["ms"], "total-ms")
	b.ReportMetric(m["rows"], "rows-changed")
	b.ReportMetric(m["wal"]/mib, "wal-MiB")
}

// fileSize returns the size of a file, or 0 when it is not there.
func fileSize(name string) int64 {
	fi, err := os.Stat(name)
	if err != nil {
		return 0
	}
	return fi.Size()
}

// BenchmarkIPStepChild is the child process of the two benchmarks above.
// Without its environment variables, it skips.
func BenchmarkIPStepChild(b *testing.B) {
	dir := os.Getenv(ipChildDir)
	if dir == "" {
		b.Skip("child process of the IP step benchmarks")
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
	if os.Getenv(ipChildMode) == "build" {
		begin := time.Now()
		if err := Migrate(db, "origin"); err != nil {
			b.Fatal(err)
		}
		fmt.Printf("ipstep-child rss=%d ms=%.3f db0=%d wal0=%d db1=%d wal1=%d\n", procStatus(b, "VmHWM"),
			ms(time.Since(begin)), db0, wal0, fileSize(file), fileSize(wal))
		return
	}
	tms, err := strconv.ParseInt(os.Getenv(ipChildTPriv), 10, 64)
	if err != nil {
		b.Fatal(err)
	}
	q, err := event.NewQueue(1, event.NewCounters())
	if err != nil {
		b.Fatal(err)
	}
	w, steps := NewWriter(db, q, false, nil, Recovery{}), []retentionStep{newIPStep(time.UnixMilli(tms), 7)}
	var total, longest time.Duration
	rows := 0
	for cur := 0; cur < len(steps); {
		begin := time.Now()
		n, err := w.chunk(steps, &cur)
		if err != nil {
			b.Fatal(err)
		}
		took := time.Since(begin)
		total, longest, rows = total+took, max(longest, took), rows+n
	}
	fmt.Printf("ipstep-child rss=%d ms=%.3f longest=%.3f rows=%d wal=%d db0=%d\n", procStatus(b, "VmHWM"),
		ms(total), ms(longest), rows, fileSize(wal), db0)
}
