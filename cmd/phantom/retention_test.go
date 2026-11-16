package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cybagard/cyba-phantom/internal/store"
	"github.com/cybagard/cyba-phantom/internal/tlog"
)

const dayMs = int64(24 * time.Hour / time.Millisecond)

// withState opens the database rel below the state directory of p, runs fn on
// it and closes it. rel is "events.db" for a store that is not open yet. The
// schema is made first, as the start does.
func withState(t *testing.T, p startParams, rel string, fn func(db *sql.DB)) {
	t.Helper()
	root, err := os.OpenRoot(p.Root)
	mustOK(t, err)
	defer root.Close()
	db, err := store.Open(root, rel, store.Options{Reserved: p.Reserved})
	mustOK(t, err)
	defer db.Close()
	mustOK(t, store.Migrate(db, p.Origin))
	fn(db)
}

// mustExec runs q and fails the test on an error.
func mustExec(t *testing.T, db *sql.DB, q string, args ...any) {
	t.Helper()
	if _, err := db.Exec(q, args...); err != nil {
		t.Fatal(err)
	}
}

// countOf returns the first column of a query with one integer row.
func countOf(t *testing.T, db *sql.DB, q string, args ...any) (n int) {
	t.Helper()
	mustOK(t, db.QueryRow(q, args...).Scan(&n))
	return n
}

// TestTU27_CapRefusalStopsTheStart has two cases. In the first, the schedule
// gets a store path that is not the open database. So SetMaxBytes refuses the
// cap. In the second, the cap is 0, and the real store is open. serve must end
// with exit 1 and one fixed line. The schedule must not run, not even the run
// at the start, which would write the mark. A refusal that is only logged
// leaves the sensor running with the cap off (T-U-27, SEC-41).
func TestTU27_CapRefusalStopsTheStart(t *testing.T) {
	cases := []struct {
		name     string
		maxBytes int64
		dbName   string // the name that the database opens as
	}{
		{"name differs", 1 << 30, "other.db"},
		{"cap 0", 0, "events.db"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			https, plain, ca := openListeners(t)
			cfg := serveCfg(t, https.Addr().String(), plain.Addr().String(), ca)
			p := tempState(t, cfg)
			p.MaxBytes = c.maxBytes
			d := realDeps
			// With other.db, the schedule gets events.db, a name that differs.
			var opened atomic.Pointer[sql.DB]
			d.openStore = func(r *os.Root, _ string, o store.Options) (*sql.DB, error) {
				db, err := store.Open(r, c.dbName, o)
				opened.Store(db)
				return db, err
			}
			ctx, cancel := context.WithTimeout(t.Context(), netWait)
			defer cancel()
			var stderr strings.Builder
			code := serveWith(ctx, cancel, nil, cfg, content{}, p, d, io.Discard, &stderr)
			if code != 1 || !strings.Contains(stderr.String(), "phantom: retention cap does not start\n") {
				t.Errorf("exit %d, stderr %q; want exit 1 and the cap line", code, stderr.String())
			}
			// The state directory is empty at the start. A refused cap gives no
			// checkpointer, so the start makes no signing key.
			for _, name := range []string{"keys/checkpoint.key", tlog.VKeyName} {
				if _, err := os.Lstat(filepath.Join(p.Root, name)); !errors.Is(err, os.ErrNotExist) {
					t.Errorf("%s after the refusal: Lstat gave %v, want a missing file", name, err)
				}
			}
			// The refusal must free the ports and the store, as a stop does.
			for name, ln := range map[string]*trackedListener{"https": https, "plain": plain} {
				// A listener that is still open waits for a client. The deadline ends
				// the wait. It gives a timeout error, not a closed one.
				ln.Listener.(*net.TCPListener).SetDeadline(time.Now().Add(50 * time.Millisecond))
				if _, err := ln.Accept(); !errors.Is(err, net.ErrClosed) {
					t.Errorf("%s listener after the refusal: Accept gave %v, want a closed listener", name, err)
				}
			}
			if db := opened.Load(); db == nil {
				t.Error("the store did not open")
			} else if err := db.Ping(); err == nil {
				t.Error("the store is open after the refusal")
			}
			withState(t, p, c.dbName, func(db *sql.DB) {
				if n := countOf(t, db, "SELECT count(*) FROM meta WHERE key = 'retention_last'"); n != 0 {
					t.Errorf("%d retention marks: the schedule ran after the refusal", n)
				}
			})
		})
	}
}

// TestTU27_ScheduleRefusesNoCap checks that the schedule of the start refuses
// a cap of 0 or less. SetMaxBytes reads such a cap as no cap. The start must
// not run with the cap off. The schedule gives an error and no run function
// (T-U-27, SEC-40).
func TestTU27_ScheduleRefusesNoCap(t *testing.T) {
	for _, maxBytes := range []int64{0, -1} {
		t.Run(strconv.FormatInt(maxBytes, 10), func(t *testing.T) {
			// The refusal comes before the schedule reads the writer.
			p := startParams{MaxBytes: maxBytes, StorePath: "events.db"}
			run, err := realDeps.schedule(nil, p, slog.New(slog.DiscardHandler))
			if err == nil || run != nil {
				t.Errorf("schedule with cap %d gave error %v and run %v, want an error and no run", maxBytes, err, run != nil)
			}
		})
	}
}

// TestTI13_StartedSensorKeepsTheCap runs one retention run in the started
// sensor with a small cap (T-I-13, SEC-41). The config has a floor of 256 MiB
// for store.max_bytes. So the test sets 2 MiB in the start values. It cannot
// set the clock of the store from this package. So the clock is +91 d in the
// stored times. The old rows are 91 d before now. The run at the start (no
// mark) takes them as 91 d old. The request rows inside the windows are 5 d
// old and have about 6 MB of body. They are above the cap alone. So only the
// cap step brings the size to the cap. After the run, the size (file and WAL)
// is at most the cap. The aggregate rows from before are as they were. The
// old rows rolled up. There is one retention event with a leaf in the log.
func TestTI13_StartedSensorKeepsTheCap(t *testing.T) {
	const capBytes = 2 << 20
	now := time.Now()
	oldTs := now.UnixMilli() - 91*dayMs
	type agg struct {
		Day, Vhost, Band, Family      string
		Sessions, Requests, Callbacks int
	}
	var before []agg
	for i := range 4 {
		before = append(before, agg{now.AddDate(0, 0, -400-i).UTC().Format(time.DateOnly), decoyName, "human", "", i + 1, 10 * (i + 1), i})
	}
	seed := func(t *testing.T, p startParams) {
		withState(t, p, p.StorePath, func(db *sql.DB) {
			for _, a := range before {
				mustExec(t, db, "INSERT INTO aggregate_day (day, vhost, band, family, sessions, requests, callbacks) VALUES (?, ?, ?, ?, ?, ?, ?)",
					a.Day, a.Vhost, a.Band, a.Family, a.Sessions, a.Requests, a.Callbacks)
			}
			for id, age := range map[string]int64{"t91": 91, "t85": 85} {
				at := now.UnixMilli() - age*dayMs
				mustExec(t, db, "INSERT INTO token (token_id, session_id, trap_id, issued_at, first_cb_at) VALUES (?, 's', 't', ?, ?)", id, at, at)
			}
			const rec = "WITH RECURSIVE c(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM c WHERE i < ?) "
			mustExec(t, db, rec+"INSERT INTO event (ts, kind, vhost, path) SELECT ? + i*1000, 'request', ?, '/old' FROM c", 199, oldTs, decoyName)
			mustExec(t, db, rec+"INSERT INTO event (ts, kind, vhost, path, body_prefix) SELECT ? + i*1000, 'request', ?, '/in', zeroblob(2000) FROM c",
				2999, now.UnixMilli()-5*dayMs, decoyName)
		})
	}
	var live atomic.Pointer[sql.DB]
	began := time.Now()
	s := startBait(t, baitOpt{bundle: true, maxBytes: capBytes, seed: seed, store: live.Store})
	size := func() int64 {
		var n int64
		for _, suffix := range []string{"", "-wal"} {
			if fi, err := os.Stat(filepath.Join(s.p.Root, s.p.StorePath+suffix)); err == nil {
				n += fi.Size()
			}
		}
		return n
	}
	untilRun(t, "retention event", began, func() bool {
		db := live.Load()
		return db != nil && countOf(t, db, "SELECT count(*) FROM event WHERE kind = 'retention'") == 1
	})
	if n := size(); n > capBytes {
		t.Errorf("size %d after the run, cap %d", n, capBytes)
	}
	s.stop(t)
	withState(t, s.p, s.p.StorePath, func(db *sql.DB) {
		if n := countOf(t, db, "SELECT count(*) FROM event WHERE kind = 'request' AND path = '/in'"); n == 3000 {
			t.Error("no window row was evicted: the cap step did not run")
		}
		rows, err := db.Query("SELECT day, vhost, band, family, sessions, requests, callbacks FROM aggregate_day WHERE day < ? ORDER BY day",
			now.AddDate(0, 0, -300).UTC().Format(time.DateOnly))
		mustOK(t, err)
		defer rows.Close()
		var got []agg
		for rows.Next() {
			var a agg
			mustOK(t, rows.Scan(&a.Day, &a.Vhost, &a.Band, &a.Family, &a.Sessions, &a.Requests, &a.Callbacks))
			got = append(got, a)
		}
		mustOK(t, rows.Err())
		slices.Reverse(got) // days of the seed go back in time
		if !slices.Equal(got, before) {
			t.Errorf("aggregate rows from before the run: %+v, want %+v", got, before)
		}
		d1, d2 := time.UnixMilli(oldTs).UTC().Format(time.DateOnly), time.UnixMilli(oldTs+199_000).UTC().Format(time.DateOnly)
		if n := countOf(t, db, "SELECT coalesce(sum(requests), 0) FROM aggregate_day WHERE day IN (?, ?)", d1, d2); n != 200 {
			t.Errorf("roll-up of the 200 old request rows: %d requests, want 200", n)
		}
		if n := countOf(t, db, "SELECT count(*) FROM event WHERE kind = 'request' AND path = '/old'"); n != 0 {
			t.Errorf("%d old request rows left", n)
		}
		var ids string
		mustOK(t, db.QueryRow("SELECT coalesce(group_concat(token_id), '') FROM token").Scan(&ids))
		if ids != "t85" {
			t.Errorf("tokens left %q, want t85: the token of 91 d goes, the token of 85 d stays", ids)
		}
		var leaf int64
		mustOK(t, db.QueryRow("SELECT leaf_index FROM event WHERE kind = 'retention'").Scan(&leaf))
		root, err := os.OpenRoot(s.p.Root)
		mustOK(t, err)
		defer root.Close()
		lg, err := tlog.OpenLog(root, s.p.TlogDir)
		mustOK(t, err)
		defer lg.Close()
		if head, _ := lg.Head(); leaf >= head {
			t.Errorf("leaf index %d of the retention event, log size %d: no leaf in the log", leaf, head)
		}
	})
	if n := size(); n > capBytes {
		t.Errorf("size %d after the stop, cap %d", n, capBytes)
	}
}

// untilRun waits until cond is true. The run writes its mark in its last
// step and its retention event at its end. It fails the test if cond is not
// true within the bound. The bound is not netWait. netWait is for one network
// step. The run rolls up thousands of rows and runs every step. With -race and
// coverage on a slow runner it takes more than netWait. So the bound comes from
// the test: its deadline, minus a margin for the stop and the checks. With no
// deadline, it is 2 minutes. The logged time starts before the start of the
// sensor, so it holds the start and the run.
func untilRun(t *testing.T, what string, start time.Time, cond func() bool) {
	t.Helper()
	bound := 2 * time.Minute
	if d, ok := t.Deadline(); ok {
		bound = time.Until(d) - 30*time.Second
	}
	for limit := time.Now().Add(bound); !cond(); time.Sleep(time.Millisecond) {
		if time.Now().After(limit) {
			t.Fatalf("no %s after %v", what, bound)
		}
	}
	t.Logf("the run took %v (%s)", time.Since(start).Round(time.Millisecond), what)
}

// hostileHosts returns n distinct Host values. First come the forms of T-S-35.
// These are case and port, trailing dot, punycode, non-ASCII, the Kelvin
// sign, IP literals, empty and 253 bytes. Then come plain unknown names.
func hostileHosts(n int) []string {
	label := func(k int) string { return strings.Repeat("a", k) }
	hosts := []string{
		strings.ToUpper(decoyName), decoyName + ":443", strings.ToUpper(decoyName) + ":8443", decoyName + ".", decoyName + ".:443",
		noVhost, strings.ToUpper(noVhost), noVhost + ":443",
		"xn--bcher-kva.zz", "bücher.zz", "Kelvin.zz", decoyName + "K",
		"127.0.0.1", "127.0.0.1:443", "[::1]", "[::1]:443", "192.0.2.7", "",
		label(63) + "." + label(63) + "." + label(63) + "." + label(61),
	}
	for i := 0; len(hosts) < n; i++ {
		hosts = append(hosts, fmt.Sprintf("h%d.other.zz", i))
	}
	return hosts
}

// sendHosts makes one HTTPS request for each Host value at addr, with 16
// connections at once. It writes the request by hand, as a client that Go does
// not check. It returns the count of each status line.
func sendHosts(t *testing.T, addr string, hosts []string) map[string]int {
	t.Helper()
	var mu sync.Mutex
	status := map[string]int{}
	jobs := make(chan string)
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			for h := range jobs {
				line := "error"
				if conn, err := tls.DialWithDialer(&net.Dialer{Timeout: netWait}, "tcp", addr, &tls.Config{ServerName: decoyName, InsecureSkipVerify: true}); err == nil {
					conn.SetDeadline(time.Now().Add(netWait))
					fmt.Fprintf(conn, "GET /page HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", h)
					if l, err := bufio.NewReader(conn).ReadString('\n'); err == nil {
						line = strings.Join(strings.Fields(l)[:2], " ")
					}
					conn.Close()
				}
				mu.Lock()
				status[line]++
				mu.Unlock()
			}
		})
	}
	for _, h := range hosts {
		jobs <- h
	}
	close(jobs)
	wg.Wait()
	return status
}

// TestTS35_HostValuesThroughTheStartedSensor sends 10 000 distinct Host
// values through the real listener and decoy handler. Then it stops the
// sensor. The store clock is not settable from this package. So the clock is
// +31 d in the stored times. The test moves the request rows 31 d back and
// deletes the mark. It starts the sensor again on the same state directory.
// The run at the start rolls the rows up. For each day of aggregate_day, the
// distinct vhost values are at most the configured names plus one (T-S-35).
// Each is a configured name or the empty name, as the roll-up stores it. The
// test config has two names, decoyName and noVhost. The bundle has a vhost for
// decoyName only. So the bound is 3.
func TestTS35_HostValuesThroughTheStartedSensor(t *testing.T) {
	names := []string{decoyName, noVhost}
	hosts := hostileHosts(10_000)
	if n := len(slices.Compact(slices.Sorted(slices.Values(hosts)))); n != len(hosts) {
		t.Fatalf("%d distinct Host values of %d", n, len(hosts))
	}
	s := startBait(t, baitOpt{bundle: true})
	status := sendHosts(t, strings.TrimPrefix(s.https, "https://"), hosts)
	t.Logf("status lines: %v", status)
	s.stop(t)
	var requests int
	withState(t, s.p, s.p.StorePath, func(db *sql.DB) {
		requests = countOf(t, db, "SELECT count(*) FROM event WHERE kind = 'request'")
		// The server answers non-ASCII Host values with 400 before the
		// handler runs. Those store no row. Every other request stores one
		// row. startBait makes one more request, the probe.
		if bad := status["HTTP/1.1 400"]; requests < len(hosts)-bad || requests > len(hosts)+1 {
			t.Fatalf("%d request rows for %d requests, of which %d got 400 (status lines %v)", requests, len(hosts), bad, status)
		}
		mustExec(t, db, "UPDATE event SET ts = ts - ? WHERE kind = 'request'", 31*dayMs)
		mustExec(t, db, "DELETE FROM meta WHERE key = 'retention_last'")
	})
	var live atomic.Pointer[sql.DB]
	began := time.Now()
	s2 := startBait(t, baitOpt{root: s.p.Root, store: live.Store})
	untilRun(t, "mark of the run", began, func() bool {
		db := live.Load()
		return db != nil && countOf(t, db, "SELECT count(*) FROM meta WHERE key = 'retention_last'") == 1
	})
	s2.stop(t)
	withState(t, s.p, s.p.StorePath, func(db *sql.DB) {
		// The second start makes its own probe request, a row of today.
		if n := countOf(t, db, "SELECT count(*) FROM event WHERE kind = 'request' AND ts < ?", time.Now().UnixMilli()-20*dayMs); n != 0 {
			t.Errorf("%d request rows of 31 d left: the run did not roll them up", n)
		}
		if n := countOf(t, db, "SELECT coalesce(sum(requests), 0) FROM aggregate_day"); n != requests {
			t.Errorf("aggregate_day has %d requests, want %d", n, requests)
		}
		rows, err := db.Query("SELECT day, vhost FROM aggregate_day")
		mustOK(t, err)
		defer rows.Close()
		perDay := map[string]map[string]bool{}
		for rows.Next() {
			var day string
			var vhost sql.NullString
			mustOK(t, rows.Scan(&day, &vhost))
			// The roll-up stores "" for no vhost. NULL has its own key. No
			// vhost text can be that key.
			key := vhost.String
			switch {
			case !vhost.Valid:
				key = "\x00null"
			case key != "" && !slices.Contains(names, key):
				t.Errorf("day %s has the vhost %q, which is not a configured name", day, key)
			}
			if perDay[day] == nil {
				perDay[day] = map[string]bool{}
			}
			perDay[day][key] = true
		}
		mustOK(t, rows.Err())
		if len(perDay) == 0 {
			t.Error("aggregate_day has no row")
		}
		for day, v := range perDay {
			if len(v) > len(names)+1 {
				t.Errorf("day %s has %d distinct vhost values, want at most %d", day, len(v), len(names)+1)
			}
		}
	})
}
