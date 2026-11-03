package store

import (
	"context"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/cybagard/cyba-phantom/internal/event"
)

// sessEvent makes an event of kind k for session id at time ts. An empty ip or
// ja4 is absent.
func sessEvent(t *testing.T, k event.Kind, id, ip, ja4 string, ts int64) *event.Event {
	t.Helper()
	e, err := event.NewEvent(func() time.Time { return time.UnixMilli(ts) },
		event.Input{Kind: k, Session: id, ClientIP: ip, JA4: ja4})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

type sessionRow struct {
	first, last, count int64
	ip, ja4            *string
	hmac, band         string
	score              int64
}

// session returns the row with id, and false when there is none.
func (r *rig) session(id string) (s sessionRow, ok bool) {
	r.t.Helper()
	rows, err := r.db.Query("SELECT first_seen, last_seen, req_count, ip, ip_hmac, ja4, band, score FROM session WHERE id = ?", id)
	if err != nil {
		r.t.Fatal(err)
	}
	defer rows.Close()
	if !rows.Next() {
		return s, false
	}
	if err := rows.Scan(&s.first, &s.last, &s.count, &s.ip, &s.hmac, &s.ja4, &s.band, &s.score); err != nil {
		r.t.Fatal(err)
	}
	return s, true
}

func (r *rig) sessionCount() (n int) {
	r.t.Helper()
	if err := r.db.QueryRow("SELECT count(*) FROM session").Scan(&n); err != nil {
		r.t.Fatal(err)
	}
	return n
}

// writeOK flushes a batch and checks that the writer stays healthy. Only flush
// stops the writer on an error, so write alone cannot show the stop.
func (r *rig) writeOK(batch ...*event.Event) {
	r.t.Helper()
	if rest := r.w.flush(batch); len(rest) != 0 {
		r.t.Fatalf("flush returned %d events, want an empty batch", len(rest))
	}
	if r.w.Err() != nil || !r.w.Healthy() {
		r.t.Fatalf("writer not healthy after a batch: %v", r.w.Err())
	}
}

// want checks a session row against the expected values. An empty ip or ja4 is
// NULL.
func (r *rig) want(id string, first, last, count int64, ip, hmac, ja4 string) {
	r.t.Helper()
	s, ok := r.session(id)
	if !ok {
		r.t.Fatalf("no session row for %q", id)
	}
	text := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}
	if s.first != first || s.last != last || s.count != count {
		r.t.Errorf("%s: first %d last %d count %d, want %d %d %d", id, s.first, s.last, s.count, first, last, count)
	}
	if text(s.ip) != ip || (s.ip == nil) != (ip == "") || text(s.ja4) != ja4 || (s.ja4 == nil) != (ja4 == "") {
		r.t.Errorf("%s: ip %q ja4 %q, want %q %q (NULL is empty)", id, text(s.ip), text(s.ja4), ip, ja4)
	}
	if s.hmac != hmac {
		r.t.Errorf("%s: ip_hmac %q, want %q", id, s.hmac, hmac)
	}
	if s.band != "human" || s.score != 0 {
		r.t.Errorf("%s: band %q score %d, want human 0", id, s.band, s.score)
	}
}

// T-S-31: 500 request events of one session make one row and one upsert
// statement. The hook counts each execution of the statement. The row keeps the
// address and the JA4 text of the first event and the smallest and largest ts.
func TestTS31OneSessionInOneBatchIsOneUpsert(t *testing.T) {
	r := newRig(t, 100)
	key := seedKeys(t, 1)[0]
	r.w.clock = func() time.Time { return day("2026-03-01T10:00:00Z") }
	execs := 0
	r.w.sessions.onExec = func() { execs++ }
	var batch []*event.Event
	for i := range maxBatch {
		// 37 and 500 have no common factor, so the ts values cover 1000..1499.
		ts := int64(1499 - i*37%500)
		batch = append(batch, sessEvent(t, event.KindRequest, "sess-one",
			fmt.Sprintf("198.51.100.%d", i%250+1), fmt.Sprintf("ja4-%d", i), ts))
	}
	r.writeOK(batch...)
	if execs != 1 {
		t.Errorf("%d upsert statements for 500 events of one session, want 1", execs)
	}
	if n := r.sessionCount(); n != 1 {
		t.Errorf("%d session rows, want 1", n)
	}
	k := netip.MustParseAddr("198.51.100.1").As4()
	r.want("sess-one", 1000, 1499, 500, "198.51.100.1", mac(key, k[:]), "ja4-0")
}

// T-S-31: 500 request events of 500 sessions make 500 rows.
func TestTS31OneRowForEachSession(t *testing.T) {
	r := newRig(t, 100)
	execs := 0
	r.w.sessions.onExec = func() { execs++ }
	var batch []*event.Event
	for i := range maxBatch {
		batch = append(batch, sessEvent(t, event.KindRequest, fmt.Sprintf("sess-%d", i), "203.0.113.5", "", int64(i)))
	}
	r.writeOK(batch...)
	if n := r.sessionCount(); n != maxBatch || execs != maxBatch {
		t.Errorf("%d session rows and %d statements, want %d of each", n, execs, maxBatch)
	}
}

// T-S-31: a second batch changes only last_seen and req_count. A later event
// from another address and JA4 text changes neither. An older ts does not move
// last_seen back.
func TestTS31SecondBatchKeepsFirstValues(t *testing.T) {
	r := newRig(t, 100)
	key := seedKeys(t, 1)[0]
	r.w.clock = func() time.Time { return day("2026-03-01T10:00:00Z") }
	r.writeOK(sessEvent(t, event.KindRequest, "s", "198.51.100.1", "ja4-a", 1000),
		sessEvent(t, event.KindRequest, "s", "198.51.100.1", "ja4-a", 2000))
	k := netip.MustParseAddr("198.51.100.1").As4()
	hm := mac(key, k[:])
	r.want("s", 1000, 2000, 2, "198.51.100.1", hm, "ja4-a")

	r.writeOK(sessEvent(t, event.KindRequest, "s", "192.0.2.9", "ja4-b", 3000),
		sessEvent(t, event.KindRequest, "s", "192.0.2.9", "ja4-b", 2500))
	r.want("s", 1000, 3000, 4, "198.51.100.1", hm, "ja4-a")

	r.writeOK(sessEvent(t, event.KindRequest, "s", "192.0.2.9", "ja4-b", 500))
	r.want("s", 1000, 3000, 5, "198.51.100.1", hm, "ja4-a")
	if n := r.sessionCount(); n != 1 {
		t.Errorf("%d session rows, want 1", n)
	}
}

// T-S-31: a refused row gets a session row. Its id is the session_id of the
// event row, and ip_hmac is the HMAC of the counter key.
func TestTS31RefusedRowGetsSessionRow(t *testing.T) {
	r := newRig(t, 100)
	key := seedKeys(t, 1)[0]
	r.w.clock = func() time.Time { return day("2026-03-01T10:00:00Z") }
	const ja4 = "t13d1516h2_8daaf6152771_b186095e22b6"
	r.writeOK(refusedEvent(t, "198.51.100.23", ja4), refusedEvent(t, "198.51.100.23", ja4))
	rows := r.stored()
	if len(rows) != 2 || rows[0].session == nil {
		t.Fatalf("event rows %+v, want two with a session", rows)
	}
	k := netip.MustParseAddr("198.51.100.23").As4()
	r.want(*rows[0].session, 5000, 5000, 2, "198.51.100.23", mac(key, k[:]), ja4)
	if n := r.sessionCount(); n != 1 {
		t.Errorf("%d session rows, want 1", n)
	}
}

// T-S-31: ip_hmac of an IPv6 address is the HMAC of its /64 key. That of an
// IPv4-mapped address is the HMAC of its IPv4 key. ip is the event text.
func TestTS31IPHMACUsesTheCounterKey(t *testing.T) {
	r := newRig(t, 100)
	key := seedKeys(t, 1)[0]
	r.w.clock = func() time.Time { return day("2026-03-01T10:00:00Z") }
	r.writeOK(sessEvent(t, event.KindRequest, "v6", "2001:db8:abcd:1234::1", "", 10),
		sessEvent(t, event.KindRequest, "v4", "::ffff:198.51.100.23", "", 20))
	v6 := netip.MustParseAddr("2001:db8:abcd:1234::").As16()
	v4 := netip.MustParseAddr("198.51.100.23").As4()
	r.want("v6", 10, 10, 1, "2001:db8:abcd:1234::1", mac(key, v6[:]), "")
	r.want("v4", 20, 20, 1, "::ffff:198.51.100.23", mac(key, v4[:]), "")
}

// T-S-31: a request with a session and no address gets ip NULL and the overflow
// ip_hmac text. The writer stays healthy.
func TestTS31NoAddressGivesOverflowHMAC(t *testing.T) {
	r := newRig(t, 100)
	r.writeOK(sessEvent(t, event.KindRequest, "none", "", "", 10))
	r.want("none", 10, 10, 1, "", overflowHMAC, "")
}

// T-S-31: a duplicate session in one batch and in two batches does not stop
// the writer. The row counts are right. Each commit counts the event rows, not
// the session rows.
func TestTS31DuplicateSessionDoesNotStopTheWriter(t *testing.T) {
	r := newRig(t, 100)
	key := seedKeys(t, 1)[0]
	r.w.clock = func() time.Time { return day("2026-03-01T10:00:00Z") }
	r.writeOK(sessEvent(t, event.KindRequest, "a", "192.0.2.1", "", 1),
		sessEvent(t, event.KindRequest, "a", "192.0.2.1", "", 2),
		sessEvent(t, event.KindRequest, "b", "192.0.2.2", "", 3))
	if n := r.sessionCount(); n != 2 {
		t.Errorf("%d session rows after batch 1, want 2", n)
	}
	r.writeOK(sessEvent(t, event.KindRequest, "a", "192.0.2.1", "", 4),
		sessEvent(t, event.KindRequest, "b", "192.0.2.2", "", 5),
		sessEvent(t, event.KindRequest, "a", "192.0.2.1", "", 6))
	if n := r.sessionCount(); n != 2 {
		t.Errorf("%d session rows after batch 2, want 2", n)
	}
	if n := len(r.stored()); n != 6 {
		t.Errorf("%d event rows, want 6", n)
	}
	k := netip.MustParseAddr("192.0.2.1").As4()
	r.want("a", 1, 6, 4, "192.0.2.1", mac(key, k[:]), "")
	wantCommits(t, r, 3, 3)
}

// T-S-31: an upsert of a known session leaves the other columns alone. Only
// last_seen (the larger value) and req_count change.
func TestTS31KnownSessionKeepsOtherColumns(t *testing.T) {
	r := newRig(t, 100)
	r.w.clock = func() time.Time { return day("2026-03-01T10:00:00Z") }
	if _, err := r.db.Exec("INSERT INTO session (id, first_seen, last_seen, ip, ip_hmac, ja4, ua, family, beacon_seen, req_count, band, score, alerted_at) VALUES ('known', 100, 200, NULL, 'h0', NULL, 'u', 'f', 1, 3, 'agent-confirmed', 97, 9)"); err != nil {
		t.Fatal(err)
	}
	r.writeOK(sessEvent(t, event.KindRequest, "known", "198.51.100.1", "ja4-a", 50),
		sessEvent(t, event.KindRequest, "known", "198.51.100.1", "ja4-a", 250))
	var first, last, beacon, count, score, alerted int64
	var ip, ja4, ua, family *string
	var hmac, band string
	if err := r.db.QueryRow("SELECT first_seen, last_seen, ip, ip_hmac, ja4, ua, family, beacon_seen, req_count, band, score, alerted_at FROM session WHERE id = 'known'").
		Scan(&first, &last, &ip, &hmac, &ja4, &ua, &family, &beacon, &count, &band, &score, &alerted); err != nil {
		t.Fatal(err)
	}
	if first != 100 || last != 250 || count != 5 {
		t.Errorf("first %d last %d count %d, want 100 250 5", first, last, count)
	}
	if ip != nil || ja4 != nil || hmac != "h0" {
		t.Errorf("ip %v ja4 %v ip_hmac %q, want NULL NULL h0", ip, ja4, hmac)
	}
	if band != "agent-confirmed" || score != 97 || beacon != 1 || alerted != 9 {
		t.Errorf("band %q score %d beacon_seen %d alerted_at %d, want agent-confirmed 97 1 9", band, score, beacon, alerted)
	}
	if ua == nil || *ua != "u" || family == nil || *family != "f" {
		t.Errorf("ua %v family %v, want u f", ua, family)
	}
}

// T-S-31: an error of the upsert stops the writer. The batch has one request
// event with a session and three evidence events. The append works, so the
// three leaves count as orphan leaves. No row exists and no commit happens.
func TestTS31UpsertErrorStopsTheWriter(t *testing.T) {
	cases := []struct {
		name  string
		sql   string
		table bool // the session table still exists
	}{
		{"statement", "CREATE TRIGGER no_session BEFORE INSERT ON session BEGIN SELECT RAISE(ABORT, 'x'); END", true},
		{"prepare", "DROP TABLE session", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t, 100)
			if _, err := r.db.Exec(c.sql); err != nil {
				t.Fatal(err)
			}
			if !r.q.Enqueue(sessEvent(t, event.KindRequest, "s", "192.0.2.1", "", 1)) {
				t.Fatal("enqueue failed")
			}
			for i := int64(2); i < 5; i++ {
				r.add(event.KindCallback, i)
			}
			r.q.Close()
			if err := r.run(context.Background()); err != nil {
				t.Fatal(err)
			}
			wantRule(t, r.w.Err(), writerName, ruleDatabase)
			s := r.w.Stats()
			if r.w.Healthy() || s.OrphanLeaves != 3 || s.Dropped != (Drops{Bulk: 1, Evidence: 3}) {
				t.Fatalf("healthy %v, stats %+v", r.w.Healthy(), s)
			}
			if r.rows() != 0 || len(r.commits) != 0 {
				t.Errorf("%d event rows, %d commits, want 0 of each", r.rows(), len(r.commits))
			}
			if c.table && r.sessionCount() != 0 {
				t.Errorf("%d session rows, want 0", r.sessionCount())
			}
		})
	}
}

// T-S-31: an evidence kind with a session adds no session row and does not
// change req_count. A beacon adds none either.
func TestTS31OtherKindsAddNothing(t *testing.T) {
	r := newRig(t, 100)
	req := rowEvent(t, event.KindRequest, true, 100)
	cb1 := rowEvent(t, event.KindCallback, true, 200)
	cb2 := sessEvent(t, event.KindCallback, "other", "192.0.2.1", "", 300)
	bc := sessEvent(t, event.KindBeacon, "beacon", "192.0.2.1", "", 400)
	r.writeOK(req, cb1, cb2, bc)
	if n := r.sessionCount(); n != 1 {
		t.Errorf("%d session rows, want 1", n)
	}
	if _, ok := r.session("other"); ok {
		t.Error("a callback event made a session row")
	}
	r.writeOK(rowEvent(t, event.KindCallback, true, 900))
	s, _ := r.session("sess-1")
	if s.first != 100 || s.last != 100 || s.count != 1 {
		t.Errorf("sess-1: first %d last %d count %d, want 100 100 1", s.first, s.last, s.count)
	}
}
