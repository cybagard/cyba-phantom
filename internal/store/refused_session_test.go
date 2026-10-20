package store

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/netip"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/cybagard/cyba-phantom/internal/event"
)

// refusedEvent makes a refused event for the client address ip and the JA4 text
// ja4. An empty ip or ja4 is absent.
func refusedEvent(t *testing.T, ip, ja4 string) *event.Event {
	t.Helper()
	e, err := event.NewEvent(func() time.Time { return time.UnixMilli(5000) },
		event.Input{Kind: event.KindRefused, Reason: event.ReasonBadHello, ClientIP: ip, JA4: ja4})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// refusedIDs writes one refused event for each ip with w. It returns the stored
// session ids in order. A NULL gives "".
func (r *rig) refusedIDs(w *Writer, ja4 string, ips ...string) []string {
	r.t.Helper()
	var batch []*event.Event
	for _, ip := range ips {
		batch = append(batch, refusedEvent(r.t, ip, ja4))
	}
	if err := w.write(batch); err != nil {
		r.t.Fatal(err)
	}
	rows, err := r.db.Query("SELECT session_id FROM event ORDER BY id DESC LIMIT ?", len(ips))
	if err != nil {
		r.t.Fatal(err)
	}
	defer rows.Close()
	ids := make([]string, len(ips))
	for i := len(ips) - 1; rows.Next(); i-- {
		var s *string
		if err := rows.Scan(&s); err != nil {
			r.t.Fatal(err)
		}
		if s != nil {
			ids[i] = *s
		}
	}
	return ids
}

// wantID is the session id by the definition. It is the first 16 bytes of the
// HMAC over the prefix, 0x00, the key bytes and the JA4 text.
func wantID(key [32]byte, k []byte, ja4 string) string {
	m := hmac.New(sha256.New, key[:])
	m.Write([]byte("phantom-session-v1"))
	m.Write([]byte{0})
	m.Write(k)
	m.Write([]byte(ja4))
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(m.Sum(nil)[:16]))
}

// T-S-22: the session id of a refused row is an HMAC function. Its inputs are
// the batch day key, the client key and the JA4 text. An IPv4-mapped address
// has the id of its IPv4 form. Two IPv6 addresses in one /64 have one id.
func TestTS22SessionIDIsTheFunctionOfTheKeyAndTheJA4(t *testing.T) {
	r := newRig(t, 100)
	r.w.clock = func() time.Time { return day("2026-03-01T10:00:00Z") }
	const ja4 = "t13d1516h2_8daaf6152771_b186095e22b6"
	ids := r.refusedIDs(r.w, ja4, "198.51.100.23", "::ffff:198.51.100.23", "2001:db8:abcd:1234::1", "2001:db8:abcd:1234:ffff::9")
	v4 := netip.MustParseAddr("198.51.100.23").As4()
	v6 := netip.MustParseAddr("2001:db8:abcd:1234::").As16()
	for i, want := range []string{wantID(r.w.dk.key, v4[:], ja4), wantID(r.w.dk.key, v4[:], ja4),
		wantID(r.w.dk.key, v6[:], ja4), wantID(r.w.dk.key, v6[:], ja4)} {
		if ids[i] != want {
			t.Errorf("event %d: session_id %q, want %q", i, ids[i], want)
		}
		if !regexp.MustCompile(`^[a-z2-7]{26}$`).MatchString(ids[i]) {
			t.Errorf("event %d: session_id %q is not 26 lower-case base32 characters", i, ids[i])
		}
	}
	if ids[0] == ids[2] {
		t.Error("an IPv4 key and an IPv6 key have one id")
	}
}

// T-S-22: the id differs from ip_hmac of the same key, also with an empty JA4.
// It changes at a new UTC date and for a new writer. An event with no address
// has no id.
func TestTS22SessionIDChangesAndDiffersFromIPHMAC(t *testing.T) {
	r := newRig(t, 100)
	const ip = "192.0.2.77"
	k := netip.MustParseAddr(ip).As4()
	at := day("2026-03-01T10:00:00Z")
	r.w.clock = func() time.Time { return at }
	first := r.refusedIDs(r.w, "", ip)[0]
	if first != wantID(r.w.dk.key, k[:], "") {
		t.Errorf("session_id %q with an empty JA4 is not the defined value", first)
	}
	idBytes, err := base32.StdEncoding.WithPadding(base32.NoPadding).
		DecodeString(strings.ToUpper(first))
	if err != nil {
		t.Fatal(err)
	}
	ipMAC, err := hex.DecodeString(r.w.dk.hmac(netip.MustParseAddr(ip)))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(idBytes, ipMAC[:16]) {
		t.Error("the session id bytes equal the first 16 bytes of ip_hmac")
	}
	if again := r.refusedIDs(r.w, "", ip)[0]; again != first {
		t.Error("the id changed inside one date")
	}
	at = day("2026-03-02T10:00:00Z")
	if next := r.refusedIDs(r.w, "", ip)[0]; next == first {
		t.Error("the id did not change at a new UTC date")
	}
	at = day("2026-03-01T10:00:00Z")
	w2 := NewWriter(r.db, r.q, r.app, r.c, false, nil, r.w.rec)
	w2.clock = func() time.Time { return at }
	if restart := r.refusedIDs(w2, "", ip)[0]; restart == first {
		t.Error("the id did not change after a restart")
	}
	if none := r.refusedIDs(r.w, "ja4", "")[0]; none != "" {
		t.Errorf("an event with no address has session_id %q", none)
	}
}

// T-U-18: a refused row keeps the event values in each column except
// session_id, also with store_body_prefix true. A request row keeps the session
// of its record: the writer makes an id for no other kind.
func TestTU18RefusedRowColumnsEqualEventValues(t *testing.T) {
	r := newRig(t, 100)
	r.w.bodyPrefix = true
	r.w.clock = func() time.Time { return day("2026-03-01T10:00:00Z") }
	const ja4 = "t13d1516h2_8daaf6152771_b186095e22b6"
	refused, request := refusedEvent(t, "198.51.100.23", ja4), rowEvent(t, event.KindRequest, true, 7000)
	if err := r.w.write([]*event.Event{refused, request}); err != nil {
		t.Fatal(err)
	}
	rows := r.stored()
	if len(rows) != 2 {
		t.Fatalf("%d rows for 2 events", len(rows))
	}
	rec, got := refused.Record(), rows[0]
	detail, err := rec.Detail.JSON()
	if err != nil {
		t.Fatal(err)
	}
	k := netip.MustParseAddr("198.51.100.23").As4()
	if got.ts != rec.TS || got.kind != "refused" {
		t.Errorf("refused row: ts %d kind %q, want %d refused", got.ts, got.kind, rec.TS)
	}
	if got.detail == nil || *got.detail != string(detail) || *got.detail != `{"reason":"bad_hello"}` {
		t.Errorf("refused row: detail %v, want %s", got.detail, detail)
	}
	if want := wantID(r.w.dk.key, k[:], ja4); got.session == nil || *got.session != want {
		t.Errorf("refused row: session_id %v, want %q", got.session, want)
	}
	for col, null := range map[string]bool{
		"vhost": got.vhost == nil, "method": got.method == nil, "path": got.path == nil,
		"status": got.status == nil, "trap_id": got.trap == nil, "token_id": got.token == nil,
		"surface": got.surface == nil, "body_prefix": got.body == nil, "hash": got.hash == nil,
		"leaf_index": got.leaf == nil, "record": got.record == nil,
	} {
		if !null {
			t.Errorf("refused row: column %s is not NULL", col)
		}
	}
	want := request.Record().Session
	if want == nil || *want != "sess-1" {
		t.Fatalf("the request record has session %v, want sess-1", want)
	}
	if got := rows[1].session; got == nil || *got != *want {
		t.Errorf("request row: session_id %v, want %q", got, *want)
	}
}

// T-U-18, T-S-22: the writer stores no address of a refused event. No column of
// any table, no log line and no returned error holds an address marker or the
// JA4 text. No session row is written.
func TestTU18RefusedEventStoresNoAddress(t *testing.T) {
	r := newRig(t, 100)
	const ja4Marker = "ja4mk7x2q9"
	var logs bytes.Buffer
	r.w.log = slog.New(slog.NewTextHandler(&logs, nil))
	ips := []string{"192.0.2.9", "198.51.100.23", "203.0.113.77", "::ffff:203.0.113.5",
		"2001:db8:abcd:1234::1", "2001:db8::beef"}
	markers := []string{"192.0.2.", "198.51.100.", "203.0.113.", "2001:db8", "2001:0db8", "20010db8",
		"c00002", "c63364", "cb0071", "0xc0", "::ffff", ja4Marker}
	var batch []*event.Event
	for _, ip := range ips {
		batch = append(batch, refusedEvent(t, ip, ja4Marker))
	}
	if err := r.w.write(batch); err != nil {
		t.Fatal(err)
	}
	check := func(what, text string) {
		t.Helper()
		low := strings.ToLower(text)
		for _, m := range markers {
			if strings.Contains(low, m) {
				t.Errorf("%s holds the marker %q", what, m)
			}
		}
	}

	db := r.db
	tables, err := db.Query("SELECT name FROM sqlite_master WHERE type = 'table'")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for tables.Next() {
		var n string
		if err := tables.Scan(&n); err != nil {
			t.Fatal(err)
		}
		names = append(names, n)
	}
	tables.Close()
	for _, n := range names {
		rows, err := db.Query(fmt.Sprintf("SELECT * FROM %q", n))
		if err != nil {
			t.Fatal(err)
		}
		cols, _ := rows.Columns()
		for rows.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				t.Fatal(err)
			}
			for i, v := range vals {
				if b, ok := v.([]byte); ok {
					v = string(b) + hex.EncodeToString(b)
				}
				check(fmt.Sprintf("table %s column %s", n, cols[i]), fmt.Sprint(v))
			}
		}
		rows.Close()
		if n == "session" {
			var c int
			if err := db.QueryRow(`SELECT count(*) FROM "session"`).Scan(&c); err != nil || c != 0 {
				t.Errorf("session has %d rows (%v)", c, err)
			}
		}
	}
	if !strings.Contains(strings.Join(names, " "), "session") {
		t.Error("no session table: the empty-table check did not run")
	}

	// A failed write returns an error, and the stop of the writer logs a line.
	r.c.Drop(netip.MustParseAddr("198.51.100.23"))
	r.db.Close()
	err = r.w.write(batch)
	if err == nil {
		t.Fatal("a write to a closed database has no error")
	}
	r.w.stop(err)
	check("an error", err.Error())
	check("the log", logs.String())
	if logs.Len() == 0 {
		t.Error("the writer logged no line, so the log check proves nothing")
	}
}
