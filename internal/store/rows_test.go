package store

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cybagard/cyba-phantom/internal/event"
)

var allKinds = []event.Kind{
	event.KindRequest, event.KindCallback, event.KindBeacon, event.KindScoreChange,
	event.KindBundleLoad, event.KindBundleRejected, event.KindAlertSent, event.KindRetention,
}

func isSystem(k event.Kind) bool {
	return k == event.KindBundleLoad || k == event.KindBundleRejected || k == event.KindRetention
}

const clientIP = "203.0.113.77"

// rowEvent makes an event of kind k. A full event sets every field that the
// kind permits; a minimal event sets only the kind.
func rowEvent(t *testing.T, k event.Kind, full bool, ts int64) *event.Event {
	t.Helper()
	in := event.Input{Kind: k}
	if full {
		st := int64(404)
		in = event.Input{
			Kind: k, Vhost: "example.test", Method: "POST", Path: "/a/b?x=%FF\"é", Status: &st,
			TrapID: "trap-1", TokenID: "tok-1", Surface: event.SurfaceQuery,
			JA4: "ja4", H2: "h2", Hdr: "hdr", ClientIP: clientIP, BodyPrefix: []byte{0, 1, 'a', 0xff},
			Detail: event.Detail{"n": event.Int(7), "s": event.Str("é\"x\\"), "b": event.Bool(true)},
		}
		if !isSystem(k) {
			in.Session = "sess-1"
		}
	}
	e, err := event.NewEvent(func() time.Time { return time.UnixMilli(ts) }, in)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

type storedRow struct {
	ts                   int64
	session              *string
	kind                 string
	vhost, method, path  *string
	status               *int64
	trap, token, surface *string
	body, hash           []byte
	leaf                 *int64
	detail               *string
	record               []byte
}

func (r *rig) stored() (out []storedRow) {
	r.t.Helper()
	rows, err := r.db.Query("SELECT ts, session_id, kind, vhost, method, path, status, trap_id, token_id, surface, body_prefix, hash, leaf_index, detail, record FROM event ORDER BY id")
	if err != nil {
		r.t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var s storedRow
		if err := rows.Scan(&s.ts, &s.session, &s.kind, &s.vhost, &s.method, &s.path, &s.status,
			&s.trap, &s.token, &s.surface, &s.body, &s.hash, &s.leaf, &s.detail, &s.record); err != nil {
			r.t.Fatal(err)
		}
		out = append(out, s)
	}
	return out
}

// T-U-18: for each kind, the stored row equals the values of the event column
// by column. A system kind has no session. The body prefix is stored only when
// the option is true. The client IP is in no event column.
func TestTU18StoredValuesEqualEventValues(t *testing.T) {
	for _, keep := range []bool{false, true} {
		t.Run(fmt.Sprintf("store_body_prefix=%v", keep), func(t *testing.T) {
			r := newRig(t, 100)
			r.w.bodyPrefix = keep
			var batch []*event.Event
			for _, k := range allKinds {
				batch = append(batch, rowEvent(t, k, true, 1000+int64(k)), rowEvent(t, k, false, 2000+int64(k)))
			}
			if err := r.w.write(batch); err != nil {
				t.Fatal(err)
			}
			rows := r.stored()
			if len(rows) != len(batch) {
				t.Fatalf("%d rows for %d events", len(rows), len(batch))
			}
			for i, e := range batch {
				rec, got := e.Record(), rows[i]
				var surface *string
				if rec.Surface != nil {
					s := string(*rec.Surface)
					surface = &s
				}
				var detail *string
				if len(rec.Detail) > 0 {
					b, err := rec.Detail.JSON()
					if err != nil {
						t.Fatal(err)
					}
					s := string(b)
					detail = &s
				}
				var body []byte
				if b := e.BodyPrefix(); keep && len(b) > 0 {
					body = b
				}
				name := fmt.Sprintf("row %d (%v)", i, rec.Kind)
				for col, pair := range map[string][2]any{
					"ts": {got.ts, rec.TS}, "session_id": {got.session, rec.Session},
					"kind": {got.kind, rec.Kind.String()}, "vhost": {got.vhost, rec.Vhost},
					"method": {got.method, rec.Method}, "path": {got.path, rec.Path},
					"status": {got.status, rec.Status}, "trap_id": {got.trap, rec.TrapID},
					"token_id": {got.token, rec.TokenID}, "surface": {got.surface, surface},
					"detail": {got.detail, detail},
				} {
					if !reflect.DeepEqual(pair[0], pair[1]) {
						t.Errorf("%s: column %s is %v, want %v", name, col, pair[0], pair[1])
					}
				}
				if (got.body == nil) != (body == nil) || !bytes.Equal(got.body, body) {
					t.Errorf("%s: body_prefix is %x, want %x", name, got.body, body)
				}
				if isSystem(rec.Kind) && got.session != nil {
					t.Errorf("%s: system kind has session_id %q", name, *got.session)
				}
				if got.session != nil && *got.session == "" {
					t.Errorf("%s: session_id is the empty text", name)
				}
				evidence, _ := rec.Kind.IsEvidence()
				if evidence != (got.leaf != nil && got.hash != nil && got.record != nil) {
					t.Errorf("%s: evidence columns %v %v", name, got.leaf, got.hash)
				}
			}
			forms := addressForms(netip.MustParseAddr(clientIP))
			for i, row := range r.dumpEvents() {
				for _, f := range forms {
					if strings.Contains(row, f) {
						t.Errorf("row %d holds the client IP as %q", i, f)
					}
				}
			}
		})
	}
}

// addressForms returns the text of a and its raw 4 and 16 bytes. It also
// returns the lower-case and upper-case hex of both.
func addressForms(a netip.Addr) []string {
	a4, a16 := a.Unmap().As4(), a.As16()
	forms := []string{a.String(), string(a4[:]), string(a16[:])}
	for _, b := range [][]byte{a4[:], a16[:]} {
		h := hex.EncodeToString(b)
		forms = append(forms, h, strings.ToUpper(h))
	}
	return forms
}

// dumpEvents returns the text of every column of every event row.
func (r *rig) dumpEvents() (out []string) {
	r.t.Helper()
	rows, err := r.db.Query("SELECT * FROM event")
	if err != nil {
		r.t.Fatal(err)
	}
	defer rows.Close()
	cols, _ := rows.Columns()
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			r.t.Fatal(err)
		}
		var sb strings.Builder
		for _, v := range vals {
			if b, ok := v.([]byte); ok {
				v = string(b)
			}
			fmt.Fprintf(&sb, "%v|", v)
		}
		out = append(out, sb.String())
	}
	return out
}

type counterRow struct {
	day, hmac         string
	requests, dropped int64
}

func (r *rig) counterRows() (out []counterRow) {
	r.t.Helper()
	rows, err := r.db.Query("SELECT day, ip_hmac, requests, dropped FROM ip_counter ORDER BY day, ip_hmac")
	if err != nil {
		r.t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var c counterRow
		if err := rows.Scan(&c.day, &c.hmac, &c.requests, &c.dropped); err != nil {
			r.t.Fatal(err)
		}
		out = append(out, c)
	}
	return out
}

// writeAt writes one batch (one request) when the clock reads at.
func (r *rig) writeAt(at time.Time) {
	r.t.Helper()
	r.w.clock = func() time.Time { return at }
	if err := r.w.write([]*event.Event{rowEvent(r.t, event.KindRequest, false, at.UnixMilli())}); err != nil {
		r.t.Fatal(err)
	}
}

func mac(key [32]byte, b []byte) string {
	m := hmac.New(sha256.New, key[:])
	m.Write(b)
	return hex.EncodeToString(m.Sum(nil))
}

func day(s string) time.Time {
	d, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		panic(err)
	}
	return d
}

// T-U-18, T-S-15: no ip_counter column holds an address in any text form, and an
// error of the store holds none. ip_hmac is the HMAC of the client key.
func TestTS15IPCounterHoldsNoAddress(t *testing.T) {
	r := newRig(t, 100)
	v4, v6, mapped := netip.MustParseAddr("198.51.100.23"), netip.MustParseAddr("2001:db8:abcd:1234:5678::9"), netip.MustParseAddr("::ffff:192.0.2.99")
	for _, a := range []netip.Addr{v4, v6, mapped} {
		r.c.Drop(a)
	}
	r.writeAt(day("2026-03-01T10:00:00Z"))
	rows := r.counterRows()
	if len(rows) != 3 {
		t.Fatalf("%d ip_counter rows, want 3", len(rows))
	}
	v6key := netip.MustParseAddr("2001:db8:abcd:1234::").As16()
	m4, m4b := netip.MustParseAddr("192.0.2.99").As4(), netip.MustParseAddr("198.51.100.23").As4()
	want := map[string]bool{
		mac(r.w.dk.s().key, m4b[:]): true, mac(r.w.dk.s().key, m4[:]): true, mac(r.w.dk.s().key, v6key[:]): true,
	}
	markers := []string{"198.51.100.23", "c6336417", "2001:db8", "20010db8abcd1234", "abcd:1234", "192.0.2.99", "c0000263", "::ffff"}
	for _, c := range rows {
		if !want[c.hmac] || c.requests != 0 || c.dropped != 1 || c.day != "2026-03-01" {
			t.Errorf("unexpected row %+v", c)
		}
		for _, m := range markers {
			if strings.Contains(strings.ToLower(fmt.Sprint(c)), m) {
				t.Errorf("row %+v holds %q", c, m)
			}
		}
	}
	// A trigger makes the counter upsert fail, and nothing else. The same batch
	// with no drop count works, so the error comes from countDrops.
	if _, err := r.db.Exec("CREATE TRIGGER refuse_counter BEFORE INSERT ON ip_counter BEGIN SELECT RAISE(ABORT, 'refused'); END"); err != nil {
		t.Fatal(err)
	}
	if err := r.w.write([]*event.Event{rowEvent(t, event.KindRequest, false, 1)}); err != nil {
		t.Fatalf("batch with no drop count: %v", err)
	}
	before := r.rows()
	r.c.Drop(v4)
	err := r.w.write([]*event.Event{rowEvent(t, event.KindRequest, false, 2)})
	wantRule(t, err, writerName, ruleDatabase)
	if n := r.rows(); n != before {
		t.Errorf("%d event rows, want %d: the failed batch is rolled back", n, before)
	}
	for _, m := range append(markers, v4.String(), v6.String()) {
		if strings.Contains(strings.ToLower(err.Error()), m) {
			t.Errorf("error %q holds %q", err, m)
		}
	}
}

// T-S-15: the same address on two UTC dates gives two ip_hmac values, and a
// step of the clock back to an earlier date gives a new key and not the old one.
func TestTS15DayKeyChangesWithTheDateInBothDirections(t *testing.T) {
	r := newRig(t, 100)
	a := netip.MustParseAddr("198.51.100.23")
	ip := a.As4()
	var keys [][32]byte
	for _, d := range []string{"2026-03-01T10:00:00Z", "2026-03-02T10:00:00Z", "2026-03-01T11:00:00Z", "2026-03-01T12:00:00Z"} {
		r.c.Drop(a)
		r.writeAt(day(d))
		keys = append(keys, r.w.dk.s().key)
	}
	if keys[0] == keys[1] || keys[0] == keys[2] || keys[1] == keys[2] {
		t.Fatal("a date change did not give a new key")
	}
	if keys[2] != keys[3] {
		t.Fatal("the key changed inside one date")
	}
	want := map[string]int64{
		"2026-03-01 " + mac(keys[0], ip[:]): 1,
		"2026-03-02 " + mac(keys[1], ip[:]): 1,
		"2026-03-01 " + mac(keys[2], ip[:]): 2,
	}
	got := r.counterRows()
	if len(got) != len(want) {
		t.Fatalf("%d ip_counter rows, want %d: %+v", len(got), len(want), got)
	}
	for _, c := range got {
		if n, ok := want[c.day+" "+c.hmac]; !ok || n != c.dropped {
			t.Errorf("unexpected row %+v", c)
		}
	}
}

// T-U-18: a batch reads the clock one time at its start. When it starts at
// 23:59:59.999, all its rows use the start date, though the clock reads after
// midnight at later reads.
func TestTU18BatchUsesTheDateOfItsStart(t *testing.T) {
	r := newRig(t, 100)
	// The clock gives the start time until the writer makes the record bytes of
	// the first evidence event. Then it gives a time after midnight. Thus a
	// read after the first event gives the next date.
	inRows := false
	start := day("2026-03-01T23:59:59.999Z")
	r.w.evidenceBytes = func(rec event.Record) ([]byte, error) {
		inRows = true
		return event.EvidenceBytes(rec)
	}
	r.w.clock = func() time.Time {
		if inRows {
			return start.Add(time.Second)
		}
		return start
	}
	r.c.Drop(netip.MustParseAddr("198.51.100.23"))
	r.c.DropNoAddr()
	batch := func(ts int64) []*event.Event {
		return []*event.Event{rowEvent(t, event.KindCallback, false, ts), rowEvent(t, event.KindRequest, false, ts+1)}
	}
	if err := r.w.write(batch(1)); err != nil {
		t.Fatal(err)
	}
	if !inRows {
		t.Fatal("the batch made no evidence record")
	}
	rows := r.counterRows()
	if len(rows) != 2 || rows[0].day != "2026-03-01" || rows[1].day != "2026-03-01" {
		t.Fatalf("rows %+v", rows)
	}
	r.c.DropNoAddr()
	if err := r.w.write(batch(3)); err != nil {
		t.Fatal(err)
	}
	if rows = r.counterRows(); len(rows) != 3 || rows[2].day != "2026-03-02" {
		t.Fatalf("rows after the second batch %+v", rows)
	}
}

// T-U-18: the overflow bucket goes to ip_hmac "overflow"; a new row has 0
// requests; a second batch adds to dropped.
func TestTU18OverflowRowAndSecondBatchAdd(t *testing.T) {
	r := newRig(t, 100)
	at := day("2026-03-01T10:00:00Z")
	r.c.DropNoAddr()
	r.c.DropNoAddr()
	r.c.DropNoAddr()
	r.writeAt(at)
	if got := r.counterRows(); !reflect.DeepEqual(got, []counterRow{{"2026-03-01", "overflow", 0, 3}}) {
		t.Fatalf("rows %+v", got)
	}
	r.c.Drop(netip.Addr{}) // an invalid address goes to the overflow bucket
	r.c.DropNoAddr()
	r.writeAt(at.Add(time.Minute))
	if got := r.counterRows(); !reflect.DeepEqual(got, []counterRow{{"2026-03-01", "overflow", 0, 5}}) {
		t.Fatalf("rows after the second batch %+v", got)
	}
	r.writeAt(at.Add(2 * time.Minute)) // no drops: no row changes
	if got := r.counterRows(); len(got) != 1 || got[0].dropped != 5 {
		t.Fatalf("rows after a batch with no drops %+v", got)
	}
}

// T-S-15: the day key is in no file below the state directory, in raw or in hex
// form. A file that cannot be read fails the test.
func TestTS15DayKeyIsNotOnDisk(t *testing.T) {
	r := newRig(t, 100)
	a := netip.MustParseAddr("198.51.100.23")
	r.c.Drop(a)
	r.writeAt(day("2026-03-01T10:00:00Z"))
	ip := a.As4()
	known := mac(r.w.dk.s().key, ip[:]) // proves that the scan sees the data
	scan := func(stage string) {
		found := false
		err := filepath.WalkDir(r.state, func(f string, d fs.DirEntry, err error) error {
			if err != nil || !d.Type().IsRegular() {
				return err
			}
			data, err := os.ReadFile(f)
			if err != nil {
				return err
			}
			if bytes.Contains(data, r.w.dk.s().key[:]) || bytes.Contains(data, []byte(hex.EncodeToString(r.w.dk.s().key[:]))) {
				t.Errorf("%s: the day key is in %s", stage, f)
			}
			found = found || bytes.Contains(data, []byte(known))
			return nil
		})
		if err != nil {
			t.Fatalf("%s: %v", stage, err)
		}
		if !found {
			t.Errorf("%s: the scan does not see the ip_hmac text", stage)
		}
	}
	scan("with the WAL")
	if _, err := r.db.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		t.Fatal(err)
	}
	scan("after the checkpoint")
}

// T-S-15: none of these fmt verbs prints a byte of the day key. This holds
// for a dayKey, a *dayKey, a Writer and a *Writer.
func TestTS15DayKeyIsNotPrinted(t *testing.T) {
	r := newRig(t, 100)
	s := r.w.dk.s()
	s.date = "2026-03-01"
	for i := range s.key {
		s.key[i] = 0xb0 + byte(i)
	}
	k := s.key
	needles := []string{
		string(k[:8]), hex.EncodeToString(k[:8]), strings.ToUpper(hex.EncodeToString(k[:8])),
		"176 177 178 179", `\xb0\xb1`, "0xb0, 0xb1",
	}
	holds := func(s string) bool {
		for _, n := range needles {
			if strings.Contains(s, n) {
				return true
			}
		}
		return false
	}
	// Interface copies the Writer with no lock copy in the source text.
	writer := reflect.ValueOf(r.w).Elem().Interface()
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%x", "%d", "%q"} {
		if !holds(fmt.Sprintf(verb, k)) {
			t.Fatalf("%s: the check does not see the bytes of a bare key", verb)
		}
		for name, v := range map[string]any{"dayKey": r.w.dk, "*dayKey": &r.w.dk, "Writer": writer, "*Writer": r.w} {
			if out := fmt.Sprintf(verb, v); holds(out) {
				t.Errorf("%s of a %s holds the day key: %.200q", verb, name, out)
			}
		}
	}
}
