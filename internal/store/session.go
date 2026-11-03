package store

import (
	"context"
	"database/sql"
	"net/netip"

	"github.com/cybagard/cyba-phantom/internal/event"
	"github.com/cybagard/cyba-phantom/internal/session"
)

// upsertSession adds a session row. A known session changes only last_seen
// and req_count. The first address, ip_hmac and JA4 stay.
const upsertSession = "INSERT INTO session (id, first_seen, last_seen, ip, ip_hmac, ja4, req_count, band, score) VALUES (?, ?, ?, ?, ?, ?, ?, 'human', 0) ON CONFLICT(id) DO UPDATE SET last_seen = max(last_seen, excluded.last_seen), req_count = req_count + excluded.req_count"

// sessionEntry is what one batch knows of one session. ip and ja4 are the
// values of the first row of the session in the batch. An empty text is absent.
type sessionEntry struct {
	first, last int64 // the smallest and the largest ts, in unix ms
	count       int64
	ip, ja4     string
}

// sessionBatch holds one entry for each session of the batch in progress. It
// has at most maxBatch entries. Only the writer goroutine uses it.
type sessionBatch struct {
	m map[string]sessionEntry
	// onExec runs before each upsert statement. A test sets it; nil in
	// production.
	onExec func()
}

// reset empties the map and keeps its memory for the next batch.
func (s *sessionBatch) reset() {
	if s.m == nil {
		s.m = make(map[string]sessionEntry, maxBatch)
	}
	clear(s.m)
}

// add counts a stored row. Only a request row or a refused row with a session
// id adds an entry.
func (s *sessionBatch) add(rec event.Record, ip string) {
	if rec.Kind != event.KindRequest && rec.Kind != event.KindRefused {
		return
	}
	if rec.Session == nil {
		return
	}
	e, ok := s.m[*rec.Session]
	if !ok {
		e = sessionEntry{first: rec.TS, last: rec.TS, ip: ip}
		if rec.FP != nil && rec.FP.JA4 != nil {
			e.ja4 = *rec.FP.JA4
		}
	}
	e.first, e.last, e.count = min(e.first, rec.TS), max(e.last, rec.TS), e.count+1
	s.m[*rec.Session] = e
}

// upsertSessions runs one upsert for each entry of the batch, in the
// transaction tx. It prepares the statement one time. A failure is a database
// error. An address that has no key gets the overflow ip_hmac text.
func (w *Writer) upsertSessions(ctx context.Context, tx *sql.Tx, key session.Key) error {
	if len(w.sessions.m) == 0 {
		return nil
	}
	stmt, err := tx.PrepareContext(ctx, upsertSession)
	if err != nil {
		return fail(writerName, ruleDatabase)
	}
	defer stmt.Close()
	for id, e := range w.sessions.m {
		var ip, ja4 any // nil is NULL
		hmac := overflowHMAC
		if e.ip != "" {
			ip = e.ip
			if a, err := netip.ParseAddr(e.ip); err == nil {
				if k, ok := event.CounterKey(a); ok {
					hmac = key.IPHMAC(k)
				}
			}
		}
		if e.ja4 != "" {
			ja4 = e.ja4
		}
		if w.sessions.onExec != nil {
			w.sessions.onExec()
		}
		if _, err := stmt.ExecContext(ctx, id, e.first, e.last, ip, hmac, ja4, e.count); err != nil {
			return fail(writerName, ruleDatabase)
		}
	}
	return nil
}
