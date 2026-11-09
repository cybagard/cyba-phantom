package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/cybagard/cyba-phantom/internal/event"
)

type tokenRow struct {
	id, session, trap string
	issuedAt, firstCb int64
	count             int64
}

func tokenRows(t *testing.T, db *sql.DB) (out []tokenRow) {
	t.Helper()
	rows, err := db.Query("SELECT token_id, session_id, trap_id, issued_at, first_cb_at, cb_count FROM token ORDER BY token_id")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var r tokenRow
		if err := rows.Scan(&r.id, &r.session, &r.trap, &r.issuedAt, &r.firstCb, &r.count); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func wantTokens(t *testing.T, r *rig, want ...tokenRow) {
	t.Helper()
	got := tokenRows(t, r.db)
	if len(got) != len(want) {
		t.Fatalf("%d token rows, want %d: %+v", len(got), len(want), got)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("token row %d: %+v, want %+v", i, got[i], want[i])
		}
	}
	if !r.w.Healthy() || r.w.Err() != nil {
		t.Errorf("writer not healthy: %v", r.w.Err())
	}
}

func wantUnlinked(t *testing.T, r *rig, none, ambiguous uint64) {
	t.Helper()
	if n, a := r.w.UnlinkedCallbacks(); n != none || a != ambiguous {
		t.Errorf("unlinked counts none %d, ambiguous %d; want %d and %d", n, a, none, ambiguous)
	}
}

// tokenID gives a token id for the counter c: 32 hex digits.
func tokenID(c uint64) string { return fmt.Sprintf("%032x", c) }

// cbEvent makes a callback event for the token with the counter of the link.
// The session of the event is the session that presents the token.
func cbEvent(t *testing.T, ts int64, l *event.CallbackLink) *event.Event {
	t.Helper()
	in := event.Input{Kind: event.KindCallback, Session: "presenter", Path: "/cb", TrapID: "trap-a",
		Surface: event.SurfacePath, Link: l}
	if l != nil {
		in.TokenID = tokenID(l.Counter)
	}
	e, err := event.NewEvent(func() time.Time { return time.UnixMilli(ts) }, in)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func link(unit uint32, counter uint64) *event.CallbackLink {
	return &event.CallbackLink{SetID: mintSet, Unit: unit, Counter: counter}
}

// render makes the request event of a render: 10 tokens from counter 100.
func render(t *testing.T) *event.Event {
	return mintEvent(t, 1, "issuer", event.MintRange{SetID: mintSet, Unit: 5, First: 100, Count: 10, IssuedAt: 1000})
}

func issued(counter uint64, count int64) tokenRow {
	return tokenRow{id: tokenID(counter), session: "issuer", trap: "trap-a", issuedAt: 1000, firstCb: 50, count: count}
}

// T-S-32: a render and its callback in one batch give one token row. The row
// has the session and issued_at of the mint row. It has the trap id, the time
// of the callback, and a count of 1. The callback can come first in the batch.
// The token rows come after all rows of the batch.
func TestTS32OneBatchGivesTheTokenRow(t *testing.T) {
	for name, order := range map[string]func(a, b *event.Event) []*event.Event{
		"render first":   func(a, b *event.Event) []*event.Event { return []*event.Event{a, b} },
		"callback first": func(a, b *event.Event) []*event.Event { return []*event.Event{b, a} },
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, 100)
			r.writeOK(order(render(t), cbEvent(t, 50, link(5, 105)))...)
			wantTokens(t, r, issued(105, 1))
			wantUnlinked(t, r, 0, 0)
			if r.rows() != 2 {
				t.Errorf("%d event rows, want 2", r.rows())
			}
		})
	}
}

// T-S-32: the render in a batch and the callback in the next batch give the
// same row.
func TestTS32TwoBatchesGiveTheTokenRow(t *testing.T) {
	r := newRig(t, 100)
	r.writeOK(render(t))
	wantTokens(t, r)
	r.writeOK(cbEvent(t, 50, link(5, 105)))
	wantTokens(t, r, issued(105, 1))
	wantUnlinked(t, r, 0, 0)
}

// T-S-32: a repeat callback adds 1 to cb_count. This is true in the same batch
// and in a later batch. The time of the first callback stays.
func TestTS32RepeatAddsToTheCount(t *testing.T) {
	l := link(5, 105)
	t.Run("same batch", func(t *testing.T) {
		r := newRig(t, 100)
		r.writeOK(render(t), cbEvent(t, 50, l), cbEvent(t, 60, l))
		wantTokens(t, r, issued(105, 2))
	})
	t.Run("later batch", func(t *testing.T) {
		r := newRig(t, 100)
		r.writeOK(render(t), cbEvent(t, 50, l))
		r.writeOK(cbEvent(t, 60, l), cbEvent(t, 70, l))
		wantTokens(t, r, issued(105, 3))
		wantUnlinked(t, r, 0, 0)
	})
}

// T-S-32: a callback with no link gives no token row and no count. This is true
// when the callback has a trap id and a token id.
func TestTS32CallbackWithoutLinkGivesNoRow(t *testing.T) {
	ids, err := event.NewEvent(func() time.Time { return time.UnixMilli(50) },
		event.Input{Kind: event.KindCallback, Session: "presenter", Path: "/cb", TrapID: "trap-a",
			TokenID: tokenID(105), Surface: event.SurfacePath})
	if err != nil {
		t.Fatal(err)
	}
	for name, cb := range map[string]*event.Event{
		"no ids":         cbEvent(t, 50, nil),
		"trap and token": ids,
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, 100)
			r.writeOK(render(t), cb)
			wantTokens(t, r)
			wantUnlinked(t, r, 0, 0)
			if r.rows() != 2 {
				t.Errorf("%d event rows, want 2", r.rows())
			}
		})
	}
}

// T-S-32: two mint rows of one set and unit can both hold the counter. Then
// there is no token row and one ambiguous count.
func TestTS32OverlappingMintRowsAreAmbiguous(t *testing.T) {
	r := newRig(t, 100)
	other := mintEvent(t, 2, "second", event.MintRange{SetID: mintSet, Unit: 5, First: 105, Count: 10, IssuedAt: 2000})
	r.writeOK(render(t), other, cbEvent(t, 50, link(5, 107)))
	wantTokens(t, r)
	wantUnlinked(t, r, 0, 1)
	// A counter that only one of the rows holds is not ambiguous.
	r.writeOK(cbEvent(t, 51, link(5, 102)))
	row := issued(102, 1)
	row.firstCb = 51
	wantTokens(t, r, row)
	wantUnlinked(t, r, 0, 1)
}

// mintSelect gives a SELECT of one mint row of mintSet with the given issued_at
// SQL value.
func mintSelect(issuedAt string) string {
	return fmt.Sprintf("SELECT x'%X', 5, 100, 10, 'issuer', %s", mintSet[:], issuedAt)
}

// insertRawMint writes a mint row of mintSet with the given issued_at SQL
// value, with no check of the value.
func insertRawMint(t *testing.T, r *rig, issuedAt string) {
	t.Helper()
	if _, err := r.db.Exec("INSERT INTO mint " + mintSelect(issuedAt)); err != nil {
		t.Fatal(err)
	}
}

// T-S-32: five cases give no token row and one none count. There is no
// mint row. Or the mint row has another unit, another set or a NULL issued_at.
// Or it is a mint row of another range.
func TestTS32NoMintRowGivesNoRow(t *testing.T) {
	otherSet := event.CallbackLink{SetID: [8]byte{9}, Unit: 5, Counter: 105}
	for name, c := range map[string]struct {
		render *event.Event
		rawAt  string // the issued_at SQL value of a raw mint row
		link   *event.CallbackLink
	}{
		"no mint row":    {nil, "", link(5, 105)},
		"another unit":   {render(t), "", link(6, 105)},
		"another set":    {render(t), "", &otherSet},
		"NULL issued_at": {nil, "NULL", link(5, 105)},
		"another range":  {render(t), "", link(5, 500)},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, 100)
			if c.rawAt != "" {
				insertRawMint(t, r, c.rawAt)
			}
			batch := []*event.Event{cbEvent(t, 50, c.link)}
			if c.render != nil {
				batch = append(batch, c.render)
			}
			r.writeOK(batch...)
			wantTokens(t, r)
			wantUnlinked(t, r, 1, 0)
		})
	}
}

// rawMint writes a mint row of mintSet with unit 5, first 100 and count 10.
// It takes the session and issued_at as SQL values, with no check.
func rawMint(t *testing.T, r *rig, session, issuedAt string) {
	t.Helper()
	q := fmt.Sprintf("INSERT INTO mint SELECT x'%X', 5, 100, 10, %s, %s", mintSet[:], session, issuedAt)
	if _, err := r.db.Exec(q); err != nil {
		t.Fatal(err)
	}
}

// T-S-32: a mint row with a NULL session gives no token row and one ambiguous
// count. This holds when its issued_at is NULL. It holds alone, and next to a
// second row that covers the counter. The mark of a duplicate key and a render
// event with no session both make such a row.
func TestTS32NullSessionMintRowIsAmbiguous(t *testing.T) {
	t.Run("alone", func(t *testing.T) {
		r := newRig(t, 100)
		r.writeOK(mintEvent(t, 1, "", event.MintRange{SetID: mintSet, Unit: 5, First: 100, Count: 10, IssuedAt: 1000}),
			cbEvent(t, 50, link(5, 105)))
		wantTokens(t, r)
		wantUnlinked(t, r, 0, 1)
	})
	t.Run("NULL issued_at", func(t *testing.T) {
		r := newRig(t, 100)
		rawMint(t, r, "NULL", "NULL")
		r.writeOK(cbEvent(t, 50, link(5, 105)))
		wantTokens(t, r)
		wantUnlinked(t, r, 0, 1)
	})
	t.Run("next to a second row", func(t *testing.T) {
		r := newRig(t, 100)
		rawMint(t, r, "NULL", "1000")
		r.writeOK(mintEvent(t, 2, "second", event.MintRange{SetID: mintSet, Unit: 5, First: 105, Count: 10, IssuedAt: 2000}),
			cbEvent(t, 50, link(5, 107)))
		wantTokens(t, r)
		wantUnlinked(t, r, 0, 1)
		// A counter that only the second row holds links to the second row.
		r.writeOK(cbEvent(t, 51, link(5, 112)))
		wantUnlinked(t, r, 0, 1)
		row := tokenRow{id: tokenID(112), session: "second", trap: "trap-a", issuedAt: 2000, firstCb: 51, count: 1}
		wantTokens(t, r, row)
	})
}

// T-S-32: two renders in two time units with one first counter keep both mint
// rows. A callback of each render gives the session of its own render.
func TestTS32SameFirstCounterInTwoUnitsLinksEachRender(t *testing.T) {
	r := newRig(t, 100)
	r.writeOK(
		mintEvent(t, 1, "five", event.MintRange{SetID: mintSet, Unit: 5, First: 500, Count: 10, IssuedAt: 1000}),
		mintEvent(t, 2, "six", event.MintRange{SetID: mintSet, Unit: 6, First: 500, Count: 10, IssuedAt: 2000}),
		cbEvent(t, 50, link(5, 505)),
		cbEvent(t, 51, link(6, 506)))
	wantTokens(t, r,
		tokenRow{id: tokenID(505), session: "five", trap: "trap-a", issuedAt: 1000, firstCb: 50, count: 1},
		tokenRow{id: tokenID(506), session: "six", trap: "trap-a", issuedAt: 2000, firstCb: 51, count: 1})
	wantUnlinked(t, r, 0, 0)
	if n := r.w.MintDuplicates(); n != 0 {
		t.Errorf("%d duplicates, want 0", n)
	}
}

// T-S-32: a duplicate mint key gives ambiguous for its callbacks. A third row
// that covers the counter does not become the link.
func TestTS32DuplicateMintKeyThenThirdRowIsAmbiguous(t *testing.T) {
	r := newRig(t, 100)
	r.writeOK(
		mintEvent(t, 1, "first", event.MintRange{SetID: mintSet, Unit: 5, First: 500, Count: 20, IssuedAt: 1000}),
		mintEvent(t, 2, "again", event.MintRange{SetID: mintSet, Unit: 5, First: 500, Count: 20, IssuedAt: 1001}),
		cbEvent(t, 50, link(5, 505)))
	wantTokens(t, r)
	wantUnlinked(t, r, 0, 1)
	r.writeOK(mintEvent(t, 3, "third", event.MintRange{SetID: mintSet, Unit: 5, First: 510, Count: 10, IssuedAt: 1002}),
		cbEvent(t, 51, link(5, 512)))
	wantTokens(t, r)
	wantUnlinked(t, r, 0, 2)
}

// T-S-32: a callback before its mint row exists gives the none count. After the
// render, the next callback of the token gives the row with a count of 1.
func TestTS32LaterCallbackRetriesTheLink(t *testing.T) {
	r := newRig(t, 100)
	l := link(5, 105)
	r.writeOK(cbEvent(t, 50, l))
	wantTokens(t, r)
	wantUnlinked(t, r, 1, 0)
	r.writeOK(render(t))
	wantTokens(t, r)
	r.writeOK(cbEvent(t, 60, l))
	wantTokens(t, r, tokenRow{id: tokenID(105), session: "issuer", trap: "trap-a", issuedAt: 1000, firstCb: 60, count: 1})
	wantUnlinked(t, r, 1, 0)
}

// wantNullSessions checks that the mint table has n rows and that each row has
// a NULL session. It shows that the ambiguous count comes from a NULL session.
func wantNullSessions(t *testing.T, r *rig, n int) {
	t.Helper()
	rows := mintRows(t, r.db)
	if len(rows) != n {
		t.Fatalf("%d mint rows, want %d", len(rows), n)
	}
	for _, m := range rows {
		if m.session != nil {
			t.Errorf("mint row %+v has a session", m)
		}
	}
}

// writeShapes runs f two times. In the first run, the mint events and the
// callbacks are in one batch. In the second run, they are in two batches.
func writeShapes(t *testing.T, f func(t *testing.T, write func(r *rig, mint []*event.Event, cbs ...*event.Event))) {
	t.Run("one batch", func(t *testing.T) {
		f(t, func(r *rig, mint []*event.Event, cbs ...*event.Event) { r.writeOK(append(mint, cbs...)...) })
	})
	t.Run("two batches", func(t *testing.T) {
		f(t, func(r *rig, mint []*event.Event, cbs ...*event.Event) { r.writeOK(mint...); r.writeOK(cbs...) })
	})
}

// T-S-32: a mint row is added after the token row exists. The row is a
// duplicate key, or a second row with another first counter. Each later
// callback of the token (two of them) gives ambiguous. A callback of a token
// with no row also gives ambiguous. The token row does not change.
func TestTS32MintRowAfterTokenRowGivesAmbiguous(t *testing.T) {
	for name, c := range map[string]struct {
		again *event.Event
		dups  uint64
	}{
		"duplicate key": {mintEvent(t, 2, "again", event.MintRange{SetID: mintSet, Unit: 5, First: 100, Count: 10, IssuedAt: 2000}), 1},
		"second row":    {mintEvent(t, 2, "second", event.MintRange{SetID: mintSet, Unit: 5, First: 105, Count: 10, IssuedAt: 2000}), 0},
	} {
		t.Run(name, func(t *testing.T) {
			writeShapes(t, func(t *testing.T, write func(*rig, []*event.Event, ...*event.Event)) {
				r := newRig(t, 100)
				r.writeOK(render(t), cbEvent(t, 50, link(5, 105)))
				wantTokens(t, r, issued(105, 1))
				write(r, []*event.Event{c.again}, cbEvent(t, 51, link(5, 105)), cbEvent(t, 52, link(5, 106)), cbEvent(t, 53, link(5, 105)))
				wantTokens(t, r, issued(105, 1))
				wantUnlinked(t, r, 0, 3)
				if n := r.w.MintDuplicates(); n != c.dups {
					t.Errorf("%d duplicates, want %d", n, c.dups)
				}
				if c.dups > 0 {
					wantNullSessions(t, r, 1)
				}
			})
		})
	}
}

// T-S-32: a mint row with a NULL session gives ambiguous and no token row. The
// two sources are the mark of a duplicate key and a render event with no
// session. A SELECT shows that the row has a NULL session.
func TestTS32NullSessionSourcesGiveAmbiguous(t *testing.T) {
	rng := event.MintRange{SetID: mintSet, Unit: 5, First: 100, Count: 10, IssuedAt: 1000}
	for name, mint := range map[string][]*event.Event{
		"duplicate key":          {mintEvent(t, 1, "issuer", rng), mintEvent(t, 2, "again", rng)},
		"render with no session": {mintEvent(t, 1, "", rng)},
	} {
		t.Run(name, func(t *testing.T) {
			writeShapes(t, func(t *testing.T, write func(*rig, []*event.Event, ...*event.Event)) {
				r := newRig(t, 100)
				write(r, mint, cbEvent(t, 50, link(5, 105)), cbEvent(t, 51, link(5, 106)))
				wantNullSessions(t, r, 1)
				wantTokens(t, r)
				wantUnlinked(t, r, 0, 2)
			})
		})
	}
}

// T-S-32: after the token row exists, a callback gives none in two cases. The
// mint row is gone (the test deletes it), or it has a NULL issued_at. The
// cb_count does not change.
func TestTS32TokenRowWithoutUsableMintRowGivesNone(t *testing.T) {
	for name, q := range map[string]string{
		"mint row deleted": "DELETE FROM mint",
		"NULL issued_at":   "UPDATE mint SET issued_at = NULL",
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, 100)
			r.writeOK(render(t), cbEvent(t, 50, link(5, 105)))
			wantTokens(t, r, issued(105, 1))
			if _, err := r.db.Exec(q); err != nil {
				t.Fatal(err)
			}
			r.writeOK(cbEvent(t, 51, link(5, 105)))
			wantTokens(t, r, issued(105, 1))
			wantUnlinked(t, r, 1, 0)
		})
	}
}

// T-S-32: a callback of a token with a row runs the update and no insert. A
// trigger that stops each insert shows this.
func TestTS32RepeatCallbackRunsNoInsert(t *testing.T) {
	r := newRig(t, 100)
	r.writeOK(render(t), cbEvent(t, 50, link(5, 105)))
	if _, err := r.db.Exec("CREATE TRIGGER no_ins BEFORE INSERT ON token BEGIN SELECT RAISE(ABORT,'x'); END"); err != nil {
		t.Fatal(err)
	}
	r.writeOK(cbEvent(t, 60, link(5, 105)))
	wantTokens(t, r, issued(105, 2))
	wantUnlinked(t, r, 0, 0)
}

// T-S-32: the first counter and the last counter of a range link. The counter
// before the first and the counter after the last do not. A range of 68 links
// its last counter. A range that wraps links a counter in each of its two rows.
func TestTS32RangeEdges(t *testing.T) {
	const top = event.MintCounterLimit
	r := newRig(t, 100)
	r.writeOK(
		render(t),
		mintEvent(t, 2, "wide", event.MintRange{SetID: mintSet, Unit: 5, First: 1000, Count: 68, IssuedAt: 2000}),
		mintEvent(t, 3, "wrap", event.MintRange{SetID: mintSet, Unit: 5, First: top - 3, Count: 5, IssuedAt: 3000}))
	linked := []uint64{100, 109, 1000, 1067, top - 3, top - 1, 0, 1}
	unlinked := []uint64{99, 110, 999, 1068, top - 4, 2}
	var batch []*event.Event
	for _, c := range append(append([]uint64(nil), linked...), unlinked...) {
		batch = append(batch, cbEvent(t, 50, link(5, c)))
	}
	r.writeOK(batch...)
	got := map[string]bool{}
	for _, row := range tokenRows(t, r.db) {
		got[row.id] = true
	}
	for _, c := range linked {
		if !got[tokenID(c)] {
			t.Errorf("counter %d does not link", c)
		}
	}
	for _, c := range unlinked {
		if got[tokenID(c)] {
			t.Errorf("counter %d links", c)
		}
	}
	wantUnlinked(t, r, uint64(len(unlinked)), 0)
	if !r.w.Healthy() {
		t.Fatal("writer not healthy")
	}
}

// T-S-32: the lookup reads the 68 first counters up to the counter, no more.
// A range has at most 68 counters, so a row 68 below the counter cannot cover
// it. A raw row of 69 counters shows the bound. The sensor never writes such a
// row. It covers the counter 68 above its first. The lookup does not read it.
func TestTS32LookupBoundIsSixtySeven(t *testing.T) {
	r := newRig(t, 100)
	if _, err := r.db.Exec(fmt.Sprintf("INSERT INTO mint SELECT x'%X', 5, 1000, 69, 'wide', 3000", mintSet[:])); err != nil {
		t.Fatal(err)
	}
	r.writeOK(cbEvent(t, 50, link(5, 1067)), cbEvent(t, 51, link(5, 1068)))
	wantTokens(t, r, tokenRow{id: tokenID(1067), session: "wide", trap: "trap-a", issuedAt: 3000, firstCb: 50, count: 1})
	wantUnlinked(t, r, 1, 0)
}

// T-S-32: a batch that the writer rolls back adds no unlinked count and no
// token row.
func TestTS32RolledBackBatchCountsNothing(t *testing.T) {
	r := newRig(t, 100)
	two := mintEvent(t, 2, "second", event.MintRange{SetID: mintSet, Unit: 5, First: 105, Count: 10, IssuedAt: 2000})
	r.writeOK(render(t), two)
	r.w.beforeCommit = func(*sql.Tx) error { return errors.New("no commit") }
	r.w.flush([]*event.Event{cbEvent(t, 50, link(5, 107)), cbEvent(t, 51, link(5, 400)), cbEvent(t, 52, link(5, 102))})
	if r.w.Healthy() {
		t.Fatal("the writer did not stop at the failed COMMIT")
	}
	wantUnlinked(t, r, 0, 0)
	if n := len(tokenRows(t, r.db)); n != 0 {
		t.Fatalf("%d token rows after a rolled-back batch", n)
	}
}

// T-S-32: an error of a token statement stops the writer with the database
// rule. The writer rolls back the batch. Each case reaches its own statement.
// The cases are: lookup prepare, lookup query, lookup scan, lookup rows,
// update prepare, update run, insert prepare, insert run. A case can first
// commit a batch.
func TestTS32TokenStatementErrorStopsTheWriter(t *testing.T) {
	cb := func(ts int64) *event.Event { return cbEvent(t, ts, link(5, 105)) }
	// The abs of the smallest int64 is an integer overflow in SQLite.
	const overflow = "abs(-9223372036854775807-1)"
	view := func(sel string) string {
		return "DROP TABLE mint; CREATE VIEW mint(set_id, unit, first, count, session_id, issued_at) AS " + sel
	}
	for name, c := range map[string]struct {
		committed []*event.Event // the batch that commits before the setup
		setup     string
		batch     []*event.Event // the batch that fails
	}{
		"update prepare": {nil, "DROP TABLE token", []*event.Event{render(t), cb(50)}},
		// The trigger runs only when a row exists to update.
		"update run": {[]*event.Event{render(t), cb(50)},
			"CREATE TRIGGER no_upd BEFORE UPDATE ON token BEGIN SELECT RAISE(ABORT,'x'); END",
			[]*event.Event{cb(60)}},
		// The lookup runs first, so its prepare fails before any update.
		"lookup prepare": {[]*event.Event{render(t)}, "DROP TABLE mint", []*event.Event{cb(50)}},
		// The column has no CHECK, so it keeps the text. Scan into int64 fails.
		"lookup scan": {nil, "INSERT INTO mint " + mintSelect("'x'"), []*event.Event{cb(50)}},
		// The view fails on its first row.
		"lookup query": {[]*event.Event{render(t)}, view(mintSelect(overflow)),
			[]*event.Event{cb(50)}},
		// The first row scans. The view fails on its second row.
		"lookup rows": {[]*event.Event{render(t)},
			view(mintSelect("1000") + " UNION ALL " + mintSelect(overflow)),
			[]*event.Event{cb(50)}},
		// The update prepare does not use the column. The insert prepare does.
		// SQLite refuses to drop an indexed column. Thus the statement drops the
		// index first.
		"insert prepare": {nil, "DROP INDEX token_first_cb; ALTER TABLE token DROP COLUMN first_cb_at", []*event.Event{render(t), cb(50)}},
		"insert run": {nil, "CREATE TRIGGER no_ins BEFORE INSERT ON token BEGIN SELECT RAISE(ABORT,'x'); END",
			[]*event.Event{render(t), cb(50)}},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, 100)
			if c.committed != nil {
				r.writeOK(c.committed...)
			}
			rows := r.rows()
			if _, err := r.db.Exec(c.setup); err != nil {
				t.Fatal(err)
			}
			r.w.flush(c.batch)
			wantRule(t, r.w.Err(), writerName, ruleDatabase)
			if r.w.Healthy() || r.rows() != rows {
				t.Fatalf("healthy %v, %d event rows, want a stopped writer and %d rows", r.w.Healthy(), r.rows(), rows)
			}
			wantUnlinked(t, r, 0, 0)
		})
	}
}

// T-S-32: a batch with a failed AppendBatch gives no token row for its linked
// callbacks, and no unlinked count. The mint row of an earlier batch exists.
func TestTS32FailedAppendGivesNoTokenRow(t *testing.T) {
	r := newRig(t, 100)
	r.writeOK(render(t))
	rows := r.rows()
	r.app.err = errors.New("append failed")
	r.w.flush([]*event.Event{cbEvent(t, 50, link(5, 105)), cbEvent(t, 51, link(5, 106))})
	wantRule(t, r.w.Err(), writerName, ruleAppend)
	if n := r.rows(); n != rows {
		t.Errorf("%d event rows after a failed append, want %d", n, rows)
	}
	if n := len(tokenRows(t, r.db)); n != 0 {
		t.Errorf("%d token rows after a failed append", n)
	}
	wantUnlinked(t, r, 0, 0)
}

// T-S-32: a conflict of the token insert is not an error. The writer is the
// only writer, so no real path gives a conflict. A trigger adds the row first.
func TestTS32TokenConflictDoesNotStopTheWriter(t *testing.T) {
	r := newRig(t, 100)
	if _, err := r.db.Exec(`CREATE TRIGGER first_in BEFORE INSERT ON token BEGIN
		INSERT INTO token VALUES (NEW.token_id, 'other', 'trap-x', 1, 2, 7); END`); err != nil {
		t.Fatal(err)
	}
	r.writeOK(render(t), cbEvent(t, 50, link(5, 105)))
	wantTokens(t, r, tokenRow{id: tokenID(105), session: "other", trap: "trap-x", issuedAt: 1, firstCb: 2, count: 7})
}

// lookupPlan is the whole plan text of the lookup. It is one search of the
// primary key. The search uses the key set, the unit and a range of first.
const lookupPlan = "SEARCH mint USING PRIMARY KEY (set_id=? AND unit=? AND first>? AND first<?)"

// T-S-32: the lookup searches the primary key of mint. It has no scan and no
// temporary b-tree.
func TestTS32LookupUsesThePrimaryKey(t *testing.T) {
	r := newRig(t, 100)
	all := strings.Join(queryPlan(t, r.db, lookupMint, mintSet[:], 5, 105, 105, 105), "; ")
	t.Logf("plan: %s", all)
	if all != lookupPlan {
		t.Fatalf("plan %q, want %q", all, lookupPlan)
	}
}
