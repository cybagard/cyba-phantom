package bundle

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"maps"
	"os"
	"testing"

	"github.com/cybagard/cyba-phantom/internal/event"
	"github.com/cybagard/cyba-phantom/internal/store"
	"github.com/cybagard/cyba-phantom/internal/tlog"
)

// T-U-08: the real store, log and writer get an accept and a rejection. They
// give one bundle_load row and one bundle_rejected row. Each has a leaf index
// and only the fixed detail members.
func TestTU08EventRowsHaveLeafIndex(t *testing.T) {
	e := running(t)
	must(t, os.Chmod(e.state, 0o700)) // The store refuses group and other bits.
	db, err := store.Open(e.root, "events.db", store.Options{})
	must(t, err)
	t.Cleanup(func() { db.Close() })
	must(t, store.Migrate(db, "origin"))
	log, err := tlog.OpenLog(e.root, "tlog")
	must(t, err)
	t.Cleanup(func() { log.Close() })
	c := event.NewCounters()
	q, err := event.NewQueue(8, c)
	must(t, err)
	w := store.NewWriter(db, q, log, c, false, nil, store.Recovery{State: e.root, Origin: "origin", Log: log})
	e.l.SetEvents(q, nil)
	sum3 := e.install("bundle/current", mf(ver(3)))
	_, err1 := e.l.LoadFrom(SourceFetch)
	sum1 := e.install("bundle/current", mf(ver(1)))
	if _, err2 := e.l.LoadFrom(SourceSignal); err1 != nil || err2 != ErrRollback {
		t.Fatal(err1, err2)
	}
	q.Close()
	must(t, w.Run(context.Background()))
	want := map[string]map[string]string{
		"bundle_load":     {"key_id": "k1", "sha256": hex.EncodeToString(sum3[:]), "source": "fetch", "version": ver(3)},
		"bundle_rejected": {"reason": "rollback", "sha256": hex.EncodeToString(sum1[:]), "source": "signal"},
	}
	rows, err := db.Query("SELECT kind, detail, leaf_index FROM event ORDER BY leaf_index")
	must(t, err)
	defer rows.Close()
	n := 0
	for ; rows.Next(); n++ {
		var kind, detail string
		var leaf *int64
		must(t, rows.Scan(&kind, &detail, &leaf))
		var got map[string]string
		must(t, json.Unmarshal([]byte(detail), &got))
		if leaf == nil || *leaf != int64(n) || !maps.Equal(got, want[kind]) {
			t.Errorf("%s: leaf index %v, detail %v; want index %d, detail %v", kind, leaf, got, n, want[kind])
		}
	}
	if n != 2 {
		t.Errorf("%d rows, want 2", n)
	}
}
