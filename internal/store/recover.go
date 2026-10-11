package store

import (
	"context"
	"database/sql"
	"errors"
	"os"

	xtlog "golang.org/x/mod/sumdb/tlog"

	"github.com/cybagard/cyba-phantom/internal/tlog"
)

// The fixed error classes of the start check.
const (
	ruleOrigin    = "log origin differs from the configured origin"
	ruleNoOrigin  = "database has no log origin"
	rulePastLog   = "database points past the end of the log"
	ruleLeafProof = "last evidence row does not verify in the log"
	ruleLogRead   = "log root or proof cannot be read"
)

// logReader is the part of the log that the start check reads. The appender
// interface has the write part.
type logReader interface {
	Head() (int64, xtlog.Hash)
	RootAt(size int64) (xtlog.Hash, error)
	ProveInclusion(index, size int64) (xtlog.RecordProof, error)
}

var _ logReader = (*tlog.Log)(nil)

// Recovery holds what the writer needs at start and at a stop. State is the
// state directory that Open used. Origin is tlog.origin. Log is the log that the
// appender writes to.
type Recovery struct {
	State  *os.Root
	Origin string
	Log    logReader
}

// start runs before the first write. A stop marker or a failed check gives an
// error, and the writer stops.
func (w *Writer) start() error {
	if err := checkMarker(w.rec.State); err != nil {
		return err
	}
	return w.checkLog()
}

// checkLog compares the database with the log. The size comes from Head. The
// root comes from RootAt(size) and never from Head, because Head does not see a
// bad tile. With no evidence row, only the origin and the root are checked.
// Leaves above the largest leaf_index are orphan leaves of a crash. They are
// permitted, and the writer logs their number one time.
func (w *Writer) checkLog() error {
	ctx := context.Background()
	var origin string
	switch err := w.db.QueryRowContext(ctx, "SELECT value FROM meta WHERE key = 'tlog_origin'").Scan(&origin); {
	case errors.Is(err, sql.ErrNoRows):
		return fail(writerName, ruleNoOrigin)
	case err != nil:
		return fail(writerName, ruleDatabase)
	case origin != w.rec.Origin:
		return fail(writerName, ruleOrigin)
	}
	size, _ := w.rec.Log.Head()
	root, err := w.rec.Log.RootAt(size)
	if err != nil {
		return fail(writerName, ruleLogRead)
	}
	var leaf int64
	var hash []byte
	switch err := w.db.QueryRowContext(ctx, "SELECT leaf_index, hash FROM event WHERE leaf_index IS NOT NULL ORDER BY leaf_index DESC LIMIT 1").Scan(&leaf, &hash); {
	case errors.Is(err, sql.ErrNoRows):
		leaf = -1
	case err != nil:
		return fail(writerName, ruleDatabase)
	case leaf >= size:
		return fail(writerName, rulePastLog)
	default:
		proof, err := w.rec.Log.ProveInclusion(leaf, size)
		if err != nil {
			return fail(writerName, ruleLogRead)
		}
		var h tlog.EventHash
		if copy(h[:], hash) != len(h) || tlog.VerifyInclusion(h, leaf, size, root, proof) != nil {
			return fail(writerName, ruleLeafProof)
		}
	}
	if n := size - (leaf + 1); n > 0 {
		w.log.Info("store writer found orphan leaves", "count", n)
	}
	return nil
}
