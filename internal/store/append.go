package store

import "github.com/cybagard/cyba-phantom/internal/tlog"

// appender puts the hashes of the evidence events of one batch in the Merkle
// log. It returns the leaf index of the first hash. The next hashes have the
// next indices. On an error, no leaf of the batch is in the log.
type appender interface {
	AppendBatch([]tlog.EventHash) (first int64, err error)
}

var _ appender = (*tlog.Log)(nil)
