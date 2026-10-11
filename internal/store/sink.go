package store

import (
	"errors"
	"math"
	"sync/atomic"
	"time"

	"golang.org/x/mod/sumdb/note"

	"github.com/cybagard/cyba-phantom/internal/tlog"
)

const rowTimeout = 5 * time.Second

// Fixed error classes of the checkpoint sink.
const (
	sinkName     = "checkpoint sink"
	ruleNote     = "note is not valid"
	ruleSize     = "note has a size that is not accepted"
	ruleRowFork  = "a fork signal stopped the sink"
	ruleRowReply = "no reply from the writer"
)

// Sink is the tlog.NoteSink of the store (FR-09). It stores the checkpoint row
// through the writer goroutine, and only then gives the note to the spool.
type Sink struct {
	w        *Writer
	spool    tlog.NoteSink
	origin   string
	verifier note.Verifier

	timeout time.Duration // a test sets it; zero means rowTimeout
	forked  atomic.Bool   // a fork signal came: no later note goes to the spool
	missing atomic.Uint64 // notes that went to the spool with no row
}

var _ tlog.NoteSink = (*Sink)(nil)

// NewSink returns a sink. w may be nil when the store did not open: the sink then
// gives each verified note to the spool with no row. origin and v check each
// note.
func NewSink(w *Writer, spool tlog.NoteSink, origin string, v note.Verifier) *Sink {
	return &Sink{w: w, spool: spool, origin: origin, verifier: v}
}

// RowMissing returns the number of notes that went to the spool with no row. It
// is for phantom_checkpoint_row_missing_total. It is safe for concurrent use.
func (s *Sink) RowMissing() uint64 { return s.missing.Load() }

// Add parses the note and refuses size 0 and a size that is not the size of the
// note. Then:
//   - after a fork signal, it returns an error and gives nothing to the spool;
//   - with no writer, or a writer that is not healthy, it gives the note to the
//     spool with no row and counts the missing row;
//   - otherwise it asks the writer to store the row, and gives the note to the
//     spool only after the row is stored. Another note for a stored size is a
//     fork signal: the writer stops, and so does the sink. An error, or no reply
//     in 5 s, gives an error and the spool gets nothing.
//
// The same note a second time is a success and changes nothing.
func (s *Sink) Add(size uint64, msg []byte) error {
	cp, err := tlog.ParseCheckpoint(msg, s.origin, s.verifier)
	if err != nil {
		return fail(sinkName, ruleNote)
	}
	if cp.Size == 0 || cp.Size != size || cp.Size > math.MaxInt64 {
		return fail(sinkName, ruleSize)
	}
	if s.forked.Load() {
		return fail(sinkName, ruleRowFork)
	}
	var stopErr error // one read of the writer state for all branches
	if s.w != nil {
		stopErr = s.w.Err()
	}
	if s.forkStop(stopErr) {
		return fail(sinkName, ruleRowFork)
	}
	if s.w == nil || stopErr != nil {
		if err := s.spool.Add(size, msg); err != nil {
			return err
		}
		s.missing.Add(1)
		return nil
	}
	if err := s.request(rowRequest{size: cp.Size, root: cp.Root, msg: msg, reply: make(chan error, 1)}); err != nil {
		if s.forkStop(s.w.Err()) {
			return fail(sinkName, ruleRowFork)
		}
		return err
	}
	return s.spool.Add(size, msg)
}

// forkStop tells if stopErr, the error of a stopped writer, is a fork signal.
// When the writer stopped for a fork signal, the sink sets its fork flag. This
// also applies when the reply of the writer comes after the timer.
func (s *Sink) forkStop(stopErr error) bool {
	var e *Error
	if !errors.As(stopErr, &e) || e.Rule != ruleFork {
		return false
	}
	s.forked.Store(true)
	return true
}

// request sends rq to the writer and waits for the reply. One timer bounds the
// send and the wait: a stopped writer takes no request.
func (s *Sink) request(rq rowRequest) error {
	d := s.timeout
	if d <= 0 {
		d = rowTimeout
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case s.w.rows <- rq:
	case <-t.C:
		return fail(sinkName, ruleRowReply)
	}
	select {
	case err := <-rq.reply:
		return err
	case <-t.C:
		return fail(sinkName, ruleRowReply)
	}
}
