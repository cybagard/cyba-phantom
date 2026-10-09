package event

import (
	"errors"
	"net/netip"
	"sync/atomic"
)

const (
	// MinQueueDepth and MaxQueueDepth are the limits of the queue depth
	// (limits.queue_depth).
	MinQueueDepth = 1
	MaxQueueDepth = 8192

	// maxQueueBytes is the byte budget of both lanes together (SEC-15). The
	// value is fixed. It is not a config value.
	maxQueueBytes = 32 << 20
)

var errQueueDepth = errors.New("event: queue depth is out of range")
var errQueueCounters = errors.New("event: queue needs a counters value from NewCounters")

// Queue is the bounded queue between the request path and the writer (SEC-15,
// C2, C3). It has two lanes. The bulk lane holds request and beacon events and
// has the capacity of the queue depth. The evidence lane holds the six
// evidence kinds and has the capacity max(1, depth/4). The kind decides the
// lane (Kind.IsEvidence). A kind that is not known is never queued.
//
// A sum of Event.Size over both lanes is at most 32 MiB. An event that does not
// fit is dropped.
//
// Enqueue never blocks and starts no goroutine. A dropped event adds one to the
// counters of its client key and one to the count of its lane. The queue writes
// no log line: a log line for each drop would be a log flood, and a summary
// line needs a timer, which belongs to the writer.
//
// One consumer takes events with TryTake or Drain. Many producers may call
// Enqueue. The zero value is not ready for use: call NewQueue.
type Queue struct {
	bulk, evidence chan *Event
	bytes          atomic.Int64
	budget         int64
	closed         atomic.Bool
	wake           chan struct{}
	counters       *Counters

	droppedBulk, droppedEvidence, droppedInvalid atomic.Uint64
}

// NewQueue returns a queue for the queue depth depth (limits.queue_depth, 1 to
// 8192). It adds each drop to c, which NewCounters made.
func NewQueue(depth int, c *Counters) (*Queue, error) {
	return newQueue(depth, maxQueueBytes, c)
}

func newQueue(depth int, budget int64, c *Counters) (*Queue, error) {
	if depth < MinQueueDepth || depth > MaxQueueDepth {
		return nil, errQueueDepth
	}
	if c == nil || c.h == nil {
		return nil, errQueueCounters
	}
	return &Queue{
		bulk:     make(chan *Event, depth),
		evidence: make(chan *Event, max(1, depth/4)),
		budget:   budget,
		wake:     make(chan struct{}, 1),
		counters: c,
	}, nil
}

// reserve adds n bytes to the sum if the result stays within the budget. The
// compare-and-swap loop never lets the sum pass the budget, also with many
// producers.
func (q *Queue) reserve(n int64) bool {
	for {
		cur := q.bytes.Load()
		if cur+n > q.budget {
			return false
		}
		if q.bytes.CompareAndSwap(cur, cur+n) {
			return true
		}
	}
}

// Enqueue adds e to the queue and tells if the queue accepted it. It never
// blocks. If the lane is full, the byte budget is used up, the queue is closed,
// or the event is not valid, it drops e and returns false.
func (q *Queue) Enqueue(e *Event) bool {
	if e == nil {
		q.droppedInvalid.Add(1)
		q.counters.DropNoAddr()
		return false
	}
	isEvidence, err := e.Record.Kind.IsEvidence()
	if err != nil {
		q.drop(&q.droppedInvalid, e)
		return false
	}
	lane, dropped := q.bulk, &q.droppedBulk
	if isEvidence {
		lane, dropped = q.evidence, &q.droppedEvidence
	}
	if q.closed.Load() {
		q.drop(dropped, e)
		return false
	}
	n := int64(e.Size())
	if !q.reserve(n) {
		q.drop(dropped, e)
		return false
	}
	select {
	case lane <- e:
		select {
		case q.wake <- struct{}{}:
		default:
		}
		return true
	default:
		q.bytes.Add(-n)
		q.drop(dropped, e)
		return false
	}
}

// drop adds one to the lane count and one to the counters of the client key.
func (q *Queue) drop(count *atomic.Uint64, e *Event) {
	count.Add(1)
	if e.DB.IP != "" {
		if a, err := netip.ParseAddr(e.DB.IP); err == nil {
			q.counters.Drop(a)
			return
		}
	}
	q.counters.DropNoAddr()
}

// TryTake returns the next event without waiting. It takes the evidence lane
// first. It takes the bulk lane only when the evidence lane is empty. The
// second result is false when both lanes are empty.
func (q *Queue) TryTake() (*Event, bool) {
	select {
	case e := <-q.evidence:
		q.bytes.Add(-int64(e.Size()))
		return e, true
	default:
	}
	select {
	case e := <-q.bulk:
		q.bytes.Add(-int64(e.Size()))
		return e, true
	default:
		return nil, false
	}
}

// Ready returns a channel for the consumer to wait on. A value arrives after an
// accepted event and after Close. A value can arrive when no event is left, so
// the consumer must call TryTake in a loop until it returns false, then check
// Closed, then wait again.
func (q *Queue) Ready() <-chan struct{} { return q.wake }

// Close stops the queue from accepting events. Producers never close a
// channel, so Enqueue after Close counts a drop and does not panic. The
// consumer can still take what is left. An Enqueue that runs at the same time
// as Close can still be accepted: call Drain after Closed is true to take it.
// Close can be called more than once.
func (q *Queue) Close() {
	if q.closed.CompareAndSwap(false, true) {
		select {
		case q.wake <- struct{}{}:
		default:
		}
	}
}

// Closed tells if Close was called.
func (q *Queue) Closed() bool { return q.closed.Load() }

// Drain takes all events that are in the lanes now, evidence first. It is for
// the consumer after Close.
func (q *Queue) Drain() []*Event {
	var out []*Event
	for {
		e, ok := q.TryTake()
		if !ok {
			return out
		}
		out = append(out, e)
	}
}

// Bytes returns the sum of Event.Size over the queued events. It can be a
// little more than the true sum while an event is in transit. It is never more
// than the budget.
func (q *Queue) Bytes() int64 { return q.bytes.Load() }

// Dropped holds the numbers of dropped events for each lane (the lane label of
// the dropped_events metric). Invalid counts events that have no lane: a nil
// event or a kind that is not known.
type Dropped struct {
	Bulk, Evidence, Invalid uint64
}

// Dropped returns the numbers of dropped events since the queue started.
func (q *Queue) Dropped() Dropped {
	return Dropped{
		Bulk:     q.droppedBulk.Load(),
		Evidence: q.droppedEvidence.Load(),
		Invalid:  q.droppedInvalid.Load(),
	}
}
