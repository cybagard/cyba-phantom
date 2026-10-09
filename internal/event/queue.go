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

	// maxBulkBytes and maxEvidenceBytes are the byte caps of the two lanes
	// (SEC-15, ADR-019). Their sum is 32 MiB. The values are fixed. They are not
	// config values.
	maxBulkBytes     = 24 << 20
	maxEvidenceBytes = 8 << 20
)

var errQueueDepth = errors.New("event: queue depth is out of range")
var errQueueCounters = errors.New("event: queue needs a counters value from NewCounters")

// Queue is the bounded queue between the request path and the writer (SEC-15,
// C2, C3). It has two lanes. The bulk lane holds request and beacon events and
// has the capacity of the queue depth. The evidence lane holds the six
// evidence kinds and has the capacity max(1, depth/4). The kind decides the
// lane (Kind.IsEvidence). A kind that is not known is never queued.
//
// Each lane has its own byte cap (ADR-019): the sum of Event.Size is at most
// 24 MiB in the bulk lane and at most 8 MiB in the evidence lane. The bytes of
// one lane are never available to the other lane. An event that does not fit in
// the cap of its lane is dropped.
//
// Enqueue never blocks and starts no goroutine. A dropped event adds one to the
// counters of its client key and one to the count of its lane. The queue writes
// no log line. A log line for each drop can flood the log. A summary line needs
// a timer, and the writer has the timer.
//
// One consumer takes events with TryTake or Drain. Many producers may call
// Enqueue. The zero value is not ready for use: call NewQueue.
type Queue struct {
	bulk, evidence           chan *Event
	bulkBytes, evidenceBytes atomic.Int64
	bulkCap, evidenceCap     int64
	closed                   atomic.Bool
	wake                     chan struct{}
	counters                 *Counters

	droppedBulk, droppedEvidence, droppedInvalid atomic.Uint64
}

// NewQueue returns a queue for the queue depth depth (limits.queue_depth, 1 to
// 8192). It adds each drop to c, which NewCounters made.
func NewQueue(depth int, c *Counters) (*Queue, error) {
	return newQueue(depth, maxBulkBytes, maxEvidenceBytes, c)
}

// newQueue is NewQueue with the byte caps of the two lanes as arguments. The
// tests use it to make small caps.
func newQueue(depth int, bulkCap, evidenceCap int64, c *Counters) (*Queue, error) {
	if depth < MinQueueDepth || depth > MaxQueueDepth {
		return nil, errQueueDepth
	}
	if c == nil || c.h == nil {
		return nil, errQueueCounters
	}
	return &Queue{
		bulk:        make(chan *Event, depth),
		evidence:    make(chan *Event, max(1, depth/4)),
		bulkCap:     bulkCap,
		evidenceCap: evidenceCap,
		wake:        make(chan struct{}, 1),
		counters:    c,
	}, nil
}

// reserve adds n bytes to sum if the result stays within limit. The
// compare-and-swap loop never lets the sum pass the limit, also with many
// producers.
func reserve(sum *atomic.Int64, n, limit int64) bool {
	for {
		cur := sum.Load()
		if cur+n > limit {
			return false
		}
		if sum.CompareAndSwap(cur, cur+n) {
			return true
		}
	}
}

// Enqueue adds e to the queue and tells if the queue accepted it. It never
// blocks. It drops e and returns false in these conditions: the lane is full,
// the byte cap of the lane is full, the queue is closed, or the event is not
// valid.
//
// Only an event from NewEvent can enter the queue. An event with Size() of 0 or
// less is not valid. An event must not change after NewEvent, because the queue
// counts the bytes from the size that NewEvent set.
func (q *Queue) Enqueue(e *Event) bool {
	if e == nil {
		q.droppedInvalid.Add(1)
		q.counters.DropNoAddr()
		return false
	}
	isEvidence, err := e.Record.Kind.IsEvidence()
	n := int64(e.Size())
	if err != nil || n <= 0 {
		q.drop(&q.droppedInvalid, e)
		return false
	}
	lane, sum, limit, dropped := q.bulk, &q.bulkBytes, q.bulkCap, &q.droppedBulk
	if isEvidence {
		lane, sum, limit, dropped = q.evidence, &q.evidenceBytes, q.evidenceCap, &q.droppedEvidence
	}
	if q.closed.Load() {
		q.drop(dropped, e)
		return false
	}
	if !reserve(sum, n, limit) {
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
		sum.Add(-n)
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
		q.evidenceBytes.Add(-int64(e.Size()))
		return e, true
	default:
	}
	select {
	case e := <-q.bulk:
		q.bulkBytes.Add(-int64(e.Size()))
		return e, true
	default:
		return nil, false
	}
}

// Ready returns a channel for the consumer to wait on. A value arrives after an
// accepted event and after Close. A value can arrive when no event is left.
// Thus the consumer must do these steps: call TryTake until it returns false,
// examine Closed, then wait again.
func (q *Queue) Ready() <-chan struct{} { return q.wake }

// Close stops the queue from accepting events. Producers never close a
// channel, so Enqueue after Close counts a drop and does not panic. The
// consumer can still take what is left. Close does not wait for an Enqueue in
// flight. An Enqueue in flight can put an event in a lane after Close returns.
//
// For a complete shutdown, do these steps in this order. Stop every producer,
// for example with http.Server.Shutdown. Call Close. Call Drain. Then Drain
// takes every event that Enqueue accepted. Close can be called more than once.
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

// Bytes holds the byte sum of the events in each lane.
type Bytes struct {
	Bulk, Evidence int64
}

// Bytes returns the sum of Event.Size over the queued events of each lane. A
// sum can be a little more than the true sum while a producer or the consumer
// is between the byte update and the lane update. The bulk sum is never more
// than 24 MiB. The evidence sum is never more than 8 MiB.
func (q *Queue) Bytes() Bytes {
	return Bytes{Bulk: q.bulkBytes.Load(), Evidence: q.evidenceBytes.Load()}
}

// Dropped holds the numbers of dropped events for each lane (the lane label of
// the dropped_events metric). Invalid counts events that have no lane: a nil
// event, a kind that is not known, or an event that NewEvent did not make.
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
