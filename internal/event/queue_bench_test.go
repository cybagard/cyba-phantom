package event

import "testing"

// T-U-17: the accepted path of Enqueue makes no allocation (C2, C3).
func TestTU17_EnqueueAcceptedNoAlloc(t *testing.T) {
	c := NewCounters()
	q, err := NewQueue(MaxQueueDepth, c)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []Kind{KindRequest, KindCallback} {
		e := qEvent(t, k, "192.0.2.1")
		if n := testing.AllocsPerRun(100, func() {
			if !q.Enqueue(e) {
				t.Fatal("enqueue dropped the event")
			}
		}); n != 0 {
			t.Errorf("%v: %v allocations on the accepted path, want 0", k, n)
		}
	}
}

func BenchmarkEnqueueAccepted(b *testing.B) {
	q, err := NewQueue(MaxQueueDepth, NewCounters())
	if err != nil {
		b.Fatal(err)
	}
	e := qEvent(b, KindRequest, "192.0.2.1")
	b.ReportAllocs()
	for b.Loop() {
		if !q.Enqueue(e) {
			b.Fatal("enqueue dropped the event")
		}
		q.TryTake()
	}
}

func BenchmarkEnqueueDropped(b *testing.B) {
	q, err := NewQueue(1, NewCounters())
	if err != nil {
		b.Fatal(err)
	}
	e := qEvent(b, KindRequest, "192.0.2.1")
	q.Enqueue(e)
	b.ReportAllocs()
	for b.Loop() {
		q.Enqueue(e)
	}
}
