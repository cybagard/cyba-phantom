package sensortime

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// stressJumps is the number of jumps of the read mark stress test. A race
// build sets a lower value.
var stressJumps = 2000000

// T-U-30 (read mark order): reader goroutines call Now in a loop. The writer
// makes jumps of 1 h and 1 ms, each a Check and then Committed. The boot clock
// is fixed, so a value of Now names the base that it loaded. A Now that
// loaded the base of jump k-1 must be in the Read or in the Committed of jump
// k. The test counts the reads that are in none.
func TestTU30_ReadMarkStressNoLostRead(t *testing.T) {
	const readers = 4
	n := stressJumps
	step := hourMS + 1
	f, c := graceClock(t, s0, time.Hour)
	var stop atomic.Bool
	seen := make([][]bool, readers)
	var wg sync.WaitGroup
	for i := range seen {
		seen[i] = make([]bool, n+1)
		wg.Add(1)
		go func(seen []bool) {
			defer wg.Done()
			for !stop.Load() {
				v, err := c.Now()
				if err != nil {
					return
				}
				k := (v - s0) / step
				if (v-s0)%step == 0 && k >= 0 && k <= int64(n) {
					seen[k] = true
				}
			}
		}(seen[i])
	}
	reported := make([]bool, n+1)
	s := s0
	for k := 1; k <= n; k++ {
		s += step
		f.wall.Store(s)
		r, err := c.Check()
		if err != nil || r.Jump == nil || !r.Write {
			stop.Store(true)
			wg.Wait()
			t.Fatalf("jump %d: %+v, %v", k, r, err)
		}
		reported[k] = c.Committed() || r.Read
	}
	stop.Store(true)
	wg.Wait()
	lost := 0
	for k := 1; k <= n; k++ {
		for i := range seen {
			if seen[i][k-1] && !reported[k] {
				lost++
				break
			}
		}
	}
	if lost > 0 {
		t.Fatalf("%d of %d jumps lost a read", lost, n)
	}
}
