package tlog

import (
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
)

// proofLoaders is the number of goroutines that call RootAt and ProveInclusion
// while BenchmarkAppendUnderProofs appends.
const proofLoaders = 2

// BenchmarkAppendUnderProofs measures the latency of Append while other
// goroutines call RootAt and ProveInclusion on the same log. Each of these calls
// holds the write lock of the log while it reads tiles, so Append waits for
// them. The log has bigLeaves leaves, so a proof reads tiles of level 0, 1 and
// 2. The ns/op value is the latency of one Append. The setup does not call
// fsync, and the timed Append calls do.
func BenchmarkAppendUnderProofs(b *testing.B) {
	dir := filepath.Join(b.TempDir(), "state")
	if err := os.Mkdir(dir, 0o700); err != nil {
		b.Fatal(err)
	}
	state, err := os.OpenRoot(dir)
	if err != nil {
		b.Fatal(err)
	}
	defer state.Close()
	l, err := OpenLog(state, "tlog")
	if err != nil {
		b.Fatal(err)
	}
	defer l.Close()
	restore := withoutSync(b)
	_, err = l.AppendBatch(batchOf(0, bigLeaves))
	restore()
	if err != nil {
		b.Fatal(err)
	}

	var (
		wg    sync.WaitGroup
		stop  = make(chan struct{})
		calls atomic.Int64
		fail  atomic.Pointer[error]
	)
	for range proofLoaders {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				size, root := l.Head()
				got, err := l.RootAt(size)
				if err == nil && got != root {
					err = newError("root", ruleProofRead)
				}
				if err == nil {
					_, err = l.ProveInclusion(size/2, size)
				}
				if err != nil {
					fail.CompareAndSwap(nil, &err)
					return
				}
				calls.Add(2)
			}
		}()
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := l.Append(testEvent(bigLeaves + i)); err != nil {
			b.StopTimer()
			close(stop)
			wg.Wait()
			b.Fatal(err)
		}
	}
	b.StopTimer()
	close(stop)
	wg.Wait()
	if err := fail.Load(); err != nil {
		b.Fatal(*err)
	}
	b.ReportMetric(float64(calls.Load())/float64(b.N), "proofcalls/op")
}
