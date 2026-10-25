package listener

import (
	"os"
	"sync"
	"syscall"
	"testing"
)

// The cache logger of certmagic is not readable from outside the package, so
// the test reads standard error. With the default logger, the maintenance
// goroutine writes a line at its start and at its stop. The test points file
// descriptor 2 at a file while it makes and stops the cache.
func TestTS16CacheLoggerWritesNothingToStderr(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "stderr")
	mustNil(t, err)
	defer f.Close()
	saved, err := syscall.Dup(2)
	mustNil(t, err)
	var once sync.Once
	restore := func() {
		once.Do(func() {
			mustNil(t, syscall.Dup3(saved, 2, 0))
			syscall.Close(saved)
		})
	}
	t.Cleanup(restore)
	mustNil(t, syscall.Dup3(int(f.Fd()), 2, 0))
	a := newTestACME(t, nil)
	a.Stop()
	restore()
	if b, err := os.ReadFile(f.Name()); err != nil || len(b) != 0 {
		t.Errorf("the cache wrote %q to stderr, %v; want nothing", b, err)
	}
}
