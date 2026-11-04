package bundle

import "time"

// SetClock sets the clock and the sleep of the loader. A test uses it, so the
// swap gap needs no real wait. The sensor never calls it. A caller must call
// it before the first load. It is not safe while a load runs.
func (l *Loader) SetClock(now func() time.Time, sleep func(time.Duration)) {
	l.now, l.sleep = now, sleep
}
