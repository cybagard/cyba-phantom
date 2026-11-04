package bundle

import "time"

// SetClock sets the clock and the sleep of the loader. A test uses it, so the
// swap gap needs no real wait. The sensor never calls it. A caller must call
// it before the first load. A call after the first load is not safe. The token
// ring and the event times read the clock on request goroutines.
func (l *Loader) SetClock(now func() time.Time, sleep func(time.Duration)) {
	l.now, l.sleep = now, sleep
}
