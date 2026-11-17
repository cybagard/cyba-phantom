//go:build !linux && !darwin

package sensortime

import "time"

// start holds the Go monotonic clock reading of the process start.
var start = time.Now()

// DefaultSource has no boot id. The Go monotonic clock gives the elapsed
// time. The caller takes the reboot rule at each start. This GOOS is not
// supported for production.
func DefaultSource() Source {
	return newSource(
		func() (time.Duration, error) { return time.Since(start), nil },
		func() (string, error) { return "", nil },
	)
}
