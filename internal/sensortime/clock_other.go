//go:build !linux && !darwin

package sensortime

// DefaultSource has no boot id. The Go monotonic clock gives the elapsed
// time. This GOOS is not supported for production.
func DefaultSource() Source { return monotonicSource() }
