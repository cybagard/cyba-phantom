//go:build race

package sensortime

// The race build is slower, so the stress test makes fewer jumps.
func init() { stressJumps = 100000 }
