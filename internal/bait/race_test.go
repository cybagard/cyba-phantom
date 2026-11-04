//go:build race

package bait

// With the race detector the token buffer pool can drop a buffer. A render
// takes two buffers (mint and verify), so its count can change by 2.
func init() { raceAllocSlack = 2 }
