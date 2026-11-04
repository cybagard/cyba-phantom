//go:build race

package bait

// The race detector drops pool items at random. A render takes the token pool
// two times and prints through the fmt pool. So the check compares means of
// 100 runs, and the means stay within 2 of each other.
func init() { raceAllocSlack = 2 }
