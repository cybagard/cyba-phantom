//go:build race

package bait

// The race detector drops pool items at random. A render takes the token pool
// two times and prints through the fmt pool. So the check compares means of
// 100 runs, and the means stay within 2 of each other.
func init() { raceAllocSlack = 2 }

// With the race detector, a callback event allocated 102.5 to 106.0 times in 10
// runs of TestTS32CallbackRequestAllocs. The test bound for each event is
// eventAllocs plus 10 %, so 105 gives 115.5.
func init() { eventAllocs = 105 }
