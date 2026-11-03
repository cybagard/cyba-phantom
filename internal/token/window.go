package token

import "time"

// The window of a fresh token, in time units (ADR-036 decision 13). The age is
// now minus the unit of the token. A token is fresh for -freshAhead to
// freshBehind. That is 1 h ahead of the clock and 25 h behind it.
const (
	freshAhead  = 6
	freshBehind = 150
)

// age gives now minus unit as a signed 20-bit value, in time units. The wall
// clock gives now. A wrap at 2^20 and a clock before the epoch give a value
// in this range.
func age(unit uint32, now time.Time) int64 {
	d := (unitOf(now) - uint64(unit)) & unitMask
	return int64(d<<(64-unitBits)) >> (64 - unitBits)
}

// classify gives the class of a token from its time unit. A token older than
// 25 h is stale. A token more than 1 h ahead of the clock is future, and also
// stale. Each age gives a class.
func classify(unit uint32, now time.Time) (stale, future bool) {
	a := age(unit, now)
	future = a < -freshAhead
	return a > freshBehind || future, future
}
