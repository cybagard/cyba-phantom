// Package testutil holds helpers that tests of more than one package share. It
// imports only the standard library, never a package of this module, so that
// each internal test package can import it with no import cycle.
package testutil

import (
	"testing"
	"time"
)

// pollEvery is the time between two checks of the condition in WaitFor.
const pollEvery = time.Millisecond

// WaitFor waits until cond is true, and fails the test if it is not true when
// limit has passed. Use it where a test has no channel to wait on. It checks
// cond one more time at the limit, so a slow machine does not give a false
// failure when cond became true just before the limit.
func WaitFor(t testing.TB, cond func() bool, limit time.Duration) {
	t.Helper()
	deadline := time.NewTimer(limit)
	defer deadline.Stop()
	tick := time.NewTicker(pollEvery)
	defer tick.Stop()
	for !cond() {
		select {
		case <-deadline.C:
			if cond() {
				return
			}
			t.Fatalf("testutil: the condition was not true after %v", limit)
		case <-tick.C:
		}
	}
}

// Set sets *p to v and restores the old value when the test ends. Use it for a
// test seam, which is a package variable that only tests change.
func Set[T any](t testing.TB, p *T, v T) {
	t.Helper()
	old := *p
	t.Cleanup(func() { *p = old })
	*p = v
}
