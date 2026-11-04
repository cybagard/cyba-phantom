package token

import (
	"fmt"
	"sync/atomic"
	"time"
)

// replacedFor is how long the key set of a replaced bundle stays in the ring
// (ADR-036 decision 14). It is the 24 h window and the 1 h tolerance.
const replacedFor = 25 * time.Hour

// Ring holds the key set of the running bundle and the key set of the bundle
// that it replaced (ADR-036). It holds key sets only, never a
// bundle. A Ring is safe for concurrent use. A copy of a Ring shares its
// state. A new Ring is empty. A restart makes a new Ring, so it has one key
// set after the first Swap.
//
// A Swap makes the new key set current. The current key set becomes the
// replaced one, and the key set that was replaced leaves the ring. The
// replaced key set also leaves the ring 25 h after the Swap.
//
// A Swap with a nil key set is for a bundle with no key set. The nil key
// set is current, so the ring holds the replaced key set only. Then
// Result.Set is Second. A second such Swap leaves the ring with no key set.
// This keeps the rule: the ring holds the running bundle and the bundle that
// it replaced, and nothing older.
//
// The clock is the wall clock, which the time unit of a token needs. The end
// is 25 h of wall time after the Swap. Swap strips the monotonic reading of
// the clock from the end. A step of the wall clock moves the end: forward
// makes it earlier, and back makes it later.
type Ring struct{ *ringState }

type ringState struct {
	now     func() time.Time
	cur     atomic.Pointer[snapshot]
	futures atomic.Uint64
}

// snapshot is one value of the ring. A Swap makes a new one. A Verify or a
// Check reads it with one atomic load.
type snapshot struct {
	sets  [2]*KeySet // the current key set, then the replaced one
	until time.Time  // the replaced key set leaves the ring at this time
}

// NewRing makes an empty ring. now gives the time of Verify, of Check and of
// Swap. A nil now is time.Now.
func NewRing(now func() time.Time) *Ring {
	if now == nil {
		now = time.Now
	}
	return &Ring{&ringState{now: now}}
}

// Swap makes next the current key set. The old current key set becomes the
// replaced one, for 25 h. One compare-and-swap of a pointer changes the ring.
// Thus a Verify or a Check sees the ring before or after a Swap and nothing
// between.
func (r *Ring) Swap(next *KeySet) {
	// Round(0) strips the monotonic reading, so Before compares wall time.
	until := r.now().Round(0).Add(replacedFor)
	for {
		old := r.cur.Load()
		s := &snapshot{until: until}
		s.sets[0] = next
		if old != nil {
			s.sets[1] = old.sets[0]
		}
		if r.cur.CompareAndSwap(old, s) {
			return
		}
	}
}

// Len gives the number of key sets that Verify and Check use now: 0, 1 or 2.
func (r *Ring) Len() int {
	n := 0
	for _, k := range r.active(r.cur.Load(), r.now()) {
		if k != nil && k.keySetState != nil {
			n++
		}
	}
	return n
}

// Futures gives the number of future tokens that Verify and Check have found.
func (r *Ring) Futures() uint64 { return r.futures.Load() }

// active gives the key sets of s that count at time now.
func (r *Ring) active(s *snapshot, now time.Time) []*KeySet {
	if s == nil {
		return nil
	}
	if now.Before(s.until) {
		return s.sets[:]
	}
	return s.sets[:1]
}

// Verify checks a token against the key sets of the ring. It keeps the rules
// of the function Verify: one decrypt for each key set, and no early return.
// Result.Set is First for the current key set and Second for the replaced
// one. For a match, Stale is true for an age of more than 25 h. Future is
// true for a token more than 1 h ahead of the clock. A future token is also
// stale, and the counter of Futures counts it. Verify never refuses a token
// for its age. It does not allocate in steady state.
func (r *Ring) Verify(tok [Size]byte) Result {
	now := r.now()
	buf := scratch.Get().(*[2 * Size]byte)
	res := r.verifyAt(buf, r.active(r.cur.Load(), now), now, tok, true)
	clear(buf[:])
	scratch.Put(buf)
	return res
}

// verifyAt checks one block against sets at time now, with the buffer of the
// caller. It always decrypts. When parsed is false, the Result is always
// zero. For a match it sets the window class, and it counts a future token.
func (r *Ring) verifyAt(buf *[2 * Size]byte, sets []*KeySet, now time.Time, tok [Size]byte, parsed bool) Result {
	res := verifyIn(buf, sets, tok)
	if !parsed || !res.OK {
		return Result{}
	}
	res.Stale, res.Future = classify(res.Unit, now)
	if res.Future {
		r.futures.Add(1)
	}
	return res
}

// Format writes one fixed text for each verb that fmt gives it. The text
// holds no key set, no trap id and no counter. Only a *Ring uses Format. fmt
// does not call it for a *Ring in an unexported struct field. The test shows
// that such a field still prints no trap id and no counter.
func (r *Ring) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("token.Ring"))
}
