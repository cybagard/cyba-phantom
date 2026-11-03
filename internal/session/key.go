// Package session holds the day key of the session id and of ip_hmac. The
// writer and the request path take the key from one DayKey. Thus both compute
// the same values for one UTC date.
package session

import (
	"crypto/rand"
	"fmt"
	"sync/atomic"
	"time"
)

// dayLayout is the layout of the UTC date that a key is for.
const dayLayout = "2006-01-02"

// state is the key of one UTC date. A state is never changed after it is
// published through a DayKey.
type state struct {
	date string
	key  [32]byte
}

func newState(date string) *state {
	s := &state{date: date}
	_, _ = rand.Read(s.key[:]) // since Go 1.24 Read does not return an error
	return s
}

// DayKey holds the day key: 32 random bytes that live in memory only. The key
// is for one UTC date. It never goes to a file, a log, an error or a metric.
// There is no exported field and no accessor for the key bytes.
//
// A DayKey is safe for use by many goroutines. Make one with NewDayKey: the
// zero DayKey has a nil pointer inside and At panics on it.
type DayKey struct {
	cur func() *atomic.Pointer[state]
}

// NewDayKey returns a DayKey with no key. The first use makes a random key. A
// new DayKey never has the key of another DayKey.
func NewDayKey() *DayKey {
	p := new(atomic.Pointer[state])
	return &DayKey{cur: func() *atomic.Pointer[state] { return p }}
}

func keyOf(s *state) Key {
	return Key{s: func() *state { return s }}
}

// At returns the key for the UTC date of t. Sometimes that date is not the
// date of the current key, in either direction. Then At makes a new key and
// drops the old one. Thus a clock step back never brings an old key back.
//
// When two goroutines see one new date at one time, both get the same key. The
// returned Key stays the same after a later date change.
func (d *DayKey) At(t time.Time) Key {
	date := t.UTC().Format(dayLayout)
	cur := d.cur()
	for {
		old := cur.Load()
		if old != nil && old.date == date {
			return keyOf(old)
		}
		n := newState(date)
		if cur.CompareAndSwap(old, n) {
			return keyOf(n)
		}
		// Another goroutine won. Use its state when its date is ours.
		if w := cur.Load(); w != nil && w.date == date {
			return keyOf(w)
		}
	}
}

// Format writes a fixed text and no key byte, for every fmt verb.
func (d *DayKey) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("session.DayKey{}"))
}

// Key is the day key of one UTC date. A Key stays the same when the DayKey
// changes the date. Make a Key only with DayKey.At.
//
// fmt cannot call Format on the unexported field of a struct. Instead, it
// prints the fields, and for a pointer it prints only an address at depth
// above zero. For a verb that does not fit, such as %s, it also prints the
// target of a pointer. Thus the key bytes are behind a func.
//
// The zero Key has no key. IPHMAC of the zero Key returns an empty text and
// SessionID of it returns nil. They never use an all-zero key.
type Key struct {
	s func() *state
}

// st returns the state of the key, or nil for the zero Key.
func (k Key) st() *state {
	if k.s == nil {
		return nil
	}
	return k.s()
}

// Format writes a fixed text and no key byte, for every fmt verb.
func (k Key) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("session.Key{}"))
}
